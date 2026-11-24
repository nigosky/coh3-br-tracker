"""Renderizador gráfico seguro e otimizado (Pillow) para Cards de Partidas e Tabelas de Ranking com Avatares Steam."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from relic_api import (
    ALLOWED_RELIC_HOSTS,
    BASE_URL as RELIC_BASE_URL,
    CORE_BR_ROSTER,
    MANUAL_OTHER_BR_DISPLAY,
    MAP_MK_SUFFIX_RE,
    OFFICIAL_COH3_BATTLEGROUPS,
    OFFICIAL_COH3_MAP_NAMES,
    STEAM_ID64_VALID_RE,
    build_roster_lookup_maps,
    clean_map_name,
    format_bound_display_alias,
    normalize_battlegroup,
)
from security import (
    HttpsOnlySchemeHandler,
    build_no_redirect_https_opener,
    create_hardened_ssl_context,
    read_bounded_http_body,
    redact_secrets,
    strip_unsafe_chars,
    validate_https_endpoint,
)

# Proteção estrita contra Decompression Bomb (CWE-409)
Image.MAX_IMAGE_PIXELS = 4_000_000

logger = logging.getLogger("coh3_br.renderer")

BASE_DIR = Path(__file__).resolve().parent
FACTIONS_DIR = BASE_DIR / "assets" / "factions"
FLAGS_DIR = BASE_DIR / "assets" / "flags"
MAPS_DIR = BASE_DIR / "assets" / "maps"
BATTLEGROUPS_DIR = BASE_DIR / "assets" / "battlegroups"
VETERANOS_BADGE_PATH = BASE_DIR / "assets" / "discord_veteranos_patente.png"
BRT_TZ = timezone(timedelta(hours=-3))

SAFE_FLAG_CODE_RE = re.compile(r"^[a-z]{2}$")
MAX_FLAG_ASSET_BYTES = 65_536      # 64 KB
SAFE_MAP_KEY_RE = re.compile(r"^[a-z0-9_]{2,64}$")
MAX_MAP_ASSET_BYTES = 262_144      # 256 KB
SAFE_BG_KEY_RE = re.compile(r"^[a-z0-9_]{2,48}$")
MAX_BG_ASSET_BYTES = 65_536        # 64 KB

STEAM_API_SUMMARIES_URL = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
STEAM_API_SUMMARIES_PATH_RE = re.compile(r"^/ISteamUser/GetPlayerSummaries/v0*2/?$")
STEAM_API_KEY_VALID_RE = re.compile(r"^[A-Za-z0-9]{16,64}$")
STEAM_XML_AVATAR_MEDIUM_RE = re.compile(
    r"<avatarMedium>\s*<!\[CDATA\[(https://[^\s\]]+)\]\]>\s*</avatarMedium>",
    re.IGNORECASE,
)
STEAM_XML_AVATAR_FULL_RE = re.compile(
    r"<avatarFull>\s*<!\[CDATA\[(https://[^\s\]]+)\]\]>\s*</avatarFull>",
    re.IGNORECASE,
)
SAFE_AVATAR_EXT_RE = re.compile(r"\.(?:jpg|jpeg|png|webp)$", re.IGNORECASE)

ALLOWED_STEAM_API_HOSTS: frozenset[str] = frozenset({"api.steampowered.com"})
ALLOWED_STEAM_XML_HOSTS: frozenset[str] = frozenset({"steamcommunity.com"})
ALLOWED_STEAM_AVATAR_HOSTS: frozenset[str] = frozenset(
    {
        "avatars.steamstatic.com",
        "avatars.akamai.steamstatic.com",
        "avatars.cloudflare.steamstatic.com",
        "avatars.fastly.steamstatic.com",
        "steamcdn-a.akamaihd.net",
        "cdn.akamai.steamstatic.com",
    }
)
ALLOWED_DECODER_FORMATS: frozenset[str] = frozenset({"JPEG", "PNG", "WEBP", "GIF"})

MAX_STEAM_XML_BYTES = 65_536       # 64 KB
MAX_STEAM_API_JSON_BYTES = 524_288 # 512 KB
MAX_STEAM_AVATAR_BYTES = 524_288   # 512 KB
MAX_RELIC_LOOKUP_BYTES = 131_072   # 128 KB

AXIS_FACTIONS: frozenset[str] = frozenset(
    {"Wehrmacht", "Afrikakorps", "Afrika Korps", "Deutsches Afrikakorps", "DAK", "Wehr", "german", "German", "dak"}
)
ALLIES_FACTIONS: frozenset[str] = frozenset(
    {"US Forces", "British Forces", "USF", "UKF", "american", "American", "british", "British"}
)

FACTION_TO_ASSET: dict[str, str] = {
    "US Forces": "american",
    "USF": "american",
    "american": "american",
    "British Forces": "british",
    "UKF": "british",
    "british": "british",
    "Afrikakorps": "dak",
    "DAK": "dak",
    "dak": "dak",
    "Wehrmacht": "german",
    "Wehr": "german",
    "german": "german",
}

HAS_CJK_RE = re.compile(
    r"[\u1100-\u11ff\u2e80-\u33ff\u3400-\u4dbf\u4e00-\u9fff"
    r"\uac00-\ud7af\uf900-\ufaff\ufe30-\ufe4f\uff00-\uffef]"
)
NEEDS_DEJAVU_RE = re.compile(r"[^\u0000-\u024f\u2013\u2014\u2022\u2026]")


class _SteamXMLRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permite até 3 redirecionamentos exclusivamente dentro de https://steamcommunity.com/(id|profiles)/."""

    max_redirections = 3

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        try:
            parsed = validate_https_endpoint(newurl, ALLOWED_STEAM_XML_HOSTS)
        except ValueError as exc:
            raise urllib.error.HTTPError(req.full_url, code, f"Redirect Steam bloqueado: {exc}", headers, fp) from None
        if not (parsed.path.startswith("/id/") or parsed.path.startswith("/profiles/")):
            raise urllib.error.HTTPError(req.full_url, code, "Caminho de redirect Steam não autorizado", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_STEAM_XML_OPENER = urllib.request.build_opener(
    HttpsOnlySchemeHandler(),
    urllib.request.HTTPSHandler(context=create_hardened_ssl_context()),
    _SteamXMLRedirectHandler(),
)
_NO_REDIRECT_OPENER = build_no_redirect_https_opener()


# ---------------------------------------------------------------------------
# Carregamento seguro de fontes com cache em memória (Latim, Cirílico e CJK)
# ---------------------------------------------------------------------------
_FONT_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont | ImageFont.ImageFont] = {}
_DISCOVERED_CJK_FONTS: dict[str, list[str]] | None = None
_WARNED_MISSING_CJK = False

FONT_CANDIDATES: dict[str, list[str]] = {
    "regular": [
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Regular.ttf",
        "/usr/share/fonts/truetype/roboto/hinted/Roboto-Regular.ttf",
        "/usr/share/fonts/truetype/roboto/Roboto-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ],
    "bold": [
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/hinted/Roboto-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/Roboto-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ],
    "condensed_bold": [
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoCondensed-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/hinted/RobotoCondensed-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/RobotoCondensed-Bold.ttf",
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ],
    "bg_italic": [
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoCondensed-Italic.ttf",
        "/usr/share/fonts/truetype/roboto/hinted/RobotoCondensed-Italic.ttf",
        "/usr/share/fonts/truetype/roboto/RobotoCondensed-Italic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSansNarrow-Italic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf",
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Italic.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ],
    "bg_italic_bold": [
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoCondensed-BoldItalic.ttf",
        "/usr/share/fonts/truetype/roboto/hinted/RobotoCondensed-BoldItalic.ttf",
        "/usr/share/fonts/truetype/roboto/RobotoCondensed-BoldItalic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSansNarrow-BoldItalic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-BoldItalic.ttf",
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-BoldItalic.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ],
    "unicode_regular": ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"],
    "unicode_bold": ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
    "cjk_regular": [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
    ],
    "cjk_bold": [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Bold.otf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    ],
}


def _discover_cjk_fonts() -> dict[str, list[str]]:
    """Varre /usr/share/fonts uma única vez para localizar fontes CJK mesmo se o caminho mudar entre versões do SO."""
    global _DISCOVERED_CJK_FONTS
    if _DISCOVERED_CJK_FONTS is not None:
        return _DISCOVERED_CJK_FONTS

    regular: list[str] = []
    bold: list[str] = []
    fonts_root = Path("/usr/share/fonts")
    if fonts_root.is_dir():
        for p in sorted(fonts_root.rglob("*")):
            if not p.is_file() or p.suffix.lower() not in (".ttc", ".ttf", ".otf"):
                continue
            low = p.name.lower()
            if not any(tok in low for tok in ("notosanscjk", "notosanssc", "notosanstc", "wqy-", "sourcehansans")):
                continue
            if "bold" in low:
                bold.append(str(p))
            else:
                regular.append(str(p))

    _DISCOVERED_CJK_FONTS = {
        "cjk_regular": regular + bold,
        "cjk_bold": bold + regular,
    }
    return _DISCOVERED_CJK_FONTS


def _load_truetype_font(path: Path, size: int, is_cjk: bool = False) -> ImageFont.FreeTypeFont:
    """Carrega fonte TrueType/OpenType; em coleções NotoSansCJK.ttc prioriza face SC (chinês simplificado + CJK pan-asiático)."""
    if is_cjk and path.suffix.lower() == ".ttc" and "notosanscjk" in path.name.lower():
        for idx in (2, 0):
            try:
                return ImageFont.truetype(str(path), size=size, index=idx)
            except OSError:
                continue
    return ImageFont.truetype(str(path), size=size)


def _get_font_by_role(role: str, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    global _WARNED_MISSING_CJK
    key = (role, size)
    cached = _FONT_CACHE.get(key)
    if cached is not None:
        return cached

    is_cjk = role in ("cjk_regular", "cjk_bold")
    candidates = list(FONT_CANDIDATES.get(role, FONT_CANDIDATES["regular"]))
    if is_cjk:
        for extra in _discover_cjk_fonts().get(role, []):
            if extra not in candidates:
                candidates.append(extra)

    for path_str in candidates:
        p = Path(path_str)
        if p.is_file():
            try:
                fnt = _load_truetype_font(p, size=size, is_cjk=is_cjk)
                _FONT_CACHE[key] = fnt
                return fnt
            except OSError:
                continue

    if is_cjk:
        if not _WARNED_MISSING_CJK:
            logger.warning("Fonte CJK (fonts-noto-cjk) não encontrada em /usr/share/fonts; usando fallback DejaVu.")
            _WARNED_MISSING_CJK = True
        return _get_font_by_role("unicode_bold" if role == "cjk_bold" else "unicode_regular", size)

    fallback = ImageFont.load_default()
    _FONT_CACHE[key] = fallback
    return fallback


def pick_font(
    text: str,
    size: int,
    bold: bool = False,
    condensed: bool = False,
    italic: bool = False,
) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Seleciona automaticamente a fonte ideal (Roboto, DejaVu, Noto CJK ou Condensada Itálica para Battlegroups)."""
    if HAS_CJK_RE.search(text):
        return _get_font_by_role("cjk_bold" if bold else "cjk_regular", size)
    if NEEDS_DEJAVU_RE.search(text):
        return _get_font_by_role("unicode_bold" if bold else "unicode_regular", size)
    if italic:
        return _get_font_by_role("bg_italic_bold" if bold else "bg_italic", size)
    if condensed:
        return _get_font_by_role("condensed_bold", size)
    return _get_font_by_role("bold" if bold else "regular", size)


def text_width(draw: ImageDraw.ImageDraw, text: str, font: Any) -> float:
    try:
        return float(draw.textlength(text, font=font))
    except AttributeError:
        bbox = draw.textbbox((0, 0), text, font=font)
        return float(bbox[2] - bbox[0])


def truncate_to_px(
    draw: ImageDraw.ImageDraw,
    text: str,
    max_px: int,
    size: int,
    bold: bool = False,
    italic: bool = False,
) -> tuple[str, Any]:
    txt = strip_unsafe_chars(text) or "Desconhecido"
    for try_sz in (size, max(11, size - 2), max(10, size - 3)):
        fnt = pick_font(txt, size=try_sz, bold=bold, italic=italic)
        if text_width(draw, txt, fnt) <= max_px:
            return txt, fnt
    fnt = pick_font(txt, size=max(10, size - 2), bold=bold, italic=italic)
    while len(txt) > 2 and text_width(draw, txt + "…", fnt) > max_px:
        txt = txt[:-1]
    return txt + "…", fnt


_SMURF_ALIAS_SPLIT_RE = re.compile(r"^(.+?)\s+\(([^()]+)\)$")


def _draw_player_alias(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    raw_alias: str,
    max_px: int,
    size: int,
    bold: bool,
    primary_color: tuple[int, int, int, int],
    sub_color: tuple[int, int, int, int] | None = None,
) -> float:
    """
    Desenha apelido de jogador respeitando `max_px`.
    Para formatos `NickPrincipal* (NovoNick)` e `NickSmurf (ContaOriginal)`, mantém o nome principal em destaque
    e usa fonte condensada menor no sufixo entre parênteses para caber por completo sem cortar.
    """
    txt = strip_unsafe_chars(raw_alias) or "Desconhecido"
    m = _SMURF_ALIAS_SPLIT_RE.match(txt)
    if not m:
        disp, fnt = truncate_to_px(draw, txt, max_px=max_px, size=size, bold=bold)
        draw.text((x, y), disp, font=fnt, fill=primary_color)
        return text_width(draw, disp, fnt)

    main_part = m.group(1).strip()
    smurf_inner = m.group(2).strip()
    sub_col = sub_color or (
        min(255, int(primary_color[0] * 0.85 + 32)),
        min(255, int(primary_color[1] * 0.85 + 32)),
        min(255, int(primary_color[2] * 0.85 + 32)),
        255,
    )
    sub_full = f" ({smurf_inner})"

    # Tenta combinações legíveis preservando o nome completo da smurf antes de truncar
    attempts: list[tuple[int, bool, int]] = [
        (size, False, max(11, size - 5)),
        (max(12, size - 2), False, max(11, size - 6)),
        (max(12, size - 2), True, max(11, size - 6)),
        (max(11, size - 3), True, max(10, size - 6)),
        (max(11, size - 3), True, max(10, size - 7)),
    ]
    chosen: tuple[Any, Any, str, int, int] | None = None
    for m_sz, m_cond, s_sz in attempts:
        m_fnt = pick_font(main_part, size=m_sz, bold=bold, condensed=m_cond)
        s_fnt = pick_font(sub_full, size=s_sz, bold=False, condensed=True)
        if text_width(draw, main_part, m_fnt) + text_width(draw, sub_full, s_fnt) <= max_px:
            chosen = (m_fnt, s_fnt, sub_full, m_sz, s_sz)
            break

    if chosen is None:
        m_sz = max(11, size - 3)
        s_sz = max(10, size - 6)
        m_fnt = pick_font(main_part, size=m_sz, bold=bold, condensed=True)
        s_fnt = pick_font(sub_full, size=s_sz, bold=False, condensed=True)
        mw = text_width(draw, main_part, m_fnt)
        rem_px = max(24.0, float(max_px) - mw)
        cut = smurf_inner
        while len(cut) > 2 and text_width(draw, f" ({cut}…)", s_fnt) > rem_px:
            cut = cut[:-1]
        sub_disp = f" ({cut}…)" if cut != smurf_inner else sub_full
        chosen = (m_fnt, s_fnt, sub_disp, m_sz, s_sz)

    m_fnt, s_fnt, sub_disp, m_sz, s_sz = chosen
    main_y = y + max(0, (size - m_sz) // 2)
    sub_y = main_y + max(0, m_sz - s_sz - 1)
    draw.text((x, main_y), main_part, font=m_fnt, fill=primary_color)
    mw = text_width(draw, main_part, m_fnt)
    draw.text((x + mw, sub_y), sub_disp, font=s_fnt, fill=sub_col)
    return mw + text_width(draw, sub_disp, s_fnt)


def _encode_rgb_png(img: Image.Image) -> bytes:
    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG", compress_level=6)
    return out.getvalue()


# ---------------------------------------------------------------------------
# Provedor seguro de Avatares da Steam (cache em SQLite + memória + lazy load)
# ---------------------------------------------------------------------------
class SteamAvatarProvider:
    """Busca e faz cache de avatares reais da Steam com validação estrita de URL, formato e dimensões."""

    def __init__(
        self,
        db: Any | None = None,
        catalog_json_path: Path | None = None,
        allow_network: bool = True,
        steam_api_key: str | None = None,
    ) -> None:
        self.db = db
        self.allow_network = allow_network
        self.catalog_json_path = catalog_json_path or (BASE_DIR / "jogadores_br_steam.json")
        raw_key = os.environ.get("STEAM_WEB_API_KEY", "") if steam_api_key is None else str(steam_api_key or "")
        clean_key = raw_key.strip()
        self._steam_api_key = clean_key if STEAM_API_KEY_VALID_RE.fullmatch(clean_key) else ""
        self._catalog_loaded = False
        self._lock = threading.Lock()
        self._mem_png_cache: dict[str, Image.Image] = {}
        self._prefetched_avatar_urls: dict[str, str] = {}
        self._circle_cache: dict[tuple[str, int, tuple[int, int, int, int] | None], Image.Image] = {}
        self._pid_to_steam: dict[int, str] = {}
        self._failed_steam_ids: set[str] = set()
        self._network_fetches_this_run = 0
        self._max_network_fetches_per_run = 90
        self._last_net_ts = 0.0

        for r in (*CORE_BR_ROSTER, *MANUAL_OTHER_BR_DISPLAY):
            r_pid = int(r.get("profile_id", 0))
            r_sid = str(r.get("merged_into_steam_id") or r.get("steam_id") or "").strip()
            if r_pid > 0 and STEAM_ID64_VALID_RE.fullmatch(r_sid):
                self._pid_to_steam.setdefault(r_pid, r_sid)

        if db is not None and hasattr(db, "get_steam_id_map"):
            try:
                for db_pid, db_sid in db.get_steam_id_map().items():
                    self._pid_to_steam.setdefault(int(db_pid), str(db_sid))
            except Exception:
                pass

    @staticmethod
    def _canonical_roster_avatar_target(profile_id: int = 0, steam_id: str = "") -> tuple[int, str]:
        """Se a conta for smurf/mesclada no CORE_BR_ROSTER, redireciona avatar para a conta principal."""
        clean_sid = str(steam_id or "").replace("/steam/", "").strip()
        pid_int = int(profile_id or 0)
        for r in CORE_BR_ROSTER:
            r_pid = int(r.get("profile_id", 0) or 0)
            r_sid = str(r.get("steam_id") or "").replace("/steam/", "").strip()
            if (pid_int > 0 and r_pid == pid_int) or (clean_sid and r_sid == clean_sid):
                m_sid = str(r.get("merged_into_steam_id") or "").replace("/steam/", "").strip()
                m_pid = int(r.get("merged_into_profile_id", 0) or 0)
                if STEAM_ID64_VALID_RE.fullmatch(m_sid):
                    return (m_pid if m_pid > 0 else pid_int), m_sid
                if m_pid > 0:
                    return m_pid, clean_sid
                break
        return pid_int, clean_sid

    def _ensure_catalog_loaded(self) -> None:
        if self._catalog_loaded:
            return
        self._catalog_loaded = True
        if not self.catalog_json_path.is_file() or self.catalog_json_path.is_symlink():
            return
        try:
            if self.catalog_json_path.stat().st_size > 5 * 1024 * 1024:
                return
            doc = json.loads(self.catalog_json_path.read_text(encoding="utf-8"))
            for p in doc.get("players", []):
                pid = int(p.get("profile_id", 0))
                sid = str(p.get("steam_id") or "").strip()
                if pid > 0 and STEAM_ID64_VALID_RE.fullmatch(sid):
                    self._pid_to_steam.setdefault(pid, sid)
        except Exception:
            pass

    def _throttle_network(self) -> bool:
        with self._lock:
            if self._network_fetches_this_run >= self._max_network_fetches_per_run:
                return False
            self._network_fetches_this_run += 1
            now_m = time.monotonic()
            wait = max(0.0, (self._last_net_ts + 0.10) - now_m)
            self._last_net_ts = max(now_m, self._last_net_ts) + 0.10
        if wait > 0:
            time.sleep(wait)
        return True

    def _lookup_steam_id_from_relic(self, profile_id: int) -> str:
        if profile_id <= 0 or not self.allow_network or not self._throttle_network():
            return ""
        url = f"{RELIC_BASE_URL}/getPersonalStat?title=coh3&profile_ids=%5B{int(profile_id)}%5D"
        try:
            validate_https_endpoint(url, ALLOWED_RELIC_HOSTS, path_prefix="/community/leaderboard/")
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CoH3-BR-Tracker/7.0", "Accept": "application/json", "Accept-Encoding": "gzip"},
            )
            with _NO_REDIRECT_OPENER.open(req, timeout=6) as resp:
                raw = read_bounded_http_body(resp, MAX_RELIC_LOOKUP_BYTES)
            data = json.loads(raw.decode("utf-8", errors="ignore"))
            for sg in data.get("statGroups", []):
                for mem in sg.get("members", []):
                    if int(mem.get("profile_id", 0)) == int(profile_id):
                        nm = str(mem.get("name") or "")
                        sid = nm[7:] if nm.startswith("/steam/") else ""
                        if STEAM_ID64_VALID_RE.fullmatch(sid):
                            return sid
        except Exception:
            pass
        return ""

    def resolve_steam_id(self, profile_id: int = 0, steam_id: str = "") -> str:
        canon_pid, clean_sid = self._canonical_roster_avatar_target(profile_id=profile_id, steam_id=steam_id)
        if STEAM_ID64_VALID_RE.fullmatch(clean_sid):
            if canon_pid > 0:
                self._pid_to_steam[canon_pid] = clean_sid
            return clean_sid
        if canon_pid > 0:
            if canon_pid in self._pid_to_steam:
                return self._pid_to_steam[canon_pid]
            self._ensure_catalog_loaded()
            if canon_pid in self._pid_to_steam:
                return self._pid_to_steam[canon_pid]
            looked_up = self._lookup_steam_id_from_relic(canon_pid)
            self._pid_to_steam[canon_pid] = looked_up
            return looked_up
        return ""

    def _validate_steam_avatar_url(self, raw_url: str) -> str:
        clean = str(raw_url or "").strip()
        if not clean:
            return ""
        try:
            parsed_av = validate_https_endpoint(clean, ALLOWED_STEAM_AVATAR_HOSTS, allow_query=False)
            if parsed_av.fragment or not SAFE_AVATAR_EXT_RE.search(parsed_av.path):
                return ""
            return clean
        except ValueError:
            return ""

    def _download_and_normalize_avatar(self, avatar_url: str) -> tuple[str, bytes] | None:
        valid_url = self._validate_steam_avatar_url(avatar_url)
        if not valid_url:
            return None
        img_req = urllib.request.Request(
            valid_url,
            headers={"User-Agent": "CoH3-BR-Tracker/7.0", "Accept": "image/*"},
        )
        with _NO_REDIRECT_OPENER.open(img_req, timeout=8) as img_resp:
            img_bytes = read_bounded_http_body(img_resp, MAX_STEAM_AVATAR_BYTES)

        with Image.open(io.BytesIO(img_bytes)) as im:
            if im.format not in ALLOWED_DECODER_FORMATS or not (1 <= im.width <= 1024 and 1 <= im.height <= 1024):
                logger.warning("Imagem de avatar Steam rejeitada por formato/dimensão inválida.")
                return None
            clean_im = im.convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
            out_buf = io.BytesIO()
            clean_im.save(out_buf, format="PNG", compress_level=6)
            return valid_url, out_buf.getvalue()

    def prefetch_avatar_urls(self, players: list[dict[str, Any]]) -> int:
        """
        Pré-carrega URLs de avatar em lote (até 100 SteamIDs por requisição) via Steam Web API
        (`ISteamUser/GetPlayerSummaries/v2`) quando `STEAM_WEB_API_KEY` estiver configurado,
        evitando falhas de HTTP 429 no XML público em aliados e oponentes das partidas.
        """
        if not self.allow_network or not self._steam_api_key or not players:
            return 0
        pending_sids: list[str] = []
        seen: set[str] = set()
        for pl in players:
            if not isinstance(pl, dict):
                continue
            pid = int(pl.get("profile_id", 0) or 0)
            raw_sid = str(pl.get("steam_id") or "")
            sid = self.resolve_steam_id(profile_id=pid, steam_id=raw_sid)
            if (
                not sid
                or sid in seen
                or sid in self._mem_png_cache
                or sid in self._prefetched_avatar_urls
                or sid in self._failed_steam_ids
            ):
                continue
            if self.db is not None and hasattr(self.db, "get_cached_avatar"):
                try:
                    if self.db.get_cached_avatar(steam_id=sid, profile_id=pid) is not None:
                        continue
                except Exception:
                    pass
            seen.add(sid)
            pending_sids.append(sid)

        if not pending_sids:
            return 0

        fetched_urls = 0
        for idx in range(0, len(pending_sids), 100):
            batch = pending_sids[idx : idx + 100]
            if not self._throttle_network():
                break
            query = urllib.parse.urlencode({"key": self._steam_api_key, "steamids": ",".join(batch)})
            url = f"{STEAM_API_SUMMARIES_URL}?{query}"
            try:
                validate_https_endpoint(
                    url,
                    ALLOWED_STEAM_API_HOSTS,
                    path_prefix="/ISteamUser/",
                    path_regex=STEAM_API_SUMMARIES_PATH_RE,
                )
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "CoH3-BR-Tracker/7.0",
                        "Accept": "application/json",
                        "Accept-Encoding": "gzip",
                    },
                )
                with _NO_REDIRECT_OPENER.open(req, timeout=10) as resp:
                    raw = read_bounded_http_body(resp, MAX_STEAM_API_JSON_BYTES)
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
                api_players = (payload.get("response") or {}).get("players") if isinstance(payload, dict) else None
                if not isinstance(api_players, list):
                    continue
                for item in api_players:
                    if not isinstance(item, dict):
                        continue
                    sid = str(item.get("steamid") or "").strip()
                    if not STEAM_ID64_VALID_RE.fullmatch(sid):
                        continue
                    av_url = self._validate_steam_avatar_url(
                        str(item.get("avatarmedium") or item.get("avatarfull") or item.get("avatar") or "")
                    )
                    if av_url:
                        self._prefetched_avatar_urls[sid] = av_url
                        fetched_urls += 1
            except Exception as exc:
                logger.warning(
                    "Steam Web API GetPlayerSummaries indisponível no Tracker (usando fallback XML): %s",
                    redact_secrets(exc),
                )
                break
        return fetched_urls

    def _fetch_steam_avatar_bytes(self, steam_id: str) -> tuple[str, bytes] | None:
        if not STEAM_ID64_VALID_RE.fullmatch(steam_id) or steam_id in self._failed_steam_ids:
            return None

        # 1. Caminho rápido: URL já pré-carregada em lote via STEAM_WEB_API_KEY (zero requisição XML)
        prefetched_url = self._prefetched_avatar_urls.get(steam_id)
        if prefetched_url:
            if self._throttle_network():
                try:
                    downloaded = self._download_and_normalize_avatar(prefetched_url)
                    if downloaded is not None:
                        return downloaded
                except Exception as exc:
                    logger.debug(
                        "Falha ao baixar avatar pré-carregado (%s); tentando fallback XML: %s",
                        steam_id,
                        redact_secrets(exc),
                    )

        # 2. Fallback automático: XML público da Steam
        xml_url = f"https://steamcommunity.com/profiles/{steam_id}/?xml=1"
        validate_https_endpoint(xml_url, ALLOWED_STEAM_XML_HOSTS, path_prefix="/profiles/")

        for attempt in range(2):
            if not self._throttle_network():
                return None
            try:
                req = urllib.request.Request(
                    xml_url,
                    headers={"User-Agent": "CoH3-BR-Tracker/7.0", "Accept": "application/xml,text/xml"},
                )
                with _STEAM_XML_OPENER.open(req, timeout=8) as resp:
                    xml_raw = read_bounded_http_body(resp, MAX_STEAM_XML_BYTES)
                xml_text = xml_raw.decode("utf-8", errors="ignore")

                m = STEAM_XML_AVATAR_MEDIUM_RE.search(xml_text) or STEAM_XML_AVATAR_FULL_RE.search(xml_text)
                if not m:
                    break

                downloaded = self._download_and_normalize_avatar(m.group(1).strip())
                if downloaded is not None:
                    return downloaded
                break
            except Exception as exc:
                if attempt == 0:
                    time.sleep(0.25)
                    continue
                logger.debug("Não foi possível baixar avatar Steam (%s): %s", steam_id, redact_secrets(exc))

        self._failed_steam_ids.add(steam_id)
        return None

    def get_circular_avatar(
        self,
        size: int,
        profile_id: int = 0,
        steam_id: str = "",
        alias: str = "",
        ring_color: tuple[int, int, int, int] | None = (34, 197, 94, 230),
    ) -> Image.Image:
        """Retorna um avatar circular RGBA cacheado (real da Steam ou monograma determinístico)."""
        canon_pid, canon_sid = self._canonical_roster_avatar_target(profile_id=profile_id, steam_id=steam_id)
        sid = self.resolve_steam_id(profile_id=canon_pid, steam_id=canon_sid)
        cache_key = sid or f"pid_{canon_pid}_{alias[:6]}"
        circle_key = (cache_key, size, ring_color)

        cached_circle = self._circle_cache.get(circle_key)
        if cached_circle is not None:
            return cached_circle

        base_img = self._mem_png_cache.get(cache_key)
        if base_img is None:
            png_blob: bytes | None = None
            if self.db is not None and hasattr(self.db, "get_cached_avatar"):
                try:
                    png_blob = self.db.get_cached_avatar(steam_id=sid, profile_id=canon_pid)
                except Exception:
                    png_blob = None

            if png_blob is None and sid and self.allow_network:
                fetched = self._fetch_steam_avatar_bytes(sid)
                if fetched is not None:
                    av_url, png_blob = fetched
                    if self.db is not None and hasattr(self.db, "save_cached_avatar"):
                        try:
                            self.db.save_cached_avatar(sid, av_url, png_blob, profile_id=canon_pid)
                        except Exception:
                            pass

            if png_blob:
                try:
                    with Image.open(io.BytesIO(png_blob)) as decoded:
                        base_img = decoded.convert("RGBA")
                        self._mem_png_cache[cache_key] = base_img
                except Exception:
                    base_img = None

        if base_img is None:
            det_seed = int(canon_pid) if canon_pid else int.from_bytes(hashlib.sha256(alias.encode("utf-8")).digest()[:4], "big")
            base_img = _build_fallback_avatar(alias or "BR", seed=det_seed)
            self._mem_png_cache[cache_key] = base_img

        masked = _mask_circle_rgba(base_img, size=size, ring_color=ring_color)
        if len(self._circle_cache) >= 256:
            self._circle_cache.clear()
        self._circle_cache[circle_key] = masked
        return masked


def _build_fallback_avatar(alias: str, seed: int) -> Image.Image:
    palettes = (
        ((22, 101, 52), (74, 222, 128)),
        ((30, 64, 175), (96, 165, 250)),
        ((146, 64, 14), (251, 191, 36)),
        ((88, 28, 135), (192, 132, 252)),
        ((15, 118, 110), (45, 212, 191)),
    )
    bg, fg = palettes[abs(int(seed)) % len(palettes)]
    im = Image.new("RGBA", (64, 64), (*bg, 255))
    drw = ImageDraw.Draw(im)
    alnum = "".join(ch for ch in strip_unsafe_chars(alias) if ch.isalnum())
    initials = (alnum[:2] or "BR").upper()
    fnt = pick_font(initials, size=26, bold=True)
    bbox = drw.textbbox((0, 0), initials, font=fnt)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    drw.text(((64 - tw) / 2 - bbox[0], (64 - th) / 2 - bbox[1]), initials, font=fnt, fill=(*fg, 255))
    return im


def _mask_circle_rgba(
    src: Image.Image,
    size: int,
    ring_color: tuple[int, int, int, int] | None = None,
) -> Image.Image:
    ss = size * 2
    resized = src.resize((ss, ss), Image.Resampling.LANCZOS)
    mask = Image.new("L", (ss, ss), 0)
    mdraw = ImageDraw.Draw(mask)
    pad = 2 if ring_color else 0
    mdraw.ellipse((pad, pad, ss - 1 - pad, ss - 1 - pad), fill=255)

    out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    out.paste(resized, (0, 0), mask)
    if ring_color:
        odraw = ImageDraw.Draw(out)
        odraw.ellipse((1, 1, ss - 2, ss - 2), outline=ring_color, width=3)
    return out.resize((size, size), Image.Resampling.LANCZOS)


# ---------------------------------------------------------------------------
# Medalhões oficiais de facções CoH3 + Miniaturas táticas de mapas + Bandeiras
# ---------------------------------------------------------------------------
_FACTION_BASE_CACHE: dict[str, Image.Image] = {}
_FACTION_ICON_CACHE: dict[tuple[str, int], Image.Image] = {}


def get_faction_icon(faction_name: str, size: int) -> Image.Image:
    asset_key = FACTION_TO_ASSET.get(str(faction_name or "").strip(), "german")
    ck = (asset_key, size)
    cached = _FACTION_ICON_CACHE.get(ck)
    if cached is not None:
        return cached

    base = _FACTION_BASE_CACHE.get(asset_key)
    if base is None:
        png_path = FACTIONS_DIR / f"{asset_key}.png"
        try:
            factions_root = FACTIONS_DIR.resolve()
            if (
                png_path.is_file()
                and not png_path.is_symlink()
                and png_path.resolve().parent == factions_root
                and png_path.stat().st_size <= 262_144
            ):
                with Image.open(png_path, formats=["PNG"]) as im:
                    base = im.convert("RGBA")
                    _FACTION_BASE_CACHE[asset_key] = base
        except Exception:
            base = None

    if base is not None:
        icon = base.resize((size, size), Image.Resampling.LANCZOS)
        _FACTION_ICON_CACHE[ck] = icon
        return icon

    # Fallback vetorial caso a pasta assets/factions não esteja presente
    icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(icon)
    colors = {
        "american": ((65, 83, 52), (234, 179, 8), "US"),
        "british": ((92, 78, 56), (220, 38, 38), "UK"),
        "dak": ((120, 82, 40), (245, 158, 11), "DAK"),
        "german": ((55, 65, 81), (209, 213, 219), "WH"),
    }
    bg, ring, lbl = colors.get(asset_key, colors["german"])
    d.ellipse((1, 1, size - 2, size - 2), fill=(*bg, 255), outline=(*ring, 255), width=max(1, size // 14))
    fnt = pick_font(lbl, size=max(8, size // 3), bold=True)
    bb = d.textbbox((0, 0), lbl, font=fnt)
    d.text(((size - (bb[2] - bb[0])) / 2, (size - (bb[3] - bb[1])) / 2 - 1), lbl, font=fnt, fill=(255, 255, 255, 255))
    _FACTION_ICON_CACHE[ck] = icon
    return icon


_FLAG_BASE_CACHE: dict[str, Image.Image | None] = {}
_FLAG_CACHE: dict[tuple[str, int, int], Image.Image] = {}

FLAG_CODE_ALIASES: dict[str, str] = {
    "uk": "gb",
}


def _load_flag_asset(code: str) -> Image.Image | None:
    """Carrega bandeira PNG local oficial (48x36) de assets/flags/<cc>.png com validação segura."""
    if not SAFE_FLAG_CODE_RE.match(code):
        return None
    if code in _FLAG_BASE_CACHE:
        return _FLAG_BASE_CACHE[code]

    png_path = FLAGS_DIR / f"{code}.png"
    base: Image.Image | None = None
    try:
        flags_root = FLAGS_DIR.resolve()
        if not png_path.is_symlink() and png_path.is_file():
            resolved = png_path.resolve()
            if resolved.parent == flags_root and resolved.stat().st_size <= MAX_FLAG_ASSET_BYTES:
                with Image.open(resolved, formats=["PNG"]) as im:
                    base = im.convert("RGBA")
    except Exception:
        base = None

    _FLAG_BASE_CACHE[code] = base
    return base


HORIZONTAL_TRICOLORS: dict[str, tuple[tuple[int, int, int], tuple[int, int, int], tuple[int, int, int]]] = {
    "de": ((20, 20, 20), (221, 0, 0), (255, 206, 0)),
    "ru": ((245, 245, 245), (0, 57, 166), (213, 43, 30)),
    "ar": ((116, 172, 223), (255, 255, 255), (116, 172, 223)),
    "nl": ((174, 28, 40), (255, 255, 255), (33, 70, 139)),
    "bg": ((255, 255, 255), (0, 150, 110), (214, 38, 18)),
    "si": ((255, 255, 255), (0, 61, 165), (237, 28, 36)),
    "sk": ((255, 255, 255), (11, 78, 162), (238, 28, 37)),
    "es": ((170, 21, 27), (241, 191, 0), (170, 21, 27)),
    "co": ((252, 209, 22), (0, 56, 147), (206, 17, 38)),
    "ve": ((252, 209, 22), (0, 56, 147), (206, 17, 38)),
    "ec": ((252, 209, 22), (0, 56, 147), (206, 17, 38)),
    "bo": ((213, 43, 30), (249, 227, 0), (0, 121, 52)),
    "py": ((213, 43, 30), (255, 255, 255), (0, 56, 168)),
    "at": ((237, 41, 57), (255, 255, 255), (237, 41, 57)),
    "hu": ((206, 41, 57), (255, 255, 255), (71, 112, 80)),
    "eg": ((206, 17, 38), (255, 255, 255), (20, 20, 20)),
    "in": ((255, 153, 51), (255, 255, 255), (19, 136, 8)),
    "lt": ((253, 185, 19), (0, 106, 68), (193, 39, 45)),
    "ee": ((0, 114, 206), (20, 20, 20), (255, 255, 255)),
    "lv": ((158, 48, 57), (255, 255, 255), (158, 48, 57)),
}

VERTICAL_TRICOLORS: dict[str, tuple[tuple[int, int, int], tuple[int, int, int], tuple[int, int, int]]] = {
    "fr": ((0, 35, 149), (255, 255, 255), (237, 41, 57)),
    "it": ((0, 146, 70), (255, 255, 255), (206, 43, 55)),
    "pe": ((217, 16, 35), (255, 255, 255), (217, 16, 35)),
    "mx": ((0, 104, 71), (255, 255, 255), (206, 17, 38)),
    "ro": ((0, 43, 127), (252, 209, 22), (206, 17, 38)),
    "be": ((20, 20, 20), (250, 224, 66), (237, 41, 57)),
}


def get_country_flag(code: str, w: int = 20, h: int = 14) -> Image.Image:
    raw = (code or "un").strip().lower()[:4]
    c = FLAG_CODE_ALIASES.get(raw, raw)
    ck = (c, w, h)
    cached = _FLAG_CACHE.get(ck)
    if cached is not None:
        return cached

    asset = _load_flag_asset(c)
    if asset is None and not SAFE_FLAG_CODE_RE.match(c):
        asset = _load_flag_asset("un")
    if asset is not None:
        resized = asset.resize((w, h), Image.Resampling.LANCZOS)
        border_draw = ImageDraw.Draw(resized)
        border_draw.rectangle((0, 0, w - 1, h - 1), outline=(0, 0, 0, 110), width=1)
        _FLAG_CACHE[ck] = resized
        return resized

    # Fallback vetorial caso assets/flags não esteja disponível
    sw, sh = w * 2, h * 2
    im = Image.new("RGBA", (sw, sh), (45, 50, 62, 255))
    d = ImageDraw.Draw(im)

    if c == "br":
        d.rectangle((0, 0, sw - 1, sh - 1), fill=(0, 156, 59, 255))
        d.polygon([(sw // 2, 3), (sw - 4, sh // 2), (sw // 2, sh - 4), (4, sh // 2)], fill=(255, 223, 0, 255))
        r = max(4, sh // 4)
        d.ellipse((sw // 2 - r, sh // 2 - r, sw // 2 + r, sh // 2 + r), fill=(0, 39, 118, 255))
    elif c == "us":
        for i in range(7):
            y0, y1 = int(i * sh / 7), int((i + 1) * sh / 7)
            d.rectangle((0, y0, sw, y1), fill=(187, 19, 62, 255) if i % 2 == 0 else (255, 255, 255, 255))
        d.rectangle((0, 0, int(sw * 0.45), int(sh * 0.55)), fill=(0, 38, 100, 255))
    elif c == "gb":
        d.rectangle((0, 0, sw, sh), fill=(1, 33, 105, 255))
        d.line([(0, 0), (sw, sh)], fill=(255, 255, 255, 255), width=5)
        d.line([(0, sh), (sw, 0)], fill=(255, 255, 255, 255), width=5)
        d.line([(0, 0), (sw, sh)], fill=(200, 16, 46, 255), width=2)
        d.line([(0, sh), (sw, 0)], fill=(200, 16, 46, 255), width=2)
        d.rectangle((0, sh // 2 - 4, sw, sh // 2 + 4), fill=(255, 255, 255, 255))
        d.rectangle((sw // 2 - 4, 0, sw // 2 + 4, sh), fill=(255, 255, 255, 255))
        d.rectangle((0, sh // 2 - 2, sw, sh // 2 + 2), fill=(200, 16, 46, 255))
        d.rectangle((sw // 2 - 2, 0, sw // 2 + 2, sh), fill=(200, 16, 46, 255))
    elif c in ("au", "nz"):
        d.rectangle((0, 0, sw, sh), fill=(0, 0, 139, 255))
        d.rectangle((0, 0, sw // 2, sh // 2), fill=(1, 33, 105, 255))
        d.line([(0, sh // 4), (sw // 2, sh // 4)], fill=(200, 16, 46, 255), width=3)
        d.line([(sw // 4, 0), (sw // 4, sh // 2)], fill=(200, 16, 46, 255), width=3)
        for sx, sy in ((int(sw * 0.72), int(sh * 0.35)), (int(sw * 0.82), int(sh * 0.65)), (int(sw * 0.62), int(sh * 0.7))):
            d.ellipse((sx - 2, sy - 2, sx + 2, sy + 2), fill=(255, 255, 255, 255))
    elif c == "kr":
        d.rectangle((0, 0, sw, sh), fill=(255, 255, 255, 255))
        r = max(5, sh // 3)
        d.pieslice((sw // 2 - r, sh // 2 - r, sw // 2 + r, sh // 2 + r), 180, 360, fill=(205, 46, 58, 255))
        d.pieslice((sw // 2 - r, sh // 2 - r, sw // 2 + r, sh // 2 + r), 0, 180, fill=(0, 71, 160, 255))
    elif c == "jp":
        d.rectangle((0, 0, sw, sh), fill=(255, 255, 255, 255))
        r = max(5, sh // 3)
        d.ellipse((sw // 2 - r, sh // 2 - r, sw // 2 + r, sh // 2 + r), fill=(188, 0, 45, 255))
    elif c == "cn":
        d.rectangle((0, 0, sw, sh), fill=(222, 41, 16, 255))
        d.ellipse((5, 4, 13, 12), fill=(255, 222, 0, 255))
    elif c == "tw":
        d.rectangle((0, 0, sw, sh), fill=(254, 0, 0, 255))
        d.rectangle((0, 0, sw // 2, sh // 2), fill=(0, 0, 149, 255))
        r = max(3, sh // 7)
        d.ellipse((sw // 4 - r, sh // 4 - r, sw // 4 + r, sh // 4 + r), fill=(255, 255, 255, 255))
    elif c == "hk":
        d.rectangle((0, 0, sw, sh), fill=(222, 41, 16, 255))
        r = max(4, sh // 4)
        d.ellipse((sw // 2 - r, sh // 2 - r, sw // 2 + r, sh // 2 + r), fill=(255, 255, 255, 255))
    elif c == "ca":
        d.rectangle((0, 0, sw, sh), fill=(255, 255, 255, 255))
        d.rectangle((0, 0, sw // 4, sh), fill=(216, 6, 33, 255))
        d.rectangle((sw - sw // 4, 0, sw, sh), fill=(216, 6, 33, 255))
        d.polygon([(sw // 2, 5), (sw // 2 + 5, sh // 2 + 2), (sw // 2, sh - 5), (sw // 2 - 5, sh // 2 + 2)], fill=(216, 6, 33, 255))
    elif c == "pl":
        d.rectangle((0, 0, sw, sh // 2), fill=(255, 255, 255, 255))
        d.rectangle((0, sh // 2, sw, sh), fill=(220, 20, 60, 255))
    elif c == "ua":
        d.rectangle((0, 0, sw, sh // 2), fill=(0, 87, 183, 255))
        d.rectangle((0, sh // 2, sw, sh), fill=(255, 215, 0, 255))
    elif c == "by":
        d.rectangle((0, 0, sw, int(sh * 0.67)), fill=(200, 49, 62, 255))
        d.rectangle((0, int(sh * 0.67), sw, sh), fill=(74, 166, 87, 255))
        d.rectangle((0, 0, 5, sh), fill=(255, 255, 255, 255))
    elif c == "uy":
        for i in range(5):
            y0, y1 = int(i * sh / 5), int((i + 1) * sh / 5)
            d.rectangle((0, y0, sw, y1), fill=(255, 255, 255, 255) if i % 2 == 0 else (0, 56, 168, 255))
        d.rectangle((0, 0, int(sw * 0.42), int(sh * 0.5)), fill=(255, 255, 255, 255))
        d.ellipse((4, 3, 11, 10), fill=(252, 209, 22, 255))
    elif c == "cl":
        d.rectangle((0, 0, sw, sh // 2), fill=(255, 255, 255, 255))
        d.rectangle((0, sh // 2, sw, sh), fill=(213, 43, 30, 255))
        d.rectangle((0, 0, int(sw * 0.38), sh // 2), fill=(0, 57, 166, 255))
    elif c == "pt":
        d.rectangle((0, 0, int(sw * 0.4), sh), fill=(0, 102, 0, 255))
        d.rectangle((int(sw * 0.4), 0, sw, sh), fill=(255, 0, 0, 255))
        d.ellipse((int(sw * 0.4) - 4, sh // 2 - 4, int(sw * 0.4) + 4, sh // 2 + 4), fill=(255, 204, 0, 255))
    elif c in HORIZONTAL_TRICOLORS:
        c1, c2, c3 = HORIZONTAL_TRICOLORS[c]
        d.rectangle((0, 0, sw, sh // 3), fill=(*c1, 255))
        d.rectangle((0, sh // 3, sw, (2 * sh) // 3), fill=(*c2, 255))
        d.rectangle((0, (2 * sh) // 3, sw, sh), fill=(*c3, 255))
    elif c in VERTICAL_TRICOLORS:
        c1, c2, c3 = VERTICAL_TRICOLORS[c]
        d.rectangle((0, 0, sw // 3, sh), fill=(*c1, 255))
        d.rectangle((sw // 3, 0, (2 * sw) // 3, sh), fill=(*c2, 255))
        d.rectangle(((2 * sw) // 3, 0, sw, sh), fill=(*c3, 255))
    else:
        lbl = (c[:2] if c != "un" else "GL").upper()
        fnt = pick_font(lbl, size=max(10, sh // 2), bold=True)
        bb = d.textbbox((0, 0), lbl, font=fnt)
        d.text(((sw - (bb[2] - bb[0])) / 2, (sh - (bb[3] - bb[1])) / 2 - 1), lbl, font=fnt, fill=(209, 213, 219, 255))

    d.rectangle((0, 0, sw - 1, sh - 1), outline=(0, 0, 0, 110), width=1)
    final = im.resize((w, h), Image.Resampling.LANCZOS)
    _FLAG_CACHE[ck] = final
    return final


def _is_curated_br_expat(profile_id: int, country_code: str) -> bool:
    """Retorna True somente se o jogador for um brasileiro emigrado confirmado no roster (nunca adversário estrangeiro)."""
    c = (country_code or "").strip().lower()
    if not c or c in ("br", "un"):
        return False
    try:
        pid_int = int(profile_id or 0)
    except (TypeError, ValueError):
        return False
    if pid_int <= 0:
        return False
    for row in (*CORE_BR_ROSTER, *MANUAL_OTHER_BR_DISPLAY):
        if int(row.get("profile_id", 0) or 0) == pid_int:
            rc = str(row.get("country") or "").strip().lower()
            return bool(rc and rc != "br")
    return False


def _draw_flag_with_expat_badge(
    img: Image.Image,
    draw: ImageDraw.ImageDraw,
    country_code: str,
    x: int,
    y: int,
    *,
    profile_id: int = 0,
    is_expat: bool | None = None,
    flag_w: int = 24,
    flag_h: int = 17,
    compact: bool = False,
) -> int:
    """Desenha a bandeira do país e, para brasileiros emigrados confirmados, a pílula verde-e-ouro `BR EXT`."""
    c = (country_code or "un").strip().lower()
    flag_im = get_country_flag(c, w=flag_w, h=flag_h)
    img.paste(flag_im, (x, y), flag_im)
    show_expat = is_expat if is_expat is not None else _is_curated_br_expat(profile_id, c)
    if not show_expat or not c or c in ("br", "un"):
        return flag_w

    label = "BR EXT"
    font_sz = 9 if compact else 10
    pill_w = 36 if compact else 42
    pill_h = max(flag_h, 13 if compact else 16)
    gap = 4
    px0 = x + flag_w + gap
    py0 = y + (flag_h - pill_h) // 2
    draw.rounded_rectangle(
        (px0, py0, px0 + pill_w, py0 + pill_h),
        radius=3,
        fill=(16, 62, 38, 255),
        outline=(234, 179, 8, 235),
        width=1,
    )
    fnt = pick_font(label, size=font_sz, bold=True, condensed=True)
    bbox = draw.textbbox((0, 0), label, font=fnt)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = px0 + (pill_w - tw) / 2 - bbox[0]
    ty = py0 + (pill_h - th) / 2 - bbox[1]
    draw.text((tx, ty), label, font=fnt, fill=(253, 224, 71, 255))
    return flag_w + gap + pill_w


_MAP_THUMB_CACHE: dict[tuple[str, int], Image.Image] = {}

_MAP_THUMB_ALIASES: dict[str, str] = {
    "radarstation mammut": "mammut_8p",
    "(6) across the rhine": "across_the_rhine_6p",
    "across the rhine": "across_the_rhine_6p",
    "rural_castle_winter_4p": "rural_castle_4p",
}

_MAP_THUMB_BASE_INDEX: dict[str, str] = {
    MAP_MK_SUFFIX_RE.sub("", k): k for k in OFFICIAL_COH3_MAP_NAMES
}


def _resolve_display_map_name(primary: dict[str, Any], fallback: str = "Mapa Desconhecido") -> str:
    """Resolve sempre o nome oficial do mapa a partir de map_raw (com fallback para map_clean)."""
    raw_map = str(primary.get("map_raw") or "").strip()
    if raw_map:
        return clean_map_name(raw_map)
    return str(primary.get("map_clean") or fallback)


def _resolve_map_thumb_path(map_raw: str) -> Path | None:
    """Resolve com segurança o PNG oficial da miniatura do mapa em assets/maps/."""
    raw_norm = str(map_raw or "").strip().lower()
    if not raw_norm:
        return None

    candidates: list[str] = []
    alias_hit = _MAP_THUMB_ALIASES.get(raw_norm)
    if alias_hit:
        candidates.append(alias_hit)
    if SAFE_MAP_KEY_RE.fullmatch(raw_norm):
        candidates.append(raw_norm)
        base_key = MAP_MK_SUFFIX_RE.sub("", raw_norm)
        if base_key != raw_norm and SAFE_MAP_KEY_RE.fullmatch(base_key):
            candidates.append(base_key)
        base_official = _MAP_THUMB_BASE_INDEX.get(base_key)
        if base_official and base_official not in candidates:
            candidates.append(base_official)

    maps_root = MAPS_DIR.resolve()
    for key in candidates:
        if not SAFE_MAP_KEY_RE.fullmatch(key):
            continue
        candidate = MAPS_DIR / f"{key}.png"
        try:
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and candidate.resolve().parent == maps_root
                and candidate.stat().st_size <= MAX_MAP_ASSET_BYTES
            ):
                return candidate
        except OSError:
            continue
    return None


def get_tactical_map_thumb(map_raw: str, size: int = 52) -> Image.Image:
    """Carrega a miniatura tática oficial do mapa (coh3stats/Relic) com fallback procedural para mapas custom."""
    sz = max(24, min(int(size), 128))
    norm_key = str(map_raw or "map").strip().lower()[:64]
    key = (norm_key, sz)
    cached = _MAP_THUMB_CACHE.get(key)
    if cached is not None:
        return cached

    out: Image.Image | None = None
    thumb_path = _resolve_map_thumb_path(norm_key)
    if thumb_path is not None:
        try:
            with Image.open(thumb_path, formats=["PNG"]) as raw_im:
                raw_im.load()
                src = raw_im.convert("RGBA")
                inner = max(16, sz - 2)
                sw, sh = src.size
                if sw > 0 and sh > 0:
                    scale = min(inner / sw, inner / sh)
                    nw = max(1, int(round(sw * scale)))
                    nh = max(1, int(round(sh * scale)))
                    fitted = src.resize((nw, nh), Image.Resampling.LANCZOS)
                    canvas = Image.new("RGBA", (sz, sz), (16, 18, 24, 255))
                    ox = (sz - nw) // 2
                    oy = (sz - nh) // 2
                    canvas.paste(fitted, (ox, oy), fitted)
                    d_frame = ImageDraw.Draw(canvas)
                    d_frame.rectangle((0, 0, sz - 1, sz - 1), outline=(78, 84, 98, 255), width=1)
                    out = canvas
        except Exception as exc:
            logger.warning("Fallback procedural ativado para miniatura de mapa '%s': %s", norm_key, redact_secrets(exc))

    if out is None:
        digest = hashlib.sha256(norm_key.encode("utf-8")).digest()
        rng = random.Random(int.from_bytes(digest[:8], "big"))

        ss = sz * 2
        im = Image.new("RGBA", (ss, ss), (112, 100, 86, 255))
        d = ImageDraw.Draw(im)

        for _ in range(9):
            cx, cy = rng.randint(0, ss), rng.randint(0, ss)
            rw, rh = rng.randint(18, 46), rng.randint(18, 46)
            shade = rng.choice(((92, 81, 69, 180), (132, 119, 103, 170), (78, 69, 58, 160)))
            d.ellipse((cx - rw, cy - rh, cx + rw, cy + rh), fill=shade)

        for g in range(ss // 4, ss, ss // 4):
            d.line([(g, 0), (g, ss)], fill=(60, 52, 44, 70), width=1)
            d.line([(0, g), (ss, g)], fill=(60, 52, 44, 70), width=1)

        for _ in range(4):
            pts = [
                (rng.randint(0, ss // 3), rng.randint(0, ss)),
                (rng.randint(ss // 3, (2 * ss) // 3), rng.randint(10, ss - 10)),
                (rng.randint((2 * ss) // 3, ss), rng.randint(0, ss)),
            ]
            d.line(pts, fill=(198, 186, 170, 225), width=rng.choice((2, 3)))

        d.rectangle((0, 0, ss - 1, ss - 1), outline=(72, 76, 88, 255), width=2)
        out = im.resize((sz, sz), Image.Resampling.LANCZOS)

    if len(_MAP_THUMB_CACHE) >= 256:
        _MAP_THUMB_CACHE.clear()
    _MAP_THUMB_CACHE[key] = out
    return out


_VETERANOS_BADGE_CACHE: dict[int, Image.Image] = {}


def get_veteranos_badge_icon(size: int = 20) -> Image.Image:
    """Carrega com segurança o ícone oficial da patente Discord Veteranos (com fallback vetorial)."""
    sz = max(12, min(int(size), 128))
    cached = _VETERANOS_BADGE_CACHE.get(sz)
    if cached is not None:
        return cached

    loaded: Image.Image | None = None
    try:
        if (
            VETERANOS_BADGE_PATH.is_file()
            and not VETERANOS_BADGE_PATH.is_symlink()
            and VETERANOS_BADGE_PATH.stat().st_size <= 262_144
        ):
            with Image.open(VETERANOS_BADGE_PATH, formats=["PNG"]) as raw_im:
                raw_im.load()
                loaded = raw_im.convert("RGBA").resize((sz, sz), Image.Resampling.LANCZOS)
    except Exception as exc:
        logger.warning("Fallback vetorial ativado para ícone Discord Veteranos: %s", redact_secrets(exc))

    if loaded is None:
        ss = sz * 4
        fb = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        d = ImageDraw.Draw(fb)
        gold = (242, 193, 68, 255)
        cx = ss // 2
        # 2 chevrons superiores + losango inferior (patente Discord Veteranos)
        d.polygon([(cx, int(ss * 0.08)), (int(ss * 0.88), int(ss * 0.42)), (int(ss * 0.88), int(ss * 0.56)), (cx, int(ss * 0.24)), (int(ss * 0.12), int(ss * 0.56)), (int(ss * 0.12), int(ss * 0.42))], fill=gold)
        d.polygon([(cx, int(ss * 0.34)), (int(ss * 0.88), int(ss * 0.68)), (int(ss * 0.88), int(ss * 0.82)), (cx, int(ss * 0.50)), (int(ss * 0.12), int(ss * 0.82)), (int(ss * 0.12), int(ss * 0.68))], fill=gold)
        d.polygon([(cx, int(ss * 0.62)), (int(ss * 0.68), int(ss * 0.78)), (cx, int(ss * 0.94)), (int(ss * 0.32), int(ss * 0.78))], fill=gold)
        loaded = fb.resize((sz, sz), Image.Resampling.LANCZOS)

    if len(_VETERANOS_BADGE_CACHE) >= 32:
        _VETERANOS_BADGE_CACHE.clear()
    _VETERANOS_BADGE_CACHE[sz] = loaded
    return loaded


_BG_BASE_CACHE: dict[str, Image.Image | None] = {}
_BG_ICON_CACHE: dict[tuple[str, int], Image.Image | None] = {}


def _load_battlegroup_asset(bg_key: str) -> Image.Image | None:
    """Carrega com segurança o ícone oficial PNG do Battlegroup em assets/battlegroups/<key>.png."""
    clean_key = re.sub(r"_icon_mipped$", "", str(bg_key or "").strip().lower())
    if not SAFE_BG_KEY_RE.fullmatch(clean_key):
        return None
    if clean_key in _BG_BASE_CACHE:
        return _BG_BASE_CACHE[clean_key]

    base: Image.Image | None = None
    png_path = BATTLEGROUPS_DIR / f"{clean_key}.png"
    try:
        bg_root = BATTLEGROUPS_DIR.resolve()
        if (
            png_path.is_file()
            and not png_path.is_symlink()
            and png_path.resolve().parent == bg_root
            and png_path.stat().st_size <= MAX_BG_ASSET_BYTES
        ):
            with Image.open(png_path, formats=["PNG"]) as raw_im:
                raw_im.load()
                base = raw_im.convert("RGBA")
    except Exception:
        base = None

    _BG_BASE_CACHE[clean_key] = base
    return base


def get_battlegroup_icon(bg_key: str, size: int = 18) -> Image.Image | None:
    """Retorna ícone RGBA redimensionado do Battlegroup oficial (ou None se ausente)."""
    clean_key = re.sub(r"_icon_mipped$", "", str(bg_key or "").strip().lower())
    if not clean_key:
        return None
    sz = max(12, min(int(size), 64))
    ck = (clean_key, sz)
    if ck in _BG_ICON_CACHE:
        return _BG_ICON_CACHE[ck]

    base = _load_battlegroup_asset(clean_key)
    out = base.resize((sz, sz), Image.Resampling.LANCZOS) if base is not None else None
    if len(_BG_ICON_CACHE) >= 128:
        _BG_ICON_CACHE.clear()
    _BG_ICON_CACHE[ck] = out
    return out


# ---------------------------------------------------------------------------
# Utilitários de formatação de tempo, modo e equipes (Axis vs Allies)
# ---------------------------------------------------------------------------
PT_BR_MONTH_ABBR: dict[int, str] = {
    1: "jan",
    2: "fev",
    3: "mar",
    4: "abr",
    5: "mai",
    6: "jun",
    7: "jul",
    8: "ago",
    9: "set",
    10: "out",
    11: "nov",
    12: "dez",
}


def format_relative_played(ts: int, now_ts: int | None = None, live_label: bool = False) -> str:
    now = now_ts or int(datetime.now(tz=timezone.utc).timestamp())
    if live_label:
        dt = datetime.fromtimestamp(int(ts), tz=BRT_TZ)
        day_month = f"{dt.day:02d}{PT_BR_MONTH_ABBR[dt.month]}"
        return f"{day_month} às {dt.strftime('%H:%M')}"

    diff = max(0, now - int(ts))
    if diff < 3600:
        return f"há {max(1, diff // 60)} min"
    if diff < 86400:
        hrs = diff // 3600
        return f"há {hrs}h" if hrs > 1 else "há 1h"
    days = diff // 86400
    if days == 1:
        return "há 1 dia"
    if days < 14:
        return f"há {days} dias"
    return f"há {days // 7} sem."


def format_mode_vs(mode_raw: str) -> str:
    s = str(mode_raw or "")
    for code, label in (("1v1", "1 vs 1"), ("2v2", "2 vs 2"), ("3v3", "3 vs 3"), ("4v4", "4 vs 4")):
        if code in s:
            return label
    if "Custom" in s or "Personalizada" in s:
        return "Personalizada"
    return strip_unsafe_chars(s)[:12] or "Partida"


def format_mm_ss(seconds: int) -> str:
    total = max(0, int(seconds))
    hrs, rem = divmod(total, 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs}:{mins:02d}:{secs:02d}" if hrs > 0 else f"{mins:02d}:{secs:02d}"


def _resolve_roster_participant(
    pid: int,
    steam_id: str,
    raw_alias: str,
    country: str,
    is_tracked: bool,
    steam_map: dict[str, dict[str, Any]],
    pid_map: dict[int, dict[str, Any]],
) -> tuple[str, str, str, bool]:
    clean_sid = str(steam_id or "").replace("/steam/", "").strip()
    r_entry = (pid_map.get(pid) if pid > 0 else None) or steam_map.get(clean_sid)
    if r_entry:
        bound_sid = str(r_entry.get("merged_into_steam_id") or clean_sid or r_entry.get("steam_id") or "")
        disp = format_bound_display_alias(
            raw_alias,
            str(r_entry.get("original_alias") or ""),
            r_entry.get("known_aliases"),
            pin_alias=bool(r_entry.get("pin_alias")),
            show_smurf_alias=bool(r_entry.get("show_smurf_alias")),
            smurf_of=str(r_entry.get("smurf_of") or ""),
        )
        roster_country = str(r_entry.get("country") or "").strip().lower()
        is_vet = bool(r_entry.get("is_veterano", True))
        return bound_sid, disp, (roster_country or str(country or "br").lower()), is_vet
    return clean_sid, raw_alias, str(country or ("br" if is_tracked else "un")).lower(), is_tracked


def _build_side_participant(
    raw_part: dict[str, Any],
    default_faction: str,
    steam_map: dict[str, dict[str, Any]],
    pid_map: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    pid = int(raw_part.get("profile_id", 0))
    old_e = raw_part.get("old_elo")
    new_e = raw_part.get("new_elo") or raw_part.get("elo")
    delta = raw_part.get("elo_delta")
    if delta is None and old_e and new_e:
        delta = int(new_e) - int(old_e)

    sid, disp_alias, ctry, is_br_ros = _resolve_roster_participant(
        pid,
        str(raw_part.get("steam_id") or ""),
        str(raw_part.get("alias") or f"ID {pid}"),
        str(raw_part.get("country") or "un"),
        False,
        steam_map,
        pid_map,
    )
    return {
        "profile_id": pid,
        "alias": disp_alias,
        "steam_id": sid,
        "country": ctry,
        "faction": raw_part.get("faction") or raw_part.get("faction_short") or default_faction,
        "old_elo": int(old_e) if old_e else (int(new_e) if new_e else None),
        "new_elo": int(new_e) if new_e else None,
        "elo_delta": int(delta) if delta is not None else None,
        "is_tracked": False,
        "is_br_roster": bool(raw_part.get("is_br_roster")) or is_br_ros,
    }


def _resolve_participant_battlegroup(
    pid: int,
    bg_map: dict[str, Any],
    raw_part: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Resolve `(bg_key, bg_name)` a partir do mapa da partida ou de metadados embutidos no participante."""
    entry = bg_map.get(str(pid)) or bg_map.get(pid)  # type: ignore[arg-type]
    raw_k = ""
    raw_n = ""
    if isinstance(entry, dict):
        raw_k = str(entry.get("key") or "")
        raw_n = str(entry.get("name") or "")
    elif isinstance(entry, str):
        raw_n = entry
    if not raw_k and not raw_n and isinstance(raw_part, dict):
        raw_k = str(raw_part.get("battlegroup_key") or "")
        raw_n = str(raw_part.get("battlegroup_name") or "")
    norm = normalize_battlegroup(raw_key=raw_k, raw_name=raw_n)
    if norm:
        return norm["key"], norm["name"]
    return "", ""


def extract_axis_and_allies_players(group: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reconstrói todos os jogadores únicos da partida e separa em (Eixo, Aliados), incluindo Battlegroups."""
    steam_map, pid_map = build_roster_lookup_maps()
    records = group.get("records") or [group.get("primary") or group]
    primary = records[0]
    tracked_by_pid: dict[int, dict[str, Any]] = {}

    bg_map: dict[str, Any] = {}
    for rec in records:
        rec_bg = rec.get("battlegroups")
        if isinstance(rec_bg, dict) and rec_bg:
            bg_map = rec_bg
            break
    if not bg_map and isinstance(group.get("battlegroups"), dict):
        bg_map = group["battlegroups"]

    for rec in records:
        pid = int(rec["tracked_profile_id"])
        old_e = rec.get("old_elo")
        new_e = rec.get("new_elo")
        delta = (int(new_e) - int(old_e)) if (old_e and new_e) else None
        sid, disp_alias, ctry, is_br_ros = _resolve_roster_participant(
            pid,
            str(rec.get("tracked_steam_id") or ""),
            str(rec.get("tracked_alias") or f"Jogador {pid}"),
            "br",
            True,
            steam_map,
            pid_map,
        )
        bg_key, bg_name = _resolve_participant_battlegroup(pid, bg_map, rec)
        tracked_by_pid[pid] = {
            "profile_id": pid,
            "alias": disp_alias,
            "steam_id": sid,
            "country": ctry,
            "faction": rec.get("tracked_faction") or "Wehrmacht",
            "old_elo": int(old_e) if old_e else None,
            "new_elo": int(new_e) if new_e else None,
            "elo_delta": delta,
            "is_tracked": True,
            "is_br_roster": is_br_ros,
            "battlegroup_key": bg_key,
            "battlegroup_name": bg_name,
        }

    primary_pid = int(primary["tracked_profile_id"])
    team_a: list[dict[str, Any]] = [tracked_by_pid[primary_pid]]
    seen_pids: set[int] = {primary_pid}

    for ally in primary.get("allies", []):
        apid = int(ally.get("profile_id", 0))
        if apid in seen_pids:
            continue
        seen_pids.add(apid)
        if apid in tracked_by_pid:
            team_a.append(tracked_by_pid[apid])
        else:
            part = _build_side_participant(ally, "Wehrmacht", steam_map, pid_map)
            part["battlegroup_key"], part["battlegroup_name"] = _resolve_participant_battlegroup(apid, bg_map, ally)
            team_a.append(part)

    team_b: list[dict[str, Any]] = []
    for opp in primary.get("opponents", []):
        opid = int(opp.get("profile_id", 0))
        if opid in seen_pids:
            continue
        seen_pids.add(opid)
        if opid in tracked_by_pid:
            team_b.append(tracked_by_pid[opid])
        else:
            part = _build_side_participant(opp, "US Forces", steam_map, pid_map)
            part["battlegroup_key"], part["battlegroup_name"] = _resolve_participant_battlegroup(opid, bg_map, opp)
            team_b.append(part)

    all_participants = team_a + team_b
    axis_players = [p for p in all_participants if str(p["faction"]) in AXIS_FACTIONS]
    allies_players = [p for p in all_participants if str(p["faction"]) in ALLIES_FACTIONS]

    if not axis_players and not allies_players:
        return team_a, team_b
    if (not axis_players or not allies_players) and team_a and team_b:
        # Partida customizada espelhada (Allies vs Allies ou Axis vs Axis): preserva os 2 times separados
        return team_b, team_a
    return axis_players, allies_players


def _is_br_veteranos_duel(
    recs: list[dict[str, Any]],
    axis_p: list[dict[str, Any]] | None = None,
    allies_p: list[dict[str, Any]] | None = None,
) -> bool:
    """Detecta confronto direto entre brasileiros monitorados dos dois lados da partida (Eixo vs Aliados)."""
    has_winner = any(bool(r.get("win")) for r in recs)
    has_loser = any(not bool(r.get("win")) for r in recs)
    if has_winner and has_loser:
        return True
    if axis_p is not None and allies_p is not None:
        axis_has_vet = any(bool(p.get("is_tracked")) or bool(p.get("is_br_roster")) for p in axis_p)
        allies_has_vet = any(bool(p.get("is_tracked")) or bool(p.get("is_br_roster")) for p in allies_p)
        if axis_has_vet and allies_has_vet:
            return True
    return False


def _compute_match_result_style(
    recs: list[dict[str, Any]],
    primary: dict[str, Any],
    axis_p: list[dict[str, Any]] | None = None,
    allies_p: list[dict[str, Any]] | None = None,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int], str]:
    if _is_br_veteranos_duel(recs, axis_p, allies_p):
        return (245, 184, 46, 255), (217, 119, 6, 255), "DUELO BR"

    old_e, new_e = primary.get("old_elo"), primary.get("new_elo")
    suffix = ""
    if old_e and new_e:
        diff = int(new_e) - int(old_e)
        suffix = f" +{diff}" if diff >= 0 else f" {diff}"

    if bool(primary.get("win")):
        return (29, 125, 250, 255), (28, 100, 242, 255), f"VITÓRIA{suffix}"
    return (224, 49, 49, 255), (214, 44, 44, 255), f"DERROTA{suffix}"


def _draw_two_team_columns(
    img: Image.Image,
    draw: ImageDraw.ImageDraw,
    width: int,
    top_bar_h: int,
    col_hdr_h: int,
    row_pitch: int,
    total_h: int,
    axis_p: list[dict[str, Any]],
    allies_p: list[dict[str, Any]],
    avatar_provider: SteamAvatarProvider,
    show_delta: bool = True,
    is_duel: bool = False,
    has_any_bg: bool = False,
    nemesis_opponent_pids: set[int] | None = None,
    fregues_opponent_pids: set[int] | None = None,
    smurf_opponent_pids: set[int] | None = None,
) -> None:
    """Desenha as duas colunas amplas (Allies à esquerda, Axis à direita) com Battlegroup tático sob o nick."""
    nem_pids = nemesis_opponent_pids or set()
    freg_pids = fregues_opponent_pids or set()
    smurf_pids = smurf_opponent_pids or set()
    hdr_bg = (30, 26, 18, 255) if is_duel else (22, 24, 30, 255)
    sep_col = (96, 78, 34, 255) if is_duel else (46, 50, 62, 255)
    row_sep_col = (54, 46, 26, 255) if is_duel else (37, 40, 49, 255)
    draw.rectangle((8, top_bar_h, width, top_bar_h + col_hdr_h), fill=hdr_bg)
    draw.line([(8, top_bar_h + col_hdr_h - 1), (width, top_bar_h + col_hdr_h - 1)], fill=sep_col, width=1)
    mid_x = width // 2 + 3
    draw.line([(mid_x, top_bar_h), (mid_x, total_h)], fill=sep_col, width=1)

    ch_col = (253, 224, 71, 255) if is_duel else (235, 238, 244, 255)
    ch_fnt = pick_font("Allies", size=17, bold=True, condensed=True)
    draw.text((22, top_bar_h + 9), "Allies", font=ch_fnt, fill=ch_col)
    draw.text((mid_x + 16, top_bar_h + 9), "Axis", font=ch_fnt, fill=ch_col)

    base_py = top_bar_h + col_hdr_h + (10 if has_any_bg else 11)
    max_rows = max(len(allies_p), len(axis_p))
    if has_any_bg and max_rows > 1:
        for ridx in range(1, max_rows):
            ly = base_py + ridx * row_pitch - 4
            draw.line([(16, ly), (mid_x - 8, ly)], fill=row_sep_col, width=1)
            draw.line([(mid_x + 8, ly), (width - 10, ly)], fill=row_sep_col, width=1)

    for col_start_x, col_limit_x, team_list in (
        (18, mid_x - 10, allies_p),
        (mid_x + 14, width - 12, axis_p),
    ):
        for pidx, pl in enumerate(team_list):
            py = base_py + pidx * row_pitch
            bg_key = str(pl.get("battlegroup_key") or "").strip()
            bg_name = str(pl.get("battlegroup_name") or "").strip()
            has_bg = bool(bg_name or bg_key)

            fac_sz = 34 if has_any_bg else 32
            fac_y = py + (12 if has_any_bg else 5)
            mini_fac = get_faction_icon(str(pl["faction"]), size=fac_sz)
            img.paste(mini_fac, (col_start_x, fac_y), mini_fac)

            elo_val = pl.get("old_elo") or pl.get("new_elo")
            elo_txt = str(elo_val) if elo_val else "S/R"
            elo_fnt = pick_font(elo_txt, size=20, bold=True, condensed=True)
            ew = text_width(draw, elo_txt, elo_fnt)
            elo_col = (243, 244, 246, 255) if elo_val else (156, 163, 175, 255)
            elo_right_x = col_start_x + (86 if show_delta else 98)
            elo_y = py + (17 if has_any_bg else 10)
            draw.text((elo_right_x - ew, elo_y), elo_txt, font=elo_fnt, fill=elo_col)

            delta = pl.get("elo_delta") if show_delta else None
            if delta is not None:
                d_txt = f"+{delta}" if delta >= 0 else f"{delta}"
                d_col = (74, 222, 128, 255) if delta >= 0 else (248, 113, 113, 255)
                d_fnt = pick_font(d_txt, size=18, bold=True, condensed=True)
                dw = text_width(draw, d_txt, d_fnt)
                draw.text((col_start_x + 128 - dw, py + (18 if has_any_bg else 11)), d_txt, font=d_fnt, fill=d_col)

            flag_x = col_start_x + (136 if show_delta else 110)
            country = str(pl.get("country") or "un").lower()
            pl_pid = int(pl.get("profile_id", 0) or 0)
            flag_used_w = _draw_flag_with_expat_badge(
                img,
                draw,
                country,
                flag_x,
                py + (21 if has_any_bg else 13),
                profile_id=pl_pid,
                flag_w=24,
                flag_h=17,
                compact=False,
            )

            name_x = flag_x + flag_used_w + 6
            is_tracked = bool(pl.get("is_tracked"))
            is_veterano = is_tracked or bool(pl.get("is_br_roster"))
            is_nemesis_opp = pl_pid > 0 and pl_pid in nem_pids
            is_fregues_opp = pl_pid > 0 and pl_pid in freg_pids
            is_smurf_opp = (not is_veterano) and pl_pid > 0 and pl_pid in smurf_pids

            if is_veterano:
                ring = (245, 184, 46, 255) if is_duel else (56, 189, 248, 255)
                av_sz = 44 if has_any_bg else 40
                av_im = avatar_provider.get_circular_avatar(
                    size=av_sz,
                    profile_id=pl_pid,
                    steam_id=str(pl.get("steam_id") or ""),
                    alias=str(pl.get("alias") or "BR"),
                    ring_color=ring,
                )
                img.paste(av_im, (name_x, py + (7 if has_any_bg else 1)), av_im)
                name_x += av_sz + 8

            badge_sz = 20 if has_any_bg else 22
            nem_badge_sz = 18
            freg_badge_sz = 18
            smurf_badge_sz = 18
            badge_reserve = (
                ((badge_sz + 8) if is_veterano else 0)
                + ((nem_badge_sz + 7) if is_nemesis_opp else 0)
                + ((freg_badge_sz + 7) if is_fregues_opp else 0)
                + ((smurf_badge_sz + 7) if is_smurf_opp else 0)
            )
            alias_sz = (20 if is_veterano else 18) if has_any_bg else (21 if is_veterano else 19)

            if is_veterano:
                alias_color = (253, 230, 138, 255) if is_duel else (125, 211, 252, 255)
                if has_any_bg:
                    alias_y = py + (5 if has_bg else 16)
                else:
                    alias_y = py + 9
            else:
                if is_smurf_opp:
                    alias_color = (253, 212, 118, 255)
                elif is_nemesis_opp:
                    alias_color = (253, 196, 206, 255)
                elif is_fregues_opp:
                    alias_color = (153, 246, 228, 255)
                else:
                    alias_color = (182, 190, 204, 255) if has_any_bg else (176, 184, 198, 255)
                if has_any_bg:
                    alias_y = py + (6 if has_bg else 17)
                else:
                    alias_y = py + 11

            alias_w = _draw_player_alias(
                draw,
                name_x,
                alias_y,
                str(pl.get("alias") or ""),
                max_px=max(56, col_limit_x - name_x - badge_reserve),
                size=alias_sz,
                bold=is_veterano or is_smurf_opp,
                primary_color=alias_color,
            )
            badge_cursor_x = int(name_x + alias_w + 6)
            if is_veterano:
                vet_ic = get_veteranos_badge_icon(size=badge_sz)
                img.paste(vet_ic, (badge_cursor_x, alias_y + 1), vet_ic)
                badge_cursor_x += badge_sz + 5
            if is_nemesis_opp:
                nb_y = alias_y + 2
                draw.rounded_rectangle(
                    (badge_cursor_x, nb_y, badge_cursor_x + nem_badge_sz, nb_y + nem_badge_sz),
                    radius=4,
                    fill=(159, 18, 57, 255),
                    outline=(251, 113, 133, 200),
                    width=1,
                )
                _draw_nemesis_swords_icon(
                    draw,
                    badge_cursor_x + nem_badge_sz / 2.0,
                    nb_y + nem_badge_sz / 2.0,
                    size=11,
                    color=(255, 241, 242, 255),
                )
                badge_cursor_x += nem_badge_sz + 5
            if is_fregues_opp:
                fb_y = alias_y + 2
                draw.rounded_rectangle(
                    (badge_cursor_x, fb_y, badge_cursor_x + freg_badge_sz, fb_y + freg_badge_sz),
                    radius=4,
                    fill=(15, 118, 110, 255),
                    outline=(94, 234, 212, 220),
                    width=1,
                )
                _draw_fregues_target_icon(
                    draw,
                    badge_cursor_x + freg_badge_sz / 2.0,
                    fb_y + freg_badge_sz / 2.0,
                    size=11,
                    color=(240, 253, 250, 255),
                )
                badge_cursor_x += freg_badge_sz + 5
            if is_smurf_opp:
                sb_y = alias_y + 2
                draw.rounded_rectangle(
                    (badge_cursor_x, sb_y, badge_cursor_x + smurf_badge_sz, sb_y + smurf_badge_sz),
                    radius=4,
                    fill=(180, 83, 9, 255),
                    outline=(251, 191, 36, 220),
                    width=1,
                )
                _draw_smurf_alert_icon(
                    draw,
                    badge_cursor_x + smurf_badge_sz / 2.0,
                    sb_y + smurf_badge_sz / 2.0,
                    size=11,
                    color=(255, 251, 235, 255),
                )

            if has_bg:
                bg_y = py + 31
                bg_ic = get_battlegroup_icon(bg_key, size=18) if bg_key else None
                ic_w = 18 if bg_ic is not None else 0
                pad_l = 5 if bg_ic is not None else 7
                pad_r = 8
                ic_gap = 5 if bg_ic is not None else 0
                avail_pill_w = max(60, col_limit_x - name_x - 2)
                max_txt_px = max(36, avail_pill_w - pad_l - ic_w - ic_gap - pad_r)

                disp_bg, bg_fnt = truncate_to_px(
                    draw,
                    bg_name or OFFICIAL_COH3_BATTLEGROUPS.get(bg_key, bg_key),
                    max_px=max_txt_px,
                    size=13,
                    bold=is_veterano,
                    italic=True,
                )
                bg_tw = text_width(draw, disp_bg, bg_fnt)
                pill_w = min(avail_pill_w, int(round(pad_l + ic_w + ic_gap + bg_tw + pad_r)))
                pill_h = 22

                pill_bg = (36, 30, 17, 255) if is_duel else (18, 20, 27, 255)
                pill_border = (118, 94, 38, 255) if is_duel else ((68, 86, 114, 255) if is_veterano else (54, 60, 74, 255))
                draw.rounded_rectangle(
                    (name_x, bg_y, name_x + pill_w, bg_y + pill_h),
                    radius=6,
                    fill=pill_bg,
                    outline=pill_border,
                    width=1,
                )
                tx = name_x + pad_l
                if bg_ic is not None:
                    img.paste(bg_ic, (tx, bg_y + 2), bg_ic)
                    tx += ic_w + ic_gap
                bg_txt_col = (232, 199, 126, 255) if is_veterano else (164, 175, 194, 255)
                draw.text((tx, bg_y + 3), disp_bg, font=bg_fnt, fill=bg_txt_col)


# ---------------------------------------------------------------------------
# RENDERIZADOR 1A: Card Grande de Partida Finalizada (PT-BR, 940px)
# ---------------------------------------------------------------------------
def _draw_nemesis_swords_icon(
    draw: ImageDraw.ImageDraw,
    cx: float,
    cy: float,
    size: int = 16,
    color: tuple[int, int, int, int] = (255, 228, 230, 255),
) -> None:
    """Desenha um emblema vetorial nítido de espadas cruzadas para o selo 1v1 Nemesis."""
    r = max(5.0, size / 2.0)
    # Lâminas cruzadas (X)
    draw.line([(cx - r + 1, cy - r + 1), (cx + r - 1, cy + r - 1)], fill=color, width=2)
    draw.line([(cx + r - 1, cy - r + 1), (cx - r + 1, cy + r - 1)], fill=color, width=2)
    # Guardas próximas aos punhos inferiores
    g = r * 0.45
    draw.line([(cx - r + 2, cy + r - 2 - g), (cx - r + 2 + g, cy + r - 2)], fill=color, width=2)
    draw.line([(cx + r - 2, cy + r - 2 - g), (cx + r - 2 - g, cy + r - 2)], fill=color, width=2)


def _draw_nemesis_footer_bar(
    draw: ImageDraw.ImageDraw,
    width: int,
    y_bar: int,
    bar_h: int,
    nemesis_entries: list[dict[str, Any]],
    fallback_tracked_alias: str,
    is_duel: bool = False,
) -> None:
    """Desenha a faixa tática inferior de Nemesis (1v1, 2v2, 3v3 e 4v4 Automatch — até 2 linhas compactas)."""
    if not nemesis_entries:
        return

    visible = nemesis_entries[:2]
    extra_rivals = max(0, len(nemesis_entries) - len(visible))
    any_new = any(bool(n.get("is_new_trigger")) for n in visible)

    bg_col = (36, 18, 22, 255) if not is_duel else (42, 24, 18, 255)
    top_border = (190, 38, 68, 220) if any_new else (136, 36, 56, 200)
    left_bar = (244, 63, 94, 255) if any_new else (225, 29, 72, 255)

    draw.rectangle((0, y_bar, width, y_bar + bar_h), fill=bg_col)
    draw.line([(0, y_bar), (width, y_bar)], fill=top_border, width=2)
    draw.rectangle((0, y_bar, 8, y_bar + bar_h), fill=left_bar)

    row_h = 34 if len(visible) > 1 else bar_h
    base_y = y_bar + (3 if len(visible) > 1 else 0)
    badge_fnt = pick_font("NOVO NEMESIS", size=13, bold=True, condensed=True)
    uniform_pill_w = max(
        int(text_width(draw, "NOVO NEMESIS" if bool(n.get("is_new_trigger")) else "NEMESIS", badge_fnt) + 34)
        for n in visible
    )

    for idx, nem in enumerate(visible):
        ry = base_y + idx * row_h
        if idx > 0:
            draw.line([(16, ry), (width - 16, ry)], fill=(78, 28, 40, 200), width=1)

        is_new = bool(nem.get("is_new_trigger"))
        wins = int(nem.get("wins", 0) or 0)
        losses = int(nem.get("losses", 0) or 0)
        total = int(nem.get("total", wins + losses) or (wins + losses))
        same_day = int(nem.get("same_day_games", 0) or 0)
        wr_pct = int(round(float(nem.get("win_rate", 0.0) or 0.0)))
        opp_pid = int(nem.get("opponent_profile_id", 0) or 0)
        raw_opp = str(nem.get("opponent_alias") or "").strip()
        opp_alias = raw_opp if raw_opp else (f"ID #{opp_pid}" if opp_pid > 0 else "Oponente")
        br_alias = str(nem.get("tracked_alias") or fallback_tracked_alias or "Veterano").strip()

        # Pílula de destaque à esquerda (largura uniforme em múltiplas linhas para alinhamento perfeito)
        badge_txt = "NOVO NEMESIS" if is_new else "NEMESIS"
        badge_tw = text_width(draw, badge_txt, badge_fnt)
        pill_x = 20
        pill_h = 24
        pill_y = ry + (row_h - pill_h) // 2 + (1 if len(visible) == 1 else 0)
        pill_w = uniform_pill_w
        pill_fill = (190, 18, 60, 255) if is_new else (136, 19, 55, 255)
        pill_outline = (251, 113, 133, 210) if is_new else (225, 29, 72, 180)
        draw.rounded_rectangle(
            (pill_x, pill_y, pill_x + pill_w, pill_y + pill_h),
            radius=6,
            fill=pill_fill,
            outline=pill_outline,
            width=1,
        )
        content_w = 18 + badge_tw
        content_x = pill_x + (pill_w - content_w) / 2.0
        _draw_nemesis_swords_icon(draw, content_x + 6, pill_y + pill_h / 2, size=13, color=(255, 241, 242, 255))
        draw.text((content_x + 18, pill_y + 4), badge_txt, font=badge_fnt, fill=(255, 241, 242, 255))

        # Metadados à direita (WR% + contagem histórica 2023+ + sequência ou ano inicial + rivais extras)
        loss_streak = int(nem.get("loss_streak", 0) or 0)
        since_year = int(nem.get("since_year", 0) or 0)
        meta_parts = [f"{wr_pct}% WR", f"{total} jogos"]
        if loss_streak >= 4:
            meta_parts.append(f"{loss_streak}D seg.")
        elif since_year >= 2023:
            meta_parts.append(f"desde {since_year}")
        if idx == len(visible) - 1 and extra_rivals > 0:
            lbl_extra = "rival" if extra_rivals == 1 else "rivais"
            meta_parts.append(f"+{extra_rivals} {lbl_extra}")
        meta_txt = "  •  ".join(meta_parts)

        meta_fnt = pick_font(meta_txt, size=13, bold=True, condensed=True)
        meta_w = text_width(draw, meta_txt, meta_fnt)
        meta_x = width - 20 - meta_w
        ty_meta = ry + (row_h - 16) // 2 + 1
        draw.text((meta_x, ty_meta), meta_txt, font=meta_fnt, fill=(253, 164, 175, 255))

        # Placar central: <Veterano>  <W>V - <L>D  vs  <Oponente>
        cursor_x = pill_x + pill_w + 16
        avail_px = max(140, int(meta_x - cursor_x - 20))

        w_str = f"{wins}V"
        sep_str = " - "
        l_str = f"{losses}D"
        vs_str = "  vs  "
        score_fnt = pick_font("99V - 99D", size=16, bold=True, condensed=True)
        vs_fnt = pick_font(vs_str, size=14, bold=False)

        is_krypt_nem = bool(nem.get("is_kryptonite"))
        krypt_icon_w = 18 if is_krypt_nem else 0

        fixed_score_w = (
            text_width(draw, w_str, score_fnt)
            + text_width(draw, sep_str, score_fnt)
            + text_width(draw, l_str, score_fnt)
            + text_width(draw, vs_str, vs_fnt)
            + 12
            + krypt_icon_w
        )
        name_budget = max(80, int(avail_px - fixed_score_w))
        br_max = max(50, int(name_budget * 0.48))
        opp_max = max(50, int(name_budget - br_max))

        br_disp, br_fnt = truncate_to_px(draw, br_alias, max_px=br_max, size=15, bold=True)
        opp_disp, opp_fnt = truncate_to_px(draw, opp_alias, max_px=opp_max, size=15, bold=False)

        ty_name = ry + (row_h - 18) // 2
        ty_score = ry + (row_h - 19) // 2

        draw.text((cursor_x, ty_name), br_disp, font=br_fnt, fill=(253, 230, 138, 255) if is_duel else (125, 211, 252, 255))
        cursor_x += text_width(draw, br_disp, br_fnt) + 12

        draw.text((cursor_x, ty_score), w_str, font=score_fnt, fill=(74, 222, 128, 255))
        cursor_x += text_width(draw, w_str, score_fnt)

        draw.text((cursor_x, ty_score), sep_str, font=score_fnt, fill=(148, 163, 184, 255))
        cursor_x += text_width(draw, sep_str, score_fnt)

        draw.text((cursor_x, ty_score), l_str, font=score_fnt, fill=(248, 113, 113, 255))
        cursor_x += text_width(draw, l_str, score_fnt)

        draw.text((cursor_x, ty_name + 1), vs_str, font=vs_fnt, fill=(180, 154, 162, 255))
        cursor_x += text_width(draw, vs_str, vs_fnt)

        if is_krypt_nem:
            _draw_kryptonite_crystal_icon(draw, cursor_x + 6, ry + row_h / 2.0, size=13, color=(236, 252, 203, 255))
            cursor_x += krypt_icon_w

        draw.text((cursor_x, ty_name), opp_disp, font=opp_fnt, fill=(241, 245, 249, 255))


def _draw_fregues_target_icon(
    draw: ImageDraw.ImageDraw,
    cx: float,
    cy: float,
    size: int = 13,
    color: tuple[int, int, int, int] = (240, 253, 250, 255),
) -> None:
    """Desenha um alvo vetorial nítido (mira/bullseye) para o selo FREGUÊS."""
    r = max(4.5, size / 2.0)
    ring_r = r * 0.72
    draw.ellipse((cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r), outline=color, width=1)
    # 4 hastes cardinais da mira
    tick_out = r * 1.02
    tick_in = r * 0.44
    draw.line([(cx, cy - tick_out), (cx, cy - tick_in)], fill=color, width=1)
    draw.line([(cx, cy + tick_in), (cx, cy + tick_out)], fill=color, width=1)
    draw.line([(cx - tick_out, cy), (cx - tick_in, cy)], fill=color, width=1)
    draw.line([(cx + tick_in, cy), (cx + tick_out, cy)], fill=color, width=1)
    # Ponto central do alvo
    dot_r = max(1.3, r * 0.24)
    draw.ellipse((cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r), fill=color)


def _draw_fregues_footer_bar(
    draw: ImageDraw.ImageDraw,
    width: int,
    y_bar: int,
    bar_h: int,
    fregues_entries: list[dict[str, Any]],
    fallback_tracked_alias: str,
    is_duel: bool = False,
) -> None:
    """Desenha a faixa tática turquesa/petróleo inferior de FREGUÊS (oposto ao Nemesis — até 2 linhas compactas)."""
    if not fregues_entries:
        return

    visible = fregues_entries[:2]
    extra_fregueses = max(0, len(fregues_entries) - len(visible))
    any_new = any(bool(f.get("is_new_trigger")) for f in visible)

    # Paleta turquesa / teal-petróleo (oposta ao carmesim do Nemesis, distinta de Criptonita e Smurf)
    bg_col = (12, 34, 38, 255) if not is_duel else (16, 36, 34, 255)
    top_border = (45, 212, 191, 225) if any_new else (20, 184, 166, 200)
    left_bar = (45, 212, 191, 255) if any_new else (20, 184, 166, 255)

    draw.rectangle((0, y_bar, width, y_bar + bar_h), fill=bg_col)
    draw.line([(0, y_bar), (width, y_bar)], fill=top_border, width=2)
    draw.rectangle((0, y_bar, 8, y_bar + bar_h), fill=left_bar)

    row_h = 34 if len(visible) > 1 else bar_h
    base_y = y_bar + (3 if len(visible) > 1 else 0)
    badge_fnt = pick_font("NOVO FREGUÊS", size=13, bold=True, condensed=True)
    uniform_pill_w = max(
        int(text_width(draw, "NOVO FREGUÊS" if bool(f.get("is_new_trigger")) else "FREGUÊS", badge_fnt) + 34)
        for f in visible
    )

    for idx, freg in enumerate(visible):
        ry = base_y + idx * row_h
        if idx > 0:
            draw.line([(16, ry), (width - 16, ry)], fill=(24, 72, 76, 200), width=1)

        is_new = bool(freg.get("is_new_trigger"))
        wins = int(freg.get("wins", 0) or 0)
        losses = int(freg.get("losses", 0) or 0)
        total = int(freg.get("total", wins + losses) or (wins + losses))
        wr_pct = int(round(float(freg.get("win_rate", 0.0) or 0.0)))
        opp_pid = int(freg.get("opponent_profile_id", 0) or 0)
        raw_opp = str(freg.get("opponent_alias") or "").strip()
        opp_alias = raw_opp if raw_opp else (f"ID #{opp_pid}" if opp_pid > 0 else "Oponente")
        br_alias = str(freg.get("tracked_alias") or fallback_tracked_alias or "Veterano").strip()

        # Pílula FREGUÊS / NOVO FREGUÊS à esquerda (turquesa-petróleo + borda água-marinha)
        badge_txt = "NOVO FREGUÊS" if is_new else "FREGUÊS"
        badge_tw = text_width(draw, badge_txt, badge_fnt)
        pill_x = 20
        pill_h = 24
        pill_y = ry + (row_h - pill_h) // 2 + (1 if len(visible) == 1 else 0)
        pill_w = uniform_pill_w
        pill_fill = (13, 148, 136, 255) if is_new else (15, 118, 110, 255)
        pill_outline = (94, 234, 212, 225) if is_new else (45, 212, 191, 190)
        draw.rounded_rectangle(
            (pill_x, pill_y, pill_x + pill_w, pill_y + pill_h),
            radius=6,
            fill=pill_fill,
            outline=pill_outline,
            width=1,
        )
        content_w = 18 + badge_tw
        content_x = pill_x + (pill_w - content_w) / 2.0
        _draw_fregues_target_icon(draw, content_x + 6, pill_y + pill_h / 2.0, size=13, color=(240, 253, 250, 255))
        draw.text((content_x + 18, pill_y + 4), badge_txt, font=badge_fnt, fill=(240, 253, 250, 255))

        # Metadados à direita (WR% + contagem histórica 2023+ + sequência de vitórias ou ano inicial + extras)
        win_streak = int(freg.get("win_streak", 0) or 0)
        since_year = int(freg.get("since_year", 0) or 0)
        meta_parts = [f"{wr_pct}% WR", f"{total} jogos"]
        if win_streak >= 4:
            meta_parts.append(f"{win_streak}V seg.")
        elif since_year >= 2023:
            meta_parts.append(f"desde {since_year}")
        if idx == len(visible) - 1 and extra_fregueses > 0:
            lbl_extra = "freguês" if extra_fregueses == 1 else "fregueses"
            meta_parts.append(f"+{extra_fregueses} {lbl_extra}")
        meta_txt = "  •  ".join(meta_parts)

        meta_fnt = pick_font(meta_txt, size=13, bold=True, condensed=True)
        meta_w = text_width(draw, meta_txt, meta_fnt)
        meta_x = width - 20 - meta_w
        ty_meta = ry + (row_h - 16) // 2 + 1
        draw.text((meta_x, ty_meta), meta_txt, font=meta_fnt, fill=(153, 246, 228, 255))

        # Placar central: <Veterano>  <W>V - <L>D  vs  <Oponente>
        cursor_x = pill_x + pill_w + 16
        avail_px = max(140, int(meta_x - cursor_x - 20))

        w_str = f"{wins}V"
        sep_str = " - "
        l_str = f"{losses}D"
        vs_str = "  vs  "
        score_fnt = pick_font("99V - 99D", size=16, bold=True, condensed=True)
        vs_fnt = pick_font(vs_str, size=14, bold=False)

        fixed_score_w = (
            text_width(draw, w_str, score_fnt)
            + text_width(draw, sep_str, score_fnt)
            + text_width(draw, l_str, score_fnt)
            + text_width(draw, vs_str, vs_fnt)
            + 12
        )
        name_budget = max(80, int(avail_px - fixed_score_w))
        br_max = max(50, int(name_budget * 0.48))
        opp_max = max(50, int(name_budget - br_max))

        br_disp, br_fnt = truncate_to_px(draw, br_alias, max_px=br_max, size=15, bold=True)
        opp_disp, opp_fnt = truncate_to_px(draw, opp_alias, max_px=opp_max, size=15, bold=False)

        ty_name = ry + (row_h - 18) // 2
        ty_score = ry + (row_h - 19) // 2

        draw.text((cursor_x, ty_name), br_disp, font=br_fnt, fill=(253, 230, 138, 255) if is_duel else (125, 211, 252, 255))
        cursor_x += text_width(draw, br_disp, br_fnt) + 12

        draw.text((cursor_x, ty_score), w_str, font=score_fnt, fill=(74, 222, 128, 255))
        cursor_x += text_width(draw, w_str, score_fnt)

        draw.text((cursor_x, ty_score), sep_str, font=score_fnt, fill=(148, 163, 184, 255))
        cursor_x += text_width(draw, sep_str, score_fnt)

        draw.text((cursor_x, ty_score), l_str, font=score_fnt, fill=(248, 113, 113, 255))
        cursor_x += text_width(draw, l_str, score_fnt)

        draw.text((cursor_x, ty_name + 1), vs_str, font=vs_fnt, fill=(126, 178, 176, 255))
        cursor_x += text_width(draw, vs_str, vs_fnt)

        draw.text((cursor_x, ty_name), opp_disp, font=opp_fnt, fill=(241, 245, 249, 255))


def _draw_smurf_alert_icon(
    draw: ImageDraw.ImageDraw,
    cx: float,
    cy: float,
    size: int = 13,
    color: tuple[int, int, int, int] = (255, 251, 235, 255),
) -> None:
    """Desenha um triângulo vetorial nítido de alerta ('!') para o selo ALERTA SMURF."""
    r = max(4.5, size / 2.0)
    top = (cx, cy - r + 0.5)
    left = (cx - r + 0.5, cy + r - 0.5)
    right = (cx + r - 0.5, cy + r - 0.5)
    draw.polygon([top, right, left], outline=color)
    draw.line([top, right, left, top], fill=color, width=2)
    # Ponto de exclamação interno
    draw.line([(cx, cy - r * 0.35), (cx, cy + r * 0.22)], fill=color, width=2)
    draw.ellipse((cx - 1.0, cy + r * 0.42, cx + 1.0, cy + r * 0.42 + 2.0), fill=color)


def _draw_smurf_alert_footer_bar(
    draw: ImageDraw.ImageDraw,
    width: int,
    y_bar: int,
    bar_h: int,
    smurf_alerts: list[dict[str, Any]],
    is_duel: bool = False,
) -> None:
    """Desenha a faixa tática âmbar inferior de ALERTA SMURF (1 ou 2 linhas com sinais forenses compactos)."""
    if not smurf_alerts:
        return

    visible = smurf_alerts[:2]
    extra_alerts = max(0, len(smurf_alerts) - len(visible))

    bg_col = (40, 26, 12, 255) if not is_duel else (46, 30, 12, 255)
    top_border = (245, 158, 11, 230)
    left_bar = (251, 191, 36, 255)

    draw.rectangle((0, y_bar, width, y_bar + bar_h), fill=bg_col)
    draw.line([(0, y_bar), (width, y_bar)], fill=top_border, width=2)
    draw.rectangle((0, y_bar, 8, y_bar + bar_h), fill=left_bar)

    row_h = 49 if len(visible) > 1 else bar_h
    base_y = y_bar + (4 if len(visible) > 1 else 2)
    badge_fnt = pick_font("ALERTA SMURF", size=13, bold=True, condensed=True)
    badge_txt = "ALERTA SMURF"
    badge_tw = text_width(draw, badge_txt, badge_fnt)
    pill_w = int(badge_tw + 32)
    pill_h = 22
    pill_x = 20

    for idx, alert in enumerate(visible):
        ry = base_y + idx * row_h
        if idx > 0:
            draw.line([(16, ry - 1), (width - 16, ry - 1)], fill=(96, 62, 24, 200), width=1)

        opp_pid = int(alert.get("opponent_profile_id", 0) or 0)
        opp_alias = str(alert.get("opponent_alias") or (f"ID #{opp_pid}" if opp_pid > 0 else "Oponente")).strip()
        main_alias = str(alert.get("suspected_main_alias") or "").strip()
        prob = int(alert.get("probability_pct", 0) or 0)
        tier = str(alert.get("confidence_tier") or "Alta").strip()
        reasons = [str(r).strip() for r in (alert.get("top_reasons") or []) if str(r or "").strip()][:4]

        # Linha 1: pílula ALERTA SMURF + manchete + probabilidade à direita
        line1_y = ry + (5 if reasons else max(10, (row_h - pill_h) // 2))
        draw.rounded_rectangle(
            (pill_x, line1_y, pill_x + pill_w, line1_y + pill_h),
            radius=6,
            fill=(180, 83, 9, 255),
            outline=(251, 191, 36, 225),
            width=1,
        )
        content_w = 18 + badge_tw
        content_x = pill_x + (pill_w - content_w) / 2.0
        _draw_smurf_alert_icon(draw, content_x + 6, line1_y + pill_h / 2.0, size=12, color=(255, 251, 235, 255))
        draw.text((content_x + 18, line1_y + 3), badge_txt, font=badge_fnt, fill=(255, 251, 235, 255))

        meta_txt = f"{prob}%  •  {tier}"
        if idx == len(visible) - 1 and extra_alerts > 0:
            meta_txt = f"{meta_txt}  •  +{extra_alerts}"
        meta_fnt = pick_font(meta_txt, size=14, bold=True, condensed=True)
        meta_w = text_width(draw, meta_txt, meta_fnt)
        meta_x = width - 20 - meta_w
        draw.text((meta_x, line1_y + 3), meta_txt, font=meta_fnt, fill=(253, 224, 71, 255))

        cursor_x = pill_x + pill_w + 14
        avail_px = max(160, int(meta_x - cursor_x - 16))
        if main_alias:
            mid_txt = "  ➔  Possível smurf de  "
            mid_fnt = pick_font(mid_txt, size=14, bold=False)
            mid_w = text_width(draw, mid_txt, mid_fnt)
            name_budget = max(80, int(avail_px - mid_w))
            opp_disp, opp_fnt = truncate_to_px(draw, opp_alias, max_px=max(50, int(name_budget * 0.48)), size=15, bold=True)
            main_disp, main_fnt = truncate_to_px(draw, main_alias, max_px=max(50, int(name_budget * 0.52)), size=15, bold=True)
            draw.text((cursor_x, line1_y + 2), opp_disp, font=opp_fnt, fill=(253, 212, 118, 255))
            cursor_x += text_width(draw, opp_disp, opp_fnt)
            draw.text((cursor_x, line1_y + 3), mid_txt, font=mid_fnt, fill=(214, 188, 152, 255))
            cursor_x += mid_w
            draw.text((cursor_x, line1_y + 2), main_disp, font=main_fnt, fill=(125, 211, 252, 255))
        else:
            mid_txt = "➔  Possível smurf BR não identificado"
            mid_fnt = pick_font(mid_txt, size=14, bold=False)
            mid_w = text_width(draw, mid_txt, mid_fnt) + 10
            opp_disp, opp_fnt = truncate_to_px(draw, opp_alias, max_px=max(60, int(avail_px - mid_w)), size=15, bold=True)
            draw.text((cursor_x, line1_y + 2), opp_disp, font=opp_fnt, fill=(253, 212, 118, 255))
            cursor_x += text_width(draw, opp_disp, opp_fnt) + 10
            suffix_disp, suffix_fnt = truncate_to_px(draw, mid_txt, max_px=max(80, int(meta_x - cursor_x - 14)), size=14, bold=False)
            draw.text((cursor_x, line1_y + 3), suffix_disp, font=suffix_fnt, fill=(238, 210, 168, 255))

        # Linha 2: chips forenses compactos
        if reasons:
            line2_y = line1_y + pill_h + 4
            sig_txt = "Sinais: " + "  •  ".join(reasons)
            sig_disp, sig_fnt = truncate_to_px(draw, sig_txt, max_px=width - 44, size=13, bold=False)
            draw.text((pill_x + 2, line2_y), sig_disp, font=sig_fnt, fill=(224, 196, 156, 255))


def _draw_kryptonite_crystal_icon(
    draw: ImageDraw.ImageDraw,
    cx: float,
    cy: float,
    size: int = 13,
    color: tuple[int, int, int, int] = (236, 252, 203, 255),
) -> None:
    """Desenha um cristal facetado vetorial verde-ácido radioativo de Criptonita para o selo CRIPTONITA."""
    rx = max(3.5, size * 0.34)
    ry = max(5.0, size * 0.50)
    pts = [
        (cx, cy - ry),
        (cx + rx, cy - ry * 0.32),
        (cx + rx * 0.85, cy + ry * 0.45),
        (cx, cy + ry),
        (cx - rx * 0.85, cy + ry * 0.45),
        (cx - rx, cy - ry * 0.32),
    ]
    draw.polygon(pts, fill=(163, 230, 53, 235), outline=color)
    draw.line([(cx, cy - ry + 1.0), (cx, cy + ry - 1.0)], fill=color, width=1)
    draw.line([(cx - rx * 0.75, cy - ry * 0.25), (cx + rx * 0.75, cy - ry * 0.25)], fill=color, width=1)


_KRYPTONITE_KIND_LABELS: dict[str, str] = {
    "map": "Mapa",
    "battlegroup": "BG",
    "nemesis": "Nêmesis",
    "opponent": "Rival",
    "partner": "Parceiro",
}


def _draw_kryptonite_footer_bar(
    img: Image.Image,
    draw: ImageDraw.ImageDraw,
    width: int,
    y_bar: int,
    bar_h: int,
    kryptonite_entries: list[dict[str, Any]],
    fallback_tracked_alias: str,
    is_duel: bool = False,
) -> None:
    """Desenha a faixa tática verde-ácido/tóxico inferior de CRIPTONITA (até 2 linhas compactas, cruzada com Nêmesis)."""
    if not kryptonite_entries:
        return

    visible = kryptonite_entries[:2]
    extra_entries = max(0, len(kryptonite_entries) - len(visible))

    # Paleta verde-ácido / chartreuse radioativo (tóxico) em fundo oliva escuro — distinto do verde positivo de vitória
    bg_col = (24, 29, 11, 255) if not is_duel else (29, 31, 12, 255)
    top_border = (163, 230, 53, 220)
    left_bar = (190, 242, 100, 255)

    draw.rectangle((0, y_bar, width, y_bar + bar_h), fill=bg_col)
    draw.line([(0, y_bar), (width, y_bar)], fill=top_border, width=2)
    draw.rectangle((0, y_bar, 8, y_bar + bar_h), fill=left_bar)

    row_h = 34 if len(visible) > 1 else bar_h
    base_y = y_bar + (3 if len(visible) > 1 else 0)
    badge_txt = "CRIPTONITA"
    badge_fnt = pick_font(badge_txt, size=13, bold=True, condensed=True)
    badge_tw = text_width(draw, badge_txt, badge_fnt)
    pill_w = int(badge_tw + 32)
    pill_h = 24
    pill_x = 20

    for idx, krypt in enumerate(visible):
        ry = base_y + idx * row_h
        if idx > 0:
            draw.line([(16, ry), (width - 16, ry)], fill=(68, 86, 26, 200), width=1)

        kind = str(krypt.get("kind") or "map").strip().lower()
        is_nem_kind = kind == "nemesis" or bool(krypt.get("is_nemesis"))
        kind_lbl = _KRYPTONITE_KIND_LABELS.get("nemesis" if is_nem_kind else kind, "Alvo")
        target_label = str(krypt.get("label") or "Desconhecido").strip()
        bg_key = str(krypt.get("bg_key") or "").strip()
        wins = int(krypt.get("wins", 0) or 0)
        losses = int(krypt.get("losses", 0) or 0)
        total = int(krypt.get("total", wins + losses) or (wins + losses))
        wr_pct = int(round(float(krypt.get("win_rate", 0.0) or 0.0)))
        loss_streak = int(krypt.get("loss_streak", 0) or 0)
        has_nem_combo = isinstance(krypt.get("nemesis_cross"), dict) and not is_nem_kind
        br_alias = str(krypt.get("tracked_alias") or fallback_tracked_alias or "Veterano").strip()

        # Pílula CRIPTONITA à esquerda (oliva tóxico + borda verde-ácido radioativo)
        pill_y = ry + (row_h - pill_h) // 2 + (1 if len(visible) == 1 else 0)
        draw.rounded_rectangle(
            (pill_x, pill_y, pill_x + pill_w, pill_y + pill_h),
            radius=6,
            fill=(77, 124, 15, 255),
            outline=(190, 242, 100, 235),
            width=1,
        )
        content_w = 18 + badge_tw
        content_x = pill_x + (pill_w - content_w) / 2.0
        _draw_kryptonite_crystal_icon(draw, content_x + 6, pill_y + pill_h / 2.0, size=13, color=(247, 254, 231, 255))
        draw.text((content_x + 18, pill_y + 4), badge_txt, font=badge_fnt, fill=(247, 254, 231, 255))

        # Metadados à direita (WR% + jogos + combo Nêmesis ou sequência de derrotas + extras)
        meta_parts = [f"{wr_pct}% WR", f"{total} jogos"]
        if has_nem_combo:
            meta_parts.append("+Nêmesis")
        elif loss_streak >= 4:
            meta_parts.append(f"{loss_streak}D seg.")
        if idx == len(visible) - 1 and extra_entries > 0:
            meta_parts.append(f"+{extra_entries}")
        meta_txt = "  •  ".join(meta_parts)
        meta_fnt = pick_font(meta_txt, size=13, bold=True, condensed=True)
        meta_w = text_width(draw, meta_txt, meta_fnt)
        meta_x = width - 20 - meta_w
        ty_meta = ry + (row_h - 16) // 2 + 1
        draw.text(
            (meta_x, ty_meta),
            meta_txt,
            font=meta_fnt,
            fill=(253, 164, 175, 255) if has_nem_combo else (217, 249, 157, 255),
        )

        # Bloco central: <Veterano>  •  [espadas] <Tipo:> [ícone BG] <Alvo>   <W>V - <L>D
        cursor_x = pill_x + pill_w + 16
        avail_px = max(160, int(meta_x - cursor_x - 18))

        sep_dot = "  •  "
        kind_prefix = f"{kind_lbl}: "
        w_str = f"{wins}V"
        dash_str = " - "
        l_str = f"{losses}D"
        sep_fnt = pick_font(sep_dot, size=14, bold=False)
        kind_fnt = pick_font(kind_prefix, size=14, bold=True)
        score_fnt = pick_font("99V - 99D", size=16, bold=True, condensed=True)

        bg_icon_im = get_battlegroup_icon(bg_key, size=18) if (kind == "battlegroup" and bg_key) else None
        bg_icon_w = 23 if bg_icon_im is not None else 0
        nem_icon_w = 18 if is_nem_kind else 0

        fixed_w = (
            text_width(draw, sep_dot, sep_fnt)
            + nem_icon_w
            + text_width(draw, kind_prefix, kind_fnt)
            + bg_icon_w
            + 14
            + text_width(draw, w_str, score_fnt)
            + text_width(draw, dash_str, score_fnt)
            + text_width(draw, l_str, score_fnt)
        )
        name_budget = max(90, int(avail_px - fixed_w))
        br_max = max(56, int(name_budget * 0.42))
        tgt_max = max(64, int(name_budget - br_max))

        br_disp, br_fnt = truncate_to_px(draw, br_alias, max_px=br_max, size=15, bold=True)
        tgt_disp, tgt_fnt = truncate_to_px(draw, target_label, max_px=tgt_max, size=15, bold=True)

        ty_name = ry + (row_h - 18) // 2
        ty_score = ry + (row_h - 19) // 2

        draw.text(
            (cursor_x, ty_name),
            br_disp,
            font=br_fnt,
            fill=(253, 230, 138, 255) if is_duel else (125, 211, 252, 255),
        )
        cursor_x += text_width(draw, br_disp, br_fnt)

        draw.text((cursor_x, ty_name + 1), sep_dot, font=sep_fnt, fill=(124, 148, 58, 255))
        cursor_x += text_width(draw, sep_dot, sep_fnt)

        if is_nem_kind:
            _draw_nemesis_swords_icon(draw, cursor_x + 6, ry + row_h / 2.0, size=12, color=(251, 113, 133, 255))
            cursor_x += nem_icon_w

        draw.text(
            (cursor_x, ty_name + 1),
            kind_prefix,
            font=kind_fnt,
            fill=(251, 113, 133, 255) if is_nem_kind else (190, 242, 100, 255),
        )
        cursor_x += text_width(draw, kind_prefix, kind_fnt)

        if bg_icon_im is not None:
            img.paste(bg_icon_im, (int(cursor_x), int(ry + (row_h - 18) // 2)), bg_icon_im)
            cursor_x += bg_icon_w

        draw.text((cursor_x, ty_name), tgt_disp, font=tgt_fnt, fill=(241, 245, 249, 255))
        cursor_x += text_width(draw, tgt_disp, tgt_fnt) + 14

        draw.text((cursor_x, ty_score), w_str, font=score_fnt, fill=(74, 222, 128, 255))
        cursor_x += text_width(draw, w_str, score_fnt)

        draw.text((cursor_x, ty_score), dash_str, font=score_fnt, fill=(148, 163, 184, 255))
        cursor_x += text_width(draw, dash_str, score_fnt)

        draw.text((cursor_x, ty_score), l_str, font=score_fnt, fill=(248, 113, 113, 255))


def render_single_match_card_png(
    grp: dict[str, Any],
    avatar_provider: SteamAvatarProvider,
) -> bytes:
    width = 940
    recs = grp.get("records") or [grp.get("primary") or grp]
    primary = recs[0]
    axis_p, allies_p = extract_axis_and_allies_players(grp)
    if hasattr(avatar_provider, "prefetch_avatar_urls"):
        avatar_provider.prefetch_avatar_urls(axis_p + allies_p)
    is_duel = _is_br_veteranos_duel(recs, axis_p, allies_p)
    has_any_bg = any(bool(p.get("battlegroup_name") or p.get("battlegroup_key")) for p in axis_p + allies_p)

    raw_nem_list = grp.get("nemesis_list") or primary.get("nemesis_list")
    nemesis_entries: list[dict[str, Any]] = []
    if isinstance(raw_nem_list, list):
        nemesis_entries = [n for n in raw_nem_list if isinstance(n, dict) and bool(n.get("triggered"))]
    if not nemesis_entries:
        nemesis_raw = grp.get("nemesis") or primary.get("nemesis")
        if isinstance(nemesis_raw, dict) and bool(nemesis_raw.get("triggered")):
            nemesis_entries = [nemesis_raw]

    raw_freg_list = grp.get("fregues_list") or primary.get("fregues_list")
    fregues_entries: list[dict[str, Any]] = []
    if isinstance(raw_freg_list, list):
        fregues_entries = [f for f in raw_freg_list if isinstance(f, dict) and bool(f.get("triggered"))]
    if not fregues_entries:
        freg_raw = grp.get("fregues") or primary.get("fregues")
        if isinstance(freg_raw, dict) and bool(freg_raw.get("triggered")):
            fregues_entries = [freg_raw]

    raw_krypt_list = grp.get("kryptonite_list") or primary.get("kryptonite_list")
    kryptonite_entries: list[dict[str, Any]] = []
    if isinstance(raw_krypt_list, list):
        kryptonite_entries = [k for k in raw_krypt_list if isinstance(k, dict) and bool(k.get("triggered"))]
    if not kryptonite_entries:
        krypt_raw = grp.get("kryptonite") or primary.get("kryptonite")
        if isinstance(krypt_raw, dict) and bool(krypt_raw.get("triggered")):
            kryptonite_entries = [krypt_raw]

    # Nemesis, Freguês e Criptonita aplicam-se a todos os modos Automatch (1v1, 2v2, 3v3, 4v4), excluindo Custom/IA
    mode_lbl = format_mode_vs(str(primary.get("mode") or ""))
    if mode_lbl not in ("1 vs 1", "2 vs 2", "3 vs 3", "4 vs 4"):
        nemesis_entries = []
        fregues_entries = []
        kryptonite_entries = []
    elif not any(isinstance(r, dict) and not bool(r.get("win")) for r in recs):
        # Garantia extra: Criptonita NUNCA aparece em cards de vitória
        kryptonite_entries = []

    nemesis_opp_pids = {
        int(n.get("opponent_profile_id", 0) or 0)
        for n in nemesis_entries
        if int(n.get("opponent_profile_id", 0) or 0) > 0
    }
    fregues_opp_pids = {
        int(f.get("opponent_profile_id", 0) or 0)
        for f in fregues_entries
        if int(f.get("opponent_profile_id", 0) or 0) > 0
    }

    raw_smurf_alerts = grp.get("smurf_alerts") or primary.get("smurf_alerts") or []
    smurf_entries: list[dict[str, Any]] = [
        a for a in (raw_smurf_alerts if isinstance(raw_smurf_alerts, list) else [])
        if isinstance(a, dict) and int(a.get("probability_pct", 0) or 0) > 0
    ]
    smurf_opp_pids = {
        int(a.get("opponent_profile_id", 0) or 0)
        for a in smurf_entries
        if int(a.get("opponent_profile_id", 0) or 0) > 0
    }

    duel_banner_h = 34 if is_duel else 0
    max_team = max(len(axis_p), len(allies_p), 1)
    top_bar_h = 90
    col_hdr_h = 38
    row_pitch = 62 if has_any_bg else 52
    columns_bottom_h = duel_banner_h + top_bar_h + col_hdr_h + max_team * row_pitch + 20
    nemesis_bar_h = (74 if len(nemesis_entries) >= 2 else 42) if nemesis_entries else 0
    fregues_bar_h = (74 if len(fregues_entries) >= 2 else 42) if fregues_entries else 0
    kryptonite_bar_h = (74 if len(kryptonite_entries) >= 2 else 42) if kryptonite_entries else 0
    smurf_bar_h = (104 if len(smurf_entries) >= 2 else 56) if smurf_entries else 0
    total_h = columns_bottom_h + nemesis_bar_h + fregues_bar_h + kryptonite_bar_h + smurf_bar_h

    bg_fill = (28, 25, 20, 255) if is_duel else (26, 28, 34, 255)
    img = Image.new("RGBA", (width, total_h), bg_fill)
    draw = ImageDraw.Draw(img)
    accent_col, pill_col, pill_text = _compute_match_result_style(recs, primary, axis_p, allies_p)

    if is_duel:
        draw.rectangle((0, 0, width, duel_banner_h), fill=(44, 34, 12, 255))
        draw.line([(0, duel_banner_h - 1), (width, duel_banner_h - 1)], fill=(245, 184, 46, 230), width=2)
        banner_txt = "CONFRONTO ENTRE VETERANOS BR  •  CLÁSSICO BRASILEIRO"
        b_fnt = pick_font(banner_txt, size=15, bold=True, condensed=True)
        btw = text_width(draw, banner_txt, b_fnt)
        vet_hdr = get_veteranos_badge_icon(size=20)
        total_bw = btw + 56
        bx0 = int((width - total_bw) / 2)
        img.paste(vet_hdr, (bx0, 7), vet_hdr)
        draw.text((bx0 + 28, 8), banner_txt, font=b_fnt, fill=(253, 224, 71, 255))
        img.paste(vet_hdr, (int(bx0 + 28 + btw + 8), 7), vet_hdr)

    y_top = duel_banner_h
    draw.rectangle((0, y_top, width, y_top + top_bar_h), fill=(24, 21, 16, 255) if is_duel else (19, 21, 26, 255))
    draw.line(
        [(0, y_top + top_bar_h - 1), (width, y_top + top_bar_h - 1)],
        fill=(120, 92, 28, 255) if is_duel else (52, 56, 68, 255),
        width=2,
    )
    draw.rectangle((0, 0, 8, columns_bottom_h), fill=accent_col)

    fac_icon = get_faction_icon(str(primary.get("tracked_faction", "Wehrmacht")), size=60)
    img.paste(fac_icon, (22, y_top + 15), fac_icon)

    pill_w, pill_h, pill_x, pill_y = 204, 42, 96, y_top + 14
    draw.rounded_rectangle((pill_x, pill_y, pill_x + pill_w, pill_y + pill_h), radius=21, fill=pill_col)
    pill_fnt = pick_font(pill_text, size=20, bold=True)
    ptw = text_width(draw, pill_text, pill_fnt)
    draw.text((pill_x + (pill_w - ptw) / 2, pill_y + 9), pill_text, font=pill_fnt, fill=(255, 255, 255, 255))

    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    played_str = f"Data: {format_relative_played(int(primary.get('completion_time', 0)), now_ts=now_ts, live_label=True)}"
    pl_fnt = pick_font(played_str, size=15, bold=True)
    draw.text((100, y_top + 62), played_str, font=pl_fnt, fill=(224, 212, 182, 255) if is_duel else (195, 202, 214, 255))

    m_thumb = get_tactical_map_thumb(str(primary.get("map_raw") or ""), size=64)
    thumb_x = width - 84
    img.paste(m_thumb, (thumb_x, y_top + 13), m_thumb)

    map_label, m_fnt = truncate_to_px(
        draw,
        _resolve_display_map_name(primary, fallback="Mapa Desconhecido"),
        max_px=380,
        size=21,
        bold=True,
    )
    mw = text_width(draw, map_label, m_fnt)
    draw.text((thumb_x - 16 - mw, y_top + 17), map_label, font=m_fnt, fill=(253, 230, 138, 255) if is_duel else (243, 244, 246, 255))

    mode_dur_str = f"{mode_lbl}   •   Duração: {format_mm_ss(int(primary.get('duration_sec', 0)))}"
    md_fnt = pick_font(mode_dur_str, size=17, bold=True)
    mdw = text_width(draw, mode_dur_str, md_fnt)
    draw.text((thumb_x - 16 - mdw, y_top + 49), mode_dur_str, font=md_fnt, fill=(214, 198, 160, 255) if is_duel else (176, 184, 196, 255))

    _draw_two_team_columns(
        img=img,
        draw=draw,
        width=width,
        top_bar_h=y_top + top_bar_h,
        col_hdr_h=col_hdr_h,
        row_pitch=row_pitch,
        total_h=columns_bottom_h,
        axis_p=axis_p,
        allies_p=allies_p,
        avatar_provider=avatar_provider,
        show_delta=True,
        is_duel=is_duel,
        has_any_bg=has_any_bg,
        nemesis_opponent_pids=nemesis_opp_pids,
        fregues_opponent_pids=fregues_opp_pids,
        smurf_opponent_pids=smurf_opp_pids,
    )

    if nemesis_entries:
        resolved_entries: list[dict[str, Any]] = []
        all_rendered = allies_p + axis_p
        for n in nemesis_entries:
            ncopy = dict(n)
            if not str(ncopy.get("tracked_alias") or "").strip():
                nem_tpid = int(ncopy.get("tracked_profile_id", 0) or 0)
                ncopy["tracked_alias"] = next(
                    (str(p.get("alias") or "") for p in all_rendered if int(p.get("profile_id", 0)) == nem_tpid),
                    str(primary.get("tracked_alias") or "Veterano"),
                )
            resolved_entries.append(ncopy)
        _draw_nemesis_footer_bar(
            draw=draw,
            width=width,
            y_bar=columns_bottom_h,
            bar_h=nemesis_bar_h,
            nemesis_entries=resolved_entries,
            fallback_tracked_alias=str(primary.get("tracked_alias") or "Veterano"),
            is_duel=is_duel,
        )

    if fregues_entries:
        resolved_freg: list[dict[str, Any]] = []
        all_rendered = allies_p + axis_p
        for f in fregues_entries:
            fcopy = dict(f)
            if not str(fcopy.get("tracked_alias") or "").strip():
                f_tpid = int(fcopy.get("tracked_profile_id", 0) or 0)
                fcopy["tracked_alias"] = next(
                    (str(p.get("alias") or "") for p in all_rendered if int(p.get("profile_id", 0)) == f_tpid),
                    str(primary.get("tracked_alias") or "Veterano"),
                )
            resolved_freg.append(fcopy)
        _draw_fregues_footer_bar(
            draw=draw,
            width=width,
            y_bar=columns_bottom_h + nemesis_bar_h,
            bar_h=fregues_bar_h,
            fregues_entries=resolved_freg,
            fallback_tracked_alias=str(primary.get("tracked_alias") or "Veterano"),
            is_duel=is_duel,
        )

    if kryptonite_entries:
        resolved_krypt: list[dict[str, Any]] = []
        all_rendered = allies_p + axis_p
        for k in kryptonite_entries:
            kcopy = dict(k)
            if not str(kcopy.get("tracked_alias") or "").strip():
                k_tpid = int(kcopy.get("tracked_profile_id", 0) or 0)
                kcopy["tracked_alias"] = next(
                    (str(p.get("alias") or "") for p in all_rendered if int(p.get("profile_id", 0)) == k_tpid),
                    str(primary.get("tracked_alias") or "Veterano"),
                )
            resolved_krypt.append(kcopy)
        _draw_kryptonite_footer_bar(
            img=img,
            draw=draw,
            width=width,
            y_bar=columns_bottom_h + nemesis_bar_h + fregues_bar_h,
            bar_h=kryptonite_bar_h,
            kryptonite_entries=resolved_krypt,
            fallback_tracked_alias=str(primary.get("tracked_alias") or "Veterano"),
            is_duel=is_duel,
        )

    if smurf_entries:
        _draw_smurf_alert_footer_bar(
            draw=draw,
            width=width,
            y_bar=columns_bottom_h + nemesis_bar_h + fregues_bar_h + kryptonite_bar_h,
            bar_h=smurf_bar_h,
            smurf_alerts=smurf_entries,
            is_duel=is_duel,
        )

    if is_duel:
        draw.rectangle((0, 0, width - 1, total_h - 1), outline=(245, 184, 46, 255), width=2)
    else:
        draw.rectangle((0, 0, width - 1, total_h - 1), outline=(48, 52, 64, 255), width=1)
    return _encode_rgb_png(img)


# ---------------------------------------------------------------------------
# RENDERIZADOR 1B: Tabela Horizontal Compacta em PT-BR (Mensagem Fixada)
# ---------------------------------------------------------------------------
def render_matches_table_png(
    grouped_matches: list[dict[str, Any]],
    avatar_provider: SteamAvatarProvider,
    live_single: bool = False,
) -> bytes:
    if live_single and len(grouped_matches) == 1:
        return render_single_match_card_png(grouped_matches[0], avatar_provider)

    header_h = 44
    prepared_rows: list[dict[str, Any]] = []
    table_has_bg = False
    for grp in grouped_matches:
        recs = grp.get("records") or [grp.get("primary") or grp]
        primary = recs[0]
        axis_p, allies_p = extract_axis_and_allies_players(grp)
        if any(bool(p.get("battlegroup_key")) for p in axis_p + allies_p):
            table_has_bg = True
        max_team = max(len(axis_p), len(allies_p), 1)
        prepared_rows.append(
            {
                "records": recs,
                "primary": primary,
                "axis": axis_p,
                "allies": allies_p,
                "row_h": max(108, 26 + max_team * 32),
            }
        )

    if hasattr(avatar_provider, "prefetch_avatar_urls") and prepared_rows:
        avatar_provider.prefetch_avatar_urls(
            [pl for row in prepared_rows for pl in (row["axis"] + row["allies"])]
        )

    bg_shift = 24 if table_has_bg else 0
    width = 1040 + bg_shift * 2
    allies_col_x = 248
    axis_col_x = 564 + bg_shift
    map_cx = 954 + bg_shift * 2

    total_h = header_h + sum(r["row_h"] for r in prepared_rows) + (2 if prepared_rows else 70)
    img = Image.new("RGBA", (width, total_h), (24, 26, 31, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, width, header_h), fill=(19, 21, 26, 255))
    draw.line([(0, header_h - 1), (width, header_h - 1)], fill=(52, 56, 68, 255), width=2)

    hdr_color = (235, 238, 244, 255)
    for hx, hlbl in (
        (22, "DATA ↓"),
        (126, "RESULTADO"),
        (allies_col_x + 10, "Allies"),
        (axis_col_x + 8, "Axis"),
        (map_cx - 52, "MAPA / MODO"),
    ):
        hdr_font = pick_font(hlbl, size=15, bold=True, condensed=True)
        draw.text((hx, 13), hlbl, font=hdr_font, fill=hdr_color)

    if not prepared_rows:
        empty_fnt = pick_font("Nenhuma partida registrada ainda.", size=16, bold=False)
        draw.text((380, header_h + 24), "Nenhuma partida registrada ainda.", font=empty_fnt, fill=(156, 163, 175, 255))

    y = header_h
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    for idx, row in enumerate(prepared_rows):
        rh = row["row_h"]
        recs = row["records"]
        primary = row["primary"]

        is_row_duel = _is_br_veteranos_duel(recs, row["axis"], row["allies"])
        bg_col = (
            (38, 33, 21, 255)
            if is_row_duel
            else ((30, 32, 38, 255) if idx % 2 == 0 else (25, 27, 33, 255))
        )
        draw.rectangle((0, y, width, y + rh), fill=bg_col)
        draw.line(
            [(0, y + rh - 1), (width, y + rh - 1)],
            fill=(82, 66, 28, 255) if is_row_duel else (46, 49, 58, 255),
            width=1,
        )

        accent_col, pill_col, pill_text = _compute_match_result_style(recs, primary, row["axis"], row["allies"])
        draw.rectangle((0, y + 5, 6, y + rh - 5), fill=accent_col)

        fac_icon = get_faction_icon(str(primary.get("tracked_faction", "Wehrmacht")), size=50)
        fac_x, fac_y = 26, y + (rh - 72) // 2
        img.paste(fac_icon, (fac_x, fac_y), fac_icon)

        played_str = format_relative_played(int(primary.get("completion_time", 0)), now_ts=now_ts, live_label=False)
        p_fnt = pick_font(played_str, size=14, bold=True)
        pw = text_width(draw, played_str, p_fnt)
        draw.text((fac_x + 25 - pw / 2, fac_y + 54), played_str, font=p_fnt, fill=(215, 220, 228, 255))

        pill_w, pill_h, pill_x = 134, 30, 102
        pill_y = y + (rh - pill_h) // 2
        draw.rounded_rectangle((pill_x, pill_y, pill_x + pill_w, pill_y + pill_h), radius=15, fill=pill_col)
        pill_fnt = pick_font(pill_text, size=14, bold=True)
        ptw = text_width(draw, pill_text, pill_fnt)
        draw.text((pill_x + (pill_w - ptw) / 2, pill_y + 7), pill_text, font=pill_fnt, fill=(255, 255, 255, 255))

        for col_x, team_list in ((allies_col_x, row["allies"]), (axis_col_x, row["axis"])):
            line_pitch = 31
            start_py = y + (rh - len(team_list) * line_pitch) // 2
            for pidx, pl in enumerate(team_list):
                py = start_py + pidx * line_pitch
                mini_fac = get_faction_icon(str(pl["faction"]), size=23)
                img.paste(mini_fac, (col_x, py + 3), mini_fac)

                if table_has_bg:
                    bg_k = str(pl.get("battlegroup_key") or "").strip()
                    bg_ic = get_battlegroup_icon(bg_k, size=20) if bg_k else None
                    if bg_ic is not None:
                        img.paste(bg_ic, (col_x + 25, py + 4), bg_ic)

                elo_val = pl.get("old_elo")
                elo_txt = str(elo_val) if elo_val else "S/R"
                elo_fnt = pick_font(elo_txt, size=15, bold=True, condensed=True)
                ew = text_width(draw, elo_txt, elo_fnt)
                elo_col = (238, 240, 244, 255) if elo_val else (156, 163, 175, 255)
                draw.text((col_x + 64 + bg_shift - ew, py + 6), elo_txt, font=elo_fnt, fill=elo_col)

                delta = pl.get("elo_delta")
                if delta is not None:
                    d_txt = f"+{delta}" if delta >= 0 else f"{delta}"
                    d_col = (74, 222, 128, 255) if delta >= 0 else (248, 113, 113, 255)
                    d_fnt = pick_font(d_txt, size=14, bold=True, condensed=True)
                    dw = text_width(draw, d_txt, d_fnt)
                    draw.text((col_x + 98 + bg_shift - dw, py + 6), d_txt, font=d_fnt, fill=d_col)

                country = str(pl.get("country") or "un").lower()
                pl_pid_row = int(pl.get("profile_id", 0) or 0)
                flag_used_w = _draw_flag_with_expat_badge(
                    img,
                    draw,
                    country,
                    col_x + 104 + bg_shift,
                    py + 8,
                    profile_id=pl_pid_row,
                    flag_w=20,
                    flag_h=14,
                    compact=True,
                )

                name_x = col_x + 104 + bg_shift + flag_used_w + 6
                is_tracked = bool(pl.get("is_tracked"))
                is_veterano = is_tracked or bool(pl.get("is_br_roster"))

                if is_veterano:
                    ring = (245, 184, 46, 250) if is_row_duel else (56, 189, 248, 250)
                    av_im = avatar_provider.get_circular_avatar(
                        size=27,
                        profile_id=int(pl.get("profile_id", 0)),
                        steam_id=str(pl.get("steam_id") or ""),
                        alias=str(pl.get("alias") or "BR"),
                        ring_color=ring,
                    )
                    img.paste(av_im, (name_x, py + 1), av_im)
                    name_x += 32

                badge_sz = 17
                badge_reserve = (badge_sz + 6) if is_veterano else 0
                if is_veterano:
                    alias_color = (253, 230, 138, 255) if is_row_duel else (125, 211, 252, 255)
                    alias_y = py + 5
                else:
                    alias_color = (176, 184, 198, 255)
                    alias_y = py + 6
                alias_w = _draw_player_alias(
                    draw,
                    name_x,
                    alias_y,
                    str(pl.get("alias") or ""),
                    max_px=max(44, (col_x + 306 + bg_shift) - name_x - badge_reserve),
                    size=16 if is_veterano else 14,
                    bold=is_veterano,
                    primary_color=alias_color,
                )
                if is_veterano:
                    vet_ic = get_veteranos_badge_icon(size=badge_sz)
                    bx = int(name_x + alias_w + 5)
                    img.paste(vet_ic, (bx, py + 5), vet_ic)

        m_thumb = get_tactical_map_thumb(str(primary.get("map_raw") or ""), size=52)
        thumb_y = y + (rh - 90) // 2
        img.paste(m_thumb, (map_cx - 26, thumb_y), m_thumb)

        map_label, m_fnt = truncate_to_px(
            draw,
            _resolve_display_map_name(primary, fallback="Mapa"),
            max_px=156,
            size=13,
            bold=True,
        )
        mw = text_width(draw, map_label, m_fnt)
        draw.text((map_cx - mw / 2, thumb_y + 56), map_label, font=m_fnt, fill=(229, 231, 235, 255))

        md_str, md_fnt = truncate_to_px(
            draw,
            f"{format_mode_vs(str(primary.get('mode') or ''))} • Duração: {format_mm_ss(int(primary.get('duration_sec', 0)))}",
            max_px=158,
            size=12,
            bold=False,
        )
        mdw = text_width(draw, md_str, md_fnt)
        draw.text((map_cx - mdw / 2, thumb_y + 74), md_str, font=md_fnt, fill=(165, 174, 188, 255))

        y += rh

    return _encode_rgb_png(img)


# ---------------------------------------------------------------------------
# RENDERIZADOR 2: Card Tático de Resumo Semanal dos Veteranos BR (PT-BR, 860px)
# ---------------------------------------------------------------------------
def render_weekly_summary_card_png(
    weekly_stats: dict[str, Any],
    avatar_provider: SteamAvatarProvider,
    max_rows: int = 8,
) -> bytes:
    width = 860
    header_h = 62
    kpi_grid_h = 166
    col_hdr_h = 34
    row_h = 40

    leaderboard = list(weekly_stats.get("leaderboard") or [])[:max_rows]
    if hasattr(avatar_provider, "prefetch_avatar_urls"):
        weekly_targets = list(leaderboard)
        for kpi_key in ("mvp", "top_elo_gainer", "most_active", "top_killer", "top_damage"):
            item = weekly_stats.get(kpi_key)
            if isinstance(item, dict):
                weekly_targets.append(item)
        avatar_provider.prefetch_avatar_urls(weekly_targets)
    total_h = header_h + kpi_grid_h + col_hdr_h + max(1, len(leaderboard)) * row_h + 10

    img = Image.new("RGBA", (width, total_h), (18, 20, 25, 255))
    draw = ImageDraw.Draw(img)

    # Cabeçalho tático dourado
    draw.rectangle((0, 0, width, header_h), fill=(26, 22, 16, 255))
    draw.rectangle((0, 0, 8, total_h), fill=(245, 184, 46, 255))
    draw.line([(0, header_h - 1), (width, header_h - 1)], fill=(234, 179, 8, 230), width=2)

    hdr_vet = get_veteranos_badge_icon(size=28)
    img.paste(hdr_vet, (22, 17), hdr_vet)

    title_str = "RESUMO SEMANAL  •  VETERANOS COH3 BRASIL"
    t_fnt = pick_font(title_str, size=20, bold=True, condensed=True)
    draw.text((58, 10), title_str, font=t_fnt, fill=(245, 184, 46, 255))

    since_ts = int(weekly_stats.get("since_ts") or 0)
    until_ts = int(weekly_stats.get("until_ts") or int(time.time()))
    d_start = datetime.fromtimestamp(since_ts, tz=BRT_TZ).strftime("%d/%m") if since_ts > 0 else "—"
    d_end = datetime.fromtimestamp(until_ts, tz=BRT_TZ).strftime("%d/%m/%Y")
    uniq_games = int(weekly_stats.get("unique_matches_count", 0))
    active_cnt = int(weekly_stats.get("active_players_with_games", 0))
    duels_cnt = int(weekly_stats.get("br_duels_count", 0))

    sub_str = (
        f"Período: {d_start} a {d_end}  •  {uniq_games} partidas únicas  •  "
        f"{active_cnt} monitorados em ação  •  {duels_cnt} clássico(s) BR"
    )
    sub_fnt = pick_font(sub_str, size=13, bold=True)
    draw.text((58, 36), sub_str, font=sub_fnt, fill=(208, 200, 184, 255))

    # Grade 2x2 de Destaques da Semana (KPI Boxes)
    most_active = weekly_stats.get("most_active_player")
    top_climber = weekly_stats.get("top_elo_climber")
    top_streak = weekly_stats.get("top_streak_player")
    top_wr = weekly_stats.get("top_winrate_player")
    top_map = weekly_stats.get("top_map")
    top_fac = weekly_stats.get("top_faction")

    def _draw_kpi_box(
        bx: int,
        by: int,
        bw: int,
        bh: int,
        kicker: str,
        main_txt: str,
        detail_txt: str,
        accent_rgb: tuple[int, int, int, int],
        player_obj: dict[str, Any] | None = None,
    ) -> None:
        draw.rounded_rectangle((bx, by, bx + bw, by + bh), radius=8, fill=(25, 28, 35, 255), outline=(52, 56, 68, 255), width=1)
        draw.rectangle((bx, by + 8, bx + 4, by + bh - 8), fill=accent_rgb)
        k_fnt = pick_font(kicker, size=12, bold=True, condensed=True)
        draw.text((bx + 14, by + 7), kicker, font=k_fnt, fill=accent_rgb)

        tx = bx + 14
        if player_obj:
            av = avatar_provider.get_circular_avatar(
                size=34,
                profile_id=int(player_obj.get("profile_id", 0)),
                steam_id=str(player_obj.get("steam_id") or ""),
                alias=str(player_obj.get("alias") or "BR"),
                ring_color=accent_rgb,
            )
            img.paste(av, (tx, by + 26), av)
            tx += 42

        badge_w = 22 if player_obj else 0
        m_disp, m_fnt = truncate_to_px(draw, main_txt, max_px=max(60, (bx + bw - 12) - tx - badge_w), size=17, bold=True)
        draw.text((tx, by + 26), m_disp, font=m_fnt, fill=(243, 244, 246, 255))
        if player_obj:
            vet_sm = get_veteranos_badge_icon(size=17)
            img.paste(vet_sm, (int(tx + text_width(draw, m_disp, m_fnt) + 5), by + 27), vet_sm)

        d_disp, d_fnt = truncate_to_px(draw, detail_txt, max_px=max(60, (bx + bw - 12) - tx), size=13, bold=True)
        draw.text((tx, by + 48), d_disp, font=d_fnt, fill=(182, 190, 204, 255))

    box_w = 402
    box_h = 68
    left_x = 22
    right_x = 438
    row1_y = header_h + 10
    row2_y = row1_y + box_h + 10

    if most_active:
        _draw_kpi_box(
            left_x,
            row1_y,
            box_w,
            box_h,
            "MAIS ATIVO DA SEMANA",
            str(most_active["alias"]),
            f"{most_active['games']} jogos  •  {most_active['wins']}V - {most_active['losses']}D ({int(round(most_active['win_rate']))}%)",
            (56, 189, 248, 255),
            player_obj=most_active,
        )
    else:
        _draw_kpi_box(left_x, row1_y, box_w, box_h, "MAIS ATIVO DA SEMANA", "Sem jogos", "Aguardando partidas", (56, 189, 248, 255))

    if top_climber:
        _draw_kpi_box(
            right_x,
            row1_y,
            box_w,
            box_h,
            "MAIOR SUBIDA DE ELO (SALDO 7 DIAS)",
            str(top_climber["alias"]),
            f"+{top_climber['net_elo_delta']} ELO líquido  •  Pico {top_climber['peak_new_elo']} ELO",
            (74, 222, 128, 255),
            player_obj=top_climber,
        )
    else:
        _draw_kpi_box(right_x, row1_y, box_w, box_h, "MAIOR SUBIDA DE ELO (SALDO 7 DIAS)", "Estável", "Sem saldo positivo registrado", (74, 222, 128, 255))

    if top_streak:
        _draw_kpi_box(
            left_x,
            row2_y,
            box_w,
            box_h,
            "MAIOR SEQUÊNCIA DE VITÓRIAS",
            str(top_streak["alias"]),
            f"{top_streak['best_win_streak']} vitórias seguidas  •  {int(round(top_streak['win_rate']))}% de taxa",
            (245, 184, 46, 255),
            player_obj=top_streak,
        )
    elif top_wr:
        _draw_kpi_box(
            left_x,
            row2_y,
            box_w,
            box_h,
            "MELHOR APROVEITAMENTO (MÍN. 5 JOGOS)",
            str(top_wr["alias"]),
            f"{int(round(top_wr['win_rate']))}% de vitórias ({top_wr['wins']}V - {top_wr['losses']}D)",
            (245, 184, 46, 255),
            player_obj=top_wr,
        )
    else:
        _draw_kpi_box(left_x, row2_y, box_w, box_h, "SEQUÊNCIA DE VITÓRIAS", "Em disputa", "Mínimo de 2 vitórias seguidas", (245, 184, 46, 255))

    map_txt = f"{top_map['map_clean']} ({top_map['games']}x)" if top_map else "Sem mapa dominante"
    fac_txt = (
        f"Facção favorita: {top_faction_pt(top_fac['faction_short'])} ({top_fac['picks']}x • {top_fac['win_rate']}% vit.)"
        if top_fac
        else f"Clássicos BR na semana: {duels_cnt}"
    )
    _draw_kpi_box(
        right_x,
        row2_y,
        box_w,
        box_h,
        "MAPA MAIS JOGADO  •  META BR",
        map_txt,
        fac_txt,
        (251, 146, 60, 255),
        player_obj=None,
    )

    # Cabeçalho da Tabela Top Jogadores da Semana
    y_tbl = header_h + kpi_grid_h
    draw.rectangle((8, y_tbl, width, y_tbl + col_hdr_h), fill=(24, 22, 18, 255))
    draw.line([(8, y_tbl), (width, y_tbl)], fill=(52, 56, 68, 255), width=1)
    draw.line([(14, y_tbl + col_hdr_h - 1), (width - 14, y_tbl + col_hdr_h - 1)], fill=(234, 179, 8, 230), width=2)

    hdr_fnt = pick_font("JOGADOR MONITORADO", size=14, bold=True, condensed=True)
    gold_col = (245, 184, 46, 255)
    for lbl, cx, align in (
        ("#", 38, "center"),
        ("TOP ATIVIDADE (7 DIAS)", 68, "left"),
        ("JOGOS", 464, "right"),
        ("VIT. / DER.", 578, "right"),
        ("TAXA", 654, "right"),
        ("SEQ.", 734, "right"),
        ("SALDO ELO", 842, "right"),
    ):
        lw = text_width(draw, lbl, hdr_fnt)
        tx = (cx - lw / 2) if align == "center" else ((cx - lw) if align == "right" else cx)
        draw.text((tx, y_tbl + 8), lbl, font=hdr_fnt, fill=gold_col)

    y = y_tbl + col_hdr_h
    if not leaderboard:
        efnt = pick_font("Nenhuma partida registrada nos últimos 7 dias.", size=15, bold=False)
        draw.text((250, y + 10), "Nenhuma partida registrada nos últimos 7 dias.", font=efnt, fill=(156, 163, 175, 255))
    else:
        num_fnt = pick_font("100%", size=16, bold=True, condensed=True)
        row_vet = get_veteranos_badge_icon(size=18)
        steam_map, pid_map = build_roster_lookup_maps()
        for idx, pl in enumerate(leaderboard, start=1):
            r_bg = (20, 23, 29, 255) if idx % 2 == 1 else (25, 28, 36, 255)
            draw.rectangle((8, y, width, y + row_h), fill=r_bg)
            draw.line([(16, y + row_h - 1), (width - 14, y + row_h - 1)], fill=(34, 38, 46, 255), width=1)

            rk_col = (250, 204, 21, 255) if idx == 1 else (229, 231, 235, 255)
            rk_str = str(idx)
            rkw = text_width(draw, rk_str, num_fnt)
            draw.text((38 - rkw / 2, y + 10), rk_str, font=num_fnt, fill=rk_col)

            pl_pid = int(pl.get("profile_id", 0))
            pl_sid = str(pl.get("steam_id") or "")
            av_im = avatar_provider.get_circular_avatar(
                size=30,
                profile_id=pl_pid,
                steam_id=pl_sid,
                alias=str(pl.get("alias") or "BR"),
                ring_color=(245, 184, 46, 245),
            )
            img.paste(av_im, (68, y + 5), av_im)
            r_entry = (pid_map.get(pl_pid) if pl_pid > 0 else None) or steam_map.get(pl_sid) or {}
            pl_country = str(r_entry.get("country") or pl.get("country") or "br").strip().lower()
            flag_used_w = _draw_flag_with_expat_badge(
                img,
                draw,
                pl_country,
                104,
                y + 13,
                profile_id=pl_pid,
                is_expat=bool(pl_country and pl_country != "br"),
                flag_w=20,
                flag_h=14,
                compact=True,
            )
            alias_x = 104 + flag_used_w + 6
            extra_w = max(0, alias_x - 130)
            disp_alias, a_fnt = truncate_to_px(draw, str(pl.get("alias") or ""), max_px=max(140, 258 - extra_w), size=16, bold=True)
            draw.text((alias_x, y + 10), disp_alias, font=a_fnt, fill=(253, 230, 138, 255))
            bx = int(alias_x + text_width(draw, disp_alias, a_fnt) + 6)
            img.paste(row_vet, (bx, y + 10), row_vet)

            games_s = str(int(pl.get("games", 0)))
            wl_s = f"{int(pl.get('wins', 0))}V - {int(pl.get('losses', 0))}D"
            wr_s = f"{int(round(float(pl.get('win_rate', 0.0))))}%"
            st_val = int(pl.get("best_win_streak", 0))
            st_s = f"+{st_val}" if st_val > 0 else "0"

            net_d = int(pl.get("net_elo_delta", 0))
            has_rk = int(pl.get("ranked_games", 0)) > 0
            if not has_rk:
                d_s, d_col = "S/R", (156, 163, 175, 255)
            elif net_d > 0:
                d_s, d_col = f"+{net_d}", (74, 222, 128, 255)
            elif net_d < 0:
                d_s, d_col = f"{net_d}", (248, 113, 113, 255)
            else:
                d_s, d_col = "0", (209, 213, 219, 255)

            for val_txt, rx, col in (
                (games_s, 464, (243, 244, 246, 255)),
                (wl_s, 578, (229, 231, 235, 255)),
                (wr_s, 654, (243, 244, 246, 255)),
                (st_s, 734, (74, 222, 128, 255) if st_val >= 2 else (209, 213, 219, 255)),
                (d_s, 842, d_col),
            ):
                vw = text_width(draw, val_txt, num_fnt)
                draw.text((rx - vw, y + 10), val_txt, font=num_fnt, fill=col)

            y += row_h

    draw.rectangle((0, 0, width - 1, total_h - 1), outline=(92, 74, 30, 255), width=2)
    return _encode_rgb_png(img)


def top_faction_pt(short_code: str) -> str:
    mapping = {
        "Wehr": "Wehrmacht",
        "DAK": "Afrikakorps",
        "USF": "Forças dos EUA",
        "UKF": "Forças Britânicas",
    }
    return mapping.get(short_code, short_code or "N/D")


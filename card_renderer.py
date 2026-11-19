"""Renderizador gráfico seguro e otimizado (Pillow) para Cards de Partidas e Tabelas de Ranking com Avatares Steam."""

from __future__ import annotations

import hashlib
import io
import json
import logging
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
    STEAM_ID64_VALID_RE,
    build_roster_lookup_maps,
    format_bound_display_alias,
)
from security import (
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
VETERANOS_BADGE_PATH = BASE_DIR / "assets" / "discord_veteranos_patente.png"
BRT_TZ = timezone(timedelta(hours=-3))

STEAM_XML_AVATAR_MEDIUM_RE = re.compile(
    r"<avatarMedium>\s*<!\[CDATA\[(https://[^\s\]]+)\]\]>\s*</avatarMedium>",
    re.IGNORECASE,
)
STEAM_XML_AVATAR_FULL_RE = re.compile(
    r"<avatarFull>\s*<!\[CDATA\[(https://[^\s\]]+)\]\]>\s*</avatarFull>",
    re.IGNORECASE,
)
SAFE_AVATAR_EXT_RE = re.compile(r"\.(?:jpg|jpeg|png|webp)$", re.IGNORECASE)

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
MAX_STEAM_AVATAR_BYTES = 524_288   # 512 KB
MAX_RELIC_LOOKUP_BYTES = 131_072   # 128 KB

AXIS_FACTIONS: frozenset[str] = frozenset({"Wehrmacht", "Afrikakorps", "DAK", "Wehr", "german", "dak"})
ALLIES_FACTIONS: frozenset[str] = frozenset({"US Forces", "British Forces", "USF", "UKF", "american", "british"})

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

HAS_CJK_RE = re.compile(r"[\u2e80-\u9fff\uac00-\ud7af\uf900-\ufaff\u3040-\u30ff]")
NEEDS_DEJAVU_RE = re.compile(r"[^\x00-\x024f]")

_DEFAULT_ROSTER_MAPS = build_roster_lookup_maps()


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
    urllib.request.HTTPSHandler(context=create_hardened_ssl_context()),
    _SteamXMLRedirectHandler(),
)
_NO_REDIRECT_OPENER = build_no_redirect_https_opener()


# ---------------------------------------------------------------------------
# Carregamento seguro de fontes com cache em memória (Latim, Cirílico e CJK)
# ---------------------------------------------------------------------------
_FONT_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont | ImageFont.ImageFont] = {}

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
    "unicode_regular": ["/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"],
    "unicode_bold": ["/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"],
    "cjk_regular": [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ],
    "cjk_bold": [
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ],
}


def _get_font_by_role(role: str, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    key = (role, size)
    cached = _FONT_CACHE.get(key)
    if cached is not None:
        return cached
    for path_str in FONT_CANDIDATES.get(role, FONT_CANDIDATES["regular"]):
        p = Path(path_str)
        if p.is_file():
            try:
                fnt = ImageFont.truetype(str(p), size=size)
                _FONT_CACHE[key] = fnt
                return fnt
            except OSError:
                continue
    fallback = ImageFont.load_default()
    _FONT_CACHE[key] = fallback
    return fallback


def pick_font(
    text: str,
    size: int,
    bold: bool = False,
    condensed: bool = False,
) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Seleciona automaticamente a fonte ideal (Roboto, DejaVu ou Noto CJK)."""
    if HAS_CJK_RE.search(text):
        return _get_font_by_role("cjk_bold" if bold else "cjk_regular", size)
    if NEEDS_DEJAVU_RE.search(text):
        return _get_font_by_role("unicode_bold" if bold else "unicode_regular", size)
    if condensed:
        return _get_font_by_role("condensed_bold", size)
    return _get_font_by_role("bold" if bold else "regular", size)


def clean_label(raw: Any, max_len: int = 28) -> str:
    txt = strip_unsafe_chars(raw)
    if not txt:
        return "Desconhecido"
    return (txt[: max_len - 1] + "…") if len(txt) > max_len else txt


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
) -> tuple[str, Any]:
    txt = strip_unsafe_chars(text) or "Desconhecido"
    for try_sz in (size, max(12, size - 2), max(11, size - 4)):
        fnt = pick_font(txt, size=try_sz, bold=bold)
        if text_width(draw, txt, fnt) <= max_px:
            return txt, fnt
    fnt = pick_font(txt, size=max(11, size - 3), bold=bold)
    while len(txt) > 2 and text_width(draw, txt + "…", fnt) > max_px:
        txt = txt[:-1]
    return txt + "…", fnt


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
    ) -> None:
        self.db = db
        self.allow_network = allow_network
        self.catalog_json_path = catalog_json_path or (BASE_DIR / "jogadores_br_steam.json")
        self._catalog_loaded = False
        self._lock = threading.Lock()
        self._mem_png_cache: dict[str, Image.Image] = {}
        self._circle_cache: dict[tuple[str, int, tuple[int, int, int, int] | None], Image.Image] = {}
        self._pid_to_steam: dict[int, str] = {}
        self._failed_steam_ids: set[str] = set()
        self._network_fetches_this_run = 0
        self._max_network_fetches_per_run = 90
        self._last_net_ts = 0.0

        for r in CORE_BR_ROSTER:
            r_pid = int(r.get("profile_id", 0))
            r_sid = str(r.get("steam_id") or "").strip()
            if r_pid > 0 and STEAM_ID64_VALID_RE.fullmatch(r_sid):
                self._pid_to_steam[r_pid] = r_sid

        if db is not None and hasattr(db, "get_steam_id_map"):
            try:
                self._pid_to_steam.update(db.get_steam_id_map())
            except Exception:
                pass

    def _ensure_catalog_loaded(self) -> None:
        if self._catalog_loaded:
            return
        self._catalog_loaded = True
        if not self.catalog_json_path.is_file():
            return
        try:
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
        clean_sid = str(steam_id or "").strip()
        if clean_sid.startswith("/steam/"):
            clean_sid = clean_sid[7:].strip()
        if STEAM_ID64_VALID_RE.fullmatch(clean_sid):
            if profile_id > 0:
                self._pid_to_steam[int(profile_id)] = clean_sid
            return clean_sid
        if profile_id > 0:
            pid_int = int(profile_id)
            if pid_int in self._pid_to_steam:
                return self._pid_to_steam[pid_int]
            self._ensure_catalog_loaded()
            if pid_int in self._pid_to_steam:
                return self._pid_to_steam[pid_int]
            looked_up = self._lookup_steam_id_from_relic(pid_int)
            self._pid_to_steam[pid_int] = looked_up
            return looked_up
        return ""

    def _fetch_steam_avatar_bytes(self, steam_id: str) -> tuple[str, bytes] | None:
        if not STEAM_ID64_VALID_RE.fullmatch(steam_id) or steam_id in self._failed_steam_ids:
            return None

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

                avatar_url = m.group(1).strip()
                parsed_av = validate_https_endpoint(avatar_url, ALLOWED_STEAM_AVATAR_HOSTS)
                if parsed_av.query or parsed_av.fragment or not SAFE_AVATAR_EXT_RE.search(parsed_av.path):
                    logger.warning("URL de avatar Steam rejeitada por formato suspeito: %s", parsed_av.hostname)
                    break

                img_req = urllib.request.Request(
                    avatar_url,
                    headers={"User-Agent": "CoH3-BR-Tracker/7.0", "Accept": "image/*"},
                )
                with _NO_REDIRECT_OPENER.open(img_req, timeout=8) as img_resp:
                    img_bytes = read_bounded_http_body(img_resp, MAX_STEAM_AVATAR_BYTES)

                with Image.open(io.BytesIO(img_bytes)) as im:
                    if im.format not in ALLOWED_DECODER_FORMATS or not (1 <= im.width <= 1024 and 1 <= im.height <= 1024):
                        logger.warning("Imagem de avatar Steam rejeitada por formato/dimensão inválida.")
                        break
                    clean_im = im.convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
                    out_buf = io.BytesIO()
                    clean_im.save(out_buf, format="PNG", compress_level=6)
                    return avatar_url, out_buf.getvalue()
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
        sid = self.resolve_steam_id(profile_id=profile_id, steam_id=steam_id)
        cache_key = sid or f"pid_{profile_id}_{alias[:6]}"
        circle_key = (cache_key, size, ring_color)

        cached_circle = self._circle_cache.get(circle_key)
        if cached_circle is not None:
            return cached_circle

        base_img = self._mem_png_cache.get(cache_key)
        if base_img is None:
            png_blob: bytes | None = None
            if self.db is not None and hasattr(self.db, "get_cached_avatar"):
                try:
                    png_blob = self.db.get_cached_avatar(steam_id=sid, profile_id=profile_id)
                except Exception:
                    png_blob = None

            if png_blob is None and sid and self.allow_network:
                fetched = self._fetch_steam_avatar_bytes(sid)
                if fetched is not None:
                    av_url, png_blob = fetched
                    if self.db is not None and hasattr(self.db, "save_cached_avatar"):
                        try:
                            self.db.save_cached_avatar(sid, av_url, png_blob, profile_id=profile_id)
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
            det_seed = int(profile_id) if profile_id else int.from_bytes(hashlib.sha256(alias.encode("utf-8")).digest()[:4], "big")
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
        if png_path.is_file():
            try:
                with Image.open(png_path) as im:
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


_FLAG_CACHE: dict[tuple[str, int, int], Image.Image] = {}

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
    c = (code or "un").strip().lower()[:4]
    ck = (c, w, h)
    cached = _FLAG_CACHE.get(ck)
    if cached is not None:
        return cached

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
    elif c in ("gb", "uk"):
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


_MAP_THUMB_CACHE: dict[tuple[str, int], Image.Image] = {}


def get_tactical_map_thumb(map_raw: str, size: int = 52) -> Image.Image:
    """Gera miniatura aérea sépia determinística do mapa no estilo coh3stats."""
    key = (str(map_raw or "map")[:64], size)
    cached = _MAP_THUMB_CACHE.get(key)
    if cached is not None:
        return cached

    digest = hashlib.sha256(key[0].encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(digest[:8], "big"))

    ss = size * 2
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
    out = im.resize((size, size), Image.Resampling.LANCZOS)
    if len(_MAP_THUMB_CACHE) >= 128:
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


def format_mode_title_pt(mode_raw: str) -> str:
    if mode_raw == "Team Games":
        return "JOGOS EM EQUIPE (3V3 + 4V4)"
    return str(mode_raw).upper()


def format_mm_ss(seconds: int) -> str:
    total = max(0, int(seconds))
    hrs, rem = divmod(total, 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs}:{mins:02d}:{secs:02d}" if hrs > 0 else f"{mins:02d}:{secs:02d}"


def _draw_rank_arrow(draw: ImageDraw.ImageDraw, cx: int, cy: int, delta: int, size_scale: float = 1.0) -> int:
    """Desenha seta vetorial verde (subida) ou vermelha (queda) + quantidade de posições."""
    if delta == 0:
        return 0
    hw = max(5, int(round(6 * size_scale)))
    hh = max(5, int(round(6 * size_scale)))
    fnt_sz = max(13, int(round(14 * size_scale)))
    num_txt = str(abs(int(delta)))
    fnt = pick_font(num_txt, size=fnt_sz, bold=True, condensed=True)

    if delta > 0:
        col = (74, 222, 128, 255)
        pts = [(cx, cy - hh), (cx - hw, cy + hh - 1), (cx + hw, cy + hh - 1)]
    else:
        col = (248, 113, 113, 255)
        pts = [(cx, cy + hh), (cx - hw, cy - hh + 1), (cx + hw, cy - hh + 1)]

    draw.polygon(pts, fill=col)
    draw.text((cx + hw + 3, cy - fnt_sz // 2 - 1), num_txt, font=fnt, fill=col)
    return int(hw * 2 + 4 + text_width(draw, num_txt, fnt))


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
    r_entry = steam_map.get(clean_sid) or pid_map.get(pid)
    if r_entry:
        bound_sid = str(r_entry.get("merged_into_steam_id") or clean_sid or r_entry.get("steam_id") or "")
        disp = format_bound_display_alias(
            raw_alias,
            str(r_entry.get("original_alias") or ""),
            r_entry.get("known_aliases"),
        )
        return bound_sid, disp, str(country or "br").lower(), True
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


def extract_axis_and_allies_players(group: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reconstrói todos os jogadores únicos da partida e separa em (Eixo, Aliados)."""
    steam_map, pid_map = _DEFAULT_ROSTER_MAPS
    records = group.get("records") or [group.get("primary") or group]
    primary = records[0]
    tracked_by_pid: dict[int, dict[str, Any]] = {}

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
        }

    primary_pid = int(primary["tracked_profile_id"])
    team_a: list[dict[str, Any]] = [tracked_by_pid[primary_pid]]
    seen_pids: set[int] = {primary_pid}

    for ally in primary.get("allies", []):
        apid = int(ally.get("profile_id", 0))
        if apid in seen_pids:
            continue
        seen_pids.add(apid)
        team_a.append(
            tracked_by_pid[apid]
            if apid in tracked_by_pid
            else _build_side_participant(ally, "Wehrmacht", steam_map, pid_map)
        )

    team_b: list[dict[str, Any]] = []
    for opp in primary.get("opponents", []):
        opid = int(opp.get("profile_id", 0))
        if opid in seen_pids:
            continue
        seen_pids.add(opid)
        team_b.append(
            tracked_by_pid[opid]
            if opid in tracked_by_pid
            else _build_side_participant(opp, "US Forces", steam_map, pid_map)
        )

    all_participants = team_a + team_b
    axis_players = [p for p in all_participants if str(p["faction"]) in AXIS_FACTIONS]
    allies_players = [p for p in all_participants if str(p["faction"]) in ALLIES_FACTIONS]

    if not axis_players or not allies_players:
        return team_a, team_b
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
) -> None:
    """Desenha as duas colunas amplas (Axis vs Allies) destacando apenas brasileiros monitorados."""
    hdr_bg = (30, 26, 18, 255) if is_duel else (22, 24, 30, 255)
    sep_col = (96, 78, 34, 255) if is_duel else (46, 50, 62, 255)
    draw.rectangle((8, top_bar_h, width, top_bar_h + col_hdr_h), fill=hdr_bg)
    draw.line([(8, top_bar_h + col_hdr_h - 1), (width, top_bar_h + col_hdr_h - 1)], fill=sep_col, width=1)
    mid_x = width // 2 + 3
    draw.line([(mid_x, top_bar_h), (mid_x, total_h)], fill=sep_col, width=1)

    ch_col = (253, 224, 71, 255) if is_duel else (235, 238, 244, 255)
    ch_fnt = pick_font("Axis", size=17, bold=True, condensed=True)
    draw.text((22, top_bar_h + 9), "Axis", font=ch_fnt, fill=ch_col)
    draw.text((mid_x + 16, top_bar_h + 9), "Allies", font=ch_fnt, fill=ch_col)

    base_py = top_bar_h + col_hdr_h + 11
    for col_start_x, col_limit_x, team_list in (
        (18, mid_x - 10, axis_p),
        (mid_x + 14, width - 12, allies_p),
    ):
        for pidx, pl in enumerate(team_list):
            py = base_py + pidx * row_pitch

            mini_fac = get_faction_icon(str(pl["faction"]), size=32)
            img.paste(mini_fac, (col_start_x, py + 5), mini_fac)

            elo_val = pl.get("old_elo") or pl.get("new_elo")
            elo_txt = str(elo_val) if elo_val else "S/R"
            elo_fnt = pick_font(elo_txt, size=20, bold=True, condensed=True)
            ew = text_width(draw, elo_txt, elo_fnt)
            elo_col = (243, 244, 246, 255) if elo_val else (156, 163, 175, 255)
            elo_right_x = col_start_x + (84 if show_delta else 96)
            draw.text((elo_right_x - ew, py + 10), elo_txt, font=elo_fnt, fill=elo_col)

            delta = pl.get("elo_delta") if show_delta else None
            if delta is not None:
                d_txt = f"+{delta}" if delta >= 0 else f"{delta}"
                d_col = (74, 222, 128, 255) if delta >= 0 else (248, 113, 113, 255)
                d_fnt = pick_font(d_txt, size=18, bold=True, condensed=True)
                dw = text_width(draw, d_txt, d_fnt)
                draw.text((col_start_x + 126 - dw, py + 11), d_txt, font=d_fnt, fill=d_col)

            flag_x = col_start_x + (134 if show_delta else 108)
            country = str(pl.get("country") or "un").lower()
            flag_im = get_country_flag(country, w=24, h=17)
            img.paste(flag_im, (flag_x, py + 13), flag_im)

            name_x = flag_x + 30
            is_tracked = bool(pl.get("is_tracked"))
            is_veterano = is_tracked or bool(pl.get("is_br_roster"))

            if is_veterano:
                ring = (245, 184, 46, 255) if is_duel else (56, 189, 248, 255)
                av_im = avatar_provider.get_circular_avatar(
                    size=40,
                    profile_id=int(pl.get("profile_id", 0)),
                    steam_id=str(pl.get("steam_id") or ""),
                    alias=str(pl.get("alias") or "BR"),
                    ring_color=ring,
                )
                img.paste(av_im, (name_x, py + 1), av_im)
                name_x += 46

            badge_sz = 22
            badge_reserve = (badge_sz + 8) if is_veterano else 0
            disp_alias, a_fnt = truncate_to_px(
                draw,
                str(pl.get("alias") or ""),
                max_px=max(56, col_limit_x - name_x - badge_reserve),
                size=21 if is_veterano else 19,
                bold=is_veterano,
            )
            if is_veterano:
                alias_color = (253, 230, 138, 255) if is_duel else (125, 211, 252, 255)
                alias_y = py + 9
            else:
                alias_color = (176, 184, 198, 255)
                alias_y = py + 11
            draw.text((name_x, alias_y), disp_alias, font=a_fnt, fill=alias_color)
            if is_veterano:
                vet_ic = get_veteranos_badge_icon(size=badge_sz)
                bx = int(name_x + text_width(draw, disp_alias, a_fnt) + 6)
                img.paste(vet_ic, (bx, py + 9), vet_ic)


# ---------------------------------------------------------------------------
# RENDERIZADOR 1A: Card Grande de Partida Finalizada (PT-BR, 860px)
# ---------------------------------------------------------------------------
def render_single_match_card_png(
    grp: dict[str, Any],
    avatar_provider: SteamAvatarProvider,
) -> bytes:
    width = 860
    recs = grp.get("records") or [grp.get("primary") or grp]
    primary = recs[0]
    axis_p, allies_p = extract_axis_and_allies_players(grp)
    is_duel = _is_br_veteranos_duel(recs, axis_p, allies_p)

    duel_banner_h = 34 if is_duel else 0
    max_team = max(len(axis_p), len(allies_p), 1)
    top_bar_h = 90
    col_hdr_h = 38
    row_pitch = 52
    total_h = duel_banner_h + top_bar_h + col_hdr_h + max_team * row_pitch + 22

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
    draw.rectangle((0, 0, 8, total_h), fill=accent_col)

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
        str(primary.get("map_clean") or "Mapa Desconhecido"),
        max_px=330,
        size=21,
        bold=True,
    )
    mw = text_width(draw, map_label, m_fnt)
    draw.text((thumb_x - 16 - mw, y_top + 17), map_label, font=m_fnt, fill=(253, 230, 138, 255) if is_duel else (243, 244, 246, 255))

    mode_dur_str = f"{format_mode_vs(str(primary.get('mode') or ''))}   •   {format_mm_ss(int(primary.get('duration_sec', 0)))}"
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
        total_h=total_h,
        axis_p=axis_p,
        allies_p=allies_p,
        avatar_provider=avatar_provider,
        show_delta=True,
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

    width = 1040
    header_h = 44

    prepared_rows: list[dict[str, Any]] = []
    for grp in grouped_matches:
        recs = grp.get("records") or [grp.get("primary") or grp]
        primary = recs[0]
        axis_p, allies_p = extract_axis_and_allies_players(grp)
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

    total_h = header_h + sum(r["row_h"] for r in prepared_rows) + (2 if prepared_rows else 70)
    img = Image.new("RGBA", (width, total_h), (24, 26, 31, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, width, header_h), fill=(19, 21, 26, 255))
    draw.line([(0, header_h - 1), (width, header_h - 1)], fill=(52, 56, 68, 255), width=2)

    hdr_font = pick_font("DATA", size=15, bold=True, condensed=True)
    hdr_color = (235, 238, 244, 255)
    for hx, hlbl in (
        (22, "DATA ↓"),
        (126, "RESULTADO"),
        (258, "Axis"),
        (572, "Allies"),
        (902, "MAPA / MODO"),
    ):
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

        for col_x, team_list in ((248, row["axis"]), (564, row["allies"])):
            line_pitch = 31
            start_py = y + (rh - len(team_list) * line_pitch) // 2
            for pidx, pl in enumerate(team_list):
                py = start_py + pidx * line_pitch
                mini_fac = get_faction_icon(str(pl["faction"]), size=23)
                img.paste(mini_fac, (col_x, py + 3), mini_fac)

                elo_val = pl.get("old_elo")
                elo_txt = str(elo_val) if elo_val else "S/R"
                elo_fnt = pick_font(elo_txt, size=15, bold=True, condensed=True)
                ew = text_width(draw, elo_txt, elo_fnt)
                elo_col = (238, 240, 244, 255) if elo_val else (156, 163, 175, 255)
                draw.text((col_x + 64 - ew, py + 6), elo_txt, font=elo_fnt, fill=elo_col)

                delta = pl.get("elo_delta")
                if delta is not None:
                    d_txt = f"+{delta}" if delta >= 0 else f"{delta}"
                    d_col = (74, 222, 128, 255) if delta >= 0 else (248, 113, 113, 255)
                    d_fnt = pick_font(d_txt, size=14, bold=True, condensed=True)
                    dw = text_width(draw, d_txt, d_fnt)
                    draw.text((col_x + 98 - dw, py + 6), d_txt, font=d_fnt, fill=d_col)

                country = str(pl.get("country") or "un").lower()
                flag_im = get_country_flag(country, w=20, h=14)
                img.paste(flag_im, (col_x + 104, py + 8), flag_im)

                name_x = col_x + 130
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
                disp_alias, a_fnt = truncate_to_px(
                    draw,
                    str(pl.get("alias") or ""),
                    max_px=max(44, (col_x + 306) - name_x - badge_reserve),
                    size=16 if is_veterano else 14,
                    bold=is_veterano,
                )
                if is_veterano:
                    alias_color = (253, 230, 138, 255) if is_row_duel else (125, 211, 252, 255)
                    alias_y = py + 5
                else:
                    alias_color = (176, 184, 198, 255)
                    alias_y = py + 6
                draw.text((name_x, alias_y), disp_alias, font=a_fnt, fill=alias_color)
                if is_veterano:
                    vet_ic = get_veteranos_badge_icon(size=badge_sz)
                    bx = int(name_x + text_width(draw, disp_alias, a_fnt) + 5)
                    img.paste(vet_ic, (bx, py + 5), vet_ic)

        map_cx = 954
        m_thumb = get_tactical_map_thumb(str(primary.get("map_raw") or ""), size=52)
        thumb_y = y + (rh - 90) // 2
        img.paste(m_thumb, (map_cx - 26, thumb_y), m_thumb)

        map_label, m_fnt = truncate_to_px(draw, str(primary.get("map_clean") or "Mapa"), max_px=156, size=13, bold=True)
        mw = text_width(draw, map_label, m_fnt)
        draw.text((map_cx - mw / 2, thumb_y + 56), map_label, font=m_fnt, fill=(229, 231, 235, 255))

        md_str = f"{format_mode_vs(str(primary.get('mode') or ''))} • {format_mm_ss(int(primary.get('duration_sec', 0)))}"
        md_fnt = pick_font(md_str, size=13, bold=False)
        mdw = text_width(draw, md_str, md_fnt)
        draw.text((map_cx - mdw / 2, thumb_y + 73), md_str, font=md_fnt, fill=(165, 174, 188, 255))

        y += rh

    return _encode_rgb_png(img)


# ---------------------------------------------------------------------------
# RENDERIZADOR 2: Tabela Tática de Ranking em PT-BR com Setas Verde/Vermelha
# ---------------------------------------------------------------------------
def render_ranking_table_png(
    entries: list[dict[str, Any]],
    mode_title: str,
    avatar_provider: SteamAvatarProvider,
    max_rows: int = 20,
    subtitle_override: str | None = None,
) -> bytes:
    width = 980
    banner_h = 36
    col_hdr_h = 34
    row_h = 36

    rows = entries[:max_rows]
    total_h = banner_h + col_hdr_h + max(1, len(rows)) * row_h + 4
    img = Image.new("RGBA", (width, total_h), (15, 17, 21, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, width, banner_h + col_hdr_h), fill=(22, 20, 17, 255))
    rng = random.Random(int.from_bytes(hashlib.sha256(mode_title.encode("utf-8")).digest()[:8], "big"))
    for _ in range(10):
        x0, y0 = rng.randint(0, width), rng.randint(0, banner_h + col_hdr_h)
        x1, y1 = x0 + rng.randint(-160, 160), y0 + rng.randint(-30, 30)
        draw.line([(x0, y0), (x1, y1)], fill=(46, 41, 33, 95), width=1)

    core_unique_cnt = sum(1 for r in CORE_BR_ROSTER if not r.get("merged_into_profile_id"))
    sub_txt = subtitle_override or f"Top 20 + {core_unique_cnt} Monitorados ({len(rows)})"
    s_fnt = pick_font(sub_txt, size=14, bold=True)
    sw = text_width(draw, sub_txt, s_fnt)

    mode_pt = format_mode_title_pt(mode_title)
    title_txt = f"COH3 BRASIL  •  RANKING DIÁRIO {mode_pt} (MÉDIA ELO)"
    t_fnt = pick_font(title_txt, size=16, bold=True, condensed=True)
    header_badge = get_veteranos_badge_icon(size=22)
    img.paste(header_badge, (16, 7), header_badge)
    title_x = 44
    max_title_w = width - title_x - 24 - sw
    if text_width(draw, title_txt, t_fnt) > max_title_w:
        title_txt = f"COH3 BRASIL • RANKING DIÁRIO {mode_pt}"
        title_txt, t_fnt = truncate_to_px(draw, title_txt, int(max_title_w), size=15, bold=True)

    draw.text((title_x, 9), title_txt, font=t_fnt, fill=(245, 184, 46, 255))
    draw.text((width - 20 - sw, 10), sub_txt, font=s_fnt, fill=(190, 184, 172, 255))
    draw.line([(0, banner_h), (width, banner_h)], fill=(48, 44, 36, 255), width=1)

    gold_col = (245, 184, 46, 255)
    ch_y = banner_h + 7
    hdr_fnt = pick_font("VITÓRIAS", size=15, bold=True, condensed=True)

    for lbl, cx, align in (
        ("POS.", 46, "center"),
        ("ELO ▾", 122, "center"),
        ("JOGADOR", 166, "left"),
        ("SEQ.", 498, "right"),
        ("VITÓRIAS ▾", 600, "right"),
        ("DERROTAS", 700, "right"),
        ("TAXA", 768, "right"),
        ("JOGOS", 838, "right"),
        ("ÚLT. JOGO", 964, "right"),
    ):
        lw = text_width(draw, lbl, hdr_fnt)
        tx = (cx - lw / 2) if align == "center" else ((cx - lw) if align == "right" else cx)
        draw.text((tx, ch_y), lbl, font=hdr_fnt, fill=gold_col)

    rule_y = banner_h + col_hdr_h - 1
    draw.line([(10, rule_y), (width - 10, rule_y)], fill=(234, 179, 8, 255), width=2)

    if not rows:
        efnt = pick_font("Sem jogadores ranqueados neste modo.", size=16, bold=False)
        draw.text((330, rule_y + 9), "Sem jogadores ranqueados neste modo.", font=efnt, fill=(156, 163, 175, 255))

    y = banner_h + col_hdr_h
    num_fnt = pick_font("1566", size=17, bold=True, condensed=True)
    row_vet_badge = get_veteranos_badge_icon(size=19)
    white = (243, 244, 246, 255)

    for idx, entry in enumerate(rows):
        is_custom = bool(entry.get("is_custom"))
        rank_val = int(entry.get("br_rank", idx + 1))
        r_bg = (
            (33, 28, 19, 255)
            if (is_custom and rank_val > 20)
            else ((17, 19, 24, 255) if idx % 2 == 0 else (24, 27, 34, 255))
        )

        draw.rectangle((0, y, width, y + row_h), fill=r_bg)
        draw.line([(10, y + row_h - 1), (width - 10, y + row_h - 1)], fill=(34, 38, 46, 255), width=1)

        elo_int = int(round(float(entry.get("avg_elo", 0))))
        wins = int(entry.get("wins", 0))
        losses = int(entry.get("losses", 0))
        total = int(entry.get("total", wins + losses))
        ratio = int(entry.get("ratio", round((wins * 100.0) / total) if total > 0 else 0))
        streak = int(entry.get("streak", 0))
        lmd = int(entry.get("last_match_date", 0))
        last_game_str = datetime.fromtimestamp(lmd, tz=BRT_TZ).strftime("%d/%m/%Y") if lmd > 0 else "—"

        rank_color = (250, 204, 21, 255) if rank_val == 1 else white
        r_str = str(rank_val)
        rw = text_width(draw, r_str, num_fnt)
        draw.text((46 - rw / 2, y + 8), r_str, font=num_fnt, fill=rank_color)

        e_str = str(elo_int)
        ew = text_width(draw, e_str, num_fnt)
        draw.text((122 - ew / 2, y + 8), e_str, font=num_fnt, fill=white)

        pid = int(entry.get("profile_id", 0))
        sid = str(entry.get("steam_id") or "")
        alias_raw = str(entry.get("alias") or f"Jogador {pid}")
        country = str(entry.get("country") or "br").lower()

        ring_col = (245, 184, 46, 245) if is_custom else (34, 197, 94, 230)
        av_im = avatar_provider.get_circular_avatar(
            size=30,
            profile_id=pid,
            steam_id=sid,
            alias=alias_raw,
            ring_color=ring_col,
        )
        img.paste(av_im, (166, y + 3), av_im)

        flag_im = get_country_flag(country, w=21, h=15)
        img.paste(flag_im, (202, y + 11), flag_im)

        disp_alias, a_fnt = truncate_to_px(
            draw,
            alias_raw,
            max_px=196 if is_custom else 224,
            size=17,
            bold=True,
        )
        name_col = (253, 230, 138, 255) if is_custom else white
        draw.text((230, y + 8), disp_alias, font=a_fnt, fill=name_col)

        if is_custom:
            bx = int(230 + text_width(draw, disp_alias, a_fnt) + 7)
            img.paste(row_vet_badge, (bx, y + 8), row_vet_badge)

        if streak > 0:
            st_str, st_col = f"+{streak}", (74, 222, 128, 255)
        elif streak < 0:
            st_str, st_col = f"{streak}", (248, 113, 113, 255)
        else:
            st_str, st_col = "0", (156, 163, 175, 255)
        stw = text_width(draw, st_str, num_fnt)
        draw.text((498 - stw, y + 8), st_str, font=num_fnt, fill=st_col)

        for val_str, right_x in (
            (str(wins), 600),
            (str(losses), 700),
            (f"{ratio}%", 768),
            (str(total), 838),
            (last_game_str, 964),
        ):
            vw = text_width(draw, val_str, num_fnt)
            draw.text((right_x - vw, y + 8), val_str, font=num_fnt, fill=white)

        y += row_h

    return _encode_rgb_png(img)


# ---------------------------------------------------------------------------
# RENDERIZADOR 3: Card de Movimentação de Posições no Ranking (▲ / ▼)
# ---------------------------------------------------------------------------
def render_ranking_movement_card_png(
    movements_by_mode: dict[str, list[dict[str, Any]]],
    avatar_provider: SteamAvatarProvider,
) -> bytes:
    width = 860
    header_h = 56
    sec_hdr_h = 34
    row_h = 44

    active_modes = [(m, items[:12]) for m, items in movements_by_mode.items() if items]
    total_rows = sum(len(items) for _, items in active_modes)
    total_h = header_h + len(active_modes) * sec_hdr_h + max(1, total_rows) * row_h + 10

    img = Image.new("RGBA", (width, total_h), (18, 20, 25, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle((0, 0, width, header_h), fill=(24, 22, 18, 255))
    draw.rectangle((0, 0, 8, total_h), fill=(234, 179, 8, 255))
    draw.line([(0, header_h - 1), (width, header_h - 1)], fill=(234, 179, 8, 220), width=2)

    title_str = "MOVIMENTAÇÃO NO RANKING BRASILEIRO"
    t_fnt = pick_font(title_str, size=20, bold=True, condensed=True)
    draw.text((24, 10), title_str, font=t_fnt, fill=(245, 184, 46, 255))

    now_brt = datetime.now(tz=BRT_TZ).strftime("%d/%m às %H:%M")
    core_unique_cnt = sum(1 for r in CORE_BR_ROSTER if not r.get("merged_into_profile_id"))
    sub_str = f"Top 20 + {core_unique_cnt} Monitorados • Atualizado em {now_brt}"
    sub_fnt = pick_font(sub_str, size=13, bold=True)
    draw.text((24, 34), sub_str, font=sub_fnt, fill=(190, 184, 172, 255))

    y = header_h
    for mode_key, items in active_modes:
        draw.rectangle((8, y, width, y + sec_hdr_h), fill=(26, 29, 36, 255))
        draw.line([(8, y + sec_hdr_h - 1), (width, y + sec_hdr_h - 1)], fill=(46, 50, 62, 255), width=1)
        m_lbl = f"RANKING {format_mode_title_pt(mode_key)}"
        m_fnt = pick_font(m_lbl, size=15, bold=True, condensed=True)
        draw.text((24, y + 8), m_lbl, font=m_fnt, fill=(243, 244, 246, 255))
        y += sec_hdr_h

        for idx, mv in enumerate(items):
            r_bg = (20, 23, 29, 255) if idx % 2 == 0 else (24, 27, 34, 255)
            draw.rectangle((8, y, width, y + row_h), fill=r_bg)
            draw.line([(16, y + row_h - 1), (width - 14, y + row_h - 1)], fill=(34, 38, 46, 255), width=1)

            delta = int(mv.get("rank_delta", 0))
            prev_r = mv.get("prev_rank")
            curr_r = int(mv.get("br_rank", 0))
            is_new = bool(mv.get("is_new_entry"))

            if is_new:
                nfnt = pick_font("NOVO", size=14, bold=True, condensed=True)
                draw.text((26, y + 13), "NOVO", font=nfnt, fill=(56, 189, 248, 255))
                pos_txt = f"Entrou em #{curr_r}"
            else:
                _draw_rank_arrow(draw, cx=34, cy=y + 22, delta=delta, size_scale=1.25)
                verb = "Subiu" if delta > 0 else "Desceu"
                pos_txt = f"{verb}: #{prev_r}  ->  #{curr_r}"

            pos_col = (74, 222, 128, 255) if delta > 0 else ((248, 113, 113, 255) if delta < 0 else (56, 189, 248, 255))
            p_fnt = pick_font(pos_txt, size=17, bold=True, condensed=True)
            draw.text((92, y + 12), pos_txt, font=p_fnt, fill=pos_col)

            pid = int(mv.get("profile_id", 0))
            sid = str(mv.get("steam_id") or "")
            alias_str = str(mv.get("alias") or f"Jogador {pid}")
            country = str(mv.get("country") or "br").lower()

            av_im = avatar_provider.get_circular_avatar(
                size=34,
                profile_id=pid,
                steam_id=sid,
                alias=alias_str,
                ring_color=(245, 184, 46, 245) if mv.get("is_custom") else (34, 197, 94, 230),
            )
            img.paste(av_im, (296, y + 5), av_im)

            flag_im = get_country_flag(country, w=22, h=16)
            img.paste(flag_im, (338, y + 14), flag_im)

            disp_alias, a_fnt = truncate_to_px(draw, alias_str, max_px=340, size=18, bold=True)
            draw.text((368, y + 11), disp_alias, font=a_fnt, fill=(243, 244, 246, 255))

            elo_txt = f"{int(round(float(mv.get('avg_elo', 0))))} ELO"
            e_fnt = pick_font(elo_txt, size=17, bold=True, condensed=True)
            ew = text_width(draw, elo_txt, e_fnt)
            draw.text((width - 24 - ew, y + 12), elo_txt, font=e_fnt, fill=(250, 204, 21, 255))

            y += row_h

    draw.rectangle((0, 0, width - 1, total_h - 1), outline=(56, 52, 42, 255), width=1)
    return _encode_rgb_png(img)


# ---------------------------------------------------------------------------
# RENDERIZADOR 4: Card Tático de Resumo Semanal dos Veteranos BR (PT-BR, 860px)
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
        flag_br = get_country_flag("br", w=20, h=14)
        for idx, pl in enumerate(leaderboard, start=1):
            r_bg = (20, 23, 29, 255) if idx % 2 == 1 else (25, 28, 36, 255)
            draw.rectangle((8, y, width, y + row_h), fill=r_bg)
            draw.line([(16, y + row_h - 1), (width - 14, y + row_h - 1)], fill=(34, 38, 46, 255), width=1)

            rk_col = (250, 204, 21, 255) if idx == 1 else (229, 231, 235, 255)
            rk_str = str(idx)
            rkw = text_width(draw, rk_str, num_fnt)
            draw.text((38 - rkw / 2, y + 10), rk_str, font=num_fnt, fill=rk_col)

            av_im = avatar_provider.get_circular_avatar(
                size=30,
                profile_id=int(pl.get("profile_id", 0)),
                steam_id=str(pl.get("steam_id") or ""),
                alias=str(pl.get("alias") or "BR"),
                ring_color=(245, 184, 46, 245),
            )
            img.paste(av_im, (68, y + 5), av_im)
            img.paste(flag_br, (104, y + 13), flag_br)

            disp_alias, a_fnt = truncate_to_px(draw, str(pl.get("alias") or ""), max_px=258, size=16, bold=True)
            draw.text((130, y + 10), disp_alias, font=a_fnt, fill=(253, 230, 138, 255))
            bx = int(130 + text_width(draw, disp_alias, a_fnt) + 6)
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


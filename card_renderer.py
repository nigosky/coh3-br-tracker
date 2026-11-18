"""Renderizador gráfico seguro (Pillow) para Cards de Partidas (coh3stats) e Tabelas de Ranking Tático com Avatares Steam."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import random
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

# Proteção estrita contra Decompression Bomb (CWE-409)
Image.MAX_IMAGE_PIXELS = 4_000_000

logger = logging.getLogger("coh3_br.renderer")

BASE_DIR = Path(__file__).resolve().parent
FACTIONS_DIR = BASE_DIR / "assets" / "factions"
BRT_TZ = timezone(timedelta(hours=-3))

STEAM_ID64_RE = re.compile(r"^\d{17}$")
STEAM_XML_AVATAR_MEDIUM_RE = re.compile(
    r"<avatarMedium>\s*<!\[CDATA\[(https://[^\]]+)\]\]>\s*</avatarMedium>",
    re.IGNORECASE,
)
STEAM_XML_AVATAR_FULL_RE = re.compile(
    r"<avatarFull>\s*<!\[CDATA\[(https://[^\]]+)\]\]>\s*</avatarFull>",
    re.IGNORECASE,
)

ALLOWED_STEAM_XML_HOST = "steamcommunity.com"
ALLOWED_STEAM_AVATAR_HOSTS = frozenset(
    {
        "avatars.steamstatic.com",
        "avatars.akamai.steamstatic.com",
        "avatars.cloudflare.steamstatic.com",
        "steamcdn-a.akamaihd.net",
        "cdn.akamai.steamstatic.com",
    }
)
MAX_STEAM_XML_BYTES = 65_536       # 64 KB
MAX_STEAM_AVATAR_BYTES = 524_288   # 512 KB

AXIS_FACTIONS = frozenset({"Wehrmacht", "Afrikakorps", "DAK", "Wehr", "german", "dak"})
ALLIES_FACTIONS = frozenset({"US Forces", "British Forces", "USF", "UKF", "american", "british"})

FACTION_TO_ASSET = {
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
CONTROL_STRIP_RE = re.compile(r"[\x00-\x1f\x7f]+")


class _SteamXMLRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permite redirecionamento apenas dentro de https://steamcommunity.com (ex.: /profiles/ID -> /id/vanity)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() != ALLOWED_STEAM_XML_HOST:
            raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento externo Steam bloqueado", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _StrictNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento de CDN bloqueado", headers, fp)


def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


_STEAM_XML_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_make_ssl_ctx()),
    _SteamXMLRedirectHandler(),
)
_STEAM_CDN_OPENER = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=_make_ssl_ctx()),
    _StrictNoRedirectHandler(),
)


# ---------------------------------------------------------------------------
# Carregamento seguro de fontes do sistema com suporte a Latim, Cirílico e CJK
# ---------------------------------------------------------------------------
_FONT_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont | ImageFont.ImageFont] = {}

FONT_CANDIDATES = {
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
    "unicode_regular": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ],
    "unicode_bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ],
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
    if key in _FONT_CACHE:
        return _FONT_CACHE[key]
    for path_str in FONT_CANDIDATES.get(role, FONT_CANDIDATES["regular"]):
        p = Path(path_str)
        if p.exists():
            try:
                fnt = ImageFont.truetype(str(p), size=size)
                _FONT_CACHE[key] = fnt
                return fnt
            except Exception:
                continue
    fallback = ImageFont.load_default()
    _FONT_CACHE[key] = fallback
    return fallback


def pick_font(text: str, size: int, bold: bool = False, condensed: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Seleciona automaticamente a fonte ideal (Roboto, DejaVu ou Noto CJK) para evitar caracteres quadrados."""
    if HAS_CJK_RE.search(text):
        return _get_font_by_role("cjk_bold" if bold else "cjk_regular", size)
    if NEEDS_DEJAVU_RE.search(text):
        return _get_font_by_role("unicode_bold" if bold else "unicode_regular", size)
    if condensed:
        return _get_font_by_role("condensed_bold", size)
    return _get_font_by_role("bold" if bold else "regular", size)


def clean_label(raw: Any, max_len: int = 28) -> str:
    txt = CONTROL_STRIP_RE.sub(" ", str(raw or "")).strip()
    if not txt:
        return "Unknown"
    if len(txt) > max_len:
        return txt[: max_len - 1] + "…"
    return txt


def text_width(draw: ImageDraw.ImageDraw, text: str, font: Any) -> float:
    try:
        return float(draw.textlength(text, font=font))
    except AttributeError:
        bbox = draw.textbbox((0, 0), text, font=font)
        return float(bbox[2] - bbox[0])


def truncate_to_px(draw: ImageDraw.ImageDraw, text: str, max_px: int, size: int, bold: bool = False) -> tuple[str, Any]:
    txt = CONTROL_STRIP_RE.sub(" ", str(text or "")).strip() or "Unknown"
    fnt = pick_font(txt, size=size, bold=bold)
    if text_width(draw, txt, fnt) <= max_px:
        return txt, fnt
    while len(txt) > 2 and text_width(draw, txt + "…", fnt) > max_px:
        txt = txt[:-1]
    return txt + "…", fnt


# ---------------------------------------------------------------------------
# Provedor seguro de Avatares da Steam (com cache em SQLite + memória)
# ---------------------------------------------------------------------------
class SteamAvatarProvider:
    """Busca e faz cache de avatares reais da Steam para jogadores brasileiros sem exigir chave de API."""

    def __init__(self, db: Any | None = None, catalog_json_path: Path | None = None, allow_network: bool = True) -> None:
        self.db = db
        self.allow_network = allow_network
        self._mem_png_cache: dict[str, Image.Image] = {}
        self._pid_to_steam: dict[int, str] = {}
        self._failed_steam_ids: set[str] = set()
        self._network_fetches_this_run = 0
        self._max_network_fetches_per_run = 75
        self._last_net_ts = 0.0

        if db is not None and hasattr(db, "get_steam_id_map"):
            try:
                self._pid_to_steam.update(db.get_steam_id_map())
            except Exception:
                pass

        cat_path = catalog_json_path or (BASE_DIR / "jogadores_br_steam.json")
        if cat_path.exists():
            try:
                doc = json.loads(cat_path.read_text(encoding="utf-8"))
                for p in doc.get("players", []):
                    pid = int(p.get("profile_id", 0))
                    sid = str(p.get("steam_id") or "").strip()
                    if pid > 0 and STEAM_ID64_RE.fullmatch(sid):
                        self._pid_to_steam.setdefault(pid, sid)
            except Exception:
                pass

    def resolve_steam_id(self, profile_id: int = 0, steam_id: str = "") -> str:
        clean_sid = str(steam_id or "").strip()
        if clean_sid.startswith("/steam/"):
            clean_sid = clean_sid.replace("/steam/", "")
        if STEAM_ID64_RE.fullmatch(clean_sid):
            if profile_id > 0:
                self._pid_to_steam[int(profile_id)] = clean_sid
            return clean_sid
        if profile_id > 0:
            mapped = self._pid_to_steam.get(int(profile_id), "")
            if STEAM_ID64_RE.fullmatch(mapped):
                return mapped
        return ""

    def _fetch_steam_avatar_bytes(self, steam_id: str) -> tuple[str, bytes] | None:
        if not STEAM_ID64_RE.fullmatch(steam_id):
            return None
        if steam_id in self._failed_steam_ids or self._network_fetches_this_run >= self._max_network_fetches_per_run:
            return None

        import time as _time

        self._network_fetches_this_run += 1
        xml_url = f"https://steamcommunity.com/profiles/{steam_id}/?xml=1"

        for attempt in range(2):
            elapsed = _time.monotonic() - self._last_net_ts
            if elapsed < 0.10:
                _time.sleep(0.10 - elapsed)
            self._last_net_ts = _time.monotonic()
            try:
                req = urllib.request.Request(
                    xml_url,
                    headers={"User-Agent": "CoH3-BR-Tracker/3.0", "Accept": "application/xml,text/xml"},
                )
                with _STEAM_XML_OPENER.open(req, timeout=8) as resp:
                    xml_raw = resp.read(MAX_STEAM_XML_BYTES + 1)
                    if len(xml_raw) > MAX_STEAM_XML_BYTES:
                        break
                    xml_text = xml_raw.decode("utf-8", errors="ignore")

                m = STEAM_XML_AVATAR_MEDIUM_RE.search(xml_text) or STEAM_XML_AVATAR_FULL_RE.search(xml_text)
                if not m:
                    break

                avatar_url = m.group(1).strip()
                parsed_av = urllib.parse.urlparse(avatar_url)
                if parsed_av.scheme != "https" or (parsed_av.hostname or "").lower() not in ALLOWED_STEAM_AVATAR_HOSTS:
                    logger.warning("Host de avatar Steam fora da allowlist bloqueado: %s", parsed_av.hostname)
                    break

                img_req = urllib.request.Request(
                    avatar_url,
                    headers={"User-Agent": "CoH3-BR-Tracker/3.0", "Accept": "image/*"},
                )
                with _STEAM_CDN_OPENER.open(img_req, timeout=8) as img_resp:
                    img_bytes = img_resp.read(MAX_STEAM_AVATAR_BYTES + 1)
                    if len(img_bytes) > MAX_STEAM_AVATAR_BYTES:
                        break

                with Image.open(io.BytesIO(img_bytes)) as im:
                    clean_im = im.convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
                    out_buf = io.BytesIO()
                    clean_im.save(out_buf, format="PNG", optimize=True)
                    return avatar_url, out_buf.getvalue()
            except Exception as exc:
                if attempt == 0:
                    _time.sleep(0.25)
                    continue
                logger.debug("Não foi possível baixar avatar Steam (%s): %s", steam_id, exc)

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
        """Retorna um avatar circular RGBA (real da Steam ou monograma tático de fallback)."""
        sid = self.resolve_steam_id(profile_id=profile_id, steam_id=steam_id)
        cache_key = sid or f"pid_{profile_id}_{alias[:4]}"

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
            base_img = _build_fallback_avatar(alias or "BR", seed=profile_id or hash(alias))
            self._mem_png_cache[cache_key] = base_img

        return _mask_circle_rgba(base_img, size=size, ring_color=ring_color)


def _build_fallback_avatar(alias: str, seed: int) -> Image.Image:
    palettes = [
        ((22, 101, 52), (74, 222, 128)),
        ((30, 64, 175), (96, 165, 250)),
        ((146, 64, 14), (251, 191, 36)),
        ((88, 28, 135), (192, 132, 252)),
        ((15, 118, 110), (45, 212, 191)),
    ]
    bg, fg = palettes[abs(int(seed)) % len(palettes)]
    im = Image.new("RGBA", (64, 64), (*bg, 255))
    drw = ImageDraw.Draw(im)
    alnum = "".join(ch for ch in alias.strip() if ch.isalnum())
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
import base64 as _b64

_EMBEDDED_FACTION_PNG_B64: dict[str, str] = {
    'american': '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',
    'british': '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',
    'dak': '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',
    'german': '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'
}

_FACTION_ICON_CACHE: dict[tuple[str, int], Image.Image] = {}


def get_faction_icon(faction_name: str, size: int) -> Image.Image:
    asset_key = FACTION_TO_ASSET.get(str(faction_name or "").strip(), "german")
    ck = (asset_key, size)
    if ck in _FACTION_ICON_CACHE:
        return _FACTION_ICON_CACHE[ck]

    png_path = FACTIONS_DIR / f"{asset_key}.png"
    if png_path.exists():
        try:
            with Image.open(png_path) as im:
                icon = im.convert("RGBA").resize((size, size), Image.Resampling.LANCZOS)
                _FACTION_ICON_CACHE[ck] = icon
                return icon
        except Exception:
            pass

    b64_str = _EMBEDDED_FACTION_PNG_B64.get(asset_key)
    if b64_str:
        try:
            with Image.open(io.BytesIO(_b64.b64decode(b64_str))) as im:
                icon = im.convert("RGBA").resize((size, size), Image.Resampling.LANCZOS)
                _FACTION_ICON_CACHE[ck] = icon
                return icon
        except Exception:
            pass

    # Fallback vetorial caso a pasta assets não esteja presente
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
    c = (code or "un").strip().lower()
    ck = (c, w, h)
    if ck in _FLAG_CACHE:
        return _FLAG_CACHE[ck]

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
            y0 = int(i * sh / 7)
            y1 = int((i + 1) * sh / 7)
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
        for sx, sy in [(int(sw * 0.72), int(sh * 0.35)), (int(sw * 0.82), int(sh * 0.65)), (int(sw * 0.62), int(sh * 0.7))]:
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
    key = (str(map_raw or "map"), size)
    if key in _MAP_THUMB_CACHE:
        return _MAP_THUMB_CACHE[key]

    digest = hashlib.sha256(key[0].encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(digest[:8], "big"))

    ss = size * 2
    im = Image.new("RGBA", (ss, ss), (112, 100, 86, 255))
    d = ImageDraw.Draw(im)

    # Manchas de terreno aéreo (sépia tático)
    for _ in range(9):
        cx, cy = rng.randint(0, ss), rng.randint(0, ss)
        rw, rh = rng.randint(18, 46), rng.randint(18, 46)
        shade = rng.choice([(92, 81, 69, 180), (132, 119, 103, 170), (78, 69, 58, 160)])
        d.ellipse((cx - rw, cy - rh, cx + rw, cy + rh), fill=shade)

    # Grade cartográfica sutil
    for g in range(ss // 4, ss, ss // 4):
        d.line([(g, 0), (g, ss)], fill=(60, 52, 44, 70), width=1)
        d.line([(0, g), (ss, g)], fill=(60, 52, 44, 70), width=1)

    # Estradas aéreas claras (como nas miniaturas de Pachino / Eindhoven / Primosole)
    for _ in range(4):
        pts = [
            (rng.randint(0, ss // 3), rng.randint(0, ss)),
            (rng.randint(ss // 3, (2 * ss) // 3), rng.randint(10, ss - 10)),
            (rng.randint((2 * ss) // 3, ss), rng.randint(0, ss)),
        ]
        d.line(pts, fill=(198, 186, 170, 225), width=rng.choice([2, 3]))

    d.rectangle((0, 0, ss - 1, ss - 1), outline=(72, 76, 88, 255), width=2)
    out = im.resize((size, size), Image.Resampling.LANCZOS)
    _MAP_THUMB_CACHE[key] = out
    return out


# ---------------------------------------------------------------------------
# Utilitários de formatação de tempo, modo e equipes (Axis vs Allies)
# ---------------------------------------------------------------------------
def format_relative_played(ts: int, now_ts: int | None = None, live_label: bool = False) -> str:
    if live_label:
        dt = datetime.fromtimestamp(ts, tz=BRT_TZ)
        return f"Hoje {dt.strftime('%H:%M')}"
    now = now_ts or int(datetime.now(tz=timezone.utc).timestamp())
    diff = max(0, now - int(ts))
    if diff < 3600:
        mins = max(1, diff // 60)
        return f"há {mins} min"
    if diff < 86400:
        hrs = diff // 3600
        return f"há {hrs}h" if hrs > 1 else "há 1h"
    days = diff // 86400
    if days == 1:
        return "há 1 dia"
    if days < 14:
        return f"há {days} dias"
    weeks = days // 7
    return f"há {weeks} sem."


def format_mode_vs(mode_raw: str) -> str:
    s = str(mode_raw or "")
    if "1v1" in s:
        return "1 vs 1"
    if "2v2" in s:
        return "2 vs 2"
    if "3v3" in s:
        return "3 vs 3"
    if "4v4" in s:
        return "4 vs 4"
    if "Custom" in s:
        return "Custom"
    return s[:10] or "Match"


def format_mm_ss(seconds: int) -> str:
    total = max(0, int(seconds))
    hrs, rem = divmod(total, 3600)
    mins, secs = divmod(rem, 60)
    if hrs > 0:
        return f"{hrs}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def extract_axis_and_allies_players(group: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Reconstrói todos os jogadores únicos da partida e separa em (Axis Players, Allies Players)
    exatamente como o layout horizontal do coh3stats.com.
    """
    records = group.get("records") or [group.get("primary") or group]
    primary = records[0]
    tracked_by_pid: dict[int, dict[str, Any]] = {}

    for rec in records:
        pid = int(rec["tracked_profile_id"])
        old_e = rec.get("old_elo")
        new_e = rec.get("new_elo")
        delta = (int(new_e) - int(old_e)) if (old_e and new_e) else None
        tracked_by_pid[pid] = {
            "profile_id": pid,
            "alias": rec.get("tracked_alias") or f"Player {pid}",
            "steam_id": str(rec.get("tracked_steam_id") or ""),
            "country": "br",
            "faction": rec.get("tracked_faction") or "Wehrmacht",
            "old_elo": int(old_e) if old_e else None,
            "new_elo": int(new_e) if new_e else None,
            "elo_delta": delta,
            "is_tracked": True,
            "team_side": 0 if pid == int(primary["tracked_profile_id"]) else 0,
        }

    team_a: list[dict[str, Any]] = [tracked_by_pid[int(primary["tracked_profile_id"])]]
    seen_pids: set[int] = {int(primary["tracked_profile_id"])}

    for ally in primary.get("allies", []):
        apid = int(ally.get("profile_id", 0))
        if apid in seen_pids:
            continue
        seen_pids.add(apid)
        if apid in tracked_by_pid:
            team_a.append(tracked_by_pid[apid])
        else:
            old_e = ally.get("old_elo")
            new_e = ally.get("new_elo") or ally.get("elo")
            delta = ally.get("elo_delta")
            if delta is None and old_e and new_e:
                delta = int(new_e) - int(old_e)
            team_a.append(
                {
                    "profile_id": apid,
                    "alias": ally.get("alias") or f"ID {apid}",
                    "steam_id": str(ally.get("steam_id") or ""),
                    "country": str(ally.get("country") or "un").lower(),
                    "faction": ally.get("faction") or ally.get("faction_short") or "Wehrmacht",
                    "old_elo": int(old_e) if old_e else (int(new_e) if new_e else None),
                    "new_elo": int(new_e) if new_e else None,
                    "elo_delta": int(delta) if delta is not None else None,
                    "is_tracked": False,
                }
            )

    team_b: list[dict[str, Any]] = []
    for opp in primary.get("opponents", []):
        opid = int(opp.get("profile_id", 0))
        if opid in seen_pids:
            continue
        seen_pids.add(opid)
        if opid in tracked_by_pid:
            team_b.append(tracked_by_pid[opid])
        else:
            old_e = opp.get("old_elo")
            new_e = opp.get("new_elo") or opp.get("elo")
            delta = opp.get("elo_delta")
            if delta is None and old_e and new_e:
                delta = int(new_e) - int(old_e)
            team_b.append(
                {
                    "profile_id": opid,
                    "alias": opp.get("alias") or f"ID {opid}",
                    "steam_id": str(opp.get("steam_id") or ""),
                    "country": str(opp.get("country") or "un").lower(),
                    "faction": opp.get("faction") or opp.get("faction_short") or "US Forces",
                    "old_elo": int(old_e) if old_e else (int(new_e) if new_e else None),
                    "new_elo": int(new_e) if new_e else None,
                    "elo_delta": int(delta) if delta is not None else None,
                    "is_tracked": False,
                }
            )

    all_participants = team_a + team_b
    axis_players = [p for p in all_participants if str(p["faction"]) in AXIS_FACTIONS]
    allies_players = [p for p in all_participants if str(p["faction"]) in ALLIES_FACTIONS]

    # Fallback para Custom Games onde ambos os lados jogam com a mesma aliança
    if not axis_players or not allies_players:
        return team_a, team_b

    return axis_players, allies_players


# ---------------------------------------------------------------------------
# RENDERIZADOR 1: Layout de Partidas Horizontal (idêntico à image.png + Avatares Steam BR)
# ---------------------------------------------------------------------------
def render_matches_table_png(
    grouped_matches: list[dict[str, Any]],
    avatar_provider: SteamAvatarProvider,
    live_single: bool = False,
) -> bytes:
    """
    Renderiza 1 ou N partidas no layout horizontal escuro do coh3stats.com (image.png):
    Played | Result [VICTORY +12 / DEFEAT -20] | Axis Players | Allies Players | Map | Mode / Duration | Details / Replay
    Com Avatares circulares da Steam para todos os jogadores brasileiros!
    """
    width = 1240
    header_h = 40

    prepared_rows: list[dict[str, Any]] = []
    for grp in grouped_matches:
        recs = grp.get("records") or [grp.get("primary") or grp]
        primary = recs[0]
        axis_p, allies_p = extract_axis_and_allies_players(grp)
        max_team = max(len(axis_p), len(allies_p), 1)
        row_h = max(94, 24 + max_team * 27)
        prepared_rows.append(
            {
                "records": recs,
                "primary": primary,
                "axis": axis_p,
                "allies": allies_p,
                "row_h": row_h,
            }
        )

    if not prepared_rows:
        prepared_rows = []

    total_h = header_h + sum(r["row_h"] for r in prepared_rows) + (2 if prepared_rows else 64)
    img = Image.new("RGBA", (width, total_h), (24, 26, 31, 255))
    draw = ImageDraw.Draw(img)

    # Cabeçalho superior estilo coh3stats
    draw.rectangle((0, 0, width, header_h), fill=(20, 22, 27, 255))
    draw.line([(0, header_h - 1), (width, header_h - 1)], fill=(48, 52, 63, 255), width=1)

    hdr_font = pick_font("Played", size=13, bold=True)
    hdr_color = (229, 231, 235, 255)
    draw.text((20, 12), "Played  ↓", font=hdr_font, fill=hdr_color)
    draw.text((140, 12), "Result", font=hdr_font, fill=hdr_color)
    draw.text((274, 12), "Axis Players", font=hdr_font, fill=hdr_color)
    draw.text((614, 12), "Allies Players", font=hdr_font, fill=hdr_color)
    draw.text((982, 12), "Map", font=hdr_font, fill=hdr_color)
    draw.text((1084, 5), "Mode", font=hdr_font, fill=hdr_color)
    draw.text((1074, 21), "Duration", font=hdr_font, fill=hdr_color)

    if not prepared_rows:
        empty_fnt = pick_font("Nenhuma partida registrada ainda.", size=15, bold=False)
        draw.text((460, header_h + 22), "Nenhuma partida registrada ainda.", font=empty_fnt, fill=(156, 163, 175, 255))

    y = header_h
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())

    for idx, row in enumerate(prepared_rows):
        rh = row["row_h"]
        recs = row["records"]
        primary = row["primary"]

        bg_col = (30, 32, 38, 255) if idx % 2 == 0 else (26, 28, 34, 255)
        draw.rectangle((0, y, width, y + rh), fill=bg_col)
        draw.line([(0, y + rh - 1), (width, y + rh - 1)], fill=(46, 49, 58, 255), width=1)

        winners = [r for r in recs if bool(r.get("win"))]
        losers = [r for r in recs if not bool(r.get("win"))]
        is_duel = bool(winners and losers)
        is_win = bool(primary.get("win"))

        # 1) Barra lateral esquerda de resultado + Medalhão Facção + Horário (Played)
        if is_duel:
            accent_col = (234, 179, 8, 255)
            pill_col = (217, 119, 6, 255)
            pill_text = "DUELO BR"
        elif is_win:
            accent_col = (29, 125, 250, 255)
            pill_col = (29, 108, 232, 255)
            old_e, new_e = primary.get("old_elo"), primary.get("new_elo")
            if old_e and new_e:
                diff = int(new_e) - int(old_e)
                sign = f"+{diff}" if diff >= 0 else f"{diff}"
                pill_text = f"VICTORY {sign}"
            else:
                pill_text = "VICTORY"
        else:
            accent_col = (224, 49, 49, 255)
            pill_col = (214, 44, 44, 255)
            old_e, new_e = primary.get("old_elo"), primary.get("new_elo")
            if old_e and new_e:
                diff = int(new_e) - int(old_e)
                sign = f"+{diff}" if diff >= 0 else f"{diff}"
                pill_text = f"DEFEAT {sign}"
            else:
                pill_text = "DEFEAT"

        draw.rectangle((0, y + 6, 5, y + rh - 6), fill=accent_col)

        fac_icon = get_faction_icon(str(primary.get("tracked_faction", "Wehrmacht")), size=46)
        fac_x = 34
        fac_y = y + (rh - 66) // 2
        img.paste(fac_icon, (fac_x, fac_y), fac_icon)

        played_str = format_relative_played(int(primary.get("completion_time", 0)), now_ts=now_ts, live_label=live_single)
        p_fnt = pick_font(played_str, size=12, bold=False)
        pw = text_width(draw, played_str, p_fnt)
        draw.text((fac_x + 23 - pw / 2, fac_y + 51), played_str, font=p_fnt, fill=(209, 213, 219, 255))

        # 2) Pílula de Resultado (VICTORY +12 / DEFEAT -20)
        pill_w, pill_h = 112, 25
        pill_x = 122
        pill_y = y + (rh - pill_h) // 2
        draw.rounded_rectangle((pill_x, pill_y, pill_x + pill_w, pill_y + pill_h), radius=12, fill=pill_col)
        pill_fnt = pick_font(pill_text, size=12, bold=True)
        ptw = text_width(draw, pill_text, pill_fnt)
        draw.text((pill_x + (pill_w - ptw) / 2, pill_y + 5), pill_text, font=pill_fnt, fill=(255, 255, 255, 255))

        # 3 & 4) Colunas Axis Players (x=254) e Allies Players (x=594)
        for col_x, team_list in ((254, row["axis"]), (594, row["allies"])):
            line_pitch = 26
            block_h = len(team_list) * line_pitch
            start_py = y + (rh - block_h) // 2
            for pidx, pl in enumerate(team_list):
                py = start_py + pidx * line_pitch
                # Mini ícone da facção (19x19)
                mini_fac = get_faction_icon(str(pl["faction"]), size=19)
                img.paste(mini_fac, (col_x, py + 2), mini_fac)

                # ELO pré-partida (ou N/A) alinhado à direita
                elo_val = pl.get("old_elo")
                elo_txt = str(elo_val) if elo_val else "N/A"
                elo_fnt = pick_font(elo_txt, size=13, bold=False)
                ew = text_width(draw, elo_txt, elo_fnt)
                elo_col = (229, 231, 235, 255) if elo_val else (156, 163, 175, 255)
                draw.text((col_x + 58 - ew, py + 4), elo_txt, font=elo_fnt, fill=elo_col)

                # Delta ELO (+12 verde / -20 vermelho)
                delta = pl.get("elo_delta")
                if delta is not None:
                    d_txt = f"+{delta}" if delta >= 0 else f"{delta}"
                    d_col = (74, 222, 128, 255) if delta >= 0 else (248, 113, 113, 255)
                else:
                    d_txt = ""
                    d_col = (156, 163, 175, 255)
                if d_txt:
                    d_fnt = pick_font(d_txt, size=13, bold=False)
                    dw = text_width(draw, d_txt, d_fnt)
                    draw.text((col_x + 93 - dw, py + 4), d_txt, font=d_fnt, fill=d_col)

                # Bandeira do país (18x13)
                country = str(pl.get("country") or "un").lower()
                flag_im = get_country_flag(country, w=18, h=13)
                img.paste(flag_im, (col_x + 100, py + 5), flag_im)

                name_x = col_x + 124
                is_br = country == "br" or bool(pl.get("is_tracked"))

                # Avatar Circular Real da Steam para jogadores brasileiros!
                if is_br:
                    ring = (56, 189, 248, 240) if pl.get("is_tracked") else (34, 197, 94, 210)
                    av_im = avatar_provider.get_circular_avatar(
                        size=22,
                        profile_id=int(pl.get("profile_id", 0)),
                        steam_id=str(pl.get("steam_id") or ""),
                        alias=str(pl.get("alias") or "BR"),
                        ring_color=ring,
                    )
                    img.paste(av_im, (name_x, py + 1), av_im)
                    name_x += 27

                max_alias_px = (col_x + 328) - name_x
                is_tracked = bool(pl.get("is_tracked"))
                disp_alias, a_fnt = truncate_to_px(
                    draw,
                    str(pl.get("alias") or ""),
                    max_px=max_alias_px,
                    size=13,
                    bold=is_tracked,
                )
                alias_color = (56, 189, 248, 255) if is_tracked else (96, 165, 250, 255)
                draw.text((name_x, py + 4), disp_alias, font=a_fnt, fill=alias_color)

        # 5) Coluna Map (Miniatura tática 50x50 + Nome do Mapa)
        map_cx = 995
        m_thumb = get_tactical_map_thumb(str(primary.get("map_raw") or ""), size=50)
        thumb_y = y + (rh - 68) // 2
        img.paste(m_thumb, (map_cx - 25, thumb_y), m_thumb)

        map_label, m_fnt = truncate_to_px(
            draw,
            str(primary.get("map_clean") or "Unknown Map"),
            max_px=138,
            size=12,
            bold=False,
        )
        mw = text_width(draw, map_label, m_fnt)
        draw.text((map_cx - mw / 2, thumb_y + 54), map_label, font=m_fnt, fill=(212, 216, 224, 255))

        # 6) Coluna Mode / Duration
        mode_cx = 1102
        mode_str = format_mode_vs(str(primary.get("mode") or ""))
        dur_str = format_mm_ss(int(primary.get("duration_sec", 0)))
        md_fnt = pick_font(mode_str, size=13, bold=False)
        du_fnt = pick_font(dur_str, size=13, bold=False)
        mdw = text_width(draw, mode_str, md_fnt)
        duw = text_width(draw, dur_str, du_fnt)
        mid_my = y + rh // 2
        draw.text((mode_cx - mdw / 2, mid_my - 17), mode_str, font=md_fnt, fill=(229, 231, 235, 255))
        draw.text((mode_cx - duw / 2, mid_my + 3), dur_str, font=du_fnt, fill=(209, 213, 219, 255))

        # 7) Botões visuais Details / Replay à direita (idêntico à image.png)
        btn_x, btn_w, btn_h = 1150, 78, 28
        b1_y = mid_my - 31
        b2_y = mid_my + 3
        for by, b_lbl in ((b1_y, "Details"), (b2_y, "Replay")):
            draw.rounded_rectangle(
                (btn_x, by, btn_x + btn_w, by + btn_h),
                radius=4,
                fill=(35, 38, 46, 255),
                outline=(68, 73, 86, 255),
                width=1,
            )
            bfnt = pick_font(b_lbl, size=12, bold=True)
            bw = text_width(draw, b_lbl, bfnt)
            draw.text((btn_x + (btn_w - bw) / 2 + 5, by + 6), b_lbl, font=bfnt, fill=(243, 244, 246, 255))

        # Ícone olho minimalista em Details
        ey_x, ey_y = btn_x + 12, b1_y + 14
        draw.ellipse((ey_x - 5, ey_y - 3, ey_x + 5, ey_y + 3), outline=(209, 213, 219, 255), width=1)
        draw.ellipse((ey_x - 1, ey_y - 1, ey_x + 1, ey_y + 1), fill=(209, 213, 219, 255))

        # Ícone download minimalista em Replay
        dl_x, dl_y = btn_x + 12, b2_y + 14
        draw.line([(dl_x, dl_y - 4), (dl_x, dl_y + 2)], fill=(209, 213, 219, 255), width=1)
        draw.polygon([(dl_x - 3, dl_y), (dl_x + 3, dl_y), (dl_x, dl_y + 3)], fill=(209, 213, 219, 255))
        draw.line([(dl_x - 4, dl_y + 5), (dl_x + 4, dl_y + 5)], fill=(209, 213, 219, 255), width=1)

        y += rh

    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG", optimize=True)
    return out.getvalue()


# ---------------------------------------------------------------------------
# RENDERIZADOR 2: Tabela Tática de Ranking (idêntica à image_2.png + Avatares Steam)
# ---------------------------------------------------------------------------
def render_ranking_table_png(
    entries: list[dict[str, Any]],
    mode_title: str,
    avatar_provider: SteamAvatarProvider,
    max_rows: int = 25,
) -> bytes:
    """
    Renderiza a tabela escura com cabeçalho dourado idêntica à image_2.png:
    RANK | ELO ▼ | ALIAS [Avatar Steam Circular + 🇧🇷] | STREAK | WINS ▼ | LOSSES | RATIO | TOTAL | LAST GAME
    """
    width = 1120
    banner_h = 38
    col_hdr_h = 34
    row_h = 40

    rows = entries[:max_rows]
    total_h = banner_h + col_hdr_h + max(1, len(rows)) * row_h + 4
    img = Image.new("RGBA", (width, total_h), (15, 17, 21, 255))
    draw = ImageDraw.Draw(img)

    # Fundo tático escuro sutil no topo (remetendo ao mapa escuro de fundo da image_2.png)
    draw.rectangle((0, 0, width, banner_h + col_hdr_h), fill=(22, 20, 17, 255))
    rng = random.Random(hashlib.sha256(mode_title.encode("utf-8")).digest()[:8])
    for _ in range(10):
        x0, y0 = rng.randint(0, width), rng.randint(0, banner_h + col_hdr_h)
        x1, y1 = x0 + rng.randint(-180, 180), y0 + rng.randint(-30, 30)
        draw.line([(x0, y0), (x1, y1)], fill=(46, 41, 33, 95), width=1)

    # Faixa de título do Modo
    title_txt = f"COH3 BRASIL  •  RANKING {mode_title.upper()} (MÉDIA ELO FACÇÕES ATIVAS)"
    t_fnt = pick_font(title_txt, size=14, bold=True, condensed=True)
    draw.text((22, 10), title_txt, font=t_fnt, fill=(245, 184, 46, 255))

    sub_txt = f"Top 20 + Convidados  •  {len(rows)} jogador(es)"
    s_fnt = pick_font(sub_txt, size=12, bold=False)
    sw = text_width(draw, sub_txt, s_fnt)
    draw.text((width - 22 - sw, 11), sub_txt, font=s_fnt, fill=(180, 175, 165, 255))

    draw.line([(0, banner_h), (width, banner_h)], fill=(48, 44, 36, 255), width=1)

    # Cabeçalhos das 9 Colunas em Dourado (image_2.png)
    gold_col = (245, 184, 46, 255)
    ch_y = banner_h + 9
    hdr_fnt = pick_font("RANK", size=14, bold=True, condensed=True)

    col_specs = [
        ("RANK", 44, "center"),
        ("ELO ▾", 112, "center"),
        ("ALIAS", 170, "left"),
        ("STREAK", 665, "right"),
        ("WINS ▾", 748, "right"),
        ("LOSSES", 832, "right"),
        ("RATIO", 912, "right"),
        ("TOTAL", 990, "right"),
        ("LAST GAME", 1098, "right"),
    ]
    for lbl, cx, align in col_specs:
        lw = text_width(draw, lbl, hdr_fnt)
        if align == "center":
            tx = cx - lw / 2
        elif align == "right":
            tx = cx - lw
        else:
            tx = cx
        draw.text((tx, ch_y), lbl, font=hdr_fnt, fill=gold_col)

    # Linha divisória dourada nítida exatamente abaixo do cabeçalho
    rule_y = banner_h + col_hdr_h - 1
    draw.line([(12, rule_y), (width - 12, rule_y)], fill=(234, 179, 8, 255), width=2)

    if not rows:
        efnt = pick_font("Sem jogadores ranqueados neste modo.", size=14, bold=False)
        draw.text((420, rule_y + 12), "Sem jogadores ranqueados neste modo.", font=efnt, fill=(156, 163, 175, 255))

    y = banner_h + col_hdr_h
    for idx, entry in enumerate(rows):
        is_custom = bool(entry.get("is_custom"))
        if is_custom and int(entry.get("br_rank", 0)) > 20:
            r_bg = (31, 27, 19, 255)
        else:
            r_bg = (17, 19, 24, 255) if idx % 2 == 0 else (23, 26, 33, 255)

        draw.rectangle((0, y, width, y + row_h), fill=r_bg)
        draw.line([(12, y + row_h - 1), (width - 12, y + row_h - 1)], fill=(34, 38, 46, 255), width=1)

        rank_val = int(entry.get("br_rank", idx + 1))
        elo_int = int(round(float(entry.get("avg_elo", 0))))
        wins = int(entry.get("wins", 0))
        losses = int(entry.get("losses", 0))
        total = int(entry.get("total", wins + losses))
        ratio = int(entry.get("ratio", round((wins * 100.0) / total) if total > 0 else 0))
        streak = int(entry.get("streak", 0))
        lmd = int(entry.get("last_match_date", 0))
        last_game_str = datetime.fromtimestamp(lmd, tz=BRT_TZ).strftime("%d/%m/%Y") if lmd > 0 else "—"

        num_fnt = pick_font("1566", size=15, bold=True, condensed=True)
        white = (243, 244, 246, 255)
        rank_color = (250, 204, 21, 255) if rank_val == 1 else white

        # 1) RANK
        r_str = str(rank_val)
        rw = text_width(draw, r_str, num_fnt)
        draw.text((44 - rw / 2, y + 11), r_str, font=num_fnt, fill=rank_color)

        # 2) ELO
        e_str = str(elo_int)
        ew = text_width(draw, e_str, num_fnt)
        draw.text((112 - ew / 2, y + 11), e_str, font=num_fnt, fill=white)

        # 3) ALIAS: Avatar Circular Real da Steam (30x30) + Bandeira 🇧🇷 (20x14) + Nome
        pid = int(entry.get("profile_id", 0))
        sid = str(entry.get("steam_id") or "")
        alias_raw = str(entry.get("alias") or f"Player {pid}")
        country = str(entry.get("country") or "br").lower()

        ring_col = (245, 184, 46, 240) if is_custom else (34, 197, 94, 220)
        av_im = avatar_provider.get_circular_avatar(
            size=30,
            profile_id=pid,
            steam_id=sid,
            alias=alias_raw,
            ring_color=ring_col,
        )
        img.paste(av_im, (170, y + 5), av_im)

        flag_im = get_country_flag(country, w=20, h=14)
        img.paste(flag_im, (206, y + 13), flag_im)

        alias_max_px = 340 if is_custom else 390
        disp_alias, a_fnt = truncate_to_px(draw, alias_raw, max_px=alias_max_px, size=14, bold=True)
        draw.text((233, y + 11), disp_alias, font=a_fnt, fill=white)

        if is_custom:
            aw = text_width(draw, disp_alias, a_fnt)
            bx = int(233 + aw + 8)
            badge_lbl = "★ EXTRA"
            bfnt = pick_font(badge_lbl, size=10, bold=True)
            bw = int(text_width(draw, badge_lbl, bfnt)) + 10
            draw.rounded_rectangle((bx, y + 11, bx + bw, y + 28), radius=4, fill=(66, 50, 16, 255), outline=(234, 179, 8, 200))
            draw.text((bx + 5, y + 13), badge_lbl, font=bfnt, fill=(250, 204, 21, 255))

        # 4) STREAK (+5 verde / -2 vermelho)
        if streak > 0:
            st_str = f"+{streak}"
            st_col = (74, 222, 128, 255)
        elif streak < 0:
            st_str = f"{streak}"
            st_col = (248, 113, 113, 255)
        else:
            st_str = "0"
            st_col = (156, 163, 175, 255)
        stw = text_width(draw, st_str, num_fnt)
        draw.text((665 - stw, y + 11), st_str, font=num_fnt, fill=st_col)

        # 5..9) WINS, LOSSES, RATIO, TOTAL, LAST GAME
        for val_str, right_x in (
            (str(wins), 748),
            (str(losses), 832),
            (f"{ratio}%", 912),
            (str(total), 990),
            (last_game_str, 1098),
        ):
            vw = text_width(draw, val_str, num_fnt)
            draw.text((right_x - vw, y + 11), val_str, font=num_fnt, fill=white)

        y += row_h

    out = io.BytesIO()
    img.convert("RGB").save(out, format="PNG", optimize=True)
    return out.getvalue()

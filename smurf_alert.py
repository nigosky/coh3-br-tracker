"""Motor forense multi-gênero em tempo real para alertar quando Veteranos enfrentam possíveis smurfs de outros brasileiros."""

from __future__ import annotations

import json
import logging
import math
import re
import statistics
import time
import unicodedata
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from relic_api import (
    ALLOWED_RADAR_HOSTS,
    AUTOMATCH_MODES,
    BR_COMMUNITY_PATH_RE,
    BR_COMMUNITY_URL,
    CORE_BR_ROSTER,
    FACTION_SHORT,
    FALLBACK_RACES,
    MANUAL_OTHER_BR_DISPLAY,
    MAX_BR_COMMUNITY_BYTES,
    OFFICIAL_COH3_BATTLEGROUPS,
    STEAM_ID64_VALID_RE,
    TRACKER_USER_AGENT,
    clean_map_name,
)
from security import (
    build_no_redirect_https_opener,
    read_bounded_http_body,
    redact_secrets,
    strip_unsafe_chars,
    validate_https_endpoint,
)

logger = logging.getLogger("coh3_br.smurf_alert")

ALLOWED_STEAM_PROFILE_HOSTS: frozenset[str] = frozenset({"steamcommunity.com"})
STEAM_PROFILE_XML_PATH_RE = re.compile(r"^/profiles/7656119\d{10}$")
MAX_STEAM_XML_BYTES = 65_536
STEAM_DEFAULT_AVATAR_HASH = "fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb"

BRT_TZ = timezone(timedelta(hours=-3))
BRT_PRIME_HOURS: frozenset[int] = frozenset({18, 19, 20, 21, 22, 23, 0, 1, 2})

# Janelas de cache e orçamento de rede para não impactar a latência do ciclo de 5 min
SMURF_PROBE_CACHE_KEY = "smurf_probe_cache_v1"
SMURF_PROBE_TTL_SEC = 6 * 3600       # 6h para contas normais/suspeitas
VETERAN_CACHE_TTL_SEC = 7 * 86400    # 7 dias para contas veteranas consolidadas (>900 jogos)
MAX_LIVE_OPPONENT_PROBES_PER_CYCLE = 4
MAX_EXTRA_MAIN_PROBES_PER_OPPONENT = 3
CONSOLIDATED_VETERAN_MIN_MATCHES = 900

# Limiares calibrados pelos modelos reais BR confirmados
ATTRIBUTED_ALERT_MIN_PROB_PCT = 58
UNATTRIBUTED_BR_ALERT_MIN_SCORE_PCT = 68

_LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_CLAN_TAG_RE = re.compile(r"(?:\[([^\[\]]{2,10})\]|『([^『』]{1,8})』|\{([^{}]{2,10})\}|<([^<>]{2,10})>)")
_GENERIC_CLAN_TAGS: frozenset[str] = frozenset({"br", "pt", "us", "eu", "ru", "cn", "de", "uk", "fr", "ar", "cl", "uy"})
_BARCODE_NICK_RE = re.compile(r"^[il1|!]{4,}$", re.I)
_THROWAWAY_NICKS: frozenset[str] = frozenset(
    {"player", "user", "guest", "smurf", "alt", "test", "noname", "unknown", "none", "newbie", "noob"}
)
_PTBR_SLANG_TOKENS: frozenset[str] = frozenset(
    {
        "brasil", "brasileiro", "brasileira", "brazuca", "tupiniquim", "carioca", "paulista", "mineiro",
        "gaucho", "baiano", "nordeste", "sampa", "favela", "sertao", "flamengo", "corinthians", "palmeiras",
        "vasco", "gremio", "cruzeiro", "botafogo", "capivara", "caramelo", "feijoada", "caipirinha",
        "churrasco", "picanha", "coxinha", "brigadeiro", "pacoca", "farofa", "cachaca", "pastel",
        "geladeira", "cachorro", "zueira", "malandro", "parca", "truta", "bolsonaro", "lula", "moco",
        "velha", "duelista", "chacineiro", "sapoboi", "alface", "binho", "itaperuna", "divisao",
    }
)
_PTBR_PHRASE_PATTERNS: tuple[str, ...] = ("seu pai", "leite moco", "pao de queijo", "eh o ", "e o ", "do br", " br")
_PTBR_DIACRITICS_RE = re.compile(r"[çãõ]", re.I)
_STEAM_BR_LOCATION_RE = re.compile(
    r"\b(?:brazil|brasil|sao paulo|são paulo|rio de janeiro|belo horizonte|curitiba|porto alegre|"
    r"brasilia|brasília|salvador|fortaleza|recife|florianopolis|florianópolis|campinas|goiania|goiânia|"
    r"manaus|belem|belém|vitoria|vitória|minas gerais|parana|paraná|bahia|ceara|ceará|pernambuco|"
    r"santa catarina|rio grande do sul|espirito santo|espírito santo|mato grosso)\b",
    re.I,
)
_SMURF_LABEL_RE = re.compile(r"\(smurf\s*:\s*([^)]{2,48})\)", re.I)

# Mapeamento canônico de matchtype_id -> rótulo de modo
_MT_TO_MODE: dict[int, str] = {
    0: "Custom",
    1: "1v1",
    2: "2v2",
    3: "3v3",
    4: "4v4",
    20: "1v1",
    21: "2v2",
    22: "3v3",
    23: "4v4",
}

_MODE_STR_NORM: dict[str, str] = {
    "1v1": "1v1",
    "2v2": "2v2",
    "3v3": "3v3",
    "4v4": "4v4",
    "Team Games (3v3)": "3v3",
    "Team Games (4v4)": "4v4",
    "Custom": "Custom",
}

_FACTION_TEXT_TO_SHORT: dict[str, str] = {
    "us forces": "USF",
    "usf": "USF",
    "american": "USF",
    "british forces": "UKF",
    "ukf": "UKF",
    "british": "UKF",
    "wehrmacht": "Wehr",
    "wehr": "Wehr",
    "german": "Wehr",
    "afrikakorps": "DAK",
    "afrika korps": "DAK",
    "afrika_corps": "DAK",
    "dak": "DAK",
}
_BG_NAME_TO_OFFICIAL: dict[str, str] = {v.casefold(): v for v in OFFICIAL_COH3_BATTLEGROUPS.values()}

# Famílias de smurfs catalogadas (garante exclusão mútua mesmo sem baixar players_roster.json)
KNOWN_SMURF_MAIN_PIDS: dict[int, int] = {
    1333418: 79327,   # Charles Bronson -> Chacineiro
    1390350: 79327,   # TearsInTheRain -> Chacineiro
    1297821: 462597,  # General Winter (Smurf 1) -> General Winter
    1318162: 462597,  # General Winter (Smurf 2) -> General Winter
    1297853: 509690,  # Shadow -> Alekel
    1297804: 844225,  # Leite Moço -> 『V』SKOBADARK
    557890: 559962,   # gabe44arg -> Gabe
    1076221: 941524,  # Lucielle -> Colossus
    1423426: 1005730, # geladeira velha -> arc
    1487738: 1005730, # Državljan H -> arc
    1482961: 1005730, # Vog -> arc
    917917: 1005730,  # arc (CoH2 original) -> arc
    1160699: 1005730, # Bubebolos/Dingo -> arc
    918241: 1005730,  # Faint/Saffa -> arc
    720147: 448521,   # アリス -> icemaker
}

SA_COUNTRIES: frozenset[str] = frozenset(
    {"br", "ar", "cl", "uy", "py", "co", "pe", "ec", "bo", "ve", "gy", "sr"}
)
SA_LEADERBOARD_REGION_ID = 2074438


def _normalize_faction_short(race_or_name: Any) -> str:
    if isinstance(race_or_name, int):
        full = FALLBACK_RACES.get(race_or_name, "")
        return FACTION_SHORT.get(full, "")
    raw = str(race_or_name or "").strip()
    if not raw:
        return ""
    if raw.isdigit():
        full = FALLBACK_RACES.get(int(raw), "")
        return FACTION_SHORT.get(full, "")
    if raw in FACTION_SHORT:
        return FACTION_SHORT[raw]
    return _FACTION_TEXT_TO_SHORT.get(raw.casefold(), "")


def _normalize_bg_label(raw_key: str = "", raw_name: str = "") -> str:
    k = re.sub(r"_icon_mipped$", "", str(raw_key or "").strip().lower())
    k = re.sub(r"[^a-z0-9_]", "", k)
    if k in OFFICIAL_COH3_BATTLEGROUPS:
        return OFFICIAL_COH3_BATTLEGROUPS[k]
    n = strip_unsafe_chars(str(raw_name or "")).strip()
    if not n or n.casefold() in ("none", "n/a", "-", "unknown"):
        return ""
    return _BG_NAME_TO_OFFICIAL.get(n.casefold(), n[:40])


def _normalize_mode_label(mode_or_mt: Any) -> str:
    if isinstance(mode_or_mt, int):
        return _MT_TO_MODE.get(mode_or_mt, "")
    raw = str(mode_or_mt or "").strip()
    if raw in _MODE_STR_NORM:
        return _MODE_STR_NORM[raw]
    if raw.isdigit():
        return _MT_TO_MODE.get(int(raw), "")
    return ""


def _is_placeholder_alias(alias: str) -> bool:
    clean = strip_unsafe_chars(alias).strip()
    return (not clean) or clean.startswith("Player ") or clean.isdigit()


def _normalize_leetspeak(text: str) -> str:
    """Remove acentos, aplica substituição leetspeak (`0->o, 1->i, 3->e, 4->a, 5->s, 7->t`) e mantém alfanuméricos."""
    raw = strip_unsafe_chars(text).strip().lower()
    if not raw:
        return ""
    decomposed = unicodedata.normalize("NFKD", raw)
    no_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    de_leet = no_marks.translate(_LEET_TABLE)
    return re.sub(r"[^a-z0-9]+", "", de_leet)


def _trigram_similarity(a: str, b: str) -> float:
    na = _normalize_leetspeak(a)
    nb = _normalize_leetspeak(b)
    if len(na) < 4 or len(nb) < 4:
        return 0.0
    ga = {na[i : i + 3] for i in range(len(na) - 2)}
    gb = {nb[i : i + 3] for i in range(len(nb) - 2)}
    if not ga or not gb:
        return 0.0
    return len(ga & gb) / float(len(ga | gb))


def _extract_clan_tags(alias: str) -> set[str]:
    tags: set[str] = set()
    for m in _CLAN_TAG_RE.finditer(str(alias or "")):
        raw_tag = next((g for g in m.groups() if g), "").strip().casefold()
        if raw_tag and raw_tag not in _GENERIC_CLAN_TAGS:
            tags.add(raw_tag)
    return tags


def _detect_ptbr_linguistic_signal(alias: str) -> tuple[bool, str]:
    """Detecta sinais linguísticos/culturais PT-BR em nicks de contas disfarçadas."""
    clean = strip_unsafe_chars(alias).strip()
    if len(clean) < 3:
        return False, ""
    if _PTBR_DIACRITICS_RE.search(clean):
        return True, f"nick PT-BR ('{clean[:20]}')"
    decomposed = unicodedata.normalize("NFKD", clean.lower())
    plain = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    for phrase in _PTBR_PHRASE_PATTERNS:
        if phrase in plain:
            return True, f"expressão PT-BR ('{clean[:20]}')"
    tokens = set(re.findall(r"[a-z]{3,}", plain))
    hits = sorted(tokens & _PTBR_SLANG_TOKENS)
    if hits:
        return True, f"termo PT-BR ('{hits[0]}')"
    return False, ""


def _is_throwaway_or_barcode_nick(alias: str) -> bool:
    clean = strip_unsafe_chars(alias).strip()
    if not clean or len(clean) <= 2:
        return True
    alnum = re.sub(r"[^A-Za-z0-9]+", "", clean)
    if not alnum or len(alnum) <= 2 or alnum.isdigit():
        return True
    if _BARCODE_NICK_RE.fullmatch(clean):
        return True
    return alnum.lower() in _THROWAWAY_NICKS


def _steam_account32(steam_id: str) -> int:
    sid = str(steam_id or "").replace("/steam/", "").strip()
    if not STEAM_ID64_VALID_RE.fullmatch(sid):
        return 0
    val = int(sid) - 76561197960265728
    return val if val > 0 else 0


def _parse_counters_detailed(raw_counters: Any) -> dict[str, float]:
    """Extrai vetor biométrico multi-gênero (APM, abil/min, K/D, DPM, capturas/m, inatividade, trocas) da Relic."""
    if not raw_counters:
        return {}
    if isinstance(raw_counters, str):
        try:
            c = json.loads(raw_counters)
        except Exception:
            return {}
    elif isinstance(raw_counters, dict):
        c = raw_counters
    else:
        return {}
    if not isinstance(c, dict):
        return {}
    gt = float(c.get("gt", 0) or 0)
    if gt < 180.0:
        return {}

    out: dict[str, float] = {}
    cmds = float(c.get("totalcmds", 0) or 0)
    if cmds > 0.0:
        apm = cmds * 60.0 / gt
        if 10.0 <= apm <= 300.0:
            out["apm"] = apm
            abil = float(c.get("abil", 0) or 0)
            if abil >= 0.0:
                out["abil_pm"] = max(0.0, min(30.0, abil * 60.0 / gt))

    ek = float(c.get("ekills", 0) or 0)
    ed = float(c.get("edeaths", 0) or 0)
    if ek >= 0.0 and ed >= 0.0 and (ek + ed) >= 10.0:
        out["kd"] = min(10.0, ek / max(1.0, ed))

    dmg = float(c.get("dmgdone", 0) or 0)
    if dmg > 0.0:
        out["dpm"] = min(2500.0, dmg * 60.0 / gt)

    pcap = float(c.get("pcap", 0) or 0)
    if pcap >= 0.0:
        out["pcap_pm"] = min(10.0, pcap * 60.0 / gt)

    inact = float(c.get("inactperiod", 0) or 0)
    if 0.0 <= inact <= gt:
        out["inact_ratio"] = min(0.5, inact / gt)

    sqk = float(c.get("sqkill", 0) or 0)
    sql = float(c.get("sqlost", 0) or 0)
    if sqk >= 0.0 and sql >= 0.0 and (sqk + sql) >= 1.0:
        out["sq_trade"] = min(12.0, (sqk + 1.0) / (sql + 1.0))

    return out


def _extract_bg_loadout_by_pid(match_items: Any) -> dict[int, list[int]]:
    if not isinstance(match_items, list) or not match_items:
        return {}
    out: dict[int, list[int]] = defaultdict(list)
    for item in match_items:
        if not isinstance(item, dict):
            continue
        pid = int(item.get("profile_id", 0) or 0)
        idef = int(item.get("itemdefinition_id", 0) or 0)
        if pid <= 0 or idef <= 0:
            continue
        raw_meta = item.get("metadata")
        if not raw_meta:
            continue
        if isinstance(raw_meta, str):
            if '"eslot"' not in raw_meta:
                continue
            try:
                meta = json.loads(raw_meta)
            except Exception:
                continue
        elif isinstance(raw_meta, dict):
            meta = raw_meta
        else:
            continue
        if str(meta.get("eslot", "")) in ("0", "1", "2"):
            out[pid].append(idef)
    return dict(out)


def _extract_cosmetic_items_by_pid(match_items: Any) -> dict[int, set[int]]:
    if not isinstance(match_items, list) or not match_items:
        return {}
    out: dict[int, set[int]] = defaultdict(set)
    for item in match_items:
        if not isinstance(item, dict):
            continue
        pid = int(item.get("profile_id", 0) or 0)
        idef = int(item.get("itemdefinition_id", 0) or 0)
        if pid <= 0 or idef <= 0:
            continue
        raw_meta = item.get("metadata")
        if not raw_meta:
            continue
        if isinstance(raw_meta, str):
            if '"eslot"' not in raw_meta:
                continue
            if '"eslot":"0"' in raw_meta or '"eslot":"1"' in raw_meta or '"eslot":"2"' in raw_meta:
                continue
            out[pid].add(idef)
        elif isinstance(raw_meta, dict):
            eslot = str(raw_meta.get("eslot", ""))
            if eslot and eslot not in ("0", "1", "2"):
                out[pid].add(idef)
    return dict(out)


class SteamProfileOSINTClient:
    """
    Cliente HTTPS endurecido (somente-leitura, zero API key, anti-redirect, teto 64 KB XML / 256 KB HTML)
    para o XML público `https://steamcommunity.com/profiles/<steam_id>?xml=1` e sinais de Steam Family Sharing.
    """

    _PRIVACY_RE = re.compile(r"<privacyState>([^<]{1,32})</privacyState>", re.I)
    _LIMITED_RE = re.compile(r"<isLimitedAccount>\s*([01])\s*</isLimitedAccount>", re.I)
    _MEMBER_SINCE_RAW_RE = re.compile(r"<memberSince>([^<]{1,40})</memberSince>", re.I)
    _YEAR_4_RE = re.compile(r"\b(20\d{2})\b")
    _MONTH_DAY_RE = re.compile(
        r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}\b",
        re.I,
    )
    _CUSTOM_URL_RE = re.compile(r"<customURL>(?:<!\[CDATA\[)?([^<\]]{0,80})(?:\]\]>)?</customURL>", re.I)
    _LOCATION_RE = re.compile(r"<location>(?:<!\[CDATA\[)?([^<\]]{1,120})(?:\]\]>)?</location>", re.I)
    _AVATAR_RE = re.compile(r"<avatarMedium>(?:<!\[CDATA\[)?(https://[^\s<\]]+)(?:\]\]>)?</avatarMedium>", re.I)
    _AVATAR_HASH_RE = re.compile(r"/([0-9a-f]{40})(?:_medium|_full)?\.(?:jpg|jpeg|png|webp)$", re.I)
    _PROFILE_HTML_PATH_RE = re.compile(r"^/profiles/7656119\d{10}/?$")
    _HTML_LEVEL_RE = re.compile(r'class="friendPlayerLevelNum">(\d{1,4})</span>', re.I)
    _HTML_FRIENDS_RE = re.compile(
        r'href="https://steamcommunity\.com/[^"]+/friends/"[^>]*>.*?<span class="profile_count_link_total">\s*([\d,]+)\s*</span>',
        re.I | re.S,
    )
    _HTML_BADGES_RE = re.compile(
        r'href="https://steamcommunity\.com/[^"]+/badges/"[^>]*>.*?<span class="profile_count_link_total">\s*([\d,]+)\s*</span>',
        re.I | re.S,
    )

    def __init__(
        self,
        *,
        pace_delay_sec: float = 0.08,
        allow_network: bool = True,
        fetch_public_html: bool = True,
    ) -> None:
        self.pace_delay_sec = max(0.0, float(pace_delay_sec))
        self.allow_network = bool(allow_network)
        self.fetch_public_html = bool(fetch_public_html)
        self._opener = build_no_redirect_https_opener()
        self._cache: dict[str, dict[str, Any]] = {}
        self._consecutive_errors = 0
        self._circuit_open = False

    @classmethod
    def parse_profile_xml(cls, xml_body: str, *, current_year: int | None = None) -> dict[str, Any]:
        body = str(xml_body or "")
        cur_yr = int(current_year) if current_year is not None else datetime.now(tz=timezone.utc).year
        priv_m = cls._PRIVACY_RE.search(body)
        privacy = priv_m.group(1).strip().lower() if priv_m else ""
        lim_m = cls._LIMITED_RE.search(body)
        is_limited = bool(lim_m and lim_m.group(1) == "1")

        ms_m = cls._MEMBER_SINCE_RAW_RE.search(body)
        member_since_raw = strip_unsafe_chars(ms_m.group(1))[:40] if ms_m else ""
        member_year = 0
        member_since_current_year = False
        if member_since_raw:
            yr_m = cls._YEAR_4_RE.search(member_since_raw)
            if yr_m:
                member_year = int(yr_m.group(1))
                member_since_current_year = member_year == cur_yr
            elif cls._MONTH_DAY_RE.search(member_since_raw):
                # Steam omite o ano em <memberSince> (ex.: "May 25", "March 23") quando a conta foi criada neste mesmo ano
                member_year = cur_yr
                member_since_current_year = True

        cu_m = cls._CUSTOM_URL_RE.search(body)
        custom_url = strip_unsafe_chars(cu_m.group(1))[:64] if cu_m else ""
        loc_m = cls._LOCATION_RE.search(body)
        location = strip_unsafe_chars(loc_m.group(1))[:80] if loc_m else ""
        is_br_loc = bool(location and _STEAM_BR_LOCATION_RE.search(location))
        av_m = cls._AVATAR_RE.search(body)
        av_hash = ""
        if av_m:
            hm = cls._AVATAR_HASH_RE.search(av_m.group(1).strip())
            if hm:
                av_hash = hm.group(1).lower()
        return {
            "ok": bool(privacy or av_hash or member_year or is_limited),
            "privacy_state": privacy,
            "is_private": bool(privacy and privacy != "public"),
            "is_limited_account": is_limited,
            "member_since_raw": member_since_raw,
            "member_since_year": member_year,
            "member_since_current_year": member_since_current_year,
            "custom_url": custom_url,
            "location": location,
            "is_br_location": is_br_loc,
            "avatar_hash": av_hash,
            "is_default_avatar": bool(av_hash == STEAM_DEFAULT_AVATAR_HASH),
            "steam_level": -1,
            "friends_count": -1,
            "badges_count": -1,
        }

    @classmethod
    def parse_profile_html_footprint(cls, html_body: str) -> dict[str, int]:
        """Extrai pegada burner/Family Sharing do HTML público (`steam_level`, `friends_count`, `badges_count`)."""
        body = str(html_body or "")
        out = {"steam_level": -1, "friends_count": -1, "badges_count": -1}
        if not body or "profile_private_info" in body:
            return out
        for key, rx in (
            ("steam_level", cls._HTML_LEVEL_RE),
            ("friends_count", cls._HTML_FRIENDS_RE),
            ("badges_count", cls._HTML_BADGES_RE),
        ):
            m = rx.search(body)
            if m:
                try:
                    out[key] = int(m.group(1).replace(",", ""))
                except ValueError:
                    pass
        return out

    def fetch_profile_osint(self, steam_id: str) -> dict[str, Any]:
        sid = str(steam_id or "").replace("/steam/", "").strip()
        if not self.allow_network or not STEAM_ID64_VALID_RE.fullmatch(sid) or self._circuit_open:
            return {}
        if sid in self._cache:
            return dict(self._cache[sid])
        url = f"https://steamcommunity.com/profiles/{sid}?xml=1"
        validate_https_endpoint(
            url,
            ALLOWED_STEAM_PROFILE_HOSTS,
            path_prefix="/profiles/",
            path_regex=STEAM_PROFILE_XML_PATH_RE,
            allow_query=True,
        )
        if self.pace_delay_sec > 0:
            time.sleep(self.pace_delay_sec)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": TRACKER_USER_AGENT,
                "Accept": "application/xml,text/xml",
                "Accept-Encoding": "gzip",
            },
            method="GET",
        )
        try:
            with self._opener.open(req, timeout=6) as resp:
                raw = read_bounded_http_body(resp, MAX_STEAM_XML_BYTES)
            self._consecutive_errors = 0
            parsed = self.parse_profile_xml(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            self._consecutive_errors += 1
            if self._consecutive_errors >= 3:
                self._circuit_open = True
                logger.debug("[SMURF ALERT] Circuit-breaker Steam OSINT ativado: %s", redact_secrets(exc))
            self._cache[sid] = {}
            return {}

        if self.fetch_public_html and parsed.get("privacy_state") == "public" and not parsed.get("custom_url"):
            html_url = f"https://steamcommunity.com/profiles/{sid}/"
            try:
                validate_https_endpoint(
                    html_url,
                    ALLOWED_STEAM_PROFILE_HOSTS,
                    path_prefix="/profiles/",
                    path_regex=self._PROFILE_HTML_PATH_RE,
                    allow_query=False,
                )
                hreq = urllib.request.Request(
                    html_url,
                    headers={
                        "User-Agent": TRACKER_USER_AGENT,
                        "Accept": "text/html",
                        "Accept-Encoding": "gzip",
                    },
                    method="GET",
                )
                with self._opener.open(hreq, timeout=6) as hresp:
                    hraw = read_bounded_http_body(hresp, 262_144)
                parsed.update(self.parse_profile_html_footprint(hraw.decode("utf-8", errors="replace")))
            except Exception:
                pass

        self._cache[sid] = parsed
        return dict(parsed)


@dataclass
class PlayerTelemetry:
    """Telemetria forense multi-gênero compacta de um jogador (Relic raw JSON + histórico SQLite)."""

    profile_id: int
    steam_id: str = ""
    alias: str = ""
    country: str = ""
    games: int = 0
    wins: int = 0
    mode_counts: Counter[str] = field(default_factory=Counter)
    mode_faction_counts: Counter[tuple[str, int]] = field(default_factory=Counter)
    mode_elo_max: dict[str, int] = field(default_factory=dict)
    hour_counts: Counter[int] = field(default_factory=Counter)
    brt_hour_counts: Counter[int] = field(default_factory=Counter)
    weekday_counts: Counter[int] = field(default_factory=Counter)
    active_brt_days: set[str] = field(default_factory=set)
    ally_counts: Counter[int] = field(default_factory=Counter)
    co_played_with: set[int] = field(default_factory=set)
    intervals: list[tuple[int, int]] = field(default_factory=list)
    seen_aliases: set[str] = field(default_factory=set)
    seen_match_ids: set[int] = field(default_factory=set)
    apm_values: list[float] = field(default_factory=list)
    apm_by_mode: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    abil_per_min: list[float] = field(default_factory=list)
    bg_loadout_by_race: dict[int, Counter[int]] = field(default_factory=lambda: defaultdict(Counter))
    kd_ratios: list[float] = field(default_factory=list)
    dpm_values: list[float] = field(default_factory=list)
    capture_rates: list[float] = field(default_factory=list)
    inactivity_ratios: list[float] = field(default_factory=list)
    squad_trade_ratios: list[float] = field(default_factory=list)
    loss_durations_sec: list[int] = field(default_factory=list)
    elo_history: list[tuple[int, int, int, int]] = field(default_factory=list)
    early_loss_count: int = 0
    long_game_count: int = 0
    long_game_wins: int = 0
    equipped_cosmetic_ids: set[int] = field(default_factory=set)
    # Matchmaking regional/ping Relic: frequência de confrontos/encontros com outros jogadores BR/SA em Automatch
    regional_observed_games: int = 0
    br_match_count: int = 0
    sa_match_count: int = 0
    br_opp_match_count: int = 0
    distinct_br_sa_opps: set[int] = field(default_factory=set)
    # Perfil de Nêmesis, Freguês & Criptonitas / Facilidades (Automatch 1v1..4v4 + histórico SQLite 2023+)
    opp_wl: dict[int, list[int]] = field(default_factory=dict)  # opp_pid -> [wins, losses]
    opp_days: dict[int, set[int]] = field(default_factory=dict)  # opp_pid -> {utc_day, ...}
    ally_wl: dict[int, list[int]] = field(default_factory=dict)  # ally_pid -> [wins, losses]
    map_wl: dict[str, list[int]] = field(default_factory=dict)  # clean_map -> [wins, losses]
    my_faction_wl: dict[str, list[int]] = field(default_factory=dict)
    enemy_faction_wl: dict[str, list[int]] = field(default_factory=dict)
    matchup_wl: dict[tuple[str, str], list[int]] = field(default_factory=dict)
    enemy_bg_wl: dict[str, list[int]] = field(default_factory=dict)
    _seen_opp_mids: set[int] = field(default_factory=set)

    def winrate(self) -> float:
        return (self.wins / float(self.games)) if self.games > 0 else 0.0

    def record_match_outcome_profile(
        self,
        *,
        won: bool,
        ct: int,
        match_id: int = 0,
        my_faction: Any = -1,
        map_name: str = "",
        enemy_pids: list[int] | None = None,
        enemy_factions: list[Any] | None = None,
        ally_pids: list[int] | None = None,
        enemy_bgs: list[str] | None = None,
    ) -> None:
        """Registra resultados por adversário, mapa, facção/matchup, aliado e BG inimigo para perfil Nêmesis/Freguês/Criptonitas."""
        idx = 0 if won else 1
        utc_day = int(ct or 0) // 86400 if int(ct or 0) > 0 else 0
        mid_i = int(match_id or 0)

        if enemy_pids and (mid_i <= 0 or mid_i not in self._seen_opp_mids):
            if mid_i > 0:
                self._seen_opp_mids.add(mid_i)
            for op_pid in dict.fromkeys(int(p) for p in enemy_pids if int(p or 0) > 0 and int(p) != self.profile_id):
                if op_pid in self.opp_wl or len(self.opp_wl) < 4000:
                    rec = self.opp_wl.setdefault(op_pid, [0, 0])
                    rec[idx] += 1
                    if utc_day > 0:
                        days = self.opp_days.setdefault(op_pid, set())
                        if len(days) < 30:
                            days.add(utc_day)

        if ally_pids:
            for ap_pid in dict.fromkeys(int(p) for p in ally_pids if int(p or 0) > 0 and int(p) != self.profile_id):
                if ap_pid in self.ally_wl or len(self.ally_wl) < 2000:
                    rec = self.ally_wl.setdefault(ap_pid, [0, 0])
                    rec[idx] += 1

        clean_map = clean_map_name(map_name) if str(map_name or "").strip() else ""
        if clean_map and clean_map != "Mapa Desconhecido":
            if clean_map in self.map_wl or len(self.map_wl) < 200:
                rec = self.map_wl.setdefault(clean_map, [0, 0])
                rec[idx] += 1

        my_fac = _normalize_faction_short(my_faction)
        if my_fac:
            rec = self.my_faction_wl.setdefault(my_fac, [0, 0])
            rec[idx] += 1

        if enemy_factions:
            efac_set = {ef for ef in (_normalize_faction_short(x) for x in enemy_factions) if ef}
            for efac in efac_set:
                rec = self.enemy_faction_wl.setdefault(efac, [0, 0])
                rec[idx] += 1
                if my_fac:
                    mrec = self.matchup_wl.setdefault((my_fac, efac), [0, 0])
                    mrec[idx] += 1

        if enemy_bgs:
            for raw_bg in dict.fromkeys(str(b or "").strip() for b in enemy_bgs if str(b or "").strip()):
                lbl = _normalize_bg_label(raw_key=raw_bg, raw_name=raw_bg)
                if lbl and (lbl in self.enemy_bg_wl or len(self.enemy_bg_wl) < 60):
                    rec = self.enemy_bg_wl.setdefault(lbl, [0, 0])
                    rec[idx] += 1

    def median_apm(self, min_samples: int = 3) -> float:
        return float(statistics.median(self.apm_values)) if len(self.apm_values) >= min_samples else 0.0

    def median_apm_for_mode(self, mode: str, min_samples: int = 3) -> float:
        vals = self.apm_by_mode.get(mode) or []
        return float(statistics.median(vals)) if len(vals) >= min_samples else 0.0

    def median_abil_per_min(self, min_samples: int = 3) -> float:
        return float(statistics.median(self.abil_per_min)) if len(self.abil_per_min) >= min_samples else 0.0

    def brt_prime_ratio(self) -> float:
        tot = sum(self.brt_hour_counts.values())
        if tot <= 0:
            return 0.0
        return sum(self.brt_hour_counts[h] for h in BRT_PRIME_HOURS) / float(tot)

    def br_match_rate(self) -> float:
        return (self.br_match_count / float(self.regional_observed_games)) if self.regional_observed_games > 0 else 0.0

    def sa_match_rate(self) -> float:
        return (self.sa_match_count / float(self.regional_observed_games)) if self.regional_observed_games > 0 else 0.0

    def br_opp_match_rate(self) -> float:
        return (self.br_opp_match_count / float(self.regional_observed_games)) if self.regional_observed_games > 0 else 0.0

    def observe_raw_relic_history(
        self,
        raw_payload: dict[str, Any] | None,
        *,
        known_br_pids: set[int] | frozenset[int] | None = None,
        pid_aliases: dict[int, str] | None = None,
    ) -> None:
        if not isinstance(raw_payload, dict):
            return
        br_set = known_br_pids or frozenset()
        profiles_by_id: dict[int, dict[str, Any]] = {}
        for pr in raw_payload.get("profiles") or []:
            if not isinstance(pr, dict):
                continue
            pid = int(pr.get("profile_id", 0) or 0)
            if pid > 0:
                profiles_by_id[pid] = pr
                if pid_aliases is not None:
                    pal = strip_unsafe_chars(pr.get("alias") or "")[:40]
                    if pal and not _is_placeholder_alias(pal):
                        pid_aliases[pid] = pal
        me_pr = profiles_by_id.get(self.profile_id)
        if me_pr:
            al = strip_unsafe_chars(me_pr.get("alias") or "")[:40]
            if al and not _is_placeholder_alias(al):
                self.alias = self.alias or al
                self.seen_aliases.add(al)
            ctry = str(me_pr.get("country") or "").strip().lower()
            if ctry and not self.country:
                self.country = ctry
            raw_name = str(me_pr.get("name") or "").strip()
            if raw_name.startswith("/steam/"):
                sid = raw_name.replace("/steam/", "").strip()
                if STEAM_ID64_VALID_RE.fullmatch(sid) and not self.steam_id:
                    self.steam_id = sid

        for m in raw_payload.get("matchHistoryStats") or []:
            if not isinstance(m, dict):
                continue
            mid = int(m.get("id", 0) or 0)
            if mid > 0 and mid in self.seen_match_ids:
                continue
            mt_id = int(m.get("matchtype_id", -1) or -1)
            mode = _MT_TO_MODE.get(mt_id, "")
            if not mode:
                continue
            reports = m.get("matchhistoryreportresults") or []
            if not isinstance(reports, list) or len(reports) < 2:
                continue

            me_rep = None
            by_team: dict[int, list[int]] = defaultdict(list)
            all_pids: list[int] = []
            pid_teams: list[tuple[int, int]] = []
            pid_team_races: list[tuple[int, int, int]] = []
            for rep in reports:
                if not isinstance(rep, dict):
                    continue
                rpid = int(rep.get("profile_id", 0) or 0)
                if rpid <= 0:
                    continue
                all_pids.append(rpid)
                raw_tid = rep.get("teamid")
                tid = int(raw_tid) if raw_tid is not None else -1
                rrace = int(rep.get("race_id", -1) if rep.get("race_id") is not None else -1)
                pid_teams.append((rpid, tid))
                pid_team_races.append((rpid, tid, rrace))
                if tid >= 0:
                    by_team[tid].append(rpid)
                if rpid == self.profile_id:
                    me_rep = rep
            if me_rep is None:
                continue

            if mid > 0:
                self.seen_match_ids.add(mid)
            ct = int(m.get("completiontime", 0) or 0)
            st = int(m.get("startgametime", 0) or 0)
            if ct <= 0 and st <= 0:
                continue
            if st <= 0 or st > ct:
                st = max(1, ct - 1200) if ct > 0 else st
            if ct <= 0:
                ct = st + 1200
            dur = max(0, ct - st)

            self.intervals.append((st, ct))
            self.games += 1
            won = int(me_rep.get("resulttype", 0) or 0) == 1
            if won:
                self.wins += 1
            dt_utc = datetime.fromtimestamp(ct, tz=timezone.utc)
            dt_brt = dt_utc.astimezone(BRT_TZ)
            self.hour_counts[dt_utc.hour] += 1
            self.brt_hour_counts[dt_brt.hour] += 1
            self.weekday_counts[dt_brt.weekday()] += 1
            self.active_brt_days.add(dt_brt.strftime("%Y-%m-%d"))

            for opid in all_pids:
                if opid != self.profile_id:
                    self.co_played_with.add(opid)
            raw_my_tid = me_rep.get("teamid")
            my_tid = int(raw_my_tid) if raw_my_tid is not None else -1
            for apid in by_team.get(my_tid, []):
                if apid != self.profile_id:
                    self.ally_counts[apid] += 1

            race_id = int(me_rep.get("race_id", -1) or -1)
            is_automatch = mode in ("1v1", "2v2", "3v3", "4v4")
            if is_automatch:
                self.mode_counts[mode] += 1
                if race_id >= 0:
                    self.mode_faction_counts[(mode, race_id)] += 1
                enemy_pids_m: list[int] = []
                ally_pids_m: list[int] = []
                enemy_races_m: list[int] = []
                for rpid, rtid, rrace in pid_team_races:
                    if rpid <= 0 or rpid == self.profile_id:
                        continue
                    if my_tid >= 0 and rtid == my_tid:
                        ally_pids_m.append(rpid)
                    elif my_tid >= 0 and rtid >= 0 and rtid != my_tid:
                        enemy_pids_m.append(rpid)
                        if rrace >= 0:
                            enemy_races_m.append(rrace)
                self.record_match_outcome_profile(
                    won=won,
                    ct=ct,
                    match_id=mid,
                    my_faction=race_id,
                    map_name=str(m.get("mapname") or ""),
                    enemy_pids=enemy_pids_m,
                    enemy_factions=enemy_races_m,
                    ally_pids=ally_pids_m,
                )
                observed_other = False
                has_br_other = False
                has_sa_other = False
                has_br_sa_opp = False
                for opid, optid in pid_teams:
                    if opid <= 0 or opid == self.profile_id:
                        continue
                    opr = profiles_by_id.get(opid)
                    octry = str((opr or {}).get("country") or "").strip().lower()
                    oreg = int((opr or {}).get("leaderboardregion_id", 0) or 0)
                    oknown_br = opid in br_set
                    if octry or oreg > 0 or oknown_br:
                        observed_other = True
                    is_br = (octry == "br") or oknown_br
                    is_sa = is_br or (octry in SA_COUNTRIES) or (oreg == SA_LEADERBOARD_REGION_ID)
                    if is_br:
                        has_br_other = True
                    if is_sa:
                        has_sa_other = True
                        if my_tid >= 0 and optid >= 0 and optid != my_tid:
                            has_br_sa_opp = True
                            if len(self.distinct_br_sa_opps) < 200:
                                self.distinct_br_sa_opps.add(opid)
                if observed_other:
                    self.regional_observed_games += 1
                    if has_br_other:
                        self.br_match_count += 1
                    if has_sa_other:
                        self.sa_match_count += 1
                    if has_br_sa_opp:
                        self.br_opp_match_count += 1
                # Busca oldrating/newrating em matchhistorymember
                old_r, new_r = 0, 0
                for mem in m.get("matchhistorymember") or []:
                    if isinstance(mem, dict) and int(mem.get("profile_id", 0) or 0) == self.profile_id:
                        old_r = int(mem.get("oldrating", 0) or 0)
                        new_r = int(mem.get("newrating", 0) or 0)
                        break
                eff_elo = max(old_r, new_r)
                if eff_elo > int(self.mode_elo_max.get(mode, 0) or 0):
                    self.mode_elo_max[mode] = eff_elo
                self.elo_history.append((ct, 1 if won else 0, old_r, new_r))
                if not won and 15 <= dur < 240:
                    self.early_loss_count += 1
                elif dur >= 480:
                    self.long_game_count += 1
                    if won:
                        self.long_game_wins += 1
                if not won and dur >= 240 and len(self.loss_durations_sec) < 120:
                    self.loss_durations_sec.append(dur)

            det = _parse_counters_detailed(me_rep.get("counters"))
            if det:
                apm = det.get("apm", 0.0)
                if apm > 0.0 and len(self.apm_values) < 120:
                    self.apm_values.append(apm)
                    if is_automatch and len(self.apm_by_mode[mode]) < 120:
                        self.apm_by_mode[mode].append(apm)
                    abil = det.get("abil_pm", 0.0)
                    if abil > 0.0 and len(self.abil_per_min) < 120:
                        self.abil_per_min.append(abil)
                for key, dest in (
                    ("kd", self.kd_ratios),
                    ("dpm", self.dpm_values),
                    ("pcap_pm", self.capture_rates),
                    ("inact_ratio", self.inactivity_ratios),
                    ("sq_trade", self.squad_trade_ratios),
                ):
                    val = det.get(key)
                    if val is not None and len(dest) < 120:
                        dest.append(float(val))

            items = m.get("matchhistoryitems") or []
            bg_l = _extract_bg_loadout_by_pid(items).get(self.profile_id)
            if race_id >= 0 and bg_l:
                rc = self.bg_loadout_by_race[race_id]
                for idef in bg_l:
                    rc[idef] += 1
            cos = _extract_cosmetic_items_by_pid(items).get(self.profile_id)
            if cos and len(self.equipped_cosmetic_ids) < 500:
                self.equipped_cosmetic_ids.update(cos)

    def observe_sqlite_match_row(
        self,
        row: dict[str, Any],
        *,
        pid_aliases: dict[int, str] | None = None,
    ) -> None:
        """Complementa intervalos/aliados/horários/ELO/Nêmesis/Criptonitas a partir de `recorded_matches` no SQLite (sem duplicar match_id)."""
        mid = int(row.get("match_id", 0) or 0)
        if mid > 0 and mid in self.seen_match_ids:
            return
        ct = int(row.get("completion_time", 0) or 0)
        st = int(row.get("start_time", 0) or 0)
        if ct <= 0:
            return
        if st <= 0 or st > ct:
            st = max(1, ct - max(60, int(row.get("duration_sec", 900) or 900)))
        if mid > 0:
            self.seen_match_ids.add(mid)
        self.intervals.append((st, ct))
        self.games += 1
        won = bool(row.get("win"))
        if won:
            self.wins += 1
        dt_utc = datetime.fromtimestamp(ct, tz=timezone.utc)
        dt_brt = dt_utc.astimezone(BRT_TZ)
        self.hour_counts[dt_utc.hour] += 1
        self.brt_hour_counts[dt_brt.hour] += 1
        self.weekday_counts[dt_brt.weekday()] += 1
        self.active_brt_days.add(dt_brt.strftime("%Y-%m-%d"))

        ally_pids: list[int] = []
        for al in row.get("allies") or []:
            if isinstance(al, dict):
                apid = int(al.get("profile_id", 0) or 0)
                if apid > 0 and apid != self.profile_id:
                    self.ally_counts[apid] += 1
                    self.co_played_with.add(apid)
                    ally_pids.append(apid)
                    if pid_aliases is not None:
                        aal = strip_unsafe_chars(al.get("alias") or "")[:40]
                        if aal and not _is_placeholder_alias(aal):
                            pid_aliases[apid] = aal

        enemy_pids: list[int] = []
        enemy_facs: list[Any] = []
        enemy_bgs: list[str] = []
        bgs_map = row.get("battlegroups") if isinstance(row.get("battlegroups"), dict) else {}
        for op in row.get("opponents") or []:
            if isinstance(op, dict):
                opid = int(op.get("profile_id", 0) or 0)
                if opid > 0 and opid != self.profile_id:
                    self.co_played_with.add(opid)
                    enemy_pids.append(opid)
                    if pid_aliases is not None:
                        oal = strip_unsafe_chars(op.get("alias") or "")[:40]
                        if oal and not _is_placeholder_alias(oal):
                            pid_aliases[opid] = oal
                    ef = op.get("faction") or op.get("race_id")
                    if ef:
                        enemy_facs.append(ef)
                    bg_entry = bgs_map.get(str(opid)) or bgs_map.get(opid)
                    if isinstance(bg_entry, dict):
                        eb = str(bg_entry.get("key") or bg_entry.get("name") or "").strip()
                        if eb:
                            enemy_bgs.append(eb)

        mode = _normalize_mode_label(row.get("mode") or row.get("matchtype_id"))
        if mode in ("1v1", "2v2", "3v3", "4v4"):
            self.mode_counts[mode] += 1
            old_r = int(row.get("old_elo") or 0)
            new_r = int(row.get("new_elo") or 0)
            eff = max(old_r, new_r)
            if eff > int(self.mode_elo_max.get(mode, 0) or 0):
                self.mode_elo_max[mode] = eff
            dur = max(0, ct - st)
            if not won and dur >= 240 and len(self.loss_durations_sec) < 120:
                self.loss_durations_sec.append(dur)
            self.record_match_outcome_profile(
                won=won,
                ct=ct,
                match_id=mid,
                my_faction=row.get("faction") or row.get("race_id") or "",
                map_name=str(row.get("map_clean") or row.get("map_raw") or ""),
                enemy_pids=enemy_pids,
                enemy_factions=enemy_facs,
                ally_pids=ally_pids,
                enemy_bgs=enemy_bgs,
            )


def _cosine_similarity(c1: Counter[Any], c2: Counter[Any]) -> float:
    if not c1 or not c2:
        return 0.0
    common = set(c1.keys()) & set(c2.keys())
    if not common:
        return 0.0
    dot = sum(float(c1[k]) * float(c2[k]) for k in common)
    n1 = math.sqrt(sum(float(v) * float(v) for v in c1.values()))
    n2 = math.sqrt(sum(float(v) * float(v) for v in c2.values()))
    return (dot / (n1 * n2)) if (n1 > 0.0 and n2 > 0.0) else 0.0


def _check_overlap_and_handoffs(
    intervals_a: list[tuple[int, int]],
    intervals_b: list[tuple[int, int]],
    *,
    overlap_margin_sec: int = 120,
    handoff_max_gap_sec: int = 1500,
) -> tuple[bool, int]:
    """Detecta sobreposição simultânea (desqualificador absoluto) e trocas rápidas (<=25 min sem sobrepor)."""
    if not intervals_a or not intervals_b:
        return False, 0
    sa = sorted(intervals_a)
    sb = sorted(intervals_b)
    i, j = 0, 0
    while i < len(sa) and j < len(sb):
        a0, a1 = sa[i]
        b0, b1 = sb[j]
        ov = min(a1, b1) - max(a0, b0)
        if ov >= overlap_margin_sec:
            return True, 0
        if a1 < b1:
            i += 1
        else:
            j += 1

    tagged = [(s, e, 0) for s, e in sa] + [(s, e, 1) for s, e in sb]
    tagged.sort(key=lambda x: (x[0], x[1]))
    handoffs = 0
    for idx in range(len(tagged) - 1):
        _s1, e1, who1 = tagged[idx]
        s2, _e2, who2 = tagged[idx + 1]
        if who1 != who2:
            gap = s2 - e1
            if -60 <= gap <= handoff_max_gap_sec:
                handoffs += 1
    return False, handoffs


def _alias_similarity_bonus(
    cand_alias: str,
    main_alias: str,
    cand_seen: set[str],
    main_seen: set[str],
) -> tuple[int, str]:
    c_raw = {a.strip() for a in ({cand_alias} | set(cand_seen)) if len(a.strip()) >= 3 and not _is_placeholder_alias(a)}
    m_raw = {a.strip() for a in ({main_alias} | set(main_seen)) if len(a.strip()) >= 3 and not _is_placeholder_alias(a)}
    if not c_raw or not m_raw:
        return 0, ""

    c_cf = {a.casefold() for a in c_raw}
    m_cf = {a.casefold() for a in m_raw}
    if c_cf & m_cf:
        return 22, "Nick idêntico"

    c_leet = {_normalize_leetspeak(a): a for a in c_raw if len(_normalize_leetspeak(a)) >= 4}
    m_leet = {_normalize_leetspeak(a): a for a in m_raw if len(_normalize_leetspeak(a)) >= 4}
    if set(c_leet.keys()) & set(m_leet.keys()):
        return 18, "Nick leetspeak"

    for ca in c_cf:
        for ma in m_cf:
            if len(ca) >= 5 and len(ma) >= 5 and (ca in ma or ma in ca):
                return 10, "Nick similar"

    best_tri = 0.0
    for ca in c_raw:
        for ma in m_raw:
            sim = _trigram_similarity(ca, ma)
            if sim > best_tri:
                best_tri = sim
    if best_tri >= 0.55:
        return 10, f"Nick {best_tri * 100:.0f}% similar"

    c_tags = {t for a in c_raw for t in _extract_clan_tags(a)}
    m_tags = {t for a in m_raw for t in _extract_clan_tags(a)}
    shared_tags = sorted(c_tags & m_tags)
    if shared_tags:
        return 10, f"Clã '{shared_tags[0]}'"

    return 0, ""


def _analyze_skill_velocity_and_tanking(
    cand_tel: PlayerTelemetry | None,
    cand_meta: dict[str, Any],
) -> dict[str, Any]:
    res: dict[str, Any] = {
        "net_elo_gain": 0,
        "elo_gain_per_game": 0.0,
        "rated_games_counted": 0,
        "max_win_streak": 0,
        "sandbagging": False,
        "multi_mode_transfer": False,
        "high_elo_modes": [],
        "barebones_cosmetics": False,
        "cosmetics_count": 0,
        "velocity_pts": 0.0,
        "strong_velocity": False,
        "chips": [],
    }
    if not cand_tel:
        return res

    cand_elo = int(cand_meta.get("max_elo", 0) or 0)
    cand_total = max(0, int(cand_meta.get("total_matches", 0) or 0))
    chrono = sorted(cand_tel.elo_history, key=lambda x: x[0])
    net_elo = 0
    rated_cnt = 0
    max_streak = 0
    cur_streak = 0
    for _ct, win01, old_r, new_r in chrono:
        if win01:
            cur_streak += 1
            if cur_streak > max_streak:
                max_streak = cur_streak
        else:
            cur_streak = 0
        if old_r > 0 and new_r > 0:
            delta = new_r - old_r
            if -80 <= delta <= 80:
                net_elo += delta
                rated_cnt += 1

    epg = round(net_elo / float(rated_cnt), 2) if rated_cnt > 0 else 0.0
    res["net_elo_gain"] = net_elo
    res["elo_gain_per_game"] = epg
    res["rated_games_counted"] = rated_cnt
    res["max_win_streak"] = max_streak

    pts = 0.0
    chips: list[str] = []
    if rated_cnt >= 5 and epg >= 12.0 and net_elo >= 65:
        pts += 9.0
        chips.append(f"+{epg:.0f} ELO/jogo (+{net_elo})")
    elif rated_cnt >= 5 and epg >= 7.5 and net_elo >= 55:
        pts += 6.0
        chips.append(f"+{epg:.0f} ELO/jogo (+{net_elo})")
    elif net_elo >= 140 and len(chrono) <= 50:
        pts += 7.0 if net_elo >= 220 else 5.0
        chips.append(f"+{net_elo} ELO rápido")

    if 0 < cand_total <= 50 and cand_elo >= 1250:
        pts += 4.0
        chips.append(f"ELO {cand_elo} em {cand_total}j")

    if max_streak >= 5:
        pts += 5.0 if max_streak >= 7 else 3.0
        chips.append(f"{max_streak}V seguidas")

    if cand_tel.early_loss_count >= 3 and cand_tel.long_game_count >= 6:
        long_wr = cand_tel.long_game_wins / float(cand_tel.long_game_count)
        if long_wr >= 0.60:
            res["sandbagging"] = True
            pts += 8.0
            chips.append(f"Tanking ({cand_tel.early_loss_count}x <4m)")

    merged_mode_elo = dict(cand_meta.get("mode_elo_max") or {})
    for m, e in cand_tel.mode_elo_max.items():
        if e > int(merged_mode_elo.get(m, 0) or 0):
            merged_mode_elo[m] = e
    high_modes = sorted(m for m, e in merged_mode_elo.items() if int(e or 0) >= 1300)
    res["high_elo_modes"] = high_modes
    if len(high_modes) >= 2 and 0 < cand_total <= 300:
        res["multi_mode_transfer"] = True
        pts += 5.0
        chips.append(f"Piso alto {len(high_modes)} filas")

    cos_cnt = len(cand_tel.equipped_cosmetic_ids)
    res["cosmetics_count"] = cos_cnt
    if 0 < cos_cnt <= 55 and cand_elo >= 1400 and cand_tel.games >= 8:
        res["barebones_cosmetics"] = True
        pts += 3.0
        chips.append(f"Burner ({cos_cnt} itens)")

    res["velocity_pts"] = min(18.0, pts)
    res["strong_velocity"] = bool(pts >= 6.0 or res["sandbagging"])
    res["chips"] = chips
    return res


def _compare_combat_dna(cand_tel: PlayerTelemetry | None, main_tel: PlayerTelemetry | None) -> dict[str, Any]:
    res: dict[str, Any] = {"valid": False, "dna_sim": 0.0, "axes_used": 0}
    if not cand_tel or not main_tel:
        return res
    axes: list[tuple[float, float, float]] = []
    if len(cand_tel.kd_ratios) >= 4 and len(main_tel.kd_ratios) >= 4:
        axes.append((float(statistics.median(cand_tel.kd_ratios)), float(statistics.median(main_tel.kd_ratios)), 0.75))
    if len(cand_tel.dpm_values) >= 4 and len(main_tel.dpm_values) >= 4:
        axes.append((float(statistics.median(cand_tel.dpm_values)), float(statistics.median(main_tel.dpm_values)), 140.0))
    if len(cand_tel.capture_rates) >= 4 and len(main_tel.capture_rates) >= 4:
        axes.append((float(statistics.median(cand_tel.capture_rates)), float(statistics.median(main_tel.capture_rates)), 0.70))
    if len(cand_tel.inactivity_ratios) >= 4 and len(main_tel.inactivity_ratios) >= 4:
        axes.append((float(statistics.median(cand_tel.inactivity_ratios)), float(statistics.median(main_tel.inactivity_ratios)), 0.025))
    if len(cand_tel.squad_trade_ratios) >= 4 and len(main_tel.squad_trade_ratios) >= 4:
        axes.append((float(statistics.median(cand_tel.squad_trade_ratios)), float(statistics.median(main_tel.squad_trade_ratios)), 1.40))
    if len(cand_tel.loss_durations_sec) >= 3 and len(main_tel.loss_durations_sec) >= 3:
        axes.append((float(statistics.median(cand_tel.loss_durations_sec)) / 60.0, float(statistics.median(main_tel.loss_durations_sec)) / 60.0, 12.0))
    if len(axes) < 4:
        return res
    avg_sim = sum(max(0.0, 1.0 - abs(cv - mv) / scale) for cv, mv, scale in axes) / float(len(axes))
    res["valid"] = True
    res["dna_sim"] = round(avg_sim, 3)
    res["axes_used"] = len(axes)
    return res


def _compare_apm(cand_tel: PlayerTelemetry | None, main_tel: PlayerTelemetry | None) -> dict[str, Any]:
    res: dict[str, Any] = {
        "valid": False,
        "delta_apm": 999.0,
        "cand_apm": 0.0,
        "main_apm": 0.0,
        "delta_abil_pm": 999.0,
    }
    if not cand_tel or not main_tel:
        return res
    w_delta, w_c, w_m, w_sum = 0.0, 0.0, 0.0, 0.0
    modes_used = 0
    for mode in ("1v1", "2v2", "3v3", "4v4"):
        ca = cand_tel.median_apm_for_mode(mode, min_samples=3)
        ma = main_tel.median_apm_for_mode(mode, min_samples=3)
        if ca > 0.0 and ma > 0.0:
            w = float(min(len(cand_tel.apm_by_mode[mode]), len(main_tel.apm_by_mode[mode])))
            w_delta += abs(ca - ma) * w
            w_c += ca * w
            w_m += ma * w
            w_sum += w
            modes_used += 1
    ov_c = cand_tel.median_apm(min_samples=4)
    ov_m = main_tel.median_apm(min_samples=4)
    ov_valid = ov_c > 0.0 and ov_m > 0.0
    ov_delta = abs(ov_c - ov_m) if ov_valid else 999.0
    m_delta = (w_delta / w_sum) if w_sum > 0.0 else 999.0

    if w_sum > 0.0 and (not ov_valid or (modes_used >= 2 and m_delta <= ov_delta) or m_delta < ov_delta):
        res["valid"] = True
        res["cand_apm"] = round(w_c / w_sum, 1)
        res["main_apm"] = round(w_m / w_sum, 1)
        res["delta_apm"] = round(m_delta, 1)
    elif ov_valid:
        res["valid"] = True
        res["cand_apm"] = round(ov_c, 1)
        res["main_apm"] = round(ov_m, 1)
        res["delta_apm"] = round(ov_delta, 1)

    cab = cand_tel.median_abil_per_min(min_samples=4)
    mab = main_tel.median_abil_per_min(min_samples=4)
    if cab > 0.0 and mab > 0.0:
        res["delta_abil_pm"] = round(abs(cab - mab), 2)
    return res


def _compare_bg_loadout(cand_tel: PlayerTelemetry | None, main_tel: PlayerTelemetry | None) -> float:
    if not cand_tel or not main_tel:
        return 0.0
    common_races = set(cand_tel.bg_loadout_by_race.keys()) & set(main_tel.bg_loadout_by_race.keys())
    w_sim, w_tot = 0.0, 0.0
    for rid in common_races:
        cc = cand_tel.bg_loadout_by_race[rid]
        mc = main_tel.bg_loadout_by_race[rid]
        if sum(cc.values()) >= 9 and sum(mc.values()) >= 9:
            w = float(min(sum(cc.values()), sum(mc.values())))
            w_sim += _cosine_similarity(cc, mc) * w
            w_tot += w
    return round(w_sim / w_tot, 3) if w_tot > 0.0 else 0.0


def _is_rivalry_nemesis_wl(wins: int, losses: int) -> bool:
    """True quando a conta perde regularmente para o adversário (alinhado ao critério Nêmesis)."""
    w = max(0, int(wins))
    l = max(0, int(losses))
    n = w + l
    if n < 2 or l <= w:
        return False
    return (w == 0 and l >= 2) or ((l / float(n)) >= 0.65 and (l - w) >= 2) or ((l / float(n)) >= 0.60 and n >= 5)


def _is_rivalry_fregues_wl(wins: int, losses: int) -> bool:
    """True quando a conta vence regularmente o adversário (alinhado ao critério Freguês)."""
    w = max(0, int(wins))
    l = max(0, int(losses))
    n = w + l
    if n < 2 or w <= l:
        return False
    return (l == 0 and w >= 2) or ((w / float(n)) >= 0.65 and (w - l) >= 2) or ((w / float(n)) >= 0.60 and n >= 5)


def _compare_rivalry_and_kryptonite_profile(
    cand_tel: PlayerTelemetry | None,
    main_tel: PlayerTelemetry | None,
    *,
    exclude_pids: set[int] | frozenset[int] | None = None,
    pid_aliases: dict[int, str] | None = None,
) -> dict[str, Any]:
    """
    Sinal 10 — Perfil de Nêmesis, Freguês & Criptonitas / Facilidades (Matchup DNA com encolhimento Bayesiano):
    Harmonizado com `coh3-br-lobby-radar/smurf_detector.py`, alavancando também o histórico 2023+ do SQLite
    (`nemesis_matches` e `kryptonite_matches`) para contas principais monitoradas.
    """
    res: dict[str, Any] = {
        "rivalry_pts": 0.0,
        "kryptonite_pts": 0.0,
        "total_pts": 0.0,
        "adds_behavioral": False,
        "adds_identity_anchor": False,
        "shared_nemeses": [],
        "shared_fregueses": [],
        "inverted_rivalries": [],
        "shared_rivalry_count": 0,
        "matchup_profile_sim": 0.0,
        "matchup_profile_valid": False,
        "compared_buckets": 0,
        "shared_kryptonites": [],
        "shared_strengths": [],
        "opposing_buckets": [],
    }
    if not cand_tel or not main_tel:
        return res

    excl = set(exclude_pids or ())
    excl.add(int(cand_tel.profile_id))
    excl.add(int(main_tel.profile_id))
    aliases = pid_aliases or {}

    shared_nemeses: list[dict[str, Any]] = []
    shared_fregueses: list[dict[str, Any]] = []
    inverted_rivalries: list[dict[str, Any]] = []

    for opp_pid in (set(cand_tel.opp_wl.keys()) & set(main_tel.opp_wl.keys())) - excl:
        cp = cand_tel.opp_wl.get(opp_pid) or [0, 0]
        mp = main_tel.opp_wl.get(opp_pid) or [0, 0]
        cw, cl = max(0, int(cp[0])), max(0, int(cp[1]))
        mw, ml = max(0, int(mp[0])), max(0, int(mp[1]))
        cn, mn = cw + cl, mw + ml
        tot = cn + mn
        if cn < 2 or mn < 2 or tot < 5:
            continue
        c_days = len(cand_tel.opp_days.get(opp_pid) or ())
        m_days = len(main_tel.opp_days.get(opp_pid) or ())
        entry = {
            "profile_id": int(opp_pid),
            "alias": strip_unsafe_chars(aliases.get(opp_pid) or f"ID #{opp_pid}")[:32],
            "cand_w": cw,
            "cand_l": cl,
            "main_w": mw,
            "main_l": ml,
            "cand_n": cn,
            "main_n": mn,
            "total": tot,
            "cand_days": c_days,
            "main_days": m_days,
        }
        if _is_rivalry_nemesis_wl(cw, cl) and _is_rivalry_nemesis_wl(mw, ml):
            shared_nemeses.append(entry)
        elif _is_rivalry_fregues_wl(cw, cl) and _is_rivalry_fregues_wl(mw, ml):
            shared_fregueses.append(entry)
        elif cn >= 3 and mn >= 3:
            c_dom_w = (cw / float(cn)) >= 0.70 and (cw - cl) >= 2
            c_dom_l = (cl / float(cn)) >= 0.70 and (cl - cw) >= 2
            m_dom_w = (mw / float(mn)) >= 0.70 and (mw - ml) >= 2
            m_dom_l = (ml / float(mn)) >= 0.70 and (ml - mw) >= 2
            if (c_dom_w and m_dom_l) or (c_dom_l and m_dom_w):
                inverted_rivalries.append(entry)

    shared_nemeses.sort(key=lambda r: (-r["total"], -(r["cand_l"] + r["main_l"])))
    shared_fregueses.sort(key=lambda r: (-r["total"], -(r["cand_w"] + r["main_w"])))
    inverted_rivalries.sort(key=lambda r: -r["total"])

    shared_riv_cnt = len(shared_nemeses) + len(shared_fregueses)
    inv_riv_cnt = len(inverted_rivalries)
    riv_total_eval = shared_riv_cnt + inv_riv_cnt
    riv_concordance = (shared_riv_cnt / float(riv_total_eval)) if riv_total_eval > 0 else 0.0
    part_a_pts = 0.0
    rivalry_adds_behavioral = False
    rivalry_adds_anchor = False

    if shared_riv_cnt > 0 and riv_concordance >= 0.70:
        if shared_riv_cnt >= 3:
            part_a_pts = 12.0
            rivalry_adds_behavioral = True
            rivalry_adds_anchor = True
        elif shared_riv_cnt == 2:
            part_a_pts = 8.0
            rivalry_adds_behavioral = True
            rivalry_adds_anchor = True
        elif shared_riv_cnt == 1:
            only_riv = (shared_nemeses + shared_fregueses)[0]
            if only_riv["total"] >= 6 or (only_riv["cand_n"] >= 3 and only_riv["main_n"] >= 3):
                part_a_pts = 5.0
                if (
                    only_riv["cand_n"] >= 3
                    and only_riv["main_n"] >= 3
                    and only_riv["total"] >= 7
                    and (only_riv["cand_days"] >= 2 or only_riv["main_days"] >= 2)
                ):
                    rivalry_adds_anchor = True
            else:
                part_a_pts = 3.0
        if inv_riv_cnt >= 1:
            part_a_pts = max(0.0, part_a_pts - 3.0 * inv_riv_cnt)
    elif inv_riv_cnt > shared_riv_cnt:
        part_a_pts = -6.0 if (inv_riv_cnt - shared_riv_cnt) >= 2 else -3.0

    cand_overall_p0 = min(0.80, max(0.20, cand_tel.winrate())) if cand_tel.games >= 5 else 0.50
    main_overall_p0 = min(0.80, max(0.20, main_tel.winrate())) if main_tel.games >= 5 else 0.50

    def _domain_baseline(wl_map: dict[Any, list[int]], fallback_p0: float) -> float:
        tw = sum(max(0, int(v[0])) for v in wl_map.values() if len(v) >= 2)
        tn = sum(max(0, int(v[0])) + max(0, int(v[1])) for v in wl_map.values() if len(v) >= 2)
        if tn >= 8:
            return min(0.80, max(0.20, tw / float(tn)))
        return fallback_p0

    cand_ally_clean = {k: v for k, v in cand_tel.ally_wl.items() if k not in excl}
    main_ally_clean = {k: v for k, v in main_tel.ally_wl.items() if k not in excl}

    domains: list[tuple[str, dict[Any, list[int]], dict[Any, list[int]], int, float]] = [
        ("Mapa", cand_tel.map_wl, main_tel.map_wl, 3, 1.00),
        ("BG", cand_tel.enemy_bg_wl, main_tel.enemy_bg_wl, 3, 1.15),
        ("Matchup", cand_tel.matchup_wl, main_tel.matchup_wl, 4, 0.90),
    ]
    shared_matchup_cnt = sum(
        1
        for k in (set(cand_tel.matchup_wl.keys()) & set(main_tel.matchup_wl.keys()))
        if sum(cand_tel.matchup_wl[k][:2]) >= 4 and sum(main_tel.matchup_wl[k][:2]) >= 4
    )
    if shared_matchup_cnt < 2:
        domains.append(("vs Facção", cand_tel.enemy_faction_wl, main_tel.enemy_faction_wl, 4, 0.75))

    cand_multi_fac = sum(1 for v in cand_tel.my_faction_wl.values() if (int(v[0]) + int(v[1])) >= 4) >= 2
    main_multi_fac = sum(1 for v in main_tel.my_faction_wl.values() if (int(v[0]) + int(v[1])) >= 4) >= 2
    if cand_multi_fac and main_multi_fac:
        fac_scale = 0.45 if shared_matchup_cnt >= 2 else 0.75
        domains.append(("Facção", cand_tel.my_faction_wl, main_tel.my_faction_wl, 4, fac_scale))

    domains.append(("Aliado", cand_ally_clean, main_ally_clean, 3, 0.85))

    alpha = 3.0
    w_dot = 0.0
    w_nc = 0.0
    w_nm = 0.0
    w_sum = 0.0
    compared_buckets = 0
    shared_kryptonites: list[dict[str, Any]] = []
    shared_strengths: list[dict[str, Any]] = []
    opposing_buckets: list[dict[str, Any]] = []

    for dim_kind, c_map, m_map, min_n, dim_scale in domains:
        if not c_map or not m_map:
            continue
        p0_c = _domain_baseline(c_map, cand_overall_p0)
        p0_m = _domain_baseline(m_map, main_overall_p0)
        for key in set(c_map.keys()) & set(m_map.keys()):
            cp = c_map[key]
            mp = m_map[key]
            cw, cl = max(0, int(cp[0])), max(0, int(cp[1]))
            mw, ml = max(0, int(mp[0])), max(0, int(mp[1]))
            cn, mn = cw + cl, mw + ml
            if cn < min_n or mn < min_n:
                continue

            dc = (cw + alpha * p0_c) / (cn + alpha) - p0_c
            dm = (mw + alpha * p0_m) / (mn + alpha) - p0_m
            raw_dc = (cw / float(cn)) - p0_c
            raw_dm = (mw / float(mn)) - p0_m

            wt = dim_scale * math.sqrt(float(min(cn, mn)))
            w_dot += wt * dc * dm
            w_nc += wt * dc * dc
            w_nm += wt * dm * dm
            w_sum += wt
            compared_buckets += 1

            if dim_kind == "Matchup" and isinstance(key, tuple) and len(key) == 2:
                label = f"{key[0]} vs {key[1]}"
            elif dim_kind == "Aliado":
                label = strip_unsafe_chars(aliases.get(int(key)) or f"ID #{key}")[:28]
            else:
                label = str(key)

            bucket_entry = {
                "kind": dim_kind,
                "label": label,
                "cand_w": cw,
                "cand_l": cl,
                "main_w": mw,
                "main_l": ml,
                "cand_delta": round(dc, 3),
                "main_delta": round(dm, 3),
            }
            if dc <= -0.055 and dm <= -0.055 and raw_dc <= -0.08 and raw_dm <= -0.08 and (cl > cw or ml > mw):
                shared_kryptonites.append(bucket_entry)
            elif dc >= 0.055 and dm >= 0.055 and raw_dc >= 0.08 and raw_dm >= 0.08 and cw > cl and mw > ml:
                shared_strengths.append(bucket_entry)
            elif (
                (dc <= -0.07 and raw_dc <= -0.10 and dm >= 0.07 and raw_dm >= 0.10)
                or (dm <= -0.07 and raw_dm <= -0.10 and dc >= 0.07 and raw_dc >= 0.10)
            ):
                opposing_buckets.append(bucket_entry)

    shared_kryptonites.sort(key=lambda b: (b["cand_delta"] + b["main_delta"]))
    shared_strengths.sort(key=lambda b: -(b["cand_delta"] + b["main_delta"]))

    part_b_pts = 0.0
    krypt_adds_behavioral = False
    matchup_profile_sim = 0.0
    matchup_profile_valid = False
    steady_state_sample = (
        cand_tel.games >= 30
        and main_tel.games >= 30
        and cand_tel.winrate() < 0.72
    )

    if compared_buckets >= 4 and w_sum > 0.0 and w_nc > 0.0 and w_nm > 0.0:
        rms_c = math.sqrt(w_nc / w_sum)
        rms_m = math.sqrt(w_nm / w_sum)
        if rms_c >= 0.035 and rms_m >= 0.035:
            matchup_profile_valid = True
            matchup_profile_sim = round(max(-1.0, min(1.0, w_dot / math.sqrt(w_nc * w_nm))), 3)
            concrete_shared = len(shared_kryptonites) + len(shared_strengths)
            if matchup_profile_sim >= 0.58 and (concrete_shared >= 2 or compared_buckets >= 6):
                part_b_pts = 8.0
                krypt_adds_behavioral = True
            elif matchup_profile_sim >= 0.40 and (concrete_shared >= 1 or compared_buckets >= 6):
                part_b_pts = 4.0
            elif steady_state_sample and compared_buckets >= 8 and matchup_profile_sim <= -0.50:
                part_b_pts = -5.0

    if part_b_pts == 0.0:
        concrete_shared = len(shared_kryptonites) + len(shared_strengths)
        if concrete_shared >= 2 and not opposing_buckets:
            part_b_pts = 4.0
        elif steady_state_sample and len(opposing_buckets) >= 3 and concrete_shared == 0:
            part_b_pts = -4.0

    total_pts = max(-8.0, min(16.0, part_a_pts + part_b_pts))
    res.update(
        {
            "rivalry_pts": round(part_a_pts, 2),
            "kryptonite_pts": round(part_b_pts, 2),
            "total_pts": round(total_pts, 2),
            "adds_behavioral": bool(rivalry_adds_behavioral or krypt_adds_behavioral),
            "adds_identity_anchor": bool(rivalry_adds_anchor),
            "shared_nemeses": shared_nemeses[:5],
            "shared_fregueses": shared_fregueses[:5],
            "inverted_rivalries": inverted_rivalries[:5],
            "shared_rivalry_count": shared_riv_cnt,
            "matchup_profile_sim": matchup_profile_sim,
            "matchup_profile_valid": matchup_profile_valid,
            "compared_buckets": compared_buckets,
            "shared_kryptonites": shared_kryptonites[:5],
            "shared_strengths": shared_strengths[:5],
            "opposing_buckets": opposing_buckets[:5],
        }
    )
    return res


def score_live_smurf_pair(
    cand: dict[str, Any],
    main: dict[str, Any],
    cand_tel: PlayerTelemetry | None,
    main_tel: PlayerTelemetry | None,
    *,
    main_family_pids: set[int] | frozenset[int] | None = None,
    family_intervals: list[tuple[int, int]] | None = None,
    cand_osint: dict[str, Any] | None = None,
    main_osint: dict[str, Any] | None = None,
    known_br_pids: set[int] | frozenset[int] | None = None,
    pid_aliases: dict[int, str] | None = None,
) -> dict[str, Any]:
    """
    Calcula a probabilidade forense (`0..99%`) de um oponente `cand` ser smurf do brasileiro `main`,
    aplicando os critérios multi-gênero anti-disfarce e todas as guardas anti-falso-positivo.
    """
    cand_pid = int(cand.get("profile_id", 0) or 0)
    main_pid = int(main.get("profile_id", 0) or 0)
    cand_ctry = str(cand.get("country") or "").strip().lower()
    cand_alias = str(cand.get("alias") or cand_pid)
    main_alias = str(main.get("alias") or main_pid)

    empty: dict[str, Any] = {
        "main_profile_id": main_pid,
        "main_alias": main_alias,
        "probability_pct": 0,
        "confidence_tier": "Descartada",
        "disqualified_reason": "",
        "behavioral_signals": 0,
        "identity_anchor_signals": 0,
        "top_reasons": [],
    }
    if cand_pid <= 0 or main_pid <= 0 or cand_pid == main_pid:
        empty["disqualified_reason"] = "mesmo_perfil"
        return empty

    family_set = {main_pid} | {int(x) for x in (main_family_pids or ()) if int(x) > 0}
    if cand_pid in family_set:
        empty["disqualified_reason"] = "ja_catalogada_na_familia"
        return empty

    # 1. Desqualificadores absolutos (co-play direto ou com smurf conhecida da família + sobreposição simultânea)
    if cand_tel and (cand_tel.co_played_with & family_set):
        empty["disqualified_reason"] = "jogaram_mesma_partida"
        return empty
    if main_tel and cand_pid in main_tel.co_played_with:
        empty["disqualified_reason"] = "jogaram_mesma_partida"
        return empty

    all_main_intervals = list(main_tel.intervals) if main_tel else []
    if family_intervals:
        all_main_intervals.extend(family_intervals)
    has_overlap, handoff_cnt = _check_overlap_and_handoffs(
        cand_tel.intervals if cand_tel else [],
        all_main_intervals,
    )
    if has_overlap:
        empty["disqualified_reason"] = "sobreposicao_simultanea"
        return empty

    cand_total = max(0, int(cand.get("total_matches", 0) or 0))
    main_total = max(0, int(main.get("total_matches", 0) or 0))
    if cand_total > CONSOLIDATED_VETERAN_MIN_MATCHES:
        empty["disqualified_reason"] = "conta_veterana_consolidada"
        return empty
    if main_total > 0 and cand_total > main_total and cand_total >= 400:
        empty["disqualified_reason"] = "candidata_mais_antiga_que_principal"
        return empty

    cand_elo = int(cand.get("max_elo", 0) or 0)
    main_elo = int(main.get("max_elo", 0) or 0)
    if main_elo > 0 and cand_elo > main_elo + 260:
        empty["disqualified_reason"] = "elo_muito_acima_da_principal"
        return empty
    if cand_elo > 0 and main_elo > 0 and abs(cand_elo - main_elo) > 520:
        empty["disqualified_reason"] = "elo_incompativel"
        return empty

    # Pré-cálculos multi-gênero
    c_osint = cand_osint or {}
    m_osint = main_osint or {}
    c_av = str(c_osint.get("avatar_hash") or "")
    m_av = str(m_osint.get("avatar_hash") or "")
    same_custom_avatar = bool(c_av and m_av and c_av == m_av and c_av != STEAM_DEFAULT_AVATAR_HASH)
    steam_br_leak = bool(c_osint.get("is_br_location"))
    ptbr_hit, ptbr_chip = _detect_ptbr_linguistic_signal(cand_alias)

    cand_seen = (cand_tel.seen_aliases if cand_tel else set()) | {cand_alias}
    main_seen = (main_tel.seen_aliases if main_tel else set()) | {main_alias} | set(main.get("known_aliases") or ())
    alias_pts, alias_chip = _alias_similarity_bonus(cand_alias, main_alias, cand_seen, main_seen)

    shared_allies: list[tuple[int, int, int]] = []
    if cand_tel and main_tel:
        for apid in set(cand_tel.ally_counts.keys()) & set(main_tel.ally_counts.keys()):
            if apid in family_set or apid == cand_pid:
                continue
            cc, mc = cand_tel.ally_counts[apid], main_tel.ally_counts[apid]
            if cc >= 2 and mc >= 2:
                shared_allies.append((apid, cc, mc))

    br_pids = known_br_pids or frozenset()
    cand_br_allies = sum(1 for apid, cnt in (cand_tel.ally_counts.items() if cand_tel else ()) if apid in br_pids and cnt >= 2)
    cand_brt_prime = cand_tel.brt_prime_ratio() if cand_tel else 0.0
    reg_obs = cand_tel.regional_observed_games if cand_tel else 0
    sa_m_rate = cand_tel.sa_match_rate() if cand_tel else 0.0
    br_opp_rate = cand_tel.br_opp_match_rate() if cand_tel else 0.0
    br_opp_cnt = cand_tel.br_opp_match_count if cand_tel else 0
    br_match_cnt = cand_tel.br_match_count if cand_tel else 0
    strong_br_sa_mm_nexus = bool(
        reg_obs >= 6
        and sa_m_rate >= 0.20
        and (br_opp_cnt >= 1 or br_match_cnt >= 3)
        and cand_brt_prime >= 0.40
    )

    # Guarda estrita anti-falso-positivo para bandeiras estrangeiras explícitas
    is_explicit_foreign = bool(cand_ctry and cand_ctry not in ("br", "??", "unknown"))
    has_br_nexus = (
        bool(shared_allies)
        or alias_pts > 0
        or same_custom_avatar
        or steam_br_leak
        or (cand_pid in br_pids)
        or (ptbr_hit and cand_brt_prime >= 0.40)
        or (cand_br_allies >= 2 and cand_brt_prime >= 0.45)
        or strong_br_sa_mm_nexus
    )
    if is_explicit_foreign and not has_br_nexus:
        empty["disqualified_reason"] = "estrangeiro_sem_vinculo_br"
        return empty

    vel = _analyze_skill_velocity_and_tanking(cand_tel, cand)
    apm = _compare_apm(cand_tel, main_tel)
    dna = _compare_combat_dna(cand_tel, main_tel)
    bg_loadout_sim = _compare_bg_loadout(cand_tel, main_tel)

    excl_day_ratio = 0.0
    dormancy_swap = False
    if cand_tel and main_tel and len(cand_tel.active_brt_days) >= 5 and len(main_tel.active_brt_days) >= 5:
        ov_days = len(cand_tel.active_brt_days & main_tel.active_brt_days)
        excl_day_ratio = 1.0 - (ov_days / float(len(cand_tel.active_brt_days)))
        dormancy_swap = excl_day_ratio >= 0.75

    score = 0.0
    behavioral_signals = 0
    identity_anchor_signals = 0
    weighted_reasons: list[tuple[float, str]] = []

    # 1. Perfil smurf (poucos jogos em ELO alto + conta mais recente)
    if 0 < cand_total <= 220 and cand_elo >= 1400:
        score += 18.0
        weighted_reasons.append((10.0, f"{cand_total} jogos em ELO {cand_elo}"))
    elif 0 < cand_total <= 450 and cand_elo >= 1350:
        score += 12.0
    elif cand_elo >= 1450 and (cand_total == 0 or cand_total <= 700):
        score += 6.0

    cand_s32 = _steam_account32(str(cand.get("steam_id") or ""))
    main_s32 = _steam_account32(str(main.get("steam_id") or ""))
    if cand_pid > main_pid and cand_pid >= 950_000 and (cand_s32 == 0 or main_s32 == 0 or cand_s32 > main_s32):
        score += 6.0

    # 1B. Velocidade de habilidade, streaks, sandbagging, multi-fila, cosméticos burner
    if vel["velocity_pts"] > 0.0:
        score += float(vel["velocity_pts"])
        if vel["strong_velocity"]:
            behavioral_signals += 1
        for ch in vel["chips"][:2]:
            weighted_reasons.append((float(vel["velocity_pts"]), ch))

    # 1C. Matchmaking regional/ping Relic (smurfs BR enfrentam outros BR/SA por ping/região)
    if reg_obs >= 6:
        if is_explicit_foreign and strong_br_sa_mm_nexus:
            score += 8.0
            identity_anchor_signals += 1
            weighted_reasons.append((15.0, f"MM BR/SA {sa_m_rate * 100:.0f}% ({cand_ctry})"))
        elif (br_opp_cnt >= 2 and br_opp_rate >= 0.08) or (sa_m_rate >= 0.35 and reg_obs >= 8):
            score += 5.0 if (br_opp_cnt >= 2 and sa_m_rate >= 0.25) else 3.0
            weighted_reasons.append((10.0, f"MM BR/SA {sa_m_rate * 100:.0f}%"))
        elif (
            reg_obs >= 12
            and cand_tel is not None
            and sum(cand_tel.brt_hour_counts.values()) >= 10
            and sa_m_rate < 0.05
            and cand_brt_prime < 0.25
            and not shared_allies
        ):
            score -= 18.0

    # 2. Handoffs temporais rápidos (<=25 min sem sobreposição)
    if handoff_cnt >= 3:
        score += 24.0
        behavioral_signals += 1
        identity_anchor_signals += 1
        weighted_reasons.append((24.0, f"{handoff_cnt} trocas <25m"))
    elif handoff_cnt == 2:
        score += 16.0
        behavioral_signals += 1
        identity_anchor_signals += 1
        weighted_reasons.append((16.0, "2 trocas <25m"))
    elif handoff_cnt == 1:
        score += 7.0

    # 3. Squad compartilhado (aliados recorrentes em comum)
    if shared_allies:
        ally_pts = min(30.0, 12.0 + len(shared_allies) * 7.0)
        score += ally_pts
        behavioral_signals += 1
        identity_anchor_signals += 1
        weighted_reasons.append((ally_pts, f"{len(shared_allies)} aliado(s) em comum"))

    # 4. Modo + facção
    mf_sim = 0.0
    hour_sim = (
        _cosine_similarity(cand_tel.hour_counts, main_tel.hour_counts)
        if (cand_tel and main_tel and cand_tel.games >= 6 and main_tel.games >= 6)
        else 0.0
    )
    if cand_tel and main_tel and cand_tel.games >= 6 and main_tel.games >= 6:
        mf_sim = _cosine_similarity(cand_tel.mode_faction_counts, main_tel.mode_faction_counts)
        if mf_sim >= 0.85:
            score += 15.0
            behavioral_signals += 1
            weighted_reasons.append((12.0, f"Modo/facção {mf_sim * 100:.0f}%"))
        elif mf_sim >= 0.68:
            score += 10.0
            behavioral_signals += 1
        elif mf_sim >= 0.55:
            score += 5.0
        elif mf_sim < 0.25:
            if not (
                shared_allies
                or (apm["valid"] and float(apm["delta_apm"]) <= 8.0)
                or (dna["valid"] and float(dna["dna_sim"]) >= 0.75)
                or hour_sim >= 0.75
            ):
                score -= 12.0

    # 5. Mesma faixa de ELO alto sem confrontos
    same_bracket = 0
    if cand_tel and main_tel:
        for mode in ("1v1", "2v2", "3v3", "4v4"):
            ce = cand_tel.mode_elo_max.get(mode, 0)
            me = main_tel.mode_elo_max.get(mode, 0)
            if ce >= 1350 and me >= 1350 and abs(ce - me) <= 150 and cand_tel.mode_counts.get(mode, 0) >= 6 and main_tel.mode_counts.get(mode, 0) >= 6:
                same_bracket += 1
    if same_bracket:
        score += 11.0 if same_bracket >= 2 else 8.0
        behavioral_signals += 1
        identity_anchor_signals += 1

    # 6. Horários + alternância de dias exclusivos (dormancy swap) + ciclo BRT
    apm_very_close = bool(apm["valid"] and float(apm["delta_apm"]) <= 4.0)
    if cand_tel and main_tel and cand_tel.games >= 6 and main_tel.games >= 6:
        if hour_sim >= 0.78:
            score += 14.0
            behavioral_signals += 1
            identity_anchor_signals += 1
            weighted_reasons.append((13.0, f"Horário {hour_sim * 100:.0f}%"))
        elif hour_sim >= 0.68:
            score += 8.0
            behavioral_signals += 1
            identity_anchor_signals += 1
        elif cand_tel.games >= 10 and main_tel.games >= 10 and hour_sim < 0.30:
            if not (apm_very_close and vel["strong_velocity"] and same_bracket):
                score -= 14.0

    if dormancy_swap and (apm_very_close or bool(shared_allies) or (dna["valid"] and float(dna["dna_sim"]) >= 0.72)):
        score += 7.0
        identity_anchor_signals += 1
        weighted_reasons.append((11.0, f"Dias alternados {excl_day_ratio * 100:.0f}%"))

    if is_explicit_foreign and cand_brt_prime >= 0.55 and cand_tel is not None and cand_tel.games >= 6:
        score += 6.0
        weighted_reasons.append((9.0, f"Prime-time BRT {cand_brt_prime * 100:.0f}%"))

    # 7. Nick (exato/leetspeak/trigramas/clã), PT-BR e OSINT Steam
    if alias_pts > 0:
        score += float(alias_pts)
        behavioral_signals += 1
        identity_anchor_signals += 1
        weighted_reasons.append((float(alias_pts), alias_chip))

    if ptbr_hit and cand_ctry != "br":
        score += 7.0
        identity_anchor_signals += 1
        weighted_reasons.append((11.0, ptbr_chip))

    if _is_throwaway_or_barcode_nick(cand_alias) and cand_elo >= 1350:
        score += 3.0

    if same_custom_avatar:
        score += 24.0
        behavioral_signals += 1
        identity_anchor_signals += 1
        weighted_reasons.append((25.0, "Avatar Steam idêntico"))
    if steam_br_leak and cand_ctry != "br":
        score += 8.0
        identity_anchor_signals += 1
        weighted_reasons.append((14.0, "Steam revela Brasil"))

    # 7B. Steam Family Sharing (Passo 1 XML/HTML público — 0/61 falsos positivos em contas principais BR)
    if c_osint.get("is_limited_account"):
        score += 12.0
        behavioral_signals += 1
        weighted_reasons.append((20.0, "Family Sharing (conta limitada)"))

    osint_pts = 0.0
    if c_osint.get("is_default_avatar") and cand_elo >= 1300:
        osint_pts += 5.0
        weighted_reasons.append((7.0, "Avatar padrão '?'"))
    if c_osint.get("is_private") and cand_elo >= 1350 and 0 < cand_total <= 350:
        osint_pts += 5.0
        weighted_reasons.append((6.0, "Steam privada"))
    cur_yr = datetime.now(tz=timezone.utc).year
    mem_yr = int(c_osint.get("member_since_year", 0) or 0)
    if c_osint.get("member_since_current_year") and cand_elo >= 1250:
        osint_pts += 8.0
        weighted_reasons.append((13.0, "Steam criada este ano"))
    elif mem_yr >= cur_yr - 2 and cand_elo >= 1350:
        osint_pts += 4.0
    s_lvl = int(c_osint.get("steam_level", -1) if c_osint.get("steam_level") is not None else -1)
    s_fr = int(c_osint.get("friends_count", -1) if c_osint.get("friends_count") is not None else -1)
    s_bdg = int(c_osint.get("badges_count", -1) if c_osint.get("badges_count") is not None else -1)
    if 0 <= s_lvl <= 2 and cand_elo >= 1300 and ((0 <= s_fr <= 15) or (0 <= s_bdg <= 2)):
        osint_pts += 4.0
        weighted_reasons.append((10.0, f"Steam Nível {s_lvl}"))
    score += min(14.0, osint_pts)

    # 8. Biometria APM + abil/min
    apm_strong = False
    if apm["valid"]:
        d_apm = float(apm["delta_apm"])
        if d_apm <= 6.0:
            pts_apm = 14.0 + (3.0 if float(apm["delta_abil_pm"]) <= 0.65 else 0.0)
            score += pts_apm
            behavioral_signals += 1
            apm_strong = True
            weighted_reasons.append((19.0, f"APM Δ={d_apm:.1f} ({apm['cand_apm']:.0f} vs {apm['main_apm']:.0f})"))
        elif d_apm <= 12.0:
            score += 8.0
            behavioral_signals += 1
            weighted_reasons.append((10.0, f"APM Δ={d_apm:.1f}"))
        elif d_apm >= 45.0:
            score -= 25.0
        elif d_apm >= 35.0:
            score -= 14.0

    # 8B. Combat DNA multi-gênero (6 eixos independente de facção)
    dna_strong = False
    if dna["valid"]:
        d_sim = float(dna["dna_sim"])
        if d_sim >= 0.78:
            score += 10.0
            behavioral_signals += 1
            dna_strong = True
            weighted_reasons.append((15.0, f"Combat DNA {d_sim * 100:.0f}%"))
        elif d_sim >= 0.70:
            score += 5.0
            weighted_reasons.append((8.0, f"Combat DNA {d_sim * 100:.0f}%"))
        elif d_sim < 0.42:
            score -= 6.0

    # 9. Loadout de Battlegroups equipado (eslot 0..2)
    bg_pts = 0.0
    if bg_loadout_sim >= 0.82:
        bg_pts = 10.0
        behavioral_signals += 1
        weighted_reasons.append((12.0, f"BGs {bg_loadout_sim * 100:.0f}%"))
    elif bg_loadout_sim >= 0.68:
        bg_pts = 6.0
    score += bg_pts

    # 10. Nêmesis, Freguês & Criptonitas / Facilidades (Matchup DNA com encolhimento Bayesiano)
    rk_info = _compare_rivalry_and_kryptonite_profile(
        cand_tel,
        main_tel,
        exclude_pids=family_set | {cand_pid, main_pid},
        pid_aliases=pid_aliases,
    )
    rk_pts = float(rk_info["total_pts"])
    if rk_pts != 0.0:
        score += rk_pts
    if rk_info["adds_behavioral"]:
        behavioral_signals += 1
    if rk_info["adds_identity_anchor"]:
        identity_anchor_signals += 1

    nem_cnt = len(rk_info["shared_nemeses"])
    freg_cnt = len(rk_info["shared_fregueses"])
    if float(rk_info["rivalry_pts"]) > 0.0:
        if nem_cnt + freg_cnt >= 2:
            weighted_reasons.append((16.0, f"Nêmesis/Freguês comum ({nem_cnt + freg_cnt})"))
        elif nem_cnt == 1 and float(rk_info["rivalry_pts"]) >= 5.0:
            weighted_reasons.append((11.0, f"Nêmesis comum: {rk_info['shared_nemeses'][0]['alias'][:16]}"))
        elif freg_cnt == 1 and float(rk_info["rivalry_pts"]) >= 5.0:
            weighted_reasons.append((11.0, f"Freguês comum: {rk_info['shared_fregueses'][0]['alias'][:16]}"))

    if float(rk_info["kryptonite_pts"]) >= 8.0 and rk_info["matchup_profile_valid"]:
        weighted_reasons.append((14.0, f"Criptonitas/Matchups {float(rk_info['matchup_profile_sim']) * 100:.0f}%"))
    elif float(rk_info["kryptonite_pts"]) >= 4.0:
        if rk_info["shared_kryptonites"]:
            weighted_reasons.append((9.0, f"Criptonita comum: {rk_info['shared_kryptonites'][0]['label'][:18]}"))
        elif rk_info["matchup_profile_valid"]:
            weighted_reasons.append((9.0, f"Criptonitas/Matchups {float(rk_info['matchup_profile_sim']) * 100:.0f}%"))

    # Deduções por contra-evidência
    elo_diff = abs(cand_elo - main_elo) if (cand_elo > 0 and main_elo > 0) else 0
    if elo_diff > 350:
        score -= 15.0
    elif elo_diff > 250:
        score -= 8.0
    elif elo_diff <= 150 and cand_elo >= 1350:
        score += 4.0

    if cand_elo > 0 and cand_elo < 1200 and cand_total >= 100:
        score -= 15.0

    if (
        cand_tel
        and main_tel
        and not shared_allies
        and handoff_cnt == 0
        and alias_pts == 0
        and int(rk_info["shared_rivalry_count"]) < 2
        and not (apm_strong and (bg_pts >= 6.0 or dna_strong))
    ):
        if (cand_tel.games - cand_tel.mode_counts.get("1v1", 0)) >= 10 and (main_tel.games - main_tel.mode_counts.get("1v1", 0)) >= 10:
            score -= 12.0

    # Guarda Anti-Ruído Meta
    if behavioral_signals < 2:
        score = min(score, 34.0)
    elif identity_anchor_signals < 1:
        score = min(score, 38.0)

    prob = max(0, min(99, int(round(score))))
    tier = "Muito Alta" if prob >= 80 else ("Alta" if prob >= 68 else ("Moderada" if prob >= 55 else "Baixa"))

    seen_r: set[str] = set()
    top_reasons: list[str] = []
    for _w, label in sorted(weighted_reasons, key=lambda x: -x[0]):
        if label and label not in seen_r:
            seen_r.add(label)
            top_reasons.append(label)
        if len(top_reasons) >= 4:
            break

    return {
        "main_profile_id": main_pid,
        "main_alias": main_alias,
        "probability_pct": prob,
        "confidence_tier": tier,
        "disqualified_reason": "",
        "behavioral_signals": behavioral_signals,
        "identity_anchor_signals": identity_anchor_signals,
        "top_reasons": top_reasons,
        "rivalry_kryptonite": {
            "pts": rk_pts,
            "shared_nemeses": len(rk_info["shared_nemeses"]),
            "shared_fregueses": len(rk_info["shared_fregueses"]),
            "inverted_rivalries": len(rk_info["inverted_rivalries"]),
            "matchup_profile_sim": rk_info["matchup_profile_sim"] if rk_info["matchup_profile_valid"] else None,
            "shared_kryptonites": [f"{b['kind']}:{b['label']}" for b in rk_info["shared_kryptonites"]],
            "shared_strengths": [f"{b['kind']}:{b['label']}" for b in rk_info["shared_strengths"]],
        },
    }


def score_unattributed_br_burner(
    cand: dict[str, Any],
    cand_tel: PlayerTelemetry | None,
    *,
    cand_osint: dict[str, Any] | None = None,
    known_br_pids: set[int] | frozenset[int] | None = None,
) -> dict[str, Any]:
    """
    Avalia se um oponente é claramente uma conta smurf/burner BRASILEIRA mesmo quando ainda não há
    dados suficientes para atribuir a um único jogador específico do Top 50 BR.
    Exige nexo brasileiro concreto + conta nova de ELO alto + >=2 anomalias burner independentes.
    """
    cand_pid = int(cand.get("profile_id", 0) or 0)
    cand_alias = str(cand.get("alias") or cand_pid)
    cand_ctry = str(cand.get("country") or "").strip().lower()
    cand_elo = int(cand.get("max_elo", 0) or 0)
    cand_total = max(0, int(cand.get("total_matches", 0) or 0))
    cand_wins = max(0, int(cand.get("total_wins", 0) or 0))
    c_osint = cand_osint or {}
    br_pids = known_br_pids or frozenset()

    empty = {"triggered": False, "probability_pct": 0, "confidence_tier": "Baixa", "top_reasons": []}
    if cand_total <= 0 or cand_total > 220 or cand_elo < 1350:
        return empty
    if cand_total > 120 and cand_elo < 1400:
        return empty

    ptbr_hit, ptbr_chip = _detect_ptbr_linguistic_signal(cand_alias)
    steam_br_leak = bool(c_osint.get("is_br_location"))
    br_allies = sum(1 for apid, cnt in (cand_tel.ally_counts.items() if cand_tel else ()) if apid in br_pids and cnt >= 2)
    brt_prime = cand_tel.brt_prime_ratio() if cand_tel else 0.0
    reg_obs = cand_tel.regional_observed_games if cand_tel else 0
    sa_m_rate = cand_tel.sa_match_rate() if cand_tel else 0.0
    br_opp_cnt = cand_tel.br_opp_match_count if cand_tel else 0
    br_match_cnt = cand_tel.br_match_count if cand_tel else 0
    strong_br_sa_mm_nexus = bool(
        reg_obs >= 6
        and sa_m_rate >= 0.20
        and (br_opp_cnt >= 1 or br_match_cnt >= 3)
        and brt_prime >= 0.40
    )

    # Anti-bandeira 'br' falsa (ex.: conta asiática/europeia com bandeira 'br', ~0% encontros BR/SA e fora do BRT)
    if (
        reg_obs >= 12
        and cand_tel is not None
        and sum(cand_tel.brt_hour_counts.values()) >= 10
        and sa_m_rate < 0.05
        and brt_prime < 0.25
        and br_allies == 0
        and not steam_br_leak
        and not ptbr_hit
    ):
        return empty

    has_br_nexus = (
        cand_ctry == "br"
        or cand_pid in br_pids
        or steam_br_leak
        or ptbr_hit
        or strong_br_sa_mm_nexus
        or (cand_ctry in ("", "??", "unknown") and br_allies >= 1 and brt_prime >= 0.45)
        or (br_allies >= 2 and brt_prime >= 0.45)
    )
    if not has_br_nexus:
        return empty

    score = 0.0
    anomalies = 0
    weighted_reasons: list[tuple[float, str]] = []

    if cand_total <= 80 and cand_elo >= 1450:
        score += 34.0
        weighted_reasons.append((20.0, f"{cand_total} jogos em ELO {cand_elo}"))
    elif cand_total <= 150 and cand_elo >= 1400:
        score += 26.0
        weighted_reasons.append((18.0, f"{cand_total} jogos em ELO {cand_elo}"))
    else:
        score += 18.0
        weighted_reasons.append((14.0, f"{cand_total} jogos em ELO {cand_elo}"))

    wr = (cand_wins / float(cand_total)) if cand_total >= 15 else 0.0
    if wr >= 0.68:
        score += 18.0
        anomalies += 1
        weighted_reasons.append((17.0, f"WR {wr * 100:.0f}%"))
    elif wr >= 0.60:
        score += 10.0
        anomalies += 1
        weighted_reasons.append((12.0, f"WR {wr * 100:.0f}%"))

    vel = _analyze_skill_velocity_and_tanking(cand_tel, cand)
    if (
        vel["net_elo_gain"] >= 140
        or vel["max_win_streak"] >= 5
        or (int(vel.get("rated_games_counted", 0) or 0) >= 5 and float(vel.get("elo_gain_per_game", 0.0) or 0.0) >= 7.5)
    ):
        score += 14.0 if (vel["net_elo_gain"] >= 180 or vel["max_win_streak"] >= 7 or float(vel.get("elo_gain_per_game", 0.0) or 0.0) >= 12.0) else 10.0
        anomalies += 1
        for ch in vel["chips"][:2]:
            weighted_reasons.append((15.0, ch))
    if cand_ctry != "br" and strong_br_sa_mm_nexus:
        score += 10.0
        anomalies += 1
        weighted_reasons.append((16.0, f"MM BR/SA {sa_m_rate * 100:.0f}% ({cand_ctry or '??'})"))
    if vel["sandbagging"]:
        score += 14.0
        anomalies += 1
        weighted_reasons.append((19.0, f"Tanking ({cand_tel.early_loss_count if cand_tel else 0}x <4m)"))
    if vel["multi_mode_transfer"]:
        score += 10.0
        anomalies += 1
        weighted_reasons.append((13.0, f"Piso alto {len(vel['high_elo_modes'])} filas"))
    if vel["barebones_cosmetics"]:
        score += 8.0
        anomalies += 1
        weighted_reasons.append((10.0, f"Burner ({vel['cosmetics_count']} itens)"))

    if c_osint.get("is_limited_account"):
        score += 18.0
        anomalies += 1
        weighted_reasons.append((21.0, "Family Sharing (conta limitada)"))

    osint_burner = 0
    if c_osint.get("is_default_avatar"):
        score += 10.0
        osint_burner += 1
        weighted_reasons.append((14.0, "Avatar padrão '?'"))
    if c_osint.get("is_private"):
        score += 8.0
        osint_burner += 1
        weighted_reasons.append((11.0, "Steam privada"))
    cur_yr = datetime.now(tz=timezone.utc).year
    mem_yr = int(c_osint.get("member_since_year", 0) or 0)
    if c_osint.get("member_since_current_year"):
        score += 10.0
        anomalies += 1
        weighted_reasons.append((15.0, "Steam criada este ano"))
    elif mem_yr >= cur_yr - 2:
        score += 8.0
        osint_burner += 1
        weighted_reasons.append((10.0, f"Steam {mem_yr}"))
    u_lvl = int(c_osint.get("steam_level", -1) if c_osint.get("steam_level") is not None else -1)
    u_fr = int(c_osint.get("friends_count", -1) if c_osint.get("friends_count") is not None else -1)
    u_bdg = int(c_osint.get("badges_count", -1) if c_osint.get("badges_count") is not None else -1)
    if 0 <= u_lvl <= 2 and ((0 <= u_fr <= 15) or (0 <= u_bdg <= 2)):
        score += 6.0
        osint_burner += 1
        weighted_reasons.append((11.0, f"Steam Nível {u_lvl}"))
    if osint_burner > 0:
        anomalies += 1

    if _is_throwaway_or_barcode_nick(cand_alias):
        score += 6.0
        anomalies += 1
        weighted_reasons.append((9.0, "Nick descartável"))

    if cand_ctry != "br" and (steam_br_leak or ptbr_hit):
        score += 10.0
        anomalies += 1
        weighted_reasons.append((16.0, "Steam revela Brasil" if steam_br_leak else ptbr_chip))

    prob = max(0, min(95, int(round(score))))
    triggered = bool(anomalies >= 2 and prob >= UNATTRIBUTED_BR_ALERT_MIN_SCORE_PCT)
    tier = "Muito Alta" if prob >= 82 else ("Alta" if prob >= 72 else "Moderada")
    seen_r: set[str] = set()
    top_reasons: list[str] = []
    for _w, label in sorted(weighted_reasons, key=lambda x: -x[0]):
        if label and label not in seen_r:
            seen_r.add(label)
            top_reasons.append(label)
        if len(top_reasons) >= 4:
            break
    return {
        "triggered": triggered,
        "probability_pct": prob if triggered else 0,
        "confidence_tier": tier if triggered else "Baixa",
        "top_reasons": top_reasons,
    }


def fetch_br_community_reference(
    *,
    url: str = BR_COMMUNITY_URL,
    local_path: Path | None = None,
    allow_network: bool = True,
) -> dict[str, Any]:
    """Baixa `br_community.json` (somente-leitura, HTTPS endurecido + anti-redirect + limite 2 MB) com fallback silencioso."""
    if local_path is not None and local_path.is_file() and not local_path.is_symlink():
        try:
            if local_path.stat().st_size <= MAX_BR_COMMUNITY_BYTES:
                data = json.loads(local_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    if not allow_network:
        return {}
    try:
        validate_https_endpoint(
            url,
            ALLOWED_RADAR_HOSTS,
            path_prefix="/nigosky/coh3-br-lobby-radar/main/",
            path_regex=BR_COMMUNITY_PATH_RE,
            allow_query=False,
        )
        opener = build_no_redirect_https_opener()
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": TRACKER_USER_AGENT,
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
            },
            method="GET",
        )
        with opener.open(req, timeout=8) as resp:
            raw = read_bounded_http_body(resp, max_bytes=MAX_BR_COMMUNITY_BYTES)
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("[SMURF ALERT] br_community.json indisponível (usando roster local): %s", redact_secrets(exc))
        return {}


@dataclass
class SmurfAlertContext:
    """Contexto pré-carregado por ciclo para análise forense em tempo real com custo mínimo de rede."""

    reference_mains: dict[int, dict[str, Any]]
    main_families: dict[int, set[int]]
    confirmed_veteran_pids: set[int]
    cataloged_smurf_pids: set[int]
    known_br_pids: set[int]
    telemetry_by_pid: dict[int, PlayerTelemetry]
    probe_cache: dict[int, dict[str, Any]]
    osint_client: SteamProfileOSINTClient
    remaining_probe_budget: int = MAX_LIVE_OPPONENT_PROBES_PER_CYCLE
    cache_dirty: bool = False
    now_ts: int = 0
    pid_aliases: dict[int, str] = field(default_factory=dict)
    kryptonite_hydrated: bool = False


def _is_cataloged_smurf_row(row: dict[str, Any]) -> bool:
    pid = int(row.get("profile_id", 0) or 0)
    if pid in KNOWN_SMURF_MAIN_PIDS:
        return True
    if int(row.get("merged_into_profile_id", 0) or 0) > 0:
        return True
    if str(row.get("smurf_of") or "").strip():
        return True
    orig = str(row.get("original_alias") or row.get("alias") or "")
    return bool(_SMURF_LABEL_RE.search(orig))


def _load_probe_cache(db: Any, now_ts: int) -> dict[int, dict[str, Any]]:
    raw = str(db.get_state(SMURF_PROBE_CACHE_KEY) or "").strip() if db is not None else ""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    cleaned: dict[int, dict[str, Any]] = {}
    for k, v in parsed.items():
        if not isinstance(v, dict):
            continue
        try:
            pid = int(k)
            ts = int(v.get("ts", 0) or 0)
        except (TypeError, ValueError):
            continue
        ttl = VETERAN_CACHE_TTL_SEC if v.get("status") == "veteran" else SMURF_PROBE_TTL_SEC
        if pid > 0 and ts > 0 and (now_ts - ts) <= ttl:
            cleaned[pid] = v
    return cleaned


def save_smurf_probe_cache(db: Any, ctx: SmurfAlertContext) -> None:
    """Persiste cache enxuto (máx 400 contas) de probes de smurf em `bot_state`."""
    if db is None or not ctx.cache_dirty:
        return
    items = sorted(
        ((int(pid), rec) for pid, rec in ctx.probe_cache.items() if int(pid) > 0 and isinstance(rec, dict)),
        key=lambda kv: int(kv[1].get("ts", 0) or 0),
        reverse=True,
    )[:400]
    payload = json.dumps({str(pid): rec for pid, rec in items}, ensure_ascii=False, separators=(",", ":"))
    db.set_state(SMURF_PROBE_CACHE_KEY, payload)
    ctx.cache_dirty = False


def _hydrate_rivalry_kryptonite_for_live_probe(
    db: Any,
    opp_tel: PlayerTelemetry,
    ctx: SmurfAlertContext,
) -> None:
    """
    Hidrata sob demanda (0ms em ciclos sem probe) o histórico permanente 2023+ de SQLite:
    1) `kryptonite_matches` (mapas + BGs inimigos) uma única vez por ciclo para os Veteranos;
    2) `nemesis_matches` via índice `idx_nemesis_all_opp` (~2ms) apenas para os adversários
       efetivamente enfrentados por `opp_tel`, sem dupla contagem de `match_id`.
    """
    if db is None:
        return

    if not ctx.kryptonite_hydrated and hasattr(db, "get_kryptonite_profile_by_tracked_pids"):
        ctx.kryptonite_hydrated = True
        try:
            target_pids = sorted(set(ctx.confirmed_veteran_pids) | set(ctx.telemetry_by_pid.keys()))
            krypt_by_pid = db.get_kryptonite_profile_by_tracked_pids(target_pids) or {}
            for tpid, prof in krypt_by_pid.items():
                tpid_i = int(tpid or 0)
                if tpid_i <= 0 or not isinstance(prof, dict):
                    continue
                mtel = ctx.telemetry_by_pid.setdefault(tpid_i, PlayerTelemetry(profile_id=tpid_i))
                k_maps = prof.get("map_wl") or {}
                if isinstance(k_maps, dict) and k_maps:
                    cur_map_games = sum(int(v[0]) + int(v[1]) for v in mtel.map_wl.values() if len(v) >= 2)
                    life_map_games = sum(int(v[0]) + int(v[1]) for v in k_maps.values() if len(v) >= 2)
                    if life_map_games > cur_map_games:
                        mtel.map_wl = {
                            str(mk): [max(0, int(mv[0])), max(0, int(mv[1]))]
                            for mk, mv in k_maps.items()
                            if str(mk).strip() and isinstance(mv, (list, tuple)) and len(mv) >= 2
                        }
                k_bgs = prof.get("enemy_bg_wl") or {}
                if isinstance(k_bgs, dict) and k_bgs:
                    norm_bgs: dict[str, list[int]] = {}
                    for raw_bk, bv in k_bgs.items():
                        if not isinstance(bv, (list, tuple)) or len(bv) < 2:
                            continue
                        lbl = _normalize_bg_label(raw_key=str(raw_bk), raw_name=str(raw_bk))
                        if not lbl:
                            continue
                        rec = norm_bgs.setdefault(lbl, [0, 0])
                        rec[0] += max(0, int(bv[0]))
                        rec[1] += max(0, int(bv[1]))
                    cur_bg_games = sum(int(v[0]) + int(v[1]) for v in mtel.enemy_bg_wl.values() if len(v) >= 2)
                    life_bg_games = sum(int(v[0]) + int(v[1]) for v in norm_bgs.values())
                    if life_bg_games > cur_bg_games:
                        mtel.enemy_bg_wl = norm_bgs
        except Exception as exc:
            logger.debug("[SMURF ALERT] Falha ao hidratar kryptonite_matches: %s", redact_secrets(exc))

    if opp_tel.opp_wl and hasattr(db, "get_nemesis_matches_for_opponents"):
        try:
            nem_rows = db.get_nemesis_matches_for_opponents(opp_tel.opp_wl.keys()) or []
            for r in nem_rows:
                tpid = int(r.get("tracked_profile_id", 0) or 0)
                opid = int(r.get("opponent_profile_id", 0) or 0)
                mid = int(r.get("match_id", 0) or 0)
                if tpid <= 0 or opid <= 0 or tpid not in ctx.reference_mains:
                    continue
                mtel = ctx.telemetry_by_pid.setdefault(tpid, PlayerTelemetry(profile_id=tpid))
                if mid > 0 and mid in mtel._seen_opp_mids:
                    continue
                if mid > 0:
                    mtel._seen_opp_mids.add(mid)
                if opid in mtel.opp_wl or len(mtel.opp_wl) < 4000:
                    rec = mtel.opp_wl.setdefault(opid, [0, 0])
                    rec[0 if r.get("win") else 1] += 1
                    ud = int(r.get("utc_day", 0) or 0)
                    if ud > 0:
                        days = mtel.opp_days.setdefault(opid, set())
                        if len(days) < 30:
                            days.add(ud)
                oal = strip_unsafe_chars(r.get("opponent_alias") or "")[:40]
                if oal and not _is_placeholder_alias(oal):
                    ctx.pid_aliases.setdefault(opid, oal)
        except Exception as exc:
            logger.debug("[SMURF ALERT] Falha ao hidratar nemesis_matches para probe: %s", redact_secrets(exc))


def build_smurf_alert_context(
    db: Any,
    relic: Any,
    custom_players: list[dict[str, Any]] | None = None,
    *,
    br_community_data: dict[str, Any] | None = None,
    osint_client: SteamProfileOSINTClient | None = None,
    allow_network: bool = True,
    max_live_probes: int = MAX_LIVE_OPPONENT_PROBES_PER_CYCLE,
    now_ts: int | None = None,
) -> SmurfAlertContext:
    """Constrói o contexto forense do ciclo combinando Veteranos, Outros BR, Top 60 BR, raw histories em memória e SQLite."""
    ts_now = int(now_ts) if now_ts is not None else int(time.time())
    comm = br_community_data if isinstance(br_community_data, dict) else fetch_br_community_reference(allow_network=allow_network)

    comm_players: dict[int, dict[str, Any]] = {}
    for sec in ("players", "dormant_players"):
        sec_map = comm.get(sec)
        if not isinstance(sec_map, dict):
            continue
        for k, v in sec_map.items():
            if not isinstance(v, dict):
                continue
            try:
                pid = int(v.get("profile_id") or k)
            except (TypeError, ValueError):
                continue
            if pid > 0 and pid not in comm_players:
                comm_players[pid] = v

    reference_mains: dict[int, dict[str, Any]] = {}
    main_families: dict[int, set[int]] = defaultdict(set)
    confirmed_veteran_pids: set[int] = set()
    cataloged_smurf_pids: set[int] = set(KNOWN_SMURF_MAIN_PIDS.keys())
    known_br_pids: set[int] = set(comm_players.keys())

    for smurf_pid, main_pid in KNOWN_SMURF_MAIN_PIDS.items():
        main_families[main_pid].add(main_pid)
        main_families[main_pid].add(smurf_pid)

    all_roster_rows = list(custom_players or CORE_BR_ROSTER) + list(MANUAL_OTHER_BR_DISPLAY)
    alias_to_main_pid: dict[str, int] = {}

    for row in all_roster_rows:
        if not isinstance(row, dict):
            continue
        pid = int(row.get("profile_id", 0) or 0)
        if pid <= 0:
            continue
        known_br_pids.add(pid)
        if _is_cataloged_smurf_row(row):
            cataloged_smurf_pids.add(pid)
            mpid = int(row.get("merged_into_profile_id", 0) or KNOWN_SMURF_MAIN_PIDS.get(pid, 0) or 0)
            if mpid > 0:
                main_families[mpid].add(mpid)
                main_families[mpid].add(pid)
            continue

        confirmed_veteran_pids.add(pid)
        orig = strip_unsafe_chars(row.get("original_alias") or row.get("alias") or f"Player {pid}")[:40]
        base_comm = comm_players.get(pid) or {}
        if pid not in reference_mains:
            reference_mains[pid] = {
                "profile_id": pid,
                "steam_id": str(row.get("steam_id") or base_comm.get("steam_id") or "").replace("/steam/", "").strip(),
                "alias": orig,
                "country": "br",
                "max_elo": int(base_comm.get("max_elo", 0) or 0),
                "total_matches": int(base_comm.get("total_matches", 0) or 0),
                "known_aliases": list(row.get("known_aliases") or []),
                "is_veterano": True,
            }
            main_families[pid].add(pid)
            alias_to_main_pid[orig.casefold()] = pid

    # Vincula smurfs que citam "(Smurf: <Main>)" por nome caso ainda não ligadas por profile_id
    for row in all_roster_rows:
        if not isinstance(row, dict) or not _is_cataloged_smurf_row(row):
            continue
        pid = int(row.get("profile_id", 0) or 0)
        if pid <= 0:
            continue
        m = _SMURF_LABEL_RE.search(str(row.get("original_alias") or row.get("alias") or ""))
        owner_name = str(row.get("smurf_of") or (m.group(1) if m else "")).strip()
        if owner_name and owner_name.casefold() in alias_to_main_pid:
            mpid = alias_to_main_pid[owner_name.casefold()]
            main_families[mpid].add(mpid)
            main_families[mpid].add(pid)

    # Adiciona Top 60 BRs ativos de br_community.json como potenciais mains (excluindo smurfs catalogadas)
    ranked_comm = sorted(
        (
            p for pid, p in comm_players.items()
            if pid not in cataloged_smurf_pids and int(p.get("max_elo", 0) or 0) >= 1250
        ),
        key=lambda x: (-int(x.get("max_elo", 0) or 0), -int(x.get("total_matches", 0) or 0)),
    )[:60]
    for p in ranked_comm:
        pid = int(p.get("profile_id", 0) or 0)
        if pid <= 0 or pid in reference_mains:
            continue
        reference_mains[pid] = {
            "profile_id": pid,
            "steam_id": str(p.get("steam_id") or "").replace("/steam/", "").strip(),
            "alias": strip_unsafe_chars(p.get("alias") or f"Player {pid}")[:40],
            "country": str(p.get("country") or "br").strip().lower(),
            "max_elo": int(p.get("max_elo", 0) or 0),
            "total_matches": int(p.get("total_matches", 0) or 0),
            "known_aliases": [],
            "is_veterano": False,
        }
        main_families[pid].add(pid)

    # Popula telemetria dos Veteranos sem 0 chamadas extras usando payloads brutos já baixados no Pass 1!
    telemetry_by_pid: dict[int, PlayerTelemetry] = {}
    pid_aliases: dict[int, str] = {}
    raw_histories = relic.get_cached_raw_histories() if (relic is not None and hasattr(relic, "get_cached_raw_histories")) else {}
    for pid, raw_hist in raw_histories.items():
        pid_i = int(pid)
        if pid_i <= 0:
            continue
        tel = telemetry_by_pid.setdefault(pid_i, PlayerTelemetry(profile_id=pid_i))
        tel.observe_raw_relic_history(raw_hist, known_br_pids=known_br_pids, pid_aliases=pid_aliases)
        if pid_i in reference_mains and tel.mode_elo_max:
            best_m_elo = max(tel.mode_elo_max.values())
            if best_m_elo > int(reference_mains[pid_i].get("max_elo", 0) or 0):
                reference_mains[pid_i]["max_elo"] = best_m_elo

    # Complementa telemetria dos Veteranos com janela recente (45d) já persistida no SQLite
    if db is not None and hasattr(db, "get_recent_recorded_matches"):
        try:
            recent_rows = db.get_recent_recorded_matches(
                limit=500,
                only_active_players=False,
                min_completion_time=max(0, ts_now - 45 * 86400),
            )
            for row in recent_rows:
                tpid = int(row.get("tracked_profile_id", 0) or 0)
                if tpid <= 0:
                    continue
                tel = telemetry_by_pid.setdefault(tpid, PlayerTelemetry(profile_id=tpid))
                tel.observe_sqlite_match_row(row, pid_aliases=pid_aliases)
        except Exception as exc:
            logger.debug("[SMURF ALERT] Falha ao carregar telemetria SQLite auxiliar: %s", redact_secrets(exc))

    return SmurfAlertContext(
        reference_mains=reference_mains,
        main_families=dict(main_families),
        confirmed_veteran_pids=confirmed_veteran_pids,
        cataloged_smurf_pids=cataloged_smurf_pids,
        known_br_pids=known_br_pids,
        telemetry_by_pid=telemetry_by_pid,
        probe_cache=_load_probe_cache(db, ts_now),
        osint_client=osint_client if osint_client is not None else SteamProfileOSINTClient(allow_network=allow_network),
        remaining_probe_budget=max(0, int(max_live_probes)),
        now_ts=ts_now,
        pid_aliases=pid_aliases,
    )


def _should_probe_opponent(opp: dict[str, Any], ctx: SmurfAlertContext) -> bool:
    """Triagem rápida (0 chamadas HTTP) para decidir se o oponente merece investigação forense."""
    opp_pid = int(opp.get("profile_id", 0) or 0)
    if opp_pid <= 0:
        return False
    if opp_pid in ctx.confirmed_veteran_pids or opp_pid in ctx.cataloged_smurf_pids:
        return False
    opp_sid = str(opp.get("steam_id") or "").replace("/steam/", "").strip()
    if opp_sid and not STEAM_ID64_VALID_RE.fullmatch(opp_sid):
        return False

    ctry = str(opp.get("country") or "").strip().lower()
    alias = strip_unsafe_chars(opp.get("alias") or "")[:40]
    opp_elo = max(int(opp.get("old_elo") or 0), int(opp.get("new_elo") or 0))

    if ctry in ("br", "", "??", "unknown"):
        return True
    if opp_pid in ctx.known_br_pids:
        return True
    pt_hit, _ = _detect_ptbr_linguistic_signal(alias)
    if pt_hit or _is_throwaway_or_barcode_nick(alias):
        return True
    for main in ctx.reference_mains.values():
        pts, _ = _alias_similarity_bonus(alias, str(main.get("alias") or ""), {alias}, set(main.get("known_aliases") or ()))
        if pts >= 10:
            return True
    # Conta nova + ELO alto mesmo sob bandeira estrangeira (smurf disfarçada)
    s32 = _steam_account32(opp_sid)
    if opp_elo >= 1250 and (opp_pid >= 850_000 or s32 >= 900_000_000):
        return True
    return False


def _evaluate_opponent_against_br_pool(
    opp: dict[str, Any],
    *,
    match_participant_pids: set[int],
    tracked_alias: str,
    relic: Any,
    ctx: SmurfAlertContext,
    db: Any = None,
) -> dict[str, Any] | None:
    opp_pid = int(opp.get("profile_id", 0) or 0)
    opp_alias = strip_unsafe_chars(opp.get("alias") or f"Player {opp_pid}")[:40]
    opp_sid = str(opp.get("steam_id") or "").replace("/steam/", "").strip()
    opp_ctry = str(opp.get("country") or "").strip().lower()
    opp_match_elo = max(int(opp.get("old_elo") or 0), int(opp.get("new_elo") or 0))

    # Regra absoluta ("Um Smurf nunca enfrenta a conta original"): consulta confrontos históricos desde 2023 em `nemesis_matches`
    historical_faced_pids: set[int] = set()
    if db is not None and hasattr(db, "get_tracked_pids_who_faced_opponent") and opp_pid > 0:
        try:
            historical_faced_pids = set(db.get_tracked_pids_who_faced_opponent(opp_pid) or ())
        except Exception as exc:
            logger.debug("[SMURF ALERT] Falha na consulta histórica nemesis_matches pid=%d: %s", opp_pid, redact_secrets(exc))
    disqualified_main_pids = set(match_participant_pids) | historical_faced_pids

    cached = ctx.probe_cache.get(opp_pid)
    if isinstance(cached, dict):
        if cached.get("status") == "veteran" or cached.get("status") == "clean":
            return None
        if cached.get("status") == "alert" and isinstance(cached.get("alert"), dict):
            alert_copy = dict(cached["alert"])
            sus_mpid = int(alert_copy.get("suspected_main_profile_id", 0) or 0)
            if sus_mpid > 0:
                sus_fam = ctx.main_families.get(sus_mpid, {sus_mpid})
                if sus_fam & disqualified_main_pids:
                    return None
            alert_copy["opponent_alias"] = opp_alias
            alert_copy["tracked_alias"] = tracked_alias
            return alert_copy

    if ctx.remaining_probe_budget <= 0 or relic is None:
        return None
    ctx.remaining_probe_budget -= 1

    # 1. Consulta getPersonalStat da conta adversária
    stats_map = relic.fetch_profile_summary_stats([opp_pid]) if hasattr(relic, "fetch_profile_summary_stats") else {}
    stat = stats_map.get(opp_pid) or {}
    total_matches = int(stat.get("total_matches", 0) or 0)
    max_elo = max(int(stat.get("max_elo", 0) or 0), opp_match_elo)
    eff_ctry = str(stat.get("country") or opp_ctry).strip().lower()
    eff_sid = str(stat.get("steam_id") or opp_sid).replace("/steam/", "").strip()
    eff_alias = strip_unsafe_chars(stat.get("alias") or opp_alias)[:40]

    if total_matches > CONSOLIDATED_VETERAN_MIN_MATCHES:
        ctx.probe_cache[opp_pid] = {"ts": ctx.now_ts, "status": "veteran", "total_matches": total_matches}
        ctx.cache_dirty = True
        return None
    if max_elo > 0 and max_elo < 1150 and opp_match_elo < 1150:
        ctx.probe_cache[opp_pid] = {"ts": ctx.now_ts, "status": "clean"}
        ctx.cache_dirty = True
        return None

    # 2. Baixa histórico bruto Relic + OSINT Steam público da conta adversária
    raw_opp_hist = relic.fetch_raw_match_history(opp_pid) if hasattr(relic, "fetch_raw_match_history") else None
    opp_tel = PlayerTelemetry(profile_id=opp_pid, steam_id=eff_sid, alias=eff_alias, country=eff_ctry)
    opp_tel.observe_raw_relic_history(raw_opp_hist, known_br_pids=ctx.known_br_pids, pid_aliases=ctx.pid_aliases)
    if historical_faced_pids:
        opp_tel.co_played_with.update(historical_faced_pids)
    opp_osint = ctx.osint_client.fetch_profile_osint(eff_sid) if eff_sid else {}

    # 2B. Hidratação sob demanda (0ms em ciclos sem probe) do histórico 2023+ de Nêmesis & Criptonitas do SQLite
    _hydrate_rivalry_kryptonite_for_live_probe(db, opp_tel, ctx)

    cand_meta = {
        "profile_id": opp_pid,
        "steam_id": eff_sid,
        "alias": eff_alias,
        "country": eff_ctry,
        "max_elo": max_elo,
        "total_matches": total_matches,
        "total_wins": int(stat.get("total_wins", 0) or 0),
        "total_losses": int(stat.get("total_losses", 0) or 0),
        "mode_elo_max": dict(stat.get("mode_elo_max") or {}),
    }

    # 3. Seleciona até MAX_EXTRA_MAIN_PROBES_PER_OPPONENT mains não-Veteranos mais plausíveis para baixar histórico bruto
    non_vet_candidates: list[tuple[float, int]] = []
    for mpid, main in ctx.reference_mains.items():
        if mpid in disqualified_main_pids or mpid in ctx.telemetry_by_pid:
            continue
        fam = ctx.main_families.get(mpid, {mpid})
        if (opp_tel.co_played_with & fam) or (disqualified_main_pids & fam):
            continue
        m_elo = int(main.get("max_elo", 0) or 0)
        if m_elo > 0 and max_elo > 0 and abs(m_elo - max_elo) > 350:
            continue
        prio = 0.0
        a_pts, _ = _alias_similarity_bonus(eff_alias, str(main.get("alias") or ""), opp_tel.seen_aliases, set(main.get("known_aliases") or ()))
        prio += float(a_pts) * 2.0
        if m_elo > 0 and max_elo > 0:
            prio += max(0.0, 20.0 - abs(m_elo - max_elo) / 20.0)
        # Prioriza Outros Brasileiros com histórico conhecido de smurf (General Winter, Alekel, SKOBADARK)
        if len(fam) >= 2:
            prio += 15.0
        non_vet_candidates.append((prio, mpid))

    for _prio, mpid in sorted(non_vet_candidates, reverse=True)[:MAX_EXTRA_MAIN_PROBES_PER_OPPONENT]:
        if hasattr(relic, "fetch_raw_match_history"):
            raw_m = relic.fetch_raw_match_history(mpid)
            if raw_m:
                mtel = ctx.telemetry_by_pid.setdefault(mpid, PlayerTelemetry(profile_id=mpid))
                mtel.observe_raw_relic_history(raw_m, known_br_pids=ctx.known_br_pids, pid_aliases=ctx.pid_aliases)

    # 4. Pontua contra todas as contas principais BR elegíveis (excluindo participantes da MESMA partida e confrontos históricos 2023+!)
    best_match: dict[str, Any] | None = None
    for mpid, main in ctx.reference_mains.items():
        fam = ctx.main_families.get(mpid, {mpid})
        if fam & disqualified_main_pids:
            continue
        main_tel = ctx.telemetry_by_pid.get(mpid)
        if main_tel is None:
            continue
        fam_intervals: list[tuple[int, int]] = []
        for fpid in fam:
            if fpid != mpid and fpid in ctx.telemetry_by_pid:
                fam_intervals.extend(ctx.telemetry_by_pid[fpid].intervals)

        # Só busca OSINT do main se houver pista real de avatar/nick/localização ou score prévio promissor
        main_osint: dict[str, Any] = {}
        scored_pre = score_live_smurf_pair(
            cand_meta,
            main,
            opp_tel,
            main_tel,
            main_family_pids=fam,
            family_intervals=fam_intervals,
            cand_osint=opp_osint,
            main_osint=None,
            known_br_pids=ctx.known_br_pids,
            pid_aliases=ctx.pid_aliases,
        )
        if (
            not scored_pre["disqualified_reason"]
            and opp_osint.get("avatar_hash")
            and not opp_osint.get("is_default_avatar")
            and scored_pre["probability_pct"] >= 35
            and main.get("steam_id")
        ):
            main_osint = ctx.osint_client.fetch_profile_osint(str(main["steam_id"]))
            if main_osint:
                scored_pre = score_live_smurf_pair(
                    cand_meta,
                    main,
                    opp_tel,
                    main_tel,
                    main_family_pids=fam,
                    family_intervals=fam_intervals,
                    cand_osint=opp_osint,
                    main_osint=main_osint,
                    known_br_pids=ctx.known_br_pids,
                    pid_aliases=ctx.pid_aliases,
                )

        if (
            not scored_pre["disqualified_reason"]
            and int(scored_pre["probability_pct"]) >= ATTRIBUTED_ALERT_MIN_PROB_PCT
            and int(scored_pre["behavioral_signals"]) >= 2
            and int(scored_pre["identity_anchor_signals"]) >= 1
        ):
            if best_match is None or int(scored_pre["probability_pct"]) > int(best_match["probability_pct"]):
                best_match = scored_pre

    alert_obj: dict[str, Any] | None = None
    if best_match is not None:
        alert_obj = {
            "kind": "attributed",
            "opponent_profile_id": opp_pid,
            "opponent_alias": opp_alias,
            "opponent_country": eff_ctry,
            "tracked_alias": tracked_alias,
            "suspected_main_profile_id": int(best_match["main_profile_id"]),
            "suspected_main_alias": str(best_match["main_alias"]),
            "probability_pct": int(best_match["probability_pct"]),
            "confidence_tier": str(best_match["confidence_tier"]),
            "top_reasons": list(best_match["top_reasons"])[:4],
        }
    else:
        unattr = score_unattributed_br_burner(
            cand_meta,
            opp_tel,
            cand_osint=opp_osint,
            known_br_pids=ctx.known_br_pids,
        )
        if unattr["triggered"]:
            alert_obj = {
                "kind": "unattributed_br",
                "opponent_profile_id": opp_pid,
                "opponent_alias": opp_alias,
                "opponent_country": eff_ctry,
                "tracked_alias": tracked_alias,
                "suspected_main_profile_id": 0,
                "suspected_main_alias": "",
                "probability_pct": int(unattr["probability_pct"]),
                "confidence_tier": str(unattr["confidence_tier"]),
                "top_reasons": list(unattr["top_reasons"])[:4],
            }

    if alert_obj is not None:
        ctx.probe_cache[opp_pid] = {"ts": ctx.now_ts, "status": "alert", "alert": dict(alert_obj)}
    else:
        ctx.probe_cache[opp_pid] = {"ts": ctx.now_ts, "status": "clean"}
    ctx.cache_dirty = True
    return alert_obj


def enrich_group_with_smurf_alerts(
    db: Any,
    relic: Any,
    grp: dict[str, Any],
    *,
    ctx: SmurfAlertContext,
) -> list[dict[str, Any]]:
    """
    Analisa todos os oponentes desconhecidos enfrentados por Veteranos na partida `grp`.
    Se detectar possível smurf de outro brasileiro (atribuída ou burner BR), anexa `grp['smurf_alerts']`
    e persiste em `recorded_matches.smurf_alerts_json` para sobreviver a PATCHes retroativos de Battlegroups.
    """
    recs = grp.get("records") or ([grp["primary"]] if isinstance(grp.get("primary"), dict) else [])
    if not recs:
        return []
    primary = grp.get("primary") or recs[0]

    # Reutiliza alertas já persistidos no SQLite caso a partida já tenha sido analisada
    existing = grp.get("smurf_alerts") or primary.get("smurf_alerts") or []
    if isinstance(existing, list) and existing:
        valid_existing = [a for a in existing if isinstance(a, dict) and int(a.get("probability_pct", 0) or 0) > 0]
        if valid_existing:
            grp["smurf_alerts"] = valid_existing
            return valid_existing

    mode_str = str(primary.get("mode") or "")
    if mode_str not in AUTOMATCH_MODES and mode_str != "Custom":
        return []

    # Todos os participantes da partida (ninguém que jogou na MESMA partida pode ser dono da smurf adversária)
    match_participant_pids: set[int] = set()
    opponents_to_check: dict[int, tuple[dict[str, Any], str]] = {}
    for rec in recs:
        tpid = int(rec.get("tracked_profile_id", 0) or 0)
        talias = strip_unsafe_chars(rec.get("tracked_alias") or f"Player {tpid}")[:40]
        if tpid > 0:
            match_participant_pids.add(tpid)
        for al in rec.get("allies") or []:
            if isinstance(al, dict):
                apid = int(al.get("profile_id", 0) or 0)
                if apid > 0:
                    match_participant_pids.add(apid)
        for opp in rec.get("opponents") or []:
            if not isinstance(opp, dict):
                continue
            opid = int(opp.get("profile_id", 0) or 0)
            if opid > 0:
                match_participant_pids.add(opid)
                if opid not in opponents_to_check:
                    opponents_to_check[opid] = (opp, talias)

    alerts: list[dict[str, Any]] = []
    for opid, (opp, talias) in opponents_to_check.items():
        if not _should_probe_opponent(opp, ctx):
            continue
        alert = _evaluate_opponent_against_br_pool(
            opp,
            match_participant_pids=match_participant_pids,
            tracked_alias=talias,
            relic=relic,
            ctx=ctx,
            db=db,
        )
        if alert is not None:
            alerts.append(alert)

    alerts.sort(key=lambda a: (-int(a.get("probability_pct", 0) or 0), str(a.get("opponent_alias") or "").casefold()))
    if alerts:
        grp["smurf_alerts"] = alerts
        if isinstance(grp.get("primary"), dict):
            grp["primary"]["smurf_alerts"] = alerts
        for r in recs:
            r["smurf_alerts"] = alerts
        mid = int(grp.get("match_id") or primary.get("match_id") or 0)
        if db is not None and mid > 0 and hasattr(db, "update_match_smurf_alerts"):
            db.update_match_smurf_alerts(mid, alerts)
    return alerts

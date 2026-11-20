"""Cliente endurecido e otimizado da API Comunitária da Relic para Company of Heroes 3 (Steam)."""

from __future__ import annotations

import ast
import codecs
import concurrent.futures
import csv
import html
import io
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any

from security import (
    atomic_write_text,
    build_no_redirect_https_opener,
    read_bounded_http_body,
    redact_secrets,
    sanitize_csv_cell,
    validate_https_endpoint,
)

logger = logging.getLogger("coh3_br.relic_api")

BASE_URL = "https://coh3-api.reliclink.com/community/leaderboard"
ALLOWED_RELIC_HOSTS: frozenset[str] = frozenset({"coh3-api.reliclink.com"})
TITLE_STEAM = "coh3"
SOUTH_AMERICA_REGION_ID = 2074438
MAX_RELIC_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB limite rígido (fio e pós-descompressão Gzip)
MAX_RELIC_DIRECT_HISTORY_BYTES = 20 * 1024 * 1024  # 20 MB limite seguro para histórico estendido getRecentMatchHistory

# Open Data público e oficial do site coh3stats.com (https://coh3stats.com/other/open-data)
COH3STATS_OPEN_DATA_BASE_URL = "https://storage.coh3stats.com/matches"
ALLOWED_COH3STATS_HOSTS: frozenset[str] = frozenset({"storage.coh3stats.com"})
COH3STATS_OPEN_DATA_PATH_RE = re.compile(r"^/matches/matches-\d{9,11}\.json$")
MAX_COH3STATS_WIRE_BYTES = 64 * 1024 * 1024  # 64 MB teto rígido no fio
MAX_COH3STATS_STREAM_BYTES = 300 * 1024 * 1024  # 300 MB teto rígido no fluxo descomprimido
MAX_COH3STATS_OBJECT_BUFFER_CHARS = 4 * 1024 * 1024  # 4 MB teto de buffer por partida individual

# Estado público somente-leitura do Radar de Lobby dos Veteranos BR (nigosky/coh3-br-lobby-radar)
VETERANOS_RADAR_STATE_URL = "https://raw.githubusercontent.com/nigosky/coh3-br-lobby-radar/main/state.json"
ALLOWED_RADAR_HOSTS: frozenset[str] = frozenset({"raw.githubusercontent.com"})
VETERANOS_RADAR_PATH_RE = re.compile(r"^/nigosky/coh3-br-lobby-radar/main/state\.json$")
MAX_RADAR_STATE_BYTES = 256 * 1024  # 256 KB teto rígido para state.json do Radar

# Consulta somente-leitura de Battlegroups em páginas canônicas públicas do cohdb.com (respeitando robots.txt)
COHDB_BASE_URL = "https://cohdb.com"
ALLOWED_COHDB_HOSTS: frozenset[str] = frozenset({"cohdb.com"})
COHDB_PLAYER_MATCHES_PATH_RE = re.compile(r"^/players/\d{1,12}/matches$")
COHDB_REPLAY_PATH_RE = re.compile(r"^/replays/\d{1,12}$")
MAX_COHDB_HTML_BYTES = 512 * 1024  # 512 KB teto rígido por página HTML do cohdb.com

# Catálogo oficial dos 28 Battlegroups do Company of Heroes 3 (Patch 3.0.x)
OFFICIAL_COH3_BATTLEGROUPS: dict[str, str] = {
    # US Forces
    "armored_us": "Armored",
    "free_french_us": "Free French",
    "infantry_us": "Advanced Infantry",
    "italian_partisan_us": "Italian Partisan",
    "paratroopers_us": "Airborne",
    "spec_ops_us": "Special Operations",
    "special_weapons_us": "Heavy Weapons",
    # British Forces
    "air_and_sea_uk": "Air and Sea",
    "armored_uk": "Heavy Armor",
    "ausdefense_uk": "Australian Defense",
    "can_shock_uk": "Canadian Shock",
    "indian_artillery_uk": "Indian Artillery",
    "polish_cavalry_uk": "Polish Cavalry",
    "special_services_uk": "Special Service",
    # Wehrmacht
    "breakthrough_ger": "Breakthrough",
    "coastal_ger": "Italian Coastal",
    "last_stand_ger": "Last Stand",
    "luftwaffe_ger": "Luftwaffe",
    "mechanized_ger": "Mechanized",
    "siege_breaker_ger": "Siege Breaker",
    "terror_ger": "Terror",
    # Afrikakorps
    "armored_ak": "Armored Support",
    "combined_arms_ak": "Italian Combined Arms",
    "dak_battlefield_ak": "Battlefield Espionage",
    "elite_forces_ak": "Elite Forces",
    "italian_infantry_ak": "Italian Infantry",
    "kriegsmarine_ak": "Kriegsmarine",
    "panzerjager_kommand_ak": "Panzerjäger Kommand",
}

_BG_NAME_TO_KEY: dict[str, str] = {
    v.casefold(): k for k, v in OFFICIAL_COH3_BATTLEGROUPS.items()
}

# IDs oficiais das leaderboards Steam usadas pelo coh3stats.com
STEAM_LEADERBOARDS: dict[str, dict[str, int]] = {
    "1v1": {
        "american": 2130255,
        "british": 2130257,
        "dak": 2130259,
        "german": 2130261,
    },
    "2v2": {
        "american": 2130300,
        "british": 2130302,
        "dak": 2130304,
        "german": 2130306,
    },
    "3v3": {
        "american": 2130329,
        "british": 2130331,
        "dak": 2130333,
        "german": 2130335,
    },
    "4v4": {
        "american": 2130353,
        "british": 2130356,
        "dak": 2130358,
        "german": 2130360,
    },
}

LEADERBOARD_ID_TO_MODE_FACTION: dict[int, tuple[str, str]] = {
    lb_id: (m_name, f_name)
    for m_name, facs in STEAM_LEADERBOARDS.items()
    for f_name, lb_id in facs.items()
}

FALLBACK_RACES: dict[int, str] = {
    129494: "US Forces",
    181726: "US Forces",
    137123: "Wehrmacht",
    196502: "Wehrmacht",
    2056968: "Wehrmacht",
    197345: "British Forces",
    203852: "British Forces",
    211661: "British Forces",
    2057044: "British Forces",
    198437: "Afrikakorps",
    2057043: "Afrikakorps",
    2057045: "Afrikakorps",
}

FALLBACK_MATCH_TYPES: dict[int, str] = {
    0: "Custom",
    1: "1v1",
    2: "2v2",
    3: "Team Games (3v3)",
    4: "Team Games (4v4)",
    20: "1v1",
    21: "2v2",
    22: "Team Games (3v3)",
    23: "Team Games (4v4)",
}

AUTOMATCH_MODES = ("1v1", "2v2", "Team Games (3v3)", "Team Games (4v4)")

FACTION_SHORT: dict[str, str] = {
    "US Forces": "USF",
    "British Forces": "UKF",
    "Wehrmacht": "Wehr",
    "Afrikakorps": "DAK",
    "DAK": "DAK",
}

FACTIONS_ORDER = ("american", "british", "dak", "german")
FACTION_KEY_LABELS: dict[str, str] = {
    "american": "USF",
    "british": "UKF",
    "dak": "DAK",
    "german": "Wehr",
}

STUDY_MODE_GROUPS: dict[str, tuple[str, ...]] = {
    "1v1": ("1v1",),
    "2v2": ("2v2",),
    "Team Games": ("3v3", "4v4"),
}

MAP_PLAYER_PREFIX_RE = re.compile(r"^\s*\(\d+\)\s*")
MAP_SIZE_SUFFIX_RE = re.compile(r"_(2p|4p|6p|8p)(?=_|$)", re.IGNORECASE)
MAP_MK_SUFFIX_RE = re.compile(r"_(mkii|mkiii|mkiv|mkv|redux|mm)(?=_|$)", re.IGNORECASE)
_MAP_LOWERCASE_WORDS: frozenset[str] = frozenset({"in", "the", "of", "to", "and", "el", "della", "de", "da", "do", "du"})

# Nomes oficiais localizados dos mapas do Company of Heroes 3 (fonte: coh3stats.com / cohstats/coh3-data Patch 3.0.0)
OFFICIAL_COH3_MAP_NAMES: dict[str, str] = {
    "across_the_rhine_6p": "Across the Savio",
    "alamein_4p": "El Alamein",
    "ancona_railyard_2p": "Ancona Railyard",
    "angoville_farms_2p": "Angoville Farms",
    "benghazi_6p": "Benghazi",
    "black_gold_8p": "Black Gold",
    "bologna_2p": "Bologna",
    "butcher_and_bolt_2p": "Butcher & Bolt",
    "castello_8p": "Castello della Nebbia",
    "catania_crossing_6p": "Catania Crossing",
    "cliff_crossing_2p": "Taranto Coastline",
    "crossing_in_the_woods_2p": "Crossing in the Woods",
    "crossing_in_the_woods_4p": "Crossing in the Woods",
    "day_101_4p": "Day 101",
    "desert_airfield_6p_mkii": "Gazala Landing Ground",
    "desert_village_2p_mkiii": "Road to Tunis",
    "djebel_2p": "Djebel Pass",
    "djebel_4p": "Djebel Pass",
    "egletons_2p": "Égletons",
    "eindhoven": "Operation Eindhoven",
    "elst_outskirts_4p": "Elst Outskirts",
    "faymonville": "Faymonville",
    "foggia_airfield_winter_6p": "Foggia Airfield",
    "gabes_gap_6p": "Gabès Gap",
    "gardens_2p": "Gardens",
    "gardens_2p_mm": "Gardens",
    "gothic_line_8p": "The Gothic Line",
    "halfa_8p": "Alam el Halfa",
    "hill_400_8p": "Hill 400",
    "hoff_dam": "Dam Busters",
    "hoff_desert": "Qattara Depression",
    "hoff_forest": "The Alpine Wall",
    "hoff_gela_outskirts": "Gela Beachhead",
    "hoff_sousse_wetlands": "Fall of Sousse",
    "hoff_torrente": "Torrente Ruins",
    "industrial_railyard_6p_mkii": "L'Aquila",
    "langres_2p": "Langres",
    "langres_winter_2p": "Langres Winter",
    "longstop_hill_6p": "Longstop Hill",
    "lorraine_4p": "Lorraine",
    "mammut_8p": "Radarstation Mammut",
    "mignano_6p": "Mignano Summit",
    "mignano_6p_redux": "Mignano Summit",
    "monte_cavo_8p": "Monte Cavo",
    "montherme_6p": "Montherme",
    "mountain_ruins_6p": "Mignano Summit",
    "mountain_ruins_8p_mkii": "Mignano Gap",
    "oasis_depot_8p": "Oasis Depot",
    "oliveto_citra_8p": "Oliveto Citra",
    "pachino_2p": "Pachino Stalemate",
    "pisa_centrale_4p": "Pisa Centrale",
    "powderkeg_8p": "Powderkeg",
    "primosole_4p": "Road to Primosole",
    "primosole_6p": "Road to Primosole",
    "rails_and_sand_4p": "Campbell's Convoy",
    "rapido_river_8p": "Rapido River Crossing",
    "rapido_river_8p_redux": "Rapido River Crossing",
    "red_ball_express_8p": "Red Ball Express",
    "rural_castle_4p": "Aere Perennius",
    "rural_castle_winter_4p": "Aere Perennius Winter",
    "rural_town_2p_mkii": "Pachino Farmlands",
    "rural_town_4p": "Pachino Farmlands",
    "sangro_river_crossing_6p": "Sangro River Crossing",
    "santuario_4p": "Santuario",
    "sedjenane_6p": "Sedjenane Marshes",
    "semois_2p": "Semois",
    "semois_4p": "Semois",
    "sousse_stronghold_8p": "Sousse Stronghold",
    "sousse_wetlands_8p": "Sousse Wetlands",
    "steppe_8p": "Steppes",
    "torrente_4p_mkiii": "Torrente",
    "turin_8p": "Turin Steelworks",
    "tuscan_vineyard_2p": "Tuscan Vineyards",
    "twin_beach_2p_mkii": "Twin Beaches",
    "villa_fiore_2p_mkii": "Villa Fiore",
    "vire_river_valley_4p": "Vire River Valley",
    "wadi_darnah_4p": "Wadi Darnah",
    "winter_line_8p_mkii": "Winter Line",
}

_OFFICIAL_MAP_BASE_LOOKUP: dict[str, str] = {
    MAP_MK_SUFFIX_RE.sub("", k): v for k, v in OFFICIAL_COH3_MAP_NAMES.items()
}

STEAM_ID64_VALID_RE = re.compile(r"^7656119\d{10}$")
STEAM_URL_EXTRACT_RE = re.compile(r"steamcommunity\.com/profiles/(7656119\d{10})", re.IGNORECASE)
COH3STATS_PLAYER_URL_RE = re.compile(
    r"coh3stats\.com/(?:[a-z]{2}/)?players/(\d{1,12})(?:\D|$)",
    re.IGNORECASE,
)

# Lista fixa dos 44 jogadores brasileiros únicos monitorados (45 contas Steam vinculadas por SteamID64 imutável)
CORE_BR_ROSTER: list[dict[str, Any]] = [
    {"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro"},
    {"profile_id": 991764, "steam_id": "76561198115923932", "original_alias": "SaNgar [BR]"},
    {"profile_id": 1088455, "steam_id": "76561198108568598", "original_alias": "luiz_fmh"},
    {"profile_id": 735940, "steam_id": "76561198034510845", "original_alias": "Jimmy Duelista"},
    {"profile_id": 559962, "steam_id": "76561198062871244", "original_alias": "É o Gabe"},
    {"profile_id": 648514, "steam_id": "76561198372757032", "original_alias": "Halokoo"},
    {"profile_id": 35952, "steam_id": "76561198121484554", "original_alias": "Sauronzinho"},
    {"profile_id": 900358, "steam_id": "76561198070545853", "original_alias": "Margheriti"},
    {"profile_id": 691, "steam_id": "76561198001604015", "original_alias": "Vítor"},
    {"profile_id": 5768, "steam_id": "76561198205052385", "original_alias": "The Dog"},
    {"profile_id": 13450, "steam_id": "76561198284234077", "original_alias": "7 DIVISAO PHANTOM"},
    {"profile_id": 19747, "steam_id": "76561198058548575", "original_alias": "twitch.tv/luck22ai"},
    {"profile_id": 944488, "steam_id": "76561198063124280", "original_alias": "gbytes™"},
    {"profile_id": 21206, "steam_id": "76561198061434984", "original_alias": "hjax"},
    {
        "profile_id": 509690,
        "steam_id": "76561198053226112",
        "original_alias": "Alekel",
        "known_aliases": ["Minhoca de ferro!", "Minhoca de ferro", "Alekel"],
    },
    {"profile_id": 1114404, "steam_id": "76561198024118058", "original_alias": "Vikitor"},
    {"profile_id": 366826, "steam_id": "76561198014985380", "original_alias": "Lem22", "country": "us"},
    {"profile_id": 1282592, "steam_id": "76561198028644178", "original_alias": "SapoBoi_BR"},
    {"profile_id": 639157, "steam_id": "76561197979883434", "original_alias": "Itaperuna"},
    {"profile_id": 110078, "steam_id": "76561198024839791", "original_alias": "Bineto"},
    {"profile_id": 1143262, "steam_id": "76561198105073246", "original_alias": "Mazzaroppee"},
    {"profile_id": 55693, "steam_id": "76561197996817129", "original_alias": "BinhoBiceps"},
    {"profile_id": 337051, "steam_id": "76561197981615184", "original_alias": "Maiti"},
    {"profile_id": 1022333, "steam_id": "76561198264285149", "original_alias": "gaules"},
    {"profile_id": 32922, "steam_id": "76561197986271242", "original_alias": "Showtaro"},
    {"profile_id": 153969, "steam_id": "76561198005412401", "original_alias": "Cunha"},
    {
        "profile_id": 557890,
        "steam_id": "76561199538846112",
        "original_alias": "É o Gabe",
        "merged_into_profile_id": 559962,
        "merged_into_steam_id": "76561198062871244",
        "known_aliases": ["gabe44arg", "gabe444arg", "É o Gabe"],
    },
    {"profile_id": 26910, "steam_id": "76561197963741792", "original_alias": "nigo_BR ᵀᴹ"},
    {"profile_id": 6557, "steam_id": "76561198135142137", "original_alias": "Dragoness"},
    {"profile_id": 1226910, "steam_id": "76561198140782132", "original_alias": "Lupus Alba"},
    {"profile_id": 3895, "steam_id": "76561198054318813", "original_alias": "Liquid"},
    {"profile_id": 1005730, "steam_id": "76561199791811246", "original_alias": "arc"},
    {"profile_id": 31145, "steam_id": "76561197985268629", "original_alias": "vonMises"},
    {"profile_id": 58737, "steam_id": "76561197993922195", "original_alias": "INFIEL"},
    {"profile_id": 431802, "steam_id": "76561198000099422", "original_alias": "Conflict.BR"},
    {"profile_id": 59864, "steam_id": "76561198123446420", "original_alias": "Lion Heart"},
    {"profile_id": 84821, "steam_id": "76561198076576055", "original_alias": "TJBR"},
    {"profile_id": 99722, "steam_id": "76561198021071716", "original_alias": "MonteiroBR"},
    {"profile_id": 31061, "steam_id": "76561198009056438", "original_alias": "ACB"},
    {"profile_id": 81751, "steam_id": "76561198080023560", "original_alias": "Razi"},
    {"profile_id": 28937, "steam_id": "76561198089948995", "original_alias": "Mjr Bruno"},
    {"profile_id": 737235, "steam_id": "76561198026394732", "original_alias": "meuqsaco"},
    {
        "profile_id": 23250,
        "steam_id": "76561198028378060",
        "original_alias": "Nargoth",
        "known_aliases": ["Nargoth de Bebbanburg", "Nargoth"],
    },
    {
        "profile_id": 1097608,
        "steam_id": "76561199498421192",
        "original_alias": "Winter Animal",
        "known_aliases": ["Superior Culture", "Winter Animal"],
    },
    {"profile_id": 975688, "steam_id": "76561197994245218", "original_alias": "Kefbr"},
]

_THREAD_LOCAL = threading.local()


def _get_thread_opener() -> urllib.request.OpenerDirector:
    opener = getattr(_THREAD_LOCAL, "opener", None)
    if opener is None:
        opener = build_no_redirect_https_opener()
        _THREAD_LOCAL.opener = opener
    return opener


def _extract_steam_id(raw_name: Any) -> str:
    s = str(raw_name or "").strip()
    if s.startswith("/steam/"):
        s = s[7:].strip()
    return s if STEAM_ID64_VALID_RE.fullmatch(s) else ""


def clean_map_name(raw_map: str) -> str:
    """Resolve o nome oficial do mapa no CoH3 (ex: 'rural_town_4p' -> 'Pachino Farmlands')."""
    raw = str(raw_map or "").strip()
    if not raw:
        return "Mapa Desconhecido"

    key = raw.lower()
    official = OFFICIAL_COH3_MAP_NAMES.get(key)
    if official:
        return official

    # Compatibilidade automática para futuras revisões (_mkiv/_redux/_mm) de mapas oficiais
    base_key = MAP_MK_SUFFIX_RE.sub("", key)
    official_base = _OFFICIAL_MAP_BASE_LOOKUP.get(base_key)
    if official_base:
        return official_base

    # Fallback limpo para mapas customizados / Steam Workshop (ex: '(4) duclair' -> 'Duclair')
    cleaned = MAP_PLAYER_PREFIX_RE.sub("", raw)
    cleaned = MAP_SIZE_SUFFIX_RE.sub("", cleaned)
    cleaned = MAP_MK_SUFFIX_RE.sub("", cleaned)
    cleaned = re.sub(r"[_]+", " ", cleaned).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return raw

    words = cleaned.split(" ")
    formatted: list[str] = []
    for idx, word in enumerate(words):
        lw = word.lower()
        if idx > 0 and lw in _MAP_LOWERCASE_WORDS:
            formatted.append(lw)
        else:
            formatted.append(word.capitalize() if word.islower() or word.isupper() else word)
    return " ".join(formatted)


def normalize_mode_name(matchtype_id: int, raw_name: str | None = None) -> str:
    """Converte o matchtype_id da Relic para rótulo padronizado."""
    if matchtype_id in FALLBACK_MATCH_TYPES:
        return FALLBACK_MATCH_TYPES[matchtype_id]
    if 5 <= matchtype_id <= 16:
        return "Co-Op vs IA"
    if raw_name:
        lower = raw_name.lower()
        if "quick match" in lower or "1v1" in lower:
            return "1v1"
        if "2v2" in lower:
            return "2v2"
        if "3v3" in lower:
            return "Team Games (3v3)"
        if "4v4" in lower:
            return "Team Games (4v4)"
        if "custom" in lower:
            return "Custom"
        return raw_name
    return f"Modo {matchtype_id}"


class RelicAPIClient:
    """Cliente HTTPS endurecido com TLS 1.2+, allowlist estrita, Gzip anti-bomb e rate-limit sem contenção."""

    def __init__(self, min_interval_sec: float = 0.06, timeout_sec: float = 15.0) -> None:
        self.min_interval_sec = max(0.01, float(min_interval_sec))
        self.timeout_sec = max(2.0, float(timeout_sec))
        self._next_req_ts = 0.0
        self._rate_lock = threading.Lock()
        self._meta_lock = threading.Lock()
        self.races: dict[int, str] = dict(FALLBACK_RACES)
        self.match_types: dict[int, str] = {}
        self._metadata_loaded = False

    def _reserve_rate_slot(self) -> None:
        with self._rate_lock:
            now_m = time.monotonic()
            target = max(now_m, self._next_req_ts)
            self._next_req_ts = target + self.min_interval_sec
            wait = target - now_m
        if wait > 0:
            time.sleep(wait)

    def _get_json(
        self,
        url: str,
        retries: int = 3,
        max_bytes: int = MAX_RELIC_RESPONSE_BYTES,
    ) -> dict[str, Any]:
        validate_https_endpoint(
            url,
            ALLOWED_RELIC_HOSTS,
            path_prefix="/community/leaderboard/",
        )
        opener = _get_thread_opener()
        headers = {
            "User-Agent": "CoH3-BR-Discord-Tracker/7.6",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        }

        last_err: Exception | None = None
        for attempt in range(retries):
            self._reserve_rate_slot()
            try:
                req = urllib.request.Request(url, headers=headers)
                with opener.open(req, timeout=self.timeout_sec) as resp:
                    raw_bytes = read_bounded_http_body(resp, max_bytes)
                payload = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Formato JSON inesperado retornado pela API da Relic.")
                return payload
            except urllib.error.HTTPError as exc:
                last_err = exc
                if exc.code in (400, 401, 403, 404):
                    break
                wait = (2**attempt) * 0.6
                logger.warning(
                    "HTTP %d na API Relic (%s) tentativa %d/%d; aguardando %.1fs",
                    exc.code,
                    url,
                    attempt + 1,
                    retries,
                    wait,
                )
                time.sleep(wait)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                last_err = exc
                wait = (2**attempt) * 0.6
                logger.warning(
                    "Falha na requisição Relic (%s) tentativa %d/%d: %s",
                    url,
                    attempt + 1,
                    retries,
                    redact_secrets(exc),
                )
                time.sleep(wait)

        raise RuntimeError(f"Erro ao consultar API da Relic ({url}): {redact_secrets(last_err)}")

    def ensure_metadata(self) -> None:
        if self._metadata_loaded:
            return
        with self._meta_lock:
            if self._metadata_loaded:
                return
            try:
                data = self._get_json(f"{BASE_URL}/getAvailableLeaderboards?title={TITLE_STEAM}")
                for race in data.get("races", []):
                    rid = race.get("id")
                    name = race.get("localizedName") or race.get("name")
                    if rid is not None and name and int(rid) not in FALLBACK_RACES:
                        self.races[int(rid)] = str(name)
                for mt in data.get("matchTypes", []):
                    mid = mt.get("id")
                    name = mt.get("localizedName") or mt.get("name")
                    if mid is not None and name:
                        self.match_types[int(mid)] = str(name)
                self._metadata_loaded = True
            except Exception as exc:
                logger.warning("Metadados dinâmicos indisponíveis; mantendo tabela estática: %s", redact_secrets(exc))

    def fetch_brazilian_players(
        self,
        include_global_top_pages: int = 2,
        max_sa_rank: int = 1000,
    ) -> list[dict[str, Any]]:
        """Varre em paralelo seguro todos os modos ranqueados da Steam filtrando country == 'br'."""
        players: dict[int, dict[str, Any]] = {}
        ingest_lock = threading.Lock()

        def ingest_response(data: dict[str, Any], mode: str, faction: str) -> int:
            stat_groups = {sg["id"]: sg for sg in data.get("statGroups", []) if "id" in sg}
            lb_stats = data.get("leaderboardStats", [])
            key = f"{mode}_{faction}"
            mode_badge = f"{mode.upper()} ({faction.upper()})"

            with ingest_lock:
                for st in lb_stats:
                    sg = stat_groups.get(st.get("statgroup_id"))
                    if not sg:
                        continue
                    for member in sg.get("members", []):
                        if str(member.get("country", "")).lower() != "br":
                            continue
                        pid = int(member["profile_id"])
                        steam_id = _extract_steam_id(member.get("name"))
                        p = players.get(pid)
                        if p is None:
                            p = {
                                "profile_id": pid,
                                "alias": member.get("alias") or f"Player {pid}",
                                "steam_id": steam_id,
                                "country": "br",
                                "level": int(member.get("level", 0)),
                                "xp": int(member.get("xp", 0)),
                                "max_elo": 0,
                                "best_mode": "",
                                "total_wins": 0,
                                "total_losses": 0,
                                "last_match_date": 0,
                                "modes": {},
                                "coh3stats_url": f"https://coh3stats.com/players/{pid}",
                            }
                            players[pid] = p
                        elif steam_id and not p.get("steam_id"):
                            p["steam_id"] = steam_id

                        elo = int(round(st.get("rating", 0)))
                        wins = int(st.get("wins", 0))
                        losses = int(st.get("losses", 0))
                        lmd = int(st.get("lastmatchdate", 0))
                        if key not in p["modes"]:
                            p["modes"][key] = {
                                "mode": mode,
                                "faction": faction,
                                "elo": elo,
                                "rank": int(st.get("rank", 0)),
                                "regionrank": int(st.get("regionrank", 0)),
                                "wins": wins,
                                "losses": losses,
                                "streak": int(st.get("streak", 0)),
                                "lastmatchdate": lmd,
                            }
                            p["total_wins"] += wins
                            p["total_losses"] += losses
                        if elo > p["max_elo"]:
                            p["max_elo"] = elo
                            p["best_mode"] = mode_badge
                        if lmd > p["last_match_date"]:
                            p["last_match_date"] = lmd
            return len(lb_stats)

        def scan_single_leaderboard(mode: str, faction: str, lb_id: int) -> None:
            start = 1
            while start <= max_sa_rank:
                url = (
                    f"{BASE_URL}/getleaderboard2?title={TITLE_STEAM}&leaderboard_id={lb_id}"
                    f"&sortBy=1&count=200&start={start}&leaderboardRegion_id={SOUTH_AMERICA_REGION_ID}"
                )
                data = self._get_json(url)
                count_rows = ingest_response(data, mode, faction)
                rank_total = int(data.get("rankTotal", 0))
                if count_rows == 0 or start + 200 > rank_total:
                    break
                start += 200

            for page in range(include_global_top_pages):
                g_start = 1 + page * 200
                g_url = (
                    f"{BASE_URL}/getleaderboard2?title={TITLE_STEAM}&leaderboard_id={lb_id}"
                    f"&sortBy=1&count=200&start={g_start}"
                )
                g_data = self._get_json(g_url)
                if ingest_response(g_data, mode, faction) == 0:
                    break

        tasks = [
            (mode, faction, lb_id)
            for mode, factions in STEAM_LEADERBOARDS.items()
            for faction, lb_id in factions.items()
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(scan_single_leaderboard, m, f, lid) for m, f, lid in tasks]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()

        return sorted(players.values(), key=lambda x: (-x["max_elo"], -x["last_match_date"]))

    def _parse_relic_match_entry(
        self,
        match: dict[str, Any],
        pid_clean: int,
        profiles_by_id: dict[int, dict[str, Any]],
        fallback_alias: str,
        only_automatch: bool,
        active_roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    ) -> dict[str, Any] | None:
        match_id = int(match.get("id", 0) or 0)
        if match_id <= 0:
            return None
        mt_id = int(match.get("matchtype_id", 0) or 0)
        mode_label = normalize_mode_name(mt_id, self.match_types.get(mt_id))

        if only_automatch and mode_label not in AUTOMATCH_MODES:
            return None

        reports = match.get("matchhistoryreportresults", [])
        if not isinstance(reports, list):
            return None
        my_rep = next((r for r in reports if isinstance(r, dict) and int(r.get("profile_id", -1)) == pid_clean), None)
        if not my_rep:
            return None

        tracked_prof = profiles_by_id.get(pid_clean, {})
        tracked_alias = tracked_prof.get("alias") or fallback_alias or f"Player {pid_clean}"
        tracked_steam_id = _extract_steam_id(tracked_prof.get("name"))

        members_by_pid: dict[int, dict[str, Any]] = {
            int(mem["profile_id"]): mem
            for mem in (match.get("matchhistorymember") or [])
            if isinstance(mem, dict) and "profile_id" in mem
        }

        my_team = my_rep.get("teamid", 0)
        allies: list[dict[str, Any]] = []
        opponents: list[dict[str, Any]] = []

        for rep in reports:
            if not isinstance(rep, dict):
                continue
            rpid = int(rep.get("profile_id", 0) or 0)
            prof = profiles_by_id.get(rpid, {})
            mem = members_by_pid.get(rpid, {})
            race_name = self.races.get(int(rep.get("race_id", -1)), f"Race {rep.get('race_id')}")
            raw_old = int(mem.get("oldrating", 0) or 0)
            raw_new = int(mem.get("newrating", 0) or 0)
            p_old_elo = raw_old if raw_old > 0 else None
            p_new_elo = raw_new if raw_new > 0 else None
            p_delta = (p_new_elo - p_old_elo) if (p_old_elo is not None and p_new_elo is not None) else None

            participant = {
                "profile_id": rpid,
                "alias": prof.get("alias") or f"ID {rpid}",
                "steam_id": _extract_steam_id(prof.get("name")),
                "country": str(prof.get("country") or "un").lower(),
                "faction": race_name,
                "faction_short": FACTION_SHORT.get(race_name, race_name),
                "old_elo": p_old_elo,
                "new_elo": p_new_elo,
                "elo_delta": p_delta,
                "elo": p_new_elo,
            }
            if rep.get("teamid") == my_team:
                if rpid != pid_clean:
                    allies.append(participant)
            else:
                opponents.append(participant)

        my_mem = members_by_pid.get(pid_clean, {})
        my_old_raw = int(my_mem.get("oldrating", 0) or 0)
        my_new_raw = int(my_mem.get("newrating", 0) or 0)
        old_elo = my_old_raw if my_old_raw > 0 else None
        new_elo = my_new_raw if my_new_raw > 0 else None

        start_ts = int(match.get("startgametime", 0) or 0)
        end_ts = int(match.get("completiontime", 0) or 0)
        raw_map = str(match.get("mapname") or "unknown_map")
        my_faction = self.races.get(int(my_rep.get("race_id", -1)), "Unknown")
        result_type = int(my_rep.get("resulttype", 0) or 0)

        m_obj = {
            "match_id": match_id,
            "tracked_profile_id": pid_clean,
            "tracked_alias": tracked_alias,
            "tracked_steam_id": tracked_steam_id,
            "tracked_faction": my_faction,
            "tracked_faction_short": FACTION_SHORT.get(my_faction, my_faction),
            "win": result_type == 1,
            "resulttype": result_type,
            "mode": mode_label,
            "matchtype_id": mt_id,
            "map_raw": raw_map,
            "map_clean": clean_map_name(raw_map),
            "start_time": start_ts,
            "completion_time": end_ts,
            "duration_sec": max(0, end_ts - start_ts),
            "old_elo": old_elo,
            "new_elo": new_elo,
            "allies": allies,
            "opponents": opponents,
            "counters": {},
            "has_replay": bool(match.get("matchurls")),
            "coh3stats_url": f"https://coh3stats.com/players/{pid_clean}/matches/{match_id}",
        }
        return enrich_match_with_roster(m_obj, active_roster_maps)

    def fetch_player_recent_matches(
        self,
        profile_id: int,
        fallback_alias: str = "",
        only_automatch: bool = False,
        roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """Retorna as partidas recentes ordenadas da mais nova para a mais antiga com vínculo SteamID."""
        pid_clean = int(profile_id)
        if pid_clean <= 0:
            raise ValueError(f"profile_id inválido: {profile_id}")

        self.ensure_metadata()
        active_roster_maps = roster_maps or build_roster_lookup_maps()
        url = f"{BASE_URL}/getRecentMatchHistoryByProfileId?title={TITLE_STEAM}&profile_id={pid_clean}"
        data = self._get_json(url)

        profiles_by_id: dict[int, dict[str, Any]] = {
            int(pr["profile_id"]): pr for pr in data.get("profiles", []) if isinstance(pr, dict) and "profile_id" in pr
        }
        raw_stats = sorted(
            data.get("matchHistoryStats", []),
            key=lambda m: int(m.get("completiontime", 0) or 0),
            reverse=True,
        )

        parsed_matches: list[dict[str, Any]] = []
        for match in raw_stats:
            if not isinstance(match, dict):
                continue
            parsed = self._parse_relic_match_entry(
                match=match,
                pid_clean=pid_clean,
                profiles_by_id=profiles_by_id,
                fallback_alias=fallback_alias,
                only_automatch=only_automatch,
                active_roster_maps=active_roster_maps,
            )
            if parsed is not None:
                parsed_matches.append(parsed)

        return parsed_matches

    def fetch_recent_matches_direct_batch(
        self,
        players: list[dict[str, Any]],
        only_automatch: bool = False,
        roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
        batch_size: int = 1,
        max_workers: int = 4,
    ) -> tuple[dict[int, list[dict[str, Any]]], int]:
        """
        Consulta direta independente ao endpoint Relic `getRecentMatchHistory` (por SteamID64 / profile_names,
        com fallback seguro por profile_ids) para auditoria de partidas recentes com histórico estendido.
        """
        self.ensure_metadata()
        active_roster_maps = roster_maps or build_roster_lookup_maps()
        safe_batch = max(1, min(int(batch_size), 10))

        steam_players: list[dict[str, Any]] = []
        pid_only_players: list[dict[str, Any]] = []
        alias_by_pid: dict[int, str] = {}
        tracked_pids: set[int] = set()

        for pl in players or []:
            pid = int(pl.get("profile_id", 0) or 0)
            if pid <= 0 or pid in tracked_pids:
                continue
            tracked_pids.add(pid)
            alias_by_pid[pid] = str(pl.get("original_alias") or pl.get("alias") or f"Player {pid}")
            sid = str(pl.get("steam_id") or "").replace("/steam/", "").strip()
            if STEAM_ID64_VALID_RE.fullmatch(sid):
                steam_players.append({"profile_id": pid, "steam_id": sid})
            else:
                pid_only_players.append({"profile_id": pid})

        if not tracked_pids:
            return {}, 0

        matches_by_pid: dict[int, dict[int, dict[str, Any]]] = {pid: {} for pid in tracked_pids}
        failed_batches = 0

        def _parse_batch_payload(data: dict[str, Any], target_pids: set[int]) -> list[tuple[int, int, dict[str, Any]]]:
            parsed_rows: list[tuple[int, int, dict[str, Any]]] = []
            profiles_by_id: dict[int, dict[str, Any]] = {
                int(pr["profile_id"]): pr
                for pr in data.get("profiles", [])
                if isinstance(pr, dict) and "profile_id" in pr
            }
            for match in data.get("matchHistoryStats", []):
                if not isinstance(match, dict):
                    continue
                reports = match.get("matchhistoryreportresults", [])
                if not isinstance(reports, list):
                    continue
                rep_pids = {
                    int(r.get("profile_id", 0) or 0)
                    for r in reports
                    if isinstance(r, dict)
                }
                for pid in rep_pids & target_pids:
                    parsed = self._parse_relic_match_entry(
                        match=match,
                        pid_clean=pid,
                        profiles_by_id=profiles_by_id,
                        fallback_alias=alias_by_pid.get(pid, f"Player {pid}"),
                        only_automatch=only_automatch,
                        active_roster_maps=active_roster_maps,
                    )
                    if parsed is not None:
                        parsed_rows.append((pid, int(parsed["match_id"]), parsed))
            return parsed_rows

        def _fetch_steam_chunk(chunk: list[dict[str, Any]]) -> tuple[list[tuple[int, int, dict[str, Any]]], list[int]]:
            chunk_pids = {int(c["profile_id"]) for c in chunk}
            names_json = json.dumps([f"/steam/{c['steam_id']}" for c in chunk], separators=(",", ":"))
            encoded_names = urllib.parse.quote(names_json)
            url = f"{BASE_URL}/getRecentMatchHistory?title={TITLE_STEAM}&profile_names={encoded_names}"
            try:
                data = self._get_json(url, retries=2, max_bytes=MAX_RELIC_DIRECT_HISTORY_BYTES)
                return _parse_batch_payload(data, chunk_pids), []
            except Exception as exc:
                logger.warning(
                    "[3ª CHECAGEM] Consulta Relic Direta por SteamID falhou (%d conta(s)); tentando fallback profile_ids: %s",
                    len(chunk),
                    redact_secrets(exc),
                )
                return [], sorted(chunk_pids)

        def _fetch_pid_chunk(chunk: list[dict[str, Any]]) -> tuple[list[tuple[int, int, dict[str, Any]]], bool]:
            chunk_pids = {int(c["profile_id"]) for c in chunk}
            encoded_ids = urllib.parse.quote("[" + ",".join(str(p) for p in sorted(chunk_pids)) + "]")
            url = f"{BASE_URL}/getRecentMatchHistory?title={TITLE_STEAM}&profile_ids={encoded_ids}"
            try:
                data = self._get_json(url, retries=2, max_bytes=MAX_RELIC_DIRECT_HISTORY_BYTES)
                return _parse_batch_payload(data, chunk_pids), False
            except Exception as exc:
                logger.warning(
                    "[3ª CHECAGEM] Consulta Relic Direta por profile_ids falhou (%d conta(s)): %s",
                    len(chunk),
                    redact_secrets(exc),
                )
                return [], True

        steam_chunks = [steam_players[i : i + safe_batch] for i in range(0, len(steam_players), safe_batch)]
        if steam_chunks:
            workers = max(1, min(int(max_workers), len(steam_chunks)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                for rows, fallback_pids in pool.map(_fetch_steam_chunk, steam_chunks):
                    for pid, mid, parsed in rows:
                        matches_by_pid[pid][mid] = parsed
                    for fpid in fallback_pids:
                        pid_only_players.append({"profile_id": fpid})

        pid_chunks = [pid_only_players[i : i + safe_batch] for i in range(0, len(pid_only_players), safe_batch)]
        if pid_chunks:
            workers = max(1, min(int(max_workers), len(pid_chunks)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                for rows, failed in pool.map(_fetch_pid_chunk, pid_chunks):
                    if failed:
                        failed_batches += 1
                    else:
                        for pid, mid, parsed in rows:
                            matches_by_pid[pid][mid] = parsed

        result: dict[int, list[dict[str, Any]]] = {}
        for pid, by_mid in matches_by_pid.items():
            ordered = sorted(by_mid.values(), key=lambda m: int(m.get("completion_time", 0)), reverse=True)
            result[pid] = ordered
        return result, failed_batches

    def fetch_players_latest_stat_timestamps(
        self,
        players: list[dict[str, Any]],
    ) -> dict[int, int]:
        """
        Consulta `getPersonalStat` em lotes de até 10 contas e retorna `{profile_id: max_lastmatchdate}`
        considerando todas as leaderboards (inclusive placement/unranked), como sinal auxiliar na 4ª checagem Radar.
        """
        clean_pids = sorted(
            {
                int(pl.get("profile_id", 0) or 0)
                for pl in (players or [])
                if isinstance(pl, dict) and int(pl.get("profile_id", 0) or 0) > 0
            }
        )
        if not clean_pids:
            return {}

        latest_by_pid: dict[int, int] = {}
        chunks = [clean_pids[i : i + 10] for i in range(0, len(clean_pids), 10)]

        for chunk in chunks:
            target_set = set(chunk)
            encoded_ids = urllib.parse.quote("[" + ",".join(str(p) for p in chunk) + "]")
            url = f"{BASE_URL}/getPersonalStat?title={TITLE_STEAM}&profile_ids={encoded_ids}"
            try:
                data = self._get_json(url, retries=2)
            except Exception as exc:
                logger.warning(
                    "[4ª CHECAGEM RADAR] Falha ao consultar getPersonalStat (%d conta(s)): %s",
                    len(chunk),
                    redact_secrets(exc),
                )
                continue

            sg_to_pids: dict[int, list[int]] = {}
            for sg in data.get("statGroups", []):
                if not isinstance(sg, dict) or "id" not in sg:
                    continue
                matched = [
                    int(m.get("profile_id", 0) or 0)
                    for m in (sg.get("members") or [])
                    if isinstance(m, dict) and int(m.get("profile_id", 0) or 0) in target_set
                ]
                if matched:
                    sg_to_pids[int(sg["id"])] = matched

            for st in data.get("leaderboardStats", []):
                if not isinstance(st, dict):
                    continue
                sg_id = int(st.get("statgroup_id", -1))
                lmd = int(st.get("lastmatchdate", 0) or 0)
                if lmd <= 0 or sg_id not in sg_to_pids:
                    continue
                for pid in sg_to_pids[sg_id]:
                    if lmd > latest_by_pid.get(pid, 0):
                        latest_by_pid[pid] = lmd

        return latest_by_pid


class Coh3StatsAPIClient:
    """
    Cliente HTTPS endurecido (streaming de baixa memória) para o Open Data público e oficial do site coh3stats.com.
    Fonte documentada: https://coh3stats.com/other/open-data (storage.coh3stats.com/matches/matches-{unixTimeStamp}.json).
    """

    def __init__(
        self,
        min_interval_sec: float = 0.25,
        timeout_sec: float = 30.0,
        circuit_breaker_threshold: int = 3,
        max_wire_bytes: int = MAX_COH3STATS_WIRE_BYTES,
        max_stream_bytes: int = MAX_COH3STATS_STREAM_BYTES,
    ) -> None:
        self.min_interval_sec = max(0.05, float(min_interval_sec))
        self.timeout_sec = max(3.0, float(timeout_sec))
        self.circuit_breaker_threshold = max(1, int(circuit_breaker_threshold))
        self.max_wire_bytes = max(1024, int(max_wire_bytes))
        self.max_stream_bytes = max(1024, int(max_stream_bytes))
        self._next_req_ts = 0.0
        self._rate_lock = threading.Lock()
        self._cb_lock = threading.Lock()
        self._consecutive_errors = 0
        self._circuit_open = False

    def reset_circuit_breaker(self) -> None:
        with self._cb_lock:
            self._consecutive_errors = 0
            self._circuit_open = False

    @property
    def is_circuit_open(self) -> bool:
        with self._cb_lock:
            return self._circuit_open

    def _record_success(self) -> None:
        with self._cb_lock:
            self._consecutive_errors = 0

    def _record_failure(self) -> bool:
        with self._cb_lock:
            self._consecutive_errors += 1
            if self._consecutive_errors >= self.circuit_breaker_threshold:
                self._circuit_open = True
            return self._circuit_open

    def _reserve_rate_slot(self) -> None:
        with self._rate_lock:
            now_m = time.monotonic()
            target = max(now_m, self._next_req_ts)
            self._next_req_ts = target + self.min_interval_sec
            wait = target - now_m
        if wait > 0:
            time.sleep(wait)

    @staticmethod
    def _parse_match_for_player(
        match: dict[str, Any],
        pid_clean: int,
        fallback_alias: str,
        only_automatch: bool,
        active_roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
        race_map: dict[int, str],
        mt_map: dict[int, str],
    ) -> dict[str, Any] | None:
        match_id = int(match.get("id", 0) or 0)
        if match_id <= 0:
            return None
        mt_id = int(match.get("matchtype_id", 0) or 0)
        mode_label = normalize_mode_name(mt_id, mt_map.get(mt_id))
        if only_automatch and mode_label not in AUTOMATCH_MODES:
            return None

        reports = match.get("matchhistoryreportresults", [])
        if not isinstance(reports, list):
            return None
        my_rep = next((r for r in reports if isinstance(r, dict) and int(r.get("profile_id", -1)) == pid_clean), None)
        if not my_rep:
            return None

        top_profiles: dict[int, dict[str, Any]] = {
            int(pr["profile_id"]): pr
            for pr in (match.get("profiles") or [])
            if isinstance(pr, dict) and "profile_id" in pr
        }
        top_members: dict[int, dict[str, Any]] = {
            int(mem["profile_id"]): mem
            for mem in (match.get("matchhistorymember") or [])
            if isinstance(mem, dict) and "profile_id" in mem
        }

        my_prof = my_rep.get("profile") if isinstance(my_rep.get("profile"), dict) else top_profiles.get(pid_clean, {})
        my_mem = my_rep.get("matchhistorymember") if isinstance(my_rep.get("matchhistorymember"), dict) else top_members.get(pid_clean, {})
        tracked_alias = str(my_prof.get("alias") or fallback_alias or f"Player {pid_clean}")
        tracked_steam_id = _extract_steam_id(my_prof.get("name"))

        my_team = my_rep.get("teamid", 0)
        allies: list[dict[str, Any]] = []
        opponents: list[dict[str, Any]] = []

        for rep in reports:
            if not isinstance(rep, dict):
                continue
            rpid = int(rep.get("profile_id", 0) or 0)
            prof = rep.get("profile") if isinstance(rep.get("profile"), dict) else top_profiles.get(rpid, {})
            mem = rep.get("matchhistorymember") if isinstance(rep.get("matchhistorymember"), dict) else top_members.get(rpid, {})
            race_name = race_map.get(int(rep.get("race_id", -1)), f"Race {rep.get('race_id')}")
            raw_old = int(mem.get("oldrating", 0) or 0)
            raw_new = int(mem.get("newrating", 0) or 0)
            p_old_elo = raw_old if raw_old > 0 else None
            p_new_elo = raw_new if raw_new > 0 else None
            p_delta = (p_new_elo - p_old_elo) if (p_old_elo is not None and p_new_elo is not None) else None

            participant = {
                "profile_id": rpid,
                "alias": prof.get("alias") or f"ID {rpid}",
                "steam_id": _extract_steam_id(prof.get("name")),
                "country": str(prof.get("country") or "un").lower(),
                "faction": race_name,
                "faction_short": FACTION_SHORT.get(race_name, race_name),
                "old_elo": p_old_elo,
                "new_elo": p_new_elo,
                "elo_delta": p_delta,
                "elo": p_new_elo,
            }
            if rep.get("teamid") == my_team:
                if rpid != pid_clean:
                    allies.append(participant)
            else:
                opponents.append(participant)

        my_old_raw = int(my_mem.get("oldrating", 0) or 0)
        my_new_raw = int(my_mem.get("newrating", 0) or 0)
        old_elo = my_old_raw if my_old_raw > 0 else None
        new_elo = my_new_raw if my_new_raw > 0 else None

        start_ts = int(match.get("startgametime", 0) or 0)
        end_ts = int(match.get("completiontime", 0) or 0)
        raw_map = str(match.get("mapname") or "unknown_map")
        my_faction = race_map.get(int(my_rep.get("race_id", -1)), "Unknown")
        result_type = int(my_rep.get("resulttype", 0) or 0)

        m_obj = {
            "match_id": match_id,
            "tracked_profile_id": pid_clean,
            "tracked_alias": tracked_alias,
            "tracked_steam_id": tracked_steam_id,
            "tracked_faction": my_faction,
            "tracked_faction_short": FACTION_SHORT.get(my_faction, my_faction),
            "win": result_type == 1,
            "resulttype": result_type,
            "mode": mode_label,
            "matchtype_id": mt_id,
            "map_raw": raw_map,
            "map_clean": clean_map_name(raw_map),
            "start_time": start_ts,
            "completion_time": end_ts,
            "duration_sec": max(0, end_ts - start_ts),
            "old_elo": old_elo,
            "new_elo": new_elo,
            "allies": allies,
            "opponents": opponents,
            "counters": {},
            "has_replay": bool(match.get("matchurls")),
            "coh3stats_url": f"https://coh3stats.com/players/{pid_clean}/matches/{match_id}",
        }
        return enrich_match_with_roster(m_obj, active_roster_maps)

    def _stream_open_data_matches(
        self,
        resp: Any,
        tracked_pids: set[int],
    ) -> tuple[list[tuple[dict[str, Any], set[int]]], int]:
        """
        Lê o dump Open Data (`{"matches":[...]}`) em streaming com memória controlada (< 4 MB),
        descompressão Gzip limitada contra Gzip-bombs e decodificador JSON nativo em C.
        """
        headers = getattr(resp, "headers", None)
        encoding = str(headers.get("Content-Encoding", "") if headers else "").lower()
        is_gzip = "gzip" in encoding
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS) if is_gzip else None
        utf8_dec = codecs.getincrementaldecoder("utf-8")("replace")
        decoder = json.JSONDecoder()
        ws_re = re.compile(r"[ \t\r\n,]*")

        matched_records: list[tuple[dict[str, Any], set[int]]] = []
        total_scanned = 0
        wire_total = 0
        decomp_total = 0
        buf = ""
        pos = 0
        started = False
        done = False

        def _drain_buffer(is_eof: bool) -> None:
            nonlocal buf, pos, started, done, total_scanned
            if done:
                return
            if not started:
                stripped_pos = 0
                while stripped_pos < len(buf) and buf[stripped_pos] in " \t\r\n\ufeff":
                    stripped_pos += 1
                if stripped_pos < len(buf) and buf[stripped_pos] == "[":
                    pos = stripped_pos + 1
                    started = True
                else:
                    idx = buf.find('"matches"')
                    if idx == -1:
                        pos = max(0, len(buf) - 32)
                        return
                    lb = buf.find("[", idx)
                    if lb == -1:
                        pos = idx
                        return
                    pos = lb + 1
                    started = True

            while True:
                m_ws = ws_re.match(buf, pos)
                pos = m_ws.end() if m_ws else pos
                if pos >= len(buf):
                    break
                if buf[pos] == "]":
                    done = True
                    pos += 1
                    break
                try:
                    obj, end_pos = decoder.raw_decode(buf, pos)
                except json.JSONDecodeError:
                    if not is_eof and (len(buf) - pos) > MAX_COH3STATS_OBJECT_BUFFER_CHARS:
                        raise RuntimeError("Objeto JSON individual no Open Data excedeu o limite seguro.")
                    break
                pos = end_pos
                if isinstance(obj, dict):
                    total_scanned += 1
                    raw_pids = obj.get("profile_ids")
                    if isinstance(raw_pids, list):
                        hit_pids = {int(p) for p in raw_pids if isinstance(p, int) or (isinstance(p, str) and p.isdigit())} & tracked_pids
                    else:
                        reports = obj.get("matchhistoryreportresults") or []
                        hit_pids = (
                            {int(r.get("profile_id", 0) or 0) for r in reports if isinstance(r, dict)} & tracked_pids
                        )
                    if hit_pids:
                        matched_records.append((obj, hit_pids))

        while not done:
            wire_chunk = resp.read(65536)
            if not wire_chunk:
                if decomp is not None:
                    remaining = self.max_stream_bytes - decomp_total
                    flushed = decomp.flush(max(1, remaining + 1))
                    decomp_total += len(flushed)
                    if decomp_total > self.max_stream_bytes:
                        raise RuntimeError(f"Fluxo Gzip Open Data excedeu o limite seguro ({self.max_stream_bytes} bytes).")
                    if flushed:
                        buf = buf[pos:] + utf8_dec.decode(flushed, final=False)
                        pos = 0
                tail_text = utf8_dec.decode(b"", final=True)
                if tail_text:
                    buf = buf[pos:] + tail_text
                    pos = 0
                _drain_buffer(is_eof=True)
                break

            wire_total += len(wire_chunk)
            if wire_total > self.max_wire_bytes:
                raise RuntimeError(f"Resposta Open Data coh3stats excedeu o limite seguro no fio ({self.max_wire_bytes} bytes).")

            text_parts: list[str] = []
            if decomp is not None:
                pending = wire_chunk
                while pending:
                    remaining = self.max_stream_bytes - decomp_total
                    out = decomp.decompress(pending, max(1, remaining + 1))
                    decomp_total += len(out)
                    if decomp_total > self.max_stream_bytes:
                        raise RuntimeError(f"Fluxo Gzip Open Data excedeu o limite seguro ({self.max_stream_bytes} bytes).")
                    if out:
                        text_parts.append(utf8_dec.decode(out, final=False))
                    pending = decomp.unconsumed_tail
            else:
                decomp_total += len(wire_chunk)
                if decomp_total > self.max_stream_bytes:
                    raise RuntimeError(f"Resposta Open Data coh3stats excedeu o limite seguro ({self.max_stream_bytes} bytes).")
                text_parts.append(utf8_dec.decode(wire_chunk, final=False))

            if text_parts:
                buf = buf[pos:] + "".join(text_parts)
                pos = 0
                _drain_buffer(is_eof=False)

        return matched_records, total_scanned

    def fetch_open_data_day_matches(
        self,
        day_utc_midnight_ts: int,
        players: list[dict[str, Any]],
        only_automatch: bool = False,
        roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
        races: dict[int, str] | None = None,
        match_types: dict[int, str] | None = None,
        retries: int = 2,
    ) -> tuple[dict[int, list[dict[str, Any]]], str, int]:
        """
        Consulta o arquivo diário oficial do Open Data do coh3stats.com (`matches-{day_ts}.json`) em streaming,
        extraindo todas as partidas dos jogadores monitorados sem carregar o arquivo inteiro em RAM.
        Retorna `(matches_by_pid, status, total_scanned)` onde status é `'ok'` ou `'not_published'` (404).
        """
        day_clean = int(day_utc_midnight_ts)
        if day_clean <= 0:
            raise ValueError(f"day_utc_midnight_ts inválido: {day_utc_midnight_ts}")

        url = f"{COH3STATS_OPEN_DATA_BASE_URL}/matches-{day_clean}.json"
        validate_https_endpoint(
            url,
            ALLOWED_COH3STATS_HOSTS,
            path_prefix="/matches/",
            path_regex=COH3STATS_OPEN_DATA_PATH_RE,
        )

        alias_by_pid: dict[int, str] = {}
        tracked_pids: set[int] = set()
        for pl in players or []:
            pid = int(pl.get("profile_id", 0) or 0)
            if pid > 0 and pid not in tracked_pids:
                tracked_pids.add(pid)
                alias_by_pid[pid] = str(pl.get("original_alias") or pl.get("alias") or f"Player {pid}")
        if not tracked_pids:
            return {}, "ok", 0

        active_roster_maps = roster_maps or build_roster_lookup_maps()
        race_map = races or FALLBACK_RACES
        mt_map = match_types or {}
        opener = _get_thread_opener()
        headers = {
            "User-Agent": "CoH3-BR-Discord-Tracker/7.6",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        }

        last_err: Exception | None = None
        for attempt in range(max(1, int(retries))):
            self._reserve_rate_slot()
            try:
                req = urllib.request.Request(url, headers=headers)
                with opener.open(req, timeout=self.timeout_sec) as resp:
                    matched_raw, total_scanned = self._stream_open_data_matches(resp, tracked_pids)

                by_pid: dict[int, dict[int, dict[str, Any]]] = {pid: {} for pid in tracked_pids}
                for match_obj, hit_pids in matched_raw:
                    for pid in hit_pids:
                        parsed = self._parse_match_for_player(
                            match=match_obj,
                            pid_clean=pid,
                            fallback_alias=alias_by_pid.get(pid, f"Player {pid}"),
                            only_automatch=only_automatch,
                            active_roster_maps=active_roster_maps,
                            race_map=race_map,
                            mt_map=mt_map,
                        )
                        if parsed is not None:
                            by_pid[pid][int(parsed["match_id"])] = parsed

                result = {
                    pid: sorted(mid_map.values(), key=lambda m: int(m.get("completion_time", 0)), reverse=True)
                    for pid, mid_map in by_pid.items()
                    if mid_map
                }
                return result, "ok", total_scanned
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return {}, "not_published", 0
                last_err = exc
                if exc.code in (400, 401, 403):
                    break
                if attempt + 1 < retries:
                    time.sleep((2**attempt) * 0.8)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = exc
                if "403" in str(exc):
                    break
                if attempt + 1 < retries:
                    time.sleep((2**attempt) * 0.8)

        raise RuntimeError(f"Erro ao consultar Open Data coh3stats ({url}): {redact_secrets(last_err)}")

    def fetch_open_data_days_matches(
        self,
        day_timestamps: list[int],
        players: list[dict[str, Any]],
        only_automatch: bool = False,
        roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
        races: dict[int, str] | None = None,
        match_types: dict[int, str] | None = None,
    ) -> tuple[dict[int, list[dict[str, Any]]], list[int], int, int]:
        """
        Audita os dias solicitados do Open Data oficial do coh3stats.com com circuit breaker seguro.
        Retorna `(matches_by_pid, audited_ok_days, total_scanned, fail_count)`.
        """
        self.reset_circuit_breaker()
        clean_days = sorted({int(d) for d in (day_timestamps or []) if int(d) > 0})
        if not clean_days or not players:
            return {}, [], 0, 0

        combined_by_pid: dict[int, dict[int, dict[str, Any]]] = {}
        ok_days: list[int] = []
        total_scanned = 0
        fail_count = 0

        for day_ts in clean_days:
            if self.is_circuit_open:
                fail_count += 1
                continue
            try:
                day_matches, status, scanned = self.fetch_open_data_day_matches(
                    day_utc_midnight_ts=day_ts,
                    players=players,
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                    races=races,
                    match_types=match_types,
                )
                self._record_success()
                if status == "ok":
                    ok_days.append(day_ts)
                    total_scanned += scanned
                    for pid, rows in day_matches.items():
                        slot = combined_by_pid.setdefault(pid, {})
                        for m in rows:
                            slot[int(m["match_id"])] = m
            except Exception as exc:
                fail_count += 1
                tripped = self._record_failure()
                if tripped:
                    logger.warning(
                        "[3ª CHECAGEM] Circuit breaker acionado para Open Data coh3stats.com após %d falhas: %s",
                        self.circuit_breaker_threshold,
                        redact_secrets(exc),
                    )
                else:
                    logger.warning(
                        "[3ª CHECAGEM] Falha ao consultar Open Data coh3stats.com (dia %d): %s",
                        day_ts,
                        redact_secrets(exc),
                    )

        final_by_pid = {
            pid: sorted(mid_map.values(), key=lambda m: int(m.get("completion_time", 0)), reverse=True)
            for pid, mid_map in combined_by_pid.items()
        }
        return final_by_pid, ok_days, total_scanned, fail_count


class VeteransRadarClient:
    """
    Cliente HTTPS endurecido (estritamente somente-leitura) para o estado público do Radar de Lobby
    dos Veteranos BR (`nigosky/coh3-br-lobby-radar/main/state.json`), usado como 4ª checagem cruzada
    de partidas recentes dos jogadores monitorados.
    """

    def __init__(
        self,
        state_url: str = VETERANOS_RADAR_STATE_URL,
        timeout_sec: float = 8.0,
        max_bytes: int = MAX_RADAR_STATE_BYTES,
    ) -> None:
        self.state_url = (state_url or VETERANOS_RADAR_STATE_URL).strip()
        self.timeout_sec = max(2.0, float(timeout_sec))
        self.max_bytes = max(4096, min(int(max_bytes), 1024 * 1024))

    @staticmethod
    def _extract_pids_from_sequence(seq: Any) -> set[int]:
        out: set[int] = set()
        if not isinstance(seq, (list, tuple, set)):
            return out
        for item in seq:
            candidate = item[0] if isinstance(item, (list, tuple)) and item else item
            if isinstance(candidate, bool):
                continue
            if isinstance(candidate, int) and candidate > 0:
                out.add(candidate)
            elif isinstance(candidate, str) and candidate.isdigit() and int(candidate) > 0:
                out.add(int(candidate))
        return out

    @staticmethod
    def _extract_steam_ids_from_sequence(seq: Any) -> set[str]:
        out: set[str] = set()
        if not isinstance(seq, (list, tuple, set)):
            return out
        for item in seq:
            candidate = item[0] if isinstance(item, (list, tuple)) and item else item
            sid = _extract_steam_id(candidate)
            if sid:
                out.add(sid)
        return out

    @classmethod
    def _parse_radar_state_payload(cls, payload: dict[str, Any]) -> tuple[set[int], set[str], int]:
        """Extrai profile_ids e SteamID64s dos Veteranos em atividade CoH3 recente do state.json do Radar."""
        last_sync_ts = int(payload.get("last_sync_ts", 0) or 0)
        active_pids: set[int] = set()
        active_sids: set[str] = set()

        active_pids.update(cls._extract_pids_from_sequence(payload.get("last_alert_coh3_pids")))

        raw_digest = payload.get("last_digest")
        if isinstance(raw_digest, str) and 2 <= len(raw_digest) <= 65536:
            try:
                dig = ast.literal_eval(raw_digest)
                if isinstance(dig, tuple) and dig and isinstance(dig[0], tuple):
                    vet_tuple = dig[0]
                    # dig[0] = (vet_in_coh3, vet_online_steam, vet_recent_relic)
                    if len(vet_tuple) >= 1:
                        active_pids.update(cls._extract_pids_from_sequence(vet_tuple[0]))
                    if len(vet_tuple) >= 3:
                        active_pids.update(cls._extract_pids_from_sequence(vet_tuple[2]))
            except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
                pass

        raw_fast_sig = payload.get("last_steam_fast_sig")
        if isinstance(raw_fast_sig, str) and 2 <= len(raw_fast_sig) <= 65536:
            try:
                fast = ast.literal_eval(raw_fast_sig)
                if isinstance(fast, tuple) and fast:
                    # fast[0] = lista ordenada de SteamID64s atualmente no CoH3 via Steam
                    active_sids.update(cls._extract_steam_ids_from_sequence(fast[0]))
            except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
                pass

        return active_pids, active_sids, last_sync_ts

    def fetch_active_veteranos(self, max_age_sec: int = 7200) -> dict[str, Any]:
        """
        Busca o estado atual do Radar dos Veteranos (somente-leitura, não-bloqueante).
        Retorna dict com: ok, stale, last_sync_ts, age_sec, active_pids, active_steam_ids, error.
        """
        try:
            validate_https_endpoint(
                self.state_url,
                ALLOWED_RADAR_HOSTS,
                path_prefix="/nigosky/coh3-br-lobby-radar/",
                path_regex=VETERANOS_RADAR_PATH_RE,
            )
        except Exception as exc:
            return {
                "ok": False,
                "stale": False,
                "last_sync_ts": 0,
                "age_sec": -1,
                "active_pids": set(),
                "active_steam_ids": set(),
                "error": redact_secrets(exc),
            }

        opener = _get_thread_opener()
        headers = {
            "User-Agent": "CoH3-BR-Discord-Tracker/7.8",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Cache-Control": "no-cache",
        }
        last_err: Exception | None = None
        for attempt in range(2):
            try:
                req = urllib.request.Request(self.state_url, headers=headers)
                with opener.open(req, timeout=self.timeout_sec) as resp:
                    raw_bytes = read_bounded_http_body(resp, self.max_bytes)
                payload = json.loads(raw_bytes.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Formato JSON inesperado no state.json do Radar.")
                active_pids, active_sids, last_sync_ts = self._parse_radar_state_payload(payload)
                now_ts = int(time.time())
                age_sec = max(0, now_ts - last_sync_ts) if last_sync_ts > 0 else -1
                stale = bool(max_age_sec > 0 and last_sync_ts > 0 and age_sec > max_age_sec)
                return {
                    "ok": True,
                    "stale": stale,
                    "last_sync_ts": last_sync_ts,
                    "age_sec": age_sec,
                    "active_pids": set() if stale else active_pids,
                    "active_steam_ids": set() if stale else active_sids,
                    "error": "",
                }
            except urllib.error.HTTPError as exc:
                last_err = exc
                if exc.code in (400, 401, 403, 404):
                    break
                if attempt == 0:
                    time.sleep(0.6)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as exc:
                last_err = exc
                if attempt == 0:
                    time.sleep(0.6)

        return {
            "ok": False,
            "stale": False,
            "last_sync_ts": 0,
            "age_sec": -1,
            "active_pids": set(),
            "active_steam_ids": set(),
            "error": redact_secrets(last_err),
        }


def normalize_battlegroup(raw_key: str = "", raw_name: str = "") -> dict[str, str] | None:
    """Normaliza chave/nome de Battlegroup do CoH3 para o catálogo oficial ({'key': ..., 'name': ...})."""
    k = re.sub(r"_icon_mipped$", "", str(raw_key or "").strip().lower())
    k = re.sub(r"[^a-z0-9_]", "", k)
    clean_name = html.unescape(str(raw_name or "")).strip()
    clean_name = re.sub(r"\s+Battlegroup$", "", clean_name, flags=re.IGNORECASE).strip()

    if k and k in OFFICIAL_COH3_BATTLEGROUPS:
        return {"key": k, "name": OFFICIAL_COH3_BATTLEGROUPS[k]}

    if clean_name and clean_name.casefold() in ("none", "n/a", "-", "—", "unknown"):
        clean_name = ""

    if clean_name:
        matched_k = _BG_NAME_TO_KEY.get(clean_name.casefold())
        if matched_k:
            return {"key": matched_k, "name": OFFICIAL_COH3_BATTLEGROUPS[matched_k]}
        # Fallback seguro para novos Battlegroups futuros de patches do CoH3
        return {"key": k, "name": clean_name[:40]}

    if k:
        pretty = " ".join(w.capitalize() for w in k.split("_") if w not in ("us", "uk", "ger", "ak"))
        return {"key": k, "name": (pretty or k)[:40]}
    return None


class CohDBClient:
    """
    Cliente HTTPS endurecido (somente-leitura, respeitando robots.txt do cohdb.com) para extrair
    o Battlegroup escolhido por cada jogador a partir das páginas canônicas públicas `/players/<id>/matches`
    e `/replays/<id>`, com cache por ciclo, rate-limit educado e circuit breaker.
    """

    _ROW_RE = re.compile(r'<tr[^>]*data-href="/replays/(\d{1,12})"[^>]*>(.*?)</tr>', re.S)
    _TITLE_MATCH_RE = re.compile(
        r"<title>\s*cohdb\s*(?:–|&ndash;|&#8211;|-)\s*Match\s+(\d{1,12})\s*</title>",
        re.IGNORECASE,
    )
    _PLAYER_LINK_RE = re.compile(r'href="/players/(\d{1,12})"')
    _BG_ICON_RE = re.compile(r'/assets/races/[^/"]+/battlegroups/([a-z0-9_]+?)(?:-[0-9a-f]+)?\.webp', re.I)
    _BG_NAME_RE = re.compile(r"Battlegroup</div>\s*<div[^>]*>([^<]{1,80})</div>", re.I)

    def __init__(
        self,
        min_interval_sec: float = 0.35,
        timeout_sec: float = 8.0,
        circuit_breaker_threshold: int = 3,
        max_bytes: int = MAX_COHDB_HTML_BYTES,
    ) -> None:
        self.min_interval_sec = max(0.15, float(min_interval_sec))
        self.timeout_sec = max(2.0, float(timeout_sec))
        self.circuit_breaker_threshold = max(1, int(circuit_breaker_threshold))
        self.max_bytes = max(32_768, min(int(max_bytes), 2 * 1024 * 1024))
        self._rate_lock = threading.Lock()
        self._next_req_ts = 0.0
        self._consecutive_errors = 0
        self._circuit_open = False
        self._player_matches_cache: dict[int, list[tuple[int, str]]] = {}
        self._replay_to_match_cache: dict[int, tuple[int, dict[int, dict[str, str]]]] = {}
        self._match_bg_cache: dict[int, dict[int, dict[str, str]]] = {}

    @property
    def is_circuit_open(self) -> bool:
        return self._circuit_open

    def _reserve_rate_slot(self) -> None:
        with self._rate_lock:
            now_m = time.monotonic()
            target = max(now_m, self._next_req_ts)
            self._next_req_ts = target + self.min_interval_sec
            wait = target - now_m
        if wait > 0:
            time.sleep(wait)

    def _fetch_canonical_html(self, path: str, path_regex: re.Pattern[str]) -> str | None:
        if self._circuit_open:
            return None
        if not path or "?" in path or "#" in path or not path_regex.fullmatch(path):
            raise ValueError(f"Caminho cohdb não canônico bloqueado: {path!r}")
        url = f"{COHDB_BASE_URL}{path}"
        parsed = validate_https_endpoint(
            url,
            ALLOWED_COHDB_HOSTS,
            path_prefix="/",
            path_regex=path_regex,
        )
        if parsed.query or parsed.fragment:
            raise ValueError("Query string ou fragmento bloqueado para cohdb.com (robots.txt).")
        opener = _get_thread_opener()
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CoH3-BR-Tracker/7.9)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Encoding": "gzip",
        }
        self._reserve_rate_slot()
        try:
            req = urllib.request.Request(url, headers=headers)
            with opener.open(req, timeout=self.timeout_sec) as resp:
                raw = read_bounded_http_body(resp, self.max_bytes)
            self._consecutive_errors = 0
            return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                self._consecutive_errors = 0
                return None
            self._consecutive_errors += 1
            if exc.code in (403, 429) or self._consecutive_errors >= self.circuit_breaker_threshold:
                self._circuit_open = True
                logger.warning(
                    "[COHDB BATTLEGROUPS] Circuit breaker acionado (HTTP %d em %s); seguindo sem bloquear o tracker.",
                    exc.code,
                    path,
                )
            return None
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            self._consecutive_errors += 1
            if self._consecutive_errors >= self.circuit_breaker_threshold:
                self._circuit_open = True
                logger.warning(
                    "[COHDB BATTLEGROUPS] Circuit breaker acionado após %d falhas (%s).",
                    self._consecutive_errors,
                    redact_secrets(exc),
                )
            return None

    def _get_player_recent_replay_rows(self, profile_id: int) -> list[tuple[int, str]]:
        pid = int(profile_id or 0)
        if pid <= 0:
            return []
        if pid in self._player_matches_cache:
            return self._player_matches_cache[pid]

        html_body = self._fetch_canonical_html(f"/players/{pid}/matches", COHDB_PLAYER_MATCHES_PATH_RE)
        if not html_body:
            self._player_matches_cache[pid] = []
            return []

        rows: list[tuple[int, str]] = []
        seen_rids: set[int] = set()
        for rid_str, row_html in self._ROW_RE.findall(html_body):
            rid = int(rid_str)
            if rid <= 0 or rid in seen_rids:
                continue
            seen_rids.add(rid)
            plain = html.unescape(re.sub(r"<[^>]+>", " ", row_html)).lower()
            rows.append((rid, re.sub(r"\s+", " ", plain).strip()))
            if len(rows) >= 12:
                break

        self._player_matches_cache[pid] = rows
        return rows

    @classmethod
    def _parse_replay_page(cls, html_body: str) -> tuple[int, dict[int, dict[str, str]]]:
        """Extrai `(relic_match_id, {profile_id: {'key': ..., 'name': ...}})` de uma página `/replays/<id>`."""
        m_title = cls._TITLE_MATCH_RE.search(html_body)
        relic_mid = int(m_title.group(1)) if m_title else 0
        bg_by_pid: dict[int, dict[str, str]] = {}

        cards = html_body.split("<div data-player-card")[1:]
        for card in cards:
            pm = cls._PLAYER_LINK_RE.search(card)
            if not pm:
                continue
            pid = int(pm.group(1))
            if pid <= 0:
                continue
            bgm = cls._BG_ICON_RE.search(card)
            bgn = cls._BG_NAME_RE.search(card)
            norm = normalize_battlegroup(
                raw_key=bgm.group(1) if bgm else "",
                raw_name=bgn.group(1) if bgn else "",
            )
            if norm:
                bg_by_pid[pid] = norm

        return relic_mid, bg_by_pid

    def invalidate_player_cache(self, profile_ids: list[int] | None = None) -> None:
        """Limpa o cache em memória de `/players/<id>/matches` para permitir retentativa fresca no mesmo ciclo."""
        if profile_ids is None:
            self._player_matches_cache.clear()
            return
        for raw_pid in profile_ids:
            pid = int(raw_pid or 0)
            if pid > 0:
                self._player_matches_cache.pop(pid, None)

    def fetch_match_battlegroups(
        self,
        match_id: int,
        tracked_profile_ids: list[int],
        expected_map_clean: str = "",
        max_replay_probes: int = 5,
        fallback_profile_ids: list[int] | None = None,
    ) -> dict[int, dict[str, str]] | None:
        """
        Retorna `{profile_id: {'key': ..., 'name': ...}}` para a partida Relic `match_id` se já indexada
        no `cohdb.com` (pode ser `{}` caso ninguém tenha escolhido Battlegroup), ou `None` se ainda não indexada.
        """
        mid = int(match_id or 0)
        if mid <= 0:
            return None
        if mid in self._match_bg_cache:
            return dict(self._match_bg_cache[mid])
        if self._circuit_open:
            return None

        clean_tracked = [int(p) for p in dict.fromkeys(tracked_profile_ids or []) if int(p) > 0]
        tracked_set = set(clean_tracked)
        clean_fallback = [
            int(p)
            for p in dict.fromkeys(fallback_profile_ids or [])
            if int(p) > 0 and int(p) not in tracked_set
        ]
        probe_pids = clean_tracked[:2] + clean_fallback[:1]
        if not probe_pids:
            return None

        map_probe = str(expected_map_clean or "").strip().lower()
        # Tenta primeiro até 2 jogadores monitorados e, se necessário, 1 participante adicional da partida
        for pid in probe_pids:
            if self._circuit_open:
                break
            rows = self._get_player_recent_replay_rows(pid)
            if not rows:
                continue

            if map_probe:
                # Prioriza replays cujo mapa bate com map_clean (reduz para 1 requisição na quase totalidade dos casos)
                ordered_rids = [rid for rid, txt in rows if map_probe in txt] + [
                    rid for rid, txt in rows if map_probe not in txt
                ]
            else:
                ordered_rids = [rid for rid, _ in rows]

            probes_done = 0
            for rid in ordered_rids:
                if mid in self._match_bg_cache:
                    return dict(self._match_bg_cache[mid])
                if rid in self._replay_to_match_cache:
                    cached_mid, cached_bgs = self._replay_to_match_cache[rid]
                    if cached_mid == mid:
                        return dict(cached_bgs)
                    continue
                if probes_done >= max(1, int(max_replay_probes)) or self._circuit_open:
                    break
                probes_done += 1

                r_html = self._fetch_canonical_html(f"/replays/{rid}", COHDB_REPLAY_PATH_RE)
                if not r_html:
                    continue
                parsed_mid, parsed_bgs = self._parse_replay_page(r_html)
                self._replay_to_match_cache[rid] = (parsed_mid, parsed_bgs)
                if parsed_mid > 0:
                    self._match_bg_cache[parsed_mid] = parsed_bgs
                    if parsed_mid == mid:
                        return dict(parsed_bgs)

        return None


def format_bound_display_alias(
    current_alias: str,
    original_alias: str = "",
    known_aliases: list[str] | tuple[str, ...] | None = None,
) -> str:
    """Exibe o nome preferencial vinculado à conta Steam ou 'NickOriginal (NovoNick)' se inédito."""
    cur = (current_alias or "").strip()
    orig = (original_alias or "").strip()
    if not orig:
        return cur or "Jogador"
    if not cur:
        return orig

    cur_cf = cur.casefold()
    orig_cf = orig.casefold()
    if cur_cf == orig_cf:
        return orig

    known_cf = {str(k).strip().casefold() for k in (known_aliases or []) if str(k).strip()}
    if cur_cf in known_cf:
        return orig
    for k_cf in known_cf:
        if cur_cf.startswith(k_cf + " (") or cur_cf.endswith(f"({k_cf})"):
            return orig

    if cur_cf.startswith(orig_cf + " ("):
        return cur
    return f"{orig} ({cur})"


def _merge_roster_fields(rec: dict[str, Any], prev: dict[str, Any]) -> None:
    for field in ("original_alias", "steam_id", "known_aliases", "merged_into_profile_id", "merged_into_steam_id", "country"):
        if not rec.get(field) and prev.get(field):
            rec[field] = prev[field]


def build_roster_lookup_maps(
    custom_players: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Cria mapas rápidos por steam_id (primário) e profile_id (secundário) unindo o elenco fixo + extras."""
    steam_map: dict[str, dict[str, Any]] = {}
    pid_map: dict[int, dict[str, Any]] = {}

    for src in (custom_players or [], CORE_BR_ROSTER):
        for item in src:
            pid = int(item.get("profile_id", 0) or 0)
            sid_raw = str(item.get("steam_id") or "").replace("/steam/", "").strip()
            sid = sid_raw if STEAM_ID64_VALID_RE.fullmatch(sid_raw) else ""
            rec: dict[str, Any] = {
                "profile_id": pid,
                "steam_id": sid,
                "original_alias": str(item.get("original_alias") or item.get("alias") or "").strip(),
                "known_aliases": list(item.get("known_aliases") or []),
                "merged_into_profile_id": int(item.get("merged_into_profile_id", 0) or 0),
                "merged_into_steam_id": str(item.get("merged_into_steam_id") or "").strip(),
                "country": str(item.get("country") or "").strip().lower(),
            }
            if sid:
                if sid in steam_map:
                    _merge_roster_fields(rec, steam_map[sid])
                steam_map[sid] = rec
            if pid > 0:
                if pid in pid_map:
                    _merge_roster_fields(rec, pid_map[pid])
                pid_map[pid] = rec

    return steam_map, pid_map


def _apply_roster_identity(
    target: dict[str, Any],
    pid: int,
    sid_field: str,
    alias_field: str,
    cur_field: str,
    orig_field: str,
    steam_map: dict[str, dict[str, Any]],
    pid_map: dict[int, dict[str, Any]],
) -> None:
    sid = str(target.get(sid_field) or "").replace("/steam/", "").strip()
    r_entry = steam_map.get(sid) or pid_map.get(pid)
    if not r_entry:
        return
    if r_entry.get("merged_into_steam_id"):
        target[sid_field] = r_entry["merged_into_steam_id"]
    elif r_entry.get("steam_id") and not sid:
        target[sid_field] = r_entry["steam_id"]
    raw_cur = str(target.get(cur_field) or target.get(alias_field) or "")
    target[cur_field] = raw_cur
    target[orig_field] = r_entry.get("original_alias", "")
    target[alias_field] = format_bound_display_alias(
        raw_cur,
        r_entry.get("original_alias", ""),
        r_entry.get("known_aliases"),
    )
    target["is_br_roster"] = True


def enrich_match_with_roster(
    match: dict[str, Any],
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
) -> dict[str, Any]:
    """Aplica vínculo por SteamID64, apelidos preferenciais e unificação de contas a todos na partida."""
    steam_map, pid_map = roster_maps
    _apply_roster_identity(
        match,
        int(match.get("tracked_profile_id", 0)),
        "tracked_steam_id",
        "tracked_alias",
        "tracked_current_alias",
        "tracked_original_alias",
        steam_map,
        pid_map,
    )
    for side_key in ("allies", "opponents"):
        for part in match.get(side_key, []):
            _apply_roster_identity(
                part,
                int(part.get("profile_id", 0)),
                "steam_id",
                "alias",
                "current_alias",
                "original_alias",
                steam_map,
                pid_map,
            )
    return match


def export_players_files(players: list[dict[str, Any]], json_path: Path, csv_path: Path) -> None:
    """Salva atomicamente a lista consolidada de jogadores brasileiros em JSON e CSV (anti-CWE-1236)."""
    json_str = json.dumps(
        {
            "updated_at": int(time.time()),
            "total_players": len(players),
            "players": players,
        },
        ensure_ascii=False,
        indent=2,
    )
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf, lineterminator="\n")
    writer.writerow(
        [
            "profile_id",
            "alias",
            "steam_id",
            "max_elo",
            "best_mode",
            "total_wins",
            "total_losses",
            "modes",
            "coh3stats_url",
        ]
    )
    for p in players:
        modes = ",".join(sorted({v["mode"] for v in p.get("modes", {}).values()}))
        pid_int = int(p["profile_id"])
        writer.writerow(
            [
                pid_int,
                sanitize_csv_cell(p["alias"]),
                sanitize_csv_cell(p.get("steam_id", "")),
                p.get("max_elo", 0),
                sanitize_csv_cell(p.get("best_mode", "")),
                p.get("total_wins", 0),
                p.get("total_losses", 0),
                sanitize_csv_cell(modes),
                f"https://coh3stats.com/players/{pid_int}",
            ]
        )

    try:
        atomic_write_text(json_path, json_str + "\n")
        atomic_write_text(csv_path, csv_buf.getvalue())
    except OSError as exc:
        logger.warning("Não foi possível exportar catálogo em disco (%s): %s", json_path.parent, exc)


def parse_profile_id_input(raw_input: str) -> int | None:
    """Extrai Relic profile_id numérico (1 a 12 dígitos) puro ou de URL coh3stats.com."""
    txt = (raw_input or "").strip()
    if not txt or STEAM_ID64_VALID_RE.fullmatch(txt) or STEAM_URL_EXTRACT_RE.search(txt):
        return None
    if txt.isdigit() and len(txt) <= 12:
        val = int(txt)
        return val if val > 0 else None
    m = COH3STATS_PLAYER_URL_RE.search(txt)
    if m:
        val = int(m.group(1))
        return val if val > 0 else None
    return None


def parse_steam_id_input(raw_input: str) -> str | None:
    """Extrai SteamID64 de 17 dígitos puro ou de URL https://steamcommunity.com/profiles/7656119..."""
    txt = (raw_input or "").strip().replace("/steam/", "")
    if STEAM_ID64_VALID_RE.fullmatch(txt):
        return txt
    m = STEAM_URL_EXTRACT_RE.search(txt)
    return m.group(1) if m else None


def _ingest_personal_stat_payload(
    data: dict[str, Any],
    results_by_pid: dict[int, dict[str, Any]],
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    allowed_pids: set[int] | None = None,
    allowed_sids: set[str] | None = None,
) -> None:
    steam_map, pid_map = roster_maps
    solo_sg_to_pid: dict[int, int] = {}

    for sg in data.get("statGroups", []):
        members = sg.get("members", [])
        if sg.get("type") != 1 or len(members) != 1:
            continue
        mem = members[0]
        pid = int(mem.get("profile_id", 0))
        steam_id = _extract_steam_id(mem.get("name"))
        if allowed_sids is not None and steam_id not in allowed_sids:
            if allowed_pids is None or pid not in allowed_pids:
                continue
        elif allowed_sids is None and allowed_pids is not None and pid not in allowed_pids:
            continue

        sg_id = int(sg["id"])
        solo_sg_to_pid[sg_id] = pid

        r_entry = steam_map.get(steam_id) or pid_map.get(pid) or {}
        orig_alias = str(r_entry.get("original_alias") or "")
        cur_alias = str(mem.get("alias") or orig_alias or f"Player {pid}")
        disp_alias = format_bound_display_alias(cur_alias, orig_alias, r_entry.get("known_aliases"))

        results_by_pid[pid] = {
            "profile_id": pid,
            "alias": disp_alias,
            "current_alias": cur_alias,
            "original_alias": orig_alias or cur_alias,
            "steam_id": steam_id or str(r_entry.get("steam_id") or ""),
            "merged_into_profile_id": int(r_entry.get("merged_into_profile_id", 0) or 0),
            "merged_into_steam_id": str(r_entry.get("merged_into_steam_id") or ""),
            "country": str(mem.get("country") or "br").lower(),
            "level": int(mem.get("level", 0)),
            "xp": int(mem.get("xp", 0)),
            "max_elo": 0,
            "best_mode": "",
            "total_wins": 0,
            "total_losses": 0,
            "last_match_date": 0,
            "modes": {},
            "inactive_modes": {},
            "is_custom": True,
            "is_br_roster": True,
            "coh3stats_url": f"https://coh3stats.com/players/{pid}",
        }

    for st in data.get("leaderboardStats", []):
        sg_id = int(st.get("statgroup_id", -1))
        lb_id = int(st.get("leaderboard_id", -1))
        if sg_id not in solo_sg_to_pid or lb_id not in LEADERBOARD_ID_TO_MODE_FACTION:
            continue
        p = results_by_pid[solo_sg_to_pid[sg_id]]
        mode, faction = LEADERBOARD_ID_TO_MODE_FACTION[lb_id]
        elo = int(round(st.get("rating", 0)))
        if elo <= 0:
            continue
        wins = int(st.get("wins", 0))
        losses = int(st.get("losses", 0))
        lmd = int(st.get("lastmatchdate", 0))
        rank_val = int(st.get("rank", -1))
        stat_obj = {
            "mode": mode,
            "faction": faction,
            "elo": elo,
            "rank": rank_val,
            "regionrank": int(st.get("regionrank", -1)),
            "wins": wins,
            "losses": losses,
            "streak": int(st.get("streak", 0)),
            "lastmatchdate": lmd,
        }
        target_dict = p["modes"] if rank_val > 0 else p["inactive_modes"]
        target_dict[f"{mode}_{faction}"] = stat_obj
        p["total_wins"] += wins
        p["total_losses"] += losses
        if elo > p["max_elo"]:
            p["max_elo"] = elo
            p["best_mode"] = f"{mode.upper()} ({faction.upper()})"
        if lmd > p["last_match_date"]:
            p["last_match_date"] = lmd


def fetch_custom_players_stats(
    client: RelicAPIClient,
    targets: list[int] | list[dict[str, Any]],
    steam_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Consulta getPersonalStat em paralelo seguro (lotes de até 10 contas) priorizando SteamID64."""
    dict_targets: list[dict[str, Any]] = []
    steam_set: set[str] = set()
    fallback_pid_set: set[int] = set()

    for item in targets or []:
        if isinstance(item, dict):
            dict_targets.append(item)
            sid = str(item.get("steam_id") or "").replace("/steam/", "").strip()
            pid = int(item.get("profile_id", 0) or 0)
            if STEAM_ID64_VALID_RE.fullmatch(sid):
                steam_set.add(sid)
            elif pid > 0:
                fallback_pid_set.add(pid)
        else:
            pid = int(item or 0)
            if pid > 0:
                fallback_pid_set.add(pid)

    for sid in steam_ids or []:
        clean_sid = str(sid or "").replace("/steam/", "").strip()
        if STEAM_ID64_VALID_RE.fullmatch(clean_sid):
            steam_set.add(clean_sid)

    roster_maps = build_roster_lookup_maps(dict_targets)
    steam_map, pid_map = roster_maps

    for pid in list(fallback_pid_set):
        known = pid_map.get(pid)
        if known and known.get("steam_id"):
            steam_set.add(known["steam_id"])
            fallback_pid_set.discard(pid)

    results_by_pid: dict[int, dict[str, Any]] = {}
    ordered_sids = sorted(steam_set)
    sid_batches = [ordered_sids[i : i + 10] for i in range(0, len(ordered_sids), 10)]

    if sid_batches:
        def _fetch_sid_batch(batch_sids: list[str]) -> tuple[list[str], dict[str, Any]]:
            names_json = json.dumps([f"/steam/{s}" for s in batch_sids], separators=(",", ":"))
            encoded_names = urllib.parse.quote(names_json)
            url = f"{BASE_URL}/getPersonalStat?title={TITLE_STEAM}&profile_names={encoded_names}"
            return batch_sids, client._get_json(url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(sid_batches))) as pool:
            for batch_sids, data in pool.map(_fetch_sid_batch, sid_batches):
                _ingest_personal_stat_payload(
                    data,
                    results_by_pid,
                    roster_maps=roster_maps,
                    allowed_sids=set(batch_sids),
                )

    resolved_sids = {str(v.get("steam_id") or "") for v in results_by_pid.values()}
    for s in ordered_sids:
        if s not in resolved_sids and s in steam_map and int(steam_map[s].get("profile_id", 0)) > 0:
            fallback_pid_set.add(int(steam_map[s]["profile_id"]))

    ordered_pids = sorted(pid for pid in fallback_pid_set if pid not in results_by_pid)
    pid_batches = [ordered_pids[i : i + 10] for i in range(0, len(ordered_pids), 10)]

    if pid_batches:
        def _fetch_pid_batch(batch_pids: list[int]) -> tuple[list[int], dict[str, Any]]:
            encoded_ids = urllib.parse.quote("[" + ",".join(str(i) for i in batch_pids) + "]")
            url = f"{BASE_URL}/getPersonalStat?title={TITLE_STEAM}&profile_ids={encoded_ids}"
            return batch_pids, client._get_json(url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(pid_batches))) as pool:
            for batch_pids, data in pool.map(_fetch_pid_batch, pid_batches):
                _ingest_personal_stat_payload(
                    data,
                    results_by_pid,
                    roster_maps=roster_maps,
                    allowed_pids=set(batch_pids),
                )

    return list(results_by_pid.values())


def _accumulate_mode_stats(
    source_modes: dict[str, Any],
    sub_modes: tuple[str, ...],
) -> tuple[list[int], dict[str, list[int]], dict[str, int], int, int, int, int]:
    all_elos: list[int] = []
    per_faction: dict[str, list[int]] = {f: [] for f in FACTIONS_ORDER}
    submode_elos: dict[str, int] = {}
    wins = 0
    losses = 0
    last_match = 0
    latest_streak = 0
    latest_streak_ts = -1

    for sub in sub_modes:
        for fac in FACTIONS_ORDER:
            key = f"{sub}_{fac}"
            st = source_modes.get(key)
            if not st:
                continue
            elo_val = int(round(st.get("elo", 0)))
            if elo_val <= 0:
                continue
            all_elos.append(elo_val)
            per_faction[fac].append(elo_val)
            submode_elos[key] = elo_val
            wins += int(st.get("wins", 0))
            losses += int(st.get("losses", 0))
            lmd_val = int(st.get("lastmatchdate", 0))
            if lmd_val > last_match:
                last_match = lmd_val
            if lmd_val >= latest_streak_ts:
                latest_streak_ts = lmd_val
                latest_streak = int(st.get("streak", 0))

    return all_elos, per_faction, submode_elos, wins, losses, last_match, latest_streak


def compute_merged_mode_rankings(
    players: list[dict[str, Any]],
    mode_groups: dict[str, tuple[str, ...]] | None = None,
    custom_ids: set[int] | None = None,
    custom_steam_ids: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Mescla os rankings das facções ativas dentro de '1v1', '2v2' e 'Team Games' pela média de ELO."""
    groups = mode_groups or STUDY_MODE_GROUPS
    custom_set = {int(x) for x in (custom_ids or set())}
    custom_sid_set = {str(s) for s in (custom_steam_ids or set()) if s}
    rankings_by_mode: dict[str, list[dict[str, Any]]] = {}

    for group_name, sub_modes in groups.items():
        mode_entries: list[dict[str, Any]] = []
        max_slots = len(sub_modes) * len(FACTIONS_ORDER)

        for p in players:
            pid = int(p["profile_id"])
            sid = str(p.get("steam_id") or "")
            is_custom = pid in custom_set or (bool(sid) and sid in custom_sid_set) or bool(p.get("is_custom"))

            (
                all_active_elos,
                per_faction_lists,
                submode_elos,
                wins_mode,
                losses_mode,
                last_match_mode,
                latest_streak,
            ) = _accumulate_mode_stats(p.get("modes", {}), sub_modes)

            used_inactive_fallback = False
            if not all_active_elos and is_custom and p.get("inactive_modes"):
                used_inactive_fallback = True
                (
                    all_active_elos,
                    per_faction_lists,
                    submode_elos,
                    wins_mode,
                    losses_mode,
                    last_match_mode,
                    latest_streak,
                ) = _accumulate_mode_stats(p["inactive_modes"], sub_modes)

            if not all_active_elos:
                continue

            faction_elos = {
                fac: int(round(sum(vals) / len(vals)))
                for fac, vals in per_faction_lists.items()
                if vals
            }
            avg_elo = round(sum(all_active_elos) / len(all_active_elos), 1)
            total_games = wins_mode + losses_mode
            win_ratio = int(round((wins_mode * 100.0) / total_games)) if total_games > 0 else 0

            mode_entries.append(
                {
                    "profile_id": pid,
                    "alias": str(p["alias"]),
                    "current_alias": str(p.get("current_alias") or p["alias"]),
                    "original_alias": str(p.get("original_alias") or p["alias"]),
                    "steam_id": sid,
                    "country": str(p.get("country") or "br").lower(),
                    "mode": group_name,
                    "sub_modes": list(sub_modes),
                    "avg_elo": avg_elo,
                    "max_mode_elo": max(all_active_elos),
                    "active_factions_count": len(faction_elos),
                    "active_rankings_count": len(all_active_elos),
                    "max_rankings_slots": max_slots,
                    "faction_elos": faction_elos,
                    "submode_elos": submode_elos,
                    "streak": latest_streak,
                    "wins": wins_mode,
                    "losses": losses_mode,
                    "total": total_games,
                    "ratio": win_ratio,
                    "last_match_date": last_match_mode,
                    "is_custom": is_custom,
                    "is_br_roster": bool(p.get("is_br_roster")) or is_custom,
                    "inactive_fallback": used_inactive_fallback,
                    "rank_delta": int(p.get("rank_delta", 0)),
                    "prev_rank": p.get("prev_rank"),
                    "coh3stats_url": f"https://coh3stats.com/players/{pid}",
                }
            )

        mode_entries.sort(
            key=lambda x: (
                1 if x.get("inactive_fallback") else 0,
                -x["avg_elo"],
                -x["active_rankings_count"],
                -x["max_mode_elo"],
                -x["wins"],
            )
        )
        for rank_pos, entry in enumerate(mode_entries, start=1):
            entry["br_rank"] = rank_pos

        rankings_by_mode[group_name] = mode_entries

    return rankings_by_mode


def build_top_tracked_players(
    rankings_by_mode: dict[str, list[dict[str, Any]]],
    top_n: int = 20,
    custom_players: list[dict[str, Any]] | None = None,
    only_custom: bool = False,
) -> list[dict[str, Any]]:
    """Constrói a lista consolidada de contas rastreadas (31 únicos + convidados ou Top N)."""
    steam_map, pid_map = build_roster_lookup_maps(custom_players)
    custom_by_id = {int(cp["profile_id"]): cp for cp in (custom_players or []) if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp.get("steam_id") or "") for cp in (custom_players or []) if cp.get("steam_id")}
    consolidated: dict[int, dict[str, Any]] = {}

    for mode, entries in rankings_by_mode.items():
        mode_pt = "Jogos em Equipe" if mode == "Team Games" else mode
        for idx, item in enumerate(entries):
            pid = int(item["profile_id"])
            sid = str(item.get("steam_id") or "")
            is_cust = pid in custom_by_id or (bool(sid) and sid in custom_sids) or bool(item.get("is_custom"))
            if only_custom and not is_cust:
                continue
            if not only_custom and idx >= top_n and not is_cust:
                continue
            if pid not in consolidated:
                r_entry = steam_map.get(sid) or pid_map.get(pid) or {}
                consolidated[pid] = {
                    "profile_id": pid,
                    "alias": item["alias"],
                    "original_alias": str(r_entry.get("original_alias") or item.get("original_alias") or item["alias"]),
                    "steam_id": sid or str(r_entry.get("steam_id") or ""),
                    "placements": [],
                    "best_avg_elo": item["avg_elo"],
                    "is_custom": is_cust,
                }
            rec = consolidated[pid]
            tag = " ⭐" if rec["is_custom"] and idx >= top_n else ""
            rec["placements"].append(f"#{item['br_rank']} {mode_pt} (média {item['avg_elo']:.1f}){tag}")
            if item["avg_elo"] > rec["best_avg_elo"]:
                rec["best_avg_elo"] = item["avg_elo"]

    for pid, cp in custom_by_id.items():
        if pid not in consolidated:
            sid = str(cp.get("steam_id") or "")
            r_entry = steam_map.get(sid) or pid_map.get(pid) or {}
            orig_alias = str(r_entry.get("original_alias") or cp.get("original_alias") or cp.get("alias") or f"Player {pid}")
            cur_alias = str(cp.get("alias") or orig_alias)
            merged_pid = int(r_entry.get("merged_into_profile_id") or cp.get("merged_into_profile_id") or 0)
            placements_lbl = (
                [f"🔗 Conta mesclada em {orig_alias} (#{merged_pid})"]
                if merged_pid
                else ["⭐ Monitorado (aguardando ranking)"]
            )
            consolidated[pid] = {
                "profile_id": pid,
                "alias": format_bound_display_alias(cur_alias, orig_alias, r_entry.get("known_aliases")),
                "original_alias": orig_alias,
                "steam_id": sid or str(r_entry.get("steam_id") or ""),
                "merged_into_profile_id": merged_pid,
                "placements": placements_lbl,
                "best_avg_elo": 0.0,
                "is_custom": True,
            }

    return sorted(consolidated.values(), key=lambda x: (-x["best_avg_elo"], x["alias"].lower()))


def export_merged_top_rankings(
    rankings_by_mode: dict[str, list[dict[str, Any]]],
    top_n: int,
    json_path: Path,
    csv_path: Path,
    custom_players: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Exporta atomicamente Top N + monitorados em JSON/CSV e retorna o dicionário filtrado."""
    custom_ids = {int(cp["profile_id"]) for cp in (custom_players or []) if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp.get("steam_id") or "") for cp in (custom_players or []) if cp.get("steam_id")}
    trimmed: dict[str, list[dict[str, Any]]] = {}

    for mode, entries in rankings_by_mode.items():
        trimmed[mode] = [
            e
            for idx, e in enumerate(entries)
            if idx < top_n
            or e["profile_id"] in custom_ids
            or (bool(e.get("steam_id")) and str(e["steam_id"]) in custom_sids)
            or bool(e.get("is_custom"))
        ]

    unique_players = build_top_tracked_players(
        rankings_by_mode,
        top_n=top_n,
        custom_players=custom_players,
        only_custom=False,
    )

    json_str = json.dumps(
        {
            "updated_at": int(time.time()),
            "methodology": "simple_average_of_active_factions_elo_1v1_2v2_team_games",
            "modes": list(rankings_by_mode.keys()),
            "top_n_per_mode": top_n,
            "unique_players_count": len(unique_players),
            "rankings_by_mode": trimmed,
            "selected_unique_players": unique_players,
        },
        ensure_ascii=False,
        indent=2,
    )

    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf, lineterminator="\n")
    writer.writerow(
        [
            "mode",
            "br_rank",
            "rank_delta",
            "is_monitored_31",
            "profile_id",
            "steam_id",
            "original_alias",
            "display_alias",
            "avg_elo",
            "active_rankings",
            "elo_usf",
            "elo_ukf",
            "elo_dak",
            "elo_wehr",
            "mode_wins",
            "mode_losses",
            "coh3stats_url",
        ]
    )
    for mode, entries in trimmed.items():
        for e in entries:
            fe = e["faction_elos"]
            pid_int = int(e["profile_id"])
            writer.writerow(
                [
                    sanitize_csv_cell(mode),
                    e["br_rank"],
                    e.get("rank_delta", 0),
                    "sim" if e.get("is_custom") else "nao",
                    pid_int,
                    sanitize_csv_cell(e.get("steam_id", "")),
                    sanitize_csv_cell(e.get("original_alias", "")),
                    sanitize_csv_cell(e["alias"]),
                    e["avg_elo"],
                    f"{e['active_rankings_count']}/{e['max_rankings_slots']}",
                    fe.get("american", ""),
                    fe.get("british", ""),
                    fe.get("dak", ""),
                    fe.get("german", ""),
                    e["wins"],
                    e["losses"],
                    f"https://coh3stats.com/players/{pid_int}",
                ]
            )

    try:
        atomic_write_text(json_path, json_str + "\n")
        atomic_write_text(csv_path, csv_buf.getvalue())
    except OSError as exc:
        logger.warning("Não foi possível exportar ranking em disco (%s): %s", json_path.parent, exc)

    return trimmed

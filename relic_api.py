"""Cliente endurecido e otimizado da API Comunitária da Relic para Company of Heroes 3 (Steam)."""

from __future__ import annotations

import concurrent.futures
import csv
import io
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
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

MAP_SIZE_SUFFIX_RE = re.compile(r"_(2p|4p|6p|8p)(?=_|$)", re.IGNORECASE)
MAP_MK_SUFFIX_RE = re.compile(r"_(mkii|mkiii|mkv)(?=_|$)", re.IGNORECASE)
STEAM_ID64_VALID_RE = re.compile(r"^7656119\d{10}$")
STEAM_URL_EXTRACT_RE = re.compile(r"steamcommunity\.com/profiles/(7656119\d{10})", re.IGNORECASE)
COH3STATS_PLAYER_URL_RE = re.compile(
    r"coh3stats\.com/(?:[a-z]{2}/)?players/(\d{1,12})(?:\D|$)",
    re.IGNORECASE,
)

# Lista fixa dos 32 jogadores brasileiros únicos monitorados (33 contas Steam vinculadas por SteamID64 imutável)
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
    {"profile_id": 366826, "steam_id": "76561198014985380", "original_alias": "Lem22"},
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
    """Formata nomes internos de mapas (ex: 'twin_beaches_2p_mkii' -> 'Twin Beaches')."""
    if not raw_map:
        return "Mapa Desconhecido"
    cleaned = MAP_SIZE_SUFFIX_RE.sub("", raw_map)
    cleaned = MAP_MK_SUFFIX_RE.sub("", cleaned)
    cleaned = cleaned.replace("_", " ").strip()
    return cleaned.title() if cleaned else raw_map


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

    def _get_json(self, url: str, retries: int = 3) -> dict[str, Any]:
        validate_https_endpoint(
            url,
            ALLOWED_RELIC_HOSTS,
            path_prefix="/community/leaderboard/",
        )
        opener = _get_thread_opener()
        headers = {
            "User-Agent": "CoH3-BR-Discord-Tracker/7.0",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        }

        last_err: Exception | None = None
        for attempt in range(retries):
            self._reserve_rate_slot()
            try:
                req = urllib.request.Request(url, headers=headers)
                with opener.open(req, timeout=self.timeout_sec) as resp:
                    raw_bytes = read_bounded_http_body(resp, MAX_RELIC_RESPONSE_BYTES)
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
            int(pr["profile_id"]): pr for pr in data.get("profiles", []) if "profile_id" in pr
        }
        tracked_prof = profiles_by_id.get(pid_clean, {})
        tracked_alias = tracked_prof.get("alias") or fallback_alias or f"Player {pid_clean}"
        tracked_steam_id = _extract_steam_id(tracked_prof.get("name"))

        raw_stats = sorted(
            data.get("matchHistoryStats", []),
            key=lambda m: int(m.get("completiontime", 0)),
            reverse=True,
        )

        parsed_matches: list[dict[str, Any]] = []
        for match in raw_stats:
            match_id = int(match.get("id", 0))
            mt_id = int(match.get("matchtype_id", 0))
            mode_label = normalize_mode_name(mt_id, self.match_types.get(mt_id))

            if only_automatch and mode_label not in AUTOMATCH_MODES:
                continue

            reports = match.get("matchhistoryreportresults", [])
            my_rep = next((r for r in reports if int(r.get("profile_id", -1)) == pid_clean), None)
            if not my_rep:
                continue

            members_by_pid: dict[int, dict[str, Any]] = {
                int(mem["profile_id"]): mem
                for mem in match.get("matchhistorymember", [])
                if "profile_id" in mem
            }

            my_team = my_rep.get("teamid", 0)
            allies: list[dict[str, Any]] = []
            opponents: list[dict[str, Any]] = []

            for rep in reports:
                rpid = int(rep.get("profile_id", 0))
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

            start_ts = int(match.get("startgametime", 0))
            end_ts = int(match.get("completiontime", 0))
            raw_map = str(match.get("mapname") or "unknown_map")
            my_faction = self.races.get(int(my_rep.get("race_id", -1)), "Unknown")
            result_type = int(my_rep.get("resulttype", 0))

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
            parsed_matches.append(enrich_match_with_roster(m_obj, active_roster_maps))

        return parsed_matches


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
    for field in ("original_alias", "steam_id", "known_aliases", "merged_into_profile_id", "merged_into_steam_id"):
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

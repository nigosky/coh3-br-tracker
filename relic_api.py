"""Cliente da API Comunitária da Relic para Company of Heroes 3 (Steam)."""

from __future__ import annotations

import csv
import json
import logging
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger("coh3_br.relic_api")

BASE_URL = "https://coh3-api.reliclink.com/community/leaderboard"
TITLE_STEAM = "coh3"
SOUTH_AMERICA_REGION_ID = 2074438

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


def clean_map_name(raw_map: str) -> str:
    """Formata nomes internos de mapas (ex: 'twin_beaches_2p_mkii' -> 'Twin Beaches')."""
    if not raw_map:
        return "Mapa Desconhecido"
    cleaned = re.sub(r"_(2p|4p|6p|8p)(?=_|$)", "", raw_map, flags=re.IGNORECASE)
    cleaned = re.sub(r"_(mkii|mkiii|mkv)(?=_|$)", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("_", " ").strip()
    return cleaned.title() if cleaned else raw_map


def normalize_mode_name(matchtype_id: int, raw_name: str | None = None) -> str:
    """Converte o matchtype_id da Relic para rótulo ('1v1', '2v2', 'Team Games (3v3)', 'Team Games (4v4)', 'Custom')."""
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


import concurrent.futures
import ssl
import threading
import urllib.parse

ALLOWED_RELIC_HOST = "coh3-api.reliclink.com"
MAX_RELIC_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB limite máximo por resposta JSON
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(val: Any) -> Any:
    """Previne CSV Formula Injection (CWE-1236) ao abrir arquivos CSV no Excel/Sheets."""
    if not isinstance(val, str):
        return val
    stripped = val.replace("\x00", "")
    if stripped.startswith(CSV_FORMULA_PREFIXES):
        return f"'{stripped}"
    return stripped


class _RelicNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento HTTP bloqueado", headers, fp)


def _build_relic_opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _RelicNoRedirectHandler())


_THREAD_LOCAL = threading.local()


def _get_thread_opener() -> urllib.request.OpenerDirector:
    opener = getattr(_THREAD_LOCAL, "opener", None)
    if opener is None:
        opener = _build_relic_opener()
        _THREAD_LOCAL.opener = opener
    return opener


class RelicAPIClient:
    """Cliente HTTPS endurecido com TLS 1.2+, allowlist de host, limite de memória e rate limit thread-safe."""

    def __init__(self, min_interval_sec: float = 0.08, timeout_sec: float = 15.0) -> None:
        self.min_interval_sec = min_interval_sec
        self.timeout_sec = timeout_sec
        self._last_req_ts = 0.0
        self._rate_lock = threading.Lock()
        self._meta_lock = threading.Lock()
        self.races: dict[int, str] = dict(FALLBACK_RACES)
        self.match_types: dict[int, str] = {}
        self._metadata_loaded = False

    def _get_json(self, url: str, retries: int = 3) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() != ALLOWED_RELIC_HOST:
            raise ValueError(f"Host não autorizado para consulta da API Relic: {parsed.hostname}")

        with self._rate_lock:
            now_m = time.monotonic()
            elapsed = now_m - self._last_req_ts
            if elapsed < self.min_interval_sec:
                time.sleep(self.min_interval_sec - elapsed)
            self._last_req_ts = time.monotonic()

        opener = _get_thread_opener()
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "CoH3-BR-Discord-Tracker/5.0", "Accept": "application/json"},
                )
                with opener.open(req, timeout=self.timeout_sec) as resp:
                    raw_bytes = resp.read(MAX_RELIC_RESPONSE_BYTES + 1)
                    if len(raw_bytes) > MAX_RELIC_RESPONSE_BYTES:
                        raise RuntimeError("Resposta da API Relic excedeu o limite máximo seguro de 5 MB.")
                    payload = json.loads(raw_bytes.decode("utf-8"))
                return payload
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
                last_err = exc
                wait = (2 ** attempt) * 0.6
                logger.warning("Falha na requisição Relic (%s) tentativa %d/%d: %s", url, attempt + 1, retries, exc)
                time.sleep(wait)

        raise RuntimeError(f"Erro ao consultar API da Relic ({url}): {last_err}")

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
                    if rid is not None and name and rid not in FALLBACK_RACES:
                        self.races[int(rid)] = str(name)
                for mt in data.get("matchTypes", []):
                    mid = mt.get("id")
                    name = mt.get("localizedName") or mt.get("name")
                    if mid is not None and name:
                        self.match_types[int(mid)] = str(name)
                self._metadata_loaded = True
            except Exception as exc:
                logger.warning("Não foi possível atualizar metadados dinâmicos; usando fallback: %s", exc)

    def fetch_brazilian_players(
        self,
        include_global_top_pages: int = 2,
        max_sa_rank: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Varre em paralelo seguro todos os modos ranqueados da Steam (1v1, 2v2, 3v3, 4v4 nas 4 facções),
        filtrando jogadores com country == 'br'.
        """
        players: dict[int, dict[str, Any]] = {}
        ingest_lock = threading.Lock()

        def ingest_response(data: dict[str, Any], mode: str, faction: str) -> int:
            stat_groups = {sg["id"]: sg for sg in data.get("statGroups", [])}
            lb_stats = data.get("leaderboardStats", [])
            with ingest_lock:
                for st in lb_stats:
                    sg = stat_groups.get(st.get("statgroup_id"), {})
                    for member in sg.get("members", []):
                        if str(member.get("country", "")).lower() != "br":
                            continue
                        pid = int(member["profile_id"])
                        steam_raw = str(member.get("name", ""))
                        steam_id = steam_raw.replace("/steam/", "") if steam_raw.startswith("/steam/") else ""
                        if pid not in players:
                            players[pid] = {
                                "profile_id": pid,
                                "alias": member.get("alias") or f"Player {pid}",
                                "steam_id": steam_id,
                                "country": "br",
                                "level": member.get("level", 0),
                                "xp": member.get("xp", 0),
                                "max_elo": 0,
                                "best_mode": "",
                                "total_wins": 0,
                                "total_losses": 0,
                                "last_match_date": 0,
                                "modes": {},
                                "coh3stats_url": f"https://coh3stats.com/players/{pid}",
                            }
                        p = players[pid]
                        elo = int(round(st.get("rating", 0)))
                        wins = int(st.get("wins", 0))
                        losses = int(st.get("losses", 0))
                        lmd = int(st.get("lastmatchdate", 0))
                        key = f"{mode}_{faction}"
                        if key not in p["modes"]:
                            p["modes"][key] = {
                                "mode": mode,
                                "faction": faction,
                                "elo": elo,
                                "rank": st.get("rank", 0),
                                "regionrank": st.get("regionrank", 0),
                                "wins": wins,
                                "losses": losses,
                                "streak": st.get("streak", 0),
                                "lastmatchdate": lmd,
                            }
                            p["total_wins"] += wins
                            p["total_losses"] += losses
                        if elo > p["max_elo"]:
                            p["max_elo"] = elo
                            p["best_mode"] = f"{mode.upper()} ({faction.upper()})"
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

        sorted_list = sorted(players.values(), key=lambda x: (-x["max_elo"], -x["last_match_date"]))
        return sorted_list

    def fetch_player_recent_matches(
        self,
        profile_id: int,
        fallback_alias: str = "",
        only_automatch: bool = False,
        roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retorna as partidas recentes de um jogador ordenadas da mais recente para a mais antiga,
        aplicando vínculo por conta Steam e preservação do nick original.
        """
        self.ensure_metadata()
        active_roster_maps = roster_maps or build_roster_lookup_maps()
        url = f"{BASE_URL}/getRecentMatchHistoryByProfileId?title={TITLE_STEAM}&profile_id={profile_id}"
        data = self._get_json(url)

        profiles_by_id: dict[int, dict[str, Any]] = {
            int(pr["profile_id"]): pr for pr in data.get("profiles", []) if "profile_id" in pr
        }
        tracked_prof = profiles_by_id.get(profile_id, {})
        tracked_alias = tracked_prof.get("alias") or fallback_alias or f"Player {profile_id}"
        tracked_steam_raw = str(tracked_prof.get("name") or "")
        tracked_steam_id = tracked_steam_raw.replace("/steam/", "") if tracked_steam_raw.startswith("/steam/") else ""

        raw_stats = data.get("matchHistoryStats", [])
        raw_stats.sort(key=lambda m: int(m.get("completiontime", 0)), reverse=True)

        parsed_matches: list[dict[str, Any]] = []
        for match in raw_stats:
            match_id = int(match.get("id", 0))
            mt_id = int(match.get("matchtype_id", 0))
            mode_label = normalize_mode_name(mt_id, self.match_types.get(mt_id))

            if only_automatch and mode_label not in AUTOMATCH_MODES:
                continue

            reports = match.get("matchhistoryreportresults", [])
            my_rep = next((r for r in reports if int(r.get("profile_id", -1)) == profile_id), None)
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
                p_old_elo = int(mem["oldrating"]) if int(mem.get("oldrating", 0) or 0) > 0 else None
                p_new_elo = int(mem["newrating"]) if int(mem.get("newrating", 0) or 0) > 0 else None
                p_delta = (p_new_elo - p_old_elo) if (p_old_elo is not None and p_new_elo is not None) else None
                p_steam_raw = str(prof.get("name") or "")
                p_steam_id = p_steam_raw.replace("/steam/", "") if p_steam_raw.startswith("/steam/") else ""

                participant = {
                    "profile_id": rpid,
                    "alias": prof.get("alias") or f"ID {rpid}",
                    "steam_id": p_steam_id,
                    "country": str(prof.get("country") or "un").lower(),
                    "faction": race_name,
                    "faction_short": FACTION_SHORT.get(race_name, race_name),
                    "old_elo": p_old_elo,
                    "new_elo": p_new_elo,
                    "elo_delta": p_delta,
                    "elo": p_new_elo,
                }
                if rep.get("teamid") == my_team:
                    if rpid != profile_id:
                        allies.append(participant)
                else:
                    opponents.append(participant)

            my_mem = members_by_pid.get(profile_id, {})
            old_elo = int(my_mem["oldrating"]) if int(my_mem.get("oldrating", 0) or 0) > 0 else None
            new_elo = int(my_mem["newrating"]) if int(my_mem.get("newrating", 0) or 0) > 0 else None

            counters: dict[str, Any] = {}
            raw_counters = my_rep.get("counters")
            if isinstance(raw_counters, str) and raw_counters.startswith("{"):
                try:
                    counters = json.loads(raw_counters)
                except json.JSONDecodeError:
                    counters = {}

            start_ts = int(match.get("startgametime", 0))
            end_ts = int(match.get("completiontime", 0))
            duration_sec = max(0, end_ts - start_ts)
            raw_map = str(match.get("mapname") or "unknown_map")
            my_faction = self.races.get(int(my_rep.get("race_id", -1)), "Unknown")
            result_type = int(my_rep.get("resulttype", 0))

            m_obj = {
                "match_id": match_id,
                "tracked_profile_id": profile_id,
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
                "duration_sec": duration_sec,
                "old_elo": old_elo,
                "new_elo": new_elo,
                "allies": allies,
                "opponents": opponents,
                "counters": counters,
                "has_replay": len(match.get("matchurls", [])) > 0,
                "coh3stats_url": f"https://coh3stats.com/players/{profile_id}/matches/{match_id}",
            }
            parsed_matches.append(enrich_match_with_roster(m_obj, active_roster_maps))

        return parsed_matches


# Lista fixa dos 31 jogadores brasileiros únicos monitorados (32 contas Steam vinculadas por SteamID64 imutável)
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
]

STEAM_ID64_VALID_RE = re.compile(r"^7656119\d{10}$")


def format_bound_display_alias(
    current_alias: str,
    original_alias: str = "",
    known_aliases: list[str] | tuple[str, ...] | None = None,
) -> str:
    """
    Exibe o nome preferencial/original vinculado à conta Steam:
    - Se current_alias estiver em known_aliases (ex.: 'Minhoca de ferro!' -> 'Alekel', 'gabe44arg' -> 'É o Gabe')
      ou coincidir com original_alias, exibe apenas original_alias limpo.
    - Se o jogador trocar para um nick inédito na Steam no futuro, exibe 'NickOriginal (NovoNick)'.
    """
    cur = (current_alias or "").strip()
    orig = (original_alias or "").strip()
    if not orig:
        return cur or "Jogador"
    if not cur:
        return orig

    known_cf = {str(k).strip().casefold() for k in (known_aliases or []) if str(k).strip()}
    if cur.casefold() in known_cf:
        return orig
    # Caso cur já estivesse no formato 'NickAntigo (NickSteam)' de versão anterior
    for k_cf in known_cf:
        if cur.casefold().startswith(k_cf + " (") or cur.casefold().endswith(f"({k_cf})"):
            return orig

    if cur.casefold() == orig.casefold():
        return orig
    if cur.casefold().startswith(orig.casefold() + " ("):
        return cur
    return f"{orig} ({cur})"


def build_roster_lookup_maps(
    custom_players: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Cria mapas rápidos por steam_id (primário) e profile_id (secundário) unindo o elenco fixo + extras."""
    steam_map: dict[str, dict[str, Any]] = {}
    pid_map: dict[int, dict[str, Any]] = {}

    # CORE_BR_ROSTER aplicado por último nas propriedades de identidade para garantir overrides (ex.: Alekel, É o Gabe)
    for src in (custom_players or [], CORE_BR_ROSTER):
        for item in src:
            pid = int(item.get("profile_id", 0) or 0)
            sid = str(item.get("steam_id") or "").replace("/steam/", "").strip()
            orig = str(item.get("original_alias") or item.get("alias") or "").strip()
            known = list(item.get("known_aliases") or [])
            merged_pid = int(item.get("merged_into_profile_id", 0) or 0)
            merged_sid = str(item.get("merged_into_steam_id") or "").strip()
            rec: dict[str, Any] = {
                "profile_id": pid,
                "steam_id": sid if STEAM_ID64_VALID_RE.fullmatch(sid) else "",
                "original_alias": orig,
                "known_aliases": known,
                "merged_into_profile_id": merged_pid,
                "merged_into_steam_id": merged_sid,
            }
            if rec["steam_id"]:
                prev = steam_map.get(rec["steam_id"], {})
                if not rec["original_alias"] and prev.get("original_alias"):
                    rec["original_alias"] = prev["original_alias"]
                if not rec["known_aliases"] and prev.get("known_aliases"):
                    rec["known_aliases"] = prev["known_aliases"]
                if not rec["merged_into_profile_id"] and prev.get("merged_into_profile_id"):
                    rec["merged_into_profile_id"] = prev["merged_into_profile_id"]
                if not rec["merged_into_steam_id"] and prev.get("merged_into_steam_id"):
                    rec["merged_into_steam_id"] = prev["merged_into_steam_id"]
                steam_map[rec["steam_id"]] = rec
            if pid > 0:
                prev_p = pid_map.get(pid, {})
                if not rec["original_alias"] and prev_p.get("original_alias"):
                    rec["original_alias"] = prev_p["original_alias"]
                if not rec["steam_id"] and prev_p.get("steam_id"):
                    rec["steam_id"] = prev_p["steam_id"]
                if not rec["known_aliases"] and prev_p.get("known_aliases"):
                    rec["known_aliases"] = prev_p["known_aliases"]
                if not rec["merged_into_profile_id"] and prev_p.get("merged_into_profile_id"):
                    rec["merged_into_profile_id"] = prev_p["merged_into_profile_id"]
                if not rec["merged_into_steam_id"] and prev_p.get("merged_into_steam_id"):
                    rec["merged_into_steam_id"] = prev_p["merged_into_steam_id"]
                pid_map[pid] = rec

    return steam_map, pid_map


def enrich_match_with_roster(
    match: dict[str, Any],
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
) -> dict[str, Any]:
    """
    Aplica vínculo por SteamID64, substituição de apelidos (ex.: Alekel) e unificação de contas
    (ex.: gabe44arg -> É o Gabe) ao jogador monitorado, aliados e oponentes da partida.
    """
    steam_map, pid_map = roster_maps

    t_pid = int(match.get("tracked_profile_id", 0))
    t_sid = str(match.get("tracked_steam_id") or "").replace("/steam/", "").strip()
    r_entry = steam_map.get(t_sid) or pid_map.get(t_pid)
    if r_entry:
        if r_entry.get("merged_into_steam_id"):
            match["tracked_steam_id"] = r_entry["merged_into_steam_id"]
        elif r_entry.get("steam_id") and not t_sid:
            match["tracked_steam_id"] = r_entry["steam_id"]
        raw_cur = str(match.get("tracked_current_alias") or match.get("tracked_alias") or "")
        match["tracked_current_alias"] = raw_cur
        match["tracked_original_alias"] = r_entry.get("original_alias", "")
        match["tracked_alias"] = format_bound_display_alias(
            raw_cur,
            r_entry.get("original_alias", ""),
            r_entry.get("known_aliases"),
        )
        match["is_br_roster"] = True

    for side_key in ("allies", "opponents"):
        for part in match.get(side_key, []):
            p_pid = int(part.get("profile_id", 0))
            p_sid = str(part.get("steam_id") or "").replace("/steam/", "").strip()
            p_entry = steam_map.get(p_sid) or pid_map.get(p_pid)
            if p_entry:
                if p_entry.get("merged_into_steam_id"):
                    part["steam_id"] = p_entry["merged_into_steam_id"]
                elif p_entry.get("steam_id") and not p_sid:
                    part["steam_id"] = p_entry["steam_id"]
                raw_p_cur = str(part.get("current_alias") or part.get("alias") or "")
                part["current_alias"] = raw_p_cur
                part["original_alias"] = p_entry.get("original_alias", "")
                part["alias"] = format_bound_display_alias(
                    raw_p_cur,
                    p_entry.get("original_alias", ""),
                    p_entry.get("known_aliases"),
                )
                part["is_br_roster"] = True

    return match


def export_players_files(players: list[dict[str, Any]], json_path: Path, csv_path: Path) -> None:
    """Salva a lista consolidada de jogadores brasileiros em JSON e CSV."""
    json_path.write_text(
        json.dumps(
            {
                "updated_at": int(time.time()),
                "total_players": len(players),
                "players": players,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
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


PROFILE_ID_EXTRACT_RE = re.compile(r"(?:coh3stats\.com/(?:[a-z]{2}/)?players/)?(\d{1,12})")
STEAM_URL_EXTRACT_RE = re.compile(r"steamcommunity\.com/profiles/(7656119\d{10})", re.IGNORECASE)

LEADERBOARD_ID_TO_MODE_FACTION: dict[int, tuple[str, str]] = {
    lb_id: (m_name, f_name)
    for m_name, facs in STEAM_LEADERBOARDS.items()
    for f_name, lb_id in facs.items()
}


def parse_profile_id_input(raw_input: str) -> int | None:
    """
    Extrai de forma segura o Relic profile_id numérico tanto de um ID puro ('87314')
    quanto de um link completo do coh3stats ('https://coh3stats.com/players/87314-...').
    Nota: IDs de 17 dígitos da Steam (7656119...) são tratados via parse_steam_id_input.
    """
    txt = (raw_input or "").strip()
    if not txt:
        return None
    if STEAM_ID64_VALID_RE.fullmatch(txt) or STEAM_URL_EXTRACT_RE.search(txt):
        return None
    if txt.isdigit() and len(txt) <= 12:
        val = int(txt)
        return val if val > 0 else None
    m = re.search(r"coh3stats\.com/(?:[a-z]{2}/)?players/(\d{1,12})", txt, flags=re.IGNORECASE)
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
    if m:
        return m.group(1)
    return None


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
        if sg.get("type") == 1 and len(members) == 1:
            mem = members[0]
            pid = int(mem.get("profile_id", 0))
            steam_raw = str(mem.get("name", ""))
            steam_id = steam_raw.replace("/steam/", "") if steam_raw.startswith("/steam/") else ""
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
            disp_alias = format_bound_display_alias(
                cur_alias,
                orig_alias,
                r_entry.get("known_aliases"),
            )

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
        pid = solo_sg_to_pid[sg_id]
        p = results_by_pid[pid]
        mode, faction = LEADERBOARD_ID_TO_MODE_FACTION[lb_id]
        elo = int(round(st.get("rating", 0)))
        if elo <= 0:
            continue
        wins = int(st.get("wins", 0))
        losses = int(st.get("losses", 0))
        lmd = int(st.get("lastmatchdate", 0))
        rank_val = int(st.get("rank", -1))
        key = f"{mode}_{faction}"
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
        if rank_val > 0:
            p["modes"][key] = stat_obj
        else:
            p["inactive_modes"][key] = stat_obj
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
    """
    Consulta getPersonalStat na API da Relic em lotes seguros de até 10 contas (limite estrito da Relic),
    priorizando o código da conta Steam (/steam/<steam_id>) para continuar monitorando mesmo se o jogador
    mudar de nome no futuro, preservando o nick original.
    """
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

    # Se algum pid em fallback já tem steam_id conhecido no roster, consulta direto pelo steam_id
    for pid in list(fallback_pid_set):
        known = pid_map.get(pid)
        if known and known.get("steam_id"):
            steam_set.add(known["steam_id"])
            fallback_pid_set.discard(pid)

    results_by_pid: dict[int, dict[str, Any]] = {}

    # 1) Consulta primária por conta Steam (/steam/7656119...) — máximo 10 por chamada na API Relic
    ordered_sids = sorted(steam_set)
    for idx in range(0, len(ordered_sids), 10):
        batch_sids = ordered_sids[idx : idx + 10]
        names_json = json.dumps([f"/steam/{s}" for s in batch_sids], separators=(",", ":"))
        encoded_names = urllib.parse.quote(names_json)
        url = f"{BASE_URL}/getPersonalStat?title={TITLE_STEAM}&profile_names={encoded_names}"
        data = client._get_json(url)
        _ingest_personal_stat_payload(
            data,
            results_by_pid,
            roster_maps=roster_maps,
            allowed_sids=set(batch_sids),
        )

    # 2) Fallback por profile_id para contas recém-adicionadas apenas por ID numérico (lotes de 10)
    resolved_sids = {str(v.get("steam_id") or "") for v in results_by_pid.values()}
    unresolved_sids = [s for s in ordered_sids if s not in resolved_sids]
    for s in unresolved_sids:
        if s in steam_map and int(steam_map[s].get("profile_id", 0)) > 0:
            fallback_pid_set.add(int(steam_map[s]["profile_id"]))

    ordered_pids = sorted(pid for pid in fallback_pid_set if pid not in results_by_pid)
    for idx in range(0, len(ordered_pids), 10):
        batch_pids = ordered_pids[idx : idx + 10]
        encoded_ids = urllib.parse.quote("[" + ",".join(str(i) for i in batch_pids) + "]")
        url = f"{BASE_URL}/getPersonalStat?title={TITLE_STEAM}&profile_ids={encoded_ids}"
        data = client._get_json(url)
        _ingest_personal_stat_payload(
            data,
            results_by_pid,
            roster_maps=roster_maps,
            allowed_pids=set(batch_pids),
        )

    return list(results_by_pid.values())


FACTIONS_ORDER = ("american", "british", "dak", "german")
FACTION_KEY_LABELS = {
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


def compute_merged_mode_rankings(
    players: list[dict[str, Any]],
    mode_groups: dict[str, tuple[str, ...]] | None = None,
    custom_ids: set[int] | None = None,
    custom_steam_ids: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    Mescla os rankings das facções ativas dentro de cada categoria ('1v1', '2v2', 'Team Games').
    Os 31 jogadores monitorados + convidados entram na classificação geral pela média de ELO.
    """
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
            is_custom = pid in custom_set or (sid and sid in custom_sid_set) or bool(p.get("is_custom"))
            p_modes = p.get("modes", {})
            p_inactive = p.get("inactive_modes", {})
            all_active_elos: list[int] = []
            per_faction_lists: dict[str, list[int]] = {f: [] for f in FACTIONS_ORDER}
            submode_elos: dict[str, int] = {}
            wins_mode = 0
            losses_mode = 0
            last_match_mode = 0
            latest_streak = 0
            latest_streak_ts = -1
            used_inactive_fallback = False

            for sub in sub_modes:
                for fac in FACTIONS_ORDER:
                    key = f"{sub}_{fac}"
                    st = p_modes.get(key)
                    if st and int(round(st.get("elo", 0))) > 0:
                        elo_val = int(round(st["elo"]))
                        all_active_elos.append(elo_val)
                        per_faction_lists[fac].append(elo_val)
                        submode_elos[key] = elo_val
                        wins_mode += int(st.get("wins", 0))
                        losses_mode += int(st.get("losses", 0))
                        lmd_val = int(st.get("lastmatchdate", 0))
                        if lmd_val > last_match_mode:
                            last_match_mode = lmd_val
                        if lmd_val >= latest_streak_ts:
                            latest_streak_ts = lmd_val
                            latest_streak = int(st.get("streak", 0))

            # Se for jogador monitorado sem ranking ativo recente no modo, aproveita seu ELO pessoal salvo na Relic
            if not all_active_elos and is_custom and p_inactive:
                used_inactive_fallback = True
                for sub in sub_modes:
                    for fac in FACTIONS_ORDER:
                        key = f"{sub}_{fac}"
                        st = p_inactive.get(key)
                        if st and int(round(st.get("elo", 0))) > 0:
                            elo_val = int(round(st["elo"]))
                            all_active_elos.append(elo_val)
                            per_faction_lists[fac].append(elo_val)
                            submode_elos[key] = elo_val
                            wins_mode += int(st.get("wins", 0))
                            losses_mode += int(st.get("losses", 0))
                            lmd_val = int(st.get("lastmatchdate", 0))
                            if lmd_val > last_match_mode:
                                last_match_mode = lmd_val
                            if lmd_val >= latest_streak_ts:
                                latest_streak_ts = lmd_val
                                latest_streak = int(st.get("streak", 0))

            if not all_active_elos:
                continue

            faction_elos: dict[str, int] = {
                fac: int(round(sum(vals) / len(vals)))
                for fac, vals in per_faction_lists.items()
                if vals
            }
            avg_elo = round(sum(all_active_elos) / len(all_active_elos), 1)
            max_mode_elo = max(all_active_elos)
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
                    "max_mode_elo": max_mode_elo,
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
    """
    Quando only_custom=True (padrão v5: Opção 2), retorna APENAS os 31 jogadores brasileiros listados
    (+ convidados extras) para monitoramento de partidas terminadas, ignorando os demais estranhos do Top 20.
    """
    steam_map, pid_map = build_roster_lookup_maps(custom_players)
    custom_by_id = {int(cp["profile_id"]): cp for cp in (custom_players or []) if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp.get("steam_id") or "") for cp in (custom_players or []) if cp.get("steam_id")}
    consolidated: dict[int, dict[str, Any]] = {}

    for mode, entries in rankings_by_mode.items():
        mode_pt = "Jogos em Equipe" if mode == "Team Games" else mode
        for idx, item in enumerate(entries):
            pid = int(item["profile_id"])
            sid = str(item.get("steam_id") or "")
            is_cust = pid in custom_by_id or (sid and sid in custom_sids) or bool(item.get("is_custom"))
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

    # Garante que todos os monitorados (incluindo contas secundárias mescladas como gabe44arg -> É o Gabe) sejam rastreados
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

    ordered = sorted(consolidated.values(), key=lambda x: (-x["best_avg_elo"], x["alias"].lower()))
    return ordered


def export_merged_top_rankings(
    rankings_by_mode: dict[str, list[dict[str, Any]]],
    top_n: int,
    json_path: Path,
    csv_path: Path,
    custom_players: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    Exporta as tabelas dos Top 20 brasileiros + todos os 31 jogadores monitorados (20 + 31).
    Retorna o dicionário filtrado por modo (pronto para exibição no Discord e detecção de movimentação).
    """
    custom_ids = {int(cp["profile_id"]) for cp in (custom_players or []) if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp.get("steam_id") or "") for cp in (custom_players or []) if cp.get("steam_id")}
    trimmed: dict[str, list[dict[str, Any]]] = {}
    for mode, entries in rankings_by_mode.items():
        selected_rows = []
        for idx, e in enumerate(entries):
            sid = str(e.get("steam_id") or "")
            if idx < top_n or e["profile_id"] in custom_ids or (sid and sid in custom_sids) or e.get("is_custom"):
                selected_rows.append(e)
        trimmed[mode] = selected_rows

    unique_players = build_top_tracked_players(rankings_by_mode, top_n=top_n, custom_players=custom_players, only_custom=False)

    json_path.write_text(
        json.dumps(
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
        ),
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
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

    return trimmed

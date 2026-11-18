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


import ssl
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


_RELIC_OPENER = _build_relic_opener()


class RelicAPIClient:
    """Cliente HTTPS endurecido com TLS 1.2+, allowlist de host, limite de memória e rate limit."""

    def __init__(self, min_interval_sec: float = 0.25, timeout_sec: float = 15.0) -> None:
        self.min_interval_sec = min_interval_sec
        self.timeout_sec = timeout_sec
        self._last_req_ts = 0.0
        self.races: dict[int, str] = dict(FALLBACK_RACES)
        self.match_types: dict[int, str] = {}
        self._metadata_loaded = False

    def _get_json(self, url: str, retries: int = 3) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() != ALLOWED_RELIC_HOST:
            raise ValueError(f"Host não autorizado para consulta da API Relic: {parsed.hostname}")

        elapsed = time.monotonic() - self._last_req_ts
        if elapsed < self.min_interval_sec:
            time.sleep(self.min_interval_sec - elapsed)

        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "CoH3-BR-Discord-Tracker/1.0", "Accept": "application/json"},
                )
                self._last_req_ts = time.monotonic()
                with _RELIC_OPENER.open(req, timeout=self.timeout_sec) as resp:
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
        Varre todos os modos ranqueados da Steam (1v1, 2v2, 3v3, 4v4 nas 4 facções),
        filtrando jogadores com country == 'br'.
        """
        players: dict[int, dict[str, Any]] = {}

        def ingest_response(data: dict[str, Any], mode: str, faction: str) -> int:
            stat_groups = {sg["id"]: sg for sg in data.get("statGroups", [])}
            lb_stats = data.get("leaderboardStats", [])
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

        for mode, factions in STEAM_LEADERBOARDS.items():
            for faction, lb_id in factions.items():
                # 1) Varredura completa na região América do Sul
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

                # 2) Top páginas globais para capturar brasileiros jogando fora da região SA
                for page in range(include_global_top_pages):
                    g_start = 1 + page * 200
                    g_url = (
                        f"{BASE_URL}/getleaderboard2?title={TITLE_STEAM}&leaderboard_id={lb_id}"
                        f"&sortBy=1&count=200&start={g_start}"
                    )
                    g_data = self._get_json(g_url)
                    if ingest_response(g_data, mode, faction) == 0:
                        break

        sorted_list = sorted(players.values(), key=lambda x: (-x["max_elo"], -x["last_match_date"]))
        return sorted_list

    def fetch_player_recent_matches(
        self,
        profile_id: int,
        fallback_alias: str = "",
        only_automatch: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Retorna as partidas recentes de um jogador ordenadas da mais recente para a mais antiga.
        """
        self.ensure_metadata()
        url = f"{BASE_URL}/getRecentMatchHistoryByProfileId?title={TITLE_STEAM}&profile_id={profile_id}"
        data = self._get_json(url)

        profiles_by_id: dict[int, dict[str, Any]] = {
            int(pr["profile_id"]): pr for pr in data.get("profiles", []) if "profile_id" in pr
        }
        tracked_prof = profiles_by_id.get(profile_id, {})
        tracked_alias = tracked_prof.get("alias") or fallback_alias or f"Player {profile_id}"

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
                new_elo = int(mem.get("newrating", 0)) if mem.get("newrating", 0) > 0 else None

                participant = {
                    "profile_id": rpid,
                    "alias": prof.get("alias") or f"ID {rpid}",
                    "country": str(prof.get("country") or "un").lower(),
                    "faction": race_name,
                    "faction_short": FACTION_SHORT.get(race_name, race_name),
                    "elo": new_elo,
                }
                if rep.get("teamid") == my_team:
                    if rpid != profile_id:
                        allies.append(participant)
                else:
                    opponents.append(participant)

            my_mem = members_by_pid.get(profile_id, {})
            old_elo = int(my_mem["oldrating"]) if my_mem.get("oldrating", 0) > 0 else None
            new_elo = int(my_mem["newrating"]) if my_mem.get("newrating", 0) > 0 else None

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

            parsed_matches.append(
                {
                    "match_id": match_id,
                    "tracked_profile_id": profile_id,
                    "tracked_alias": tracked_alias,
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
            )

        return parsed_matches


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
) -> dict[str, list[dict[str, Any]]]:
    """
    Mescla os rankings das facções ativas dentro de cada categoria de estudo:
      - '1v1': média simples das facções ativas no 1v1 (até 4 rankings)
      - '2v2': média simples das facções ativas no 2v2 (até 4 rankings)
      - 'Team Games': mescla 3v3 e 4v4 pela média simples de todos os rankings ativos (até 8 rankings)
    """
    groups = mode_groups or STUDY_MODE_GROUPS
    rankings_by_mode: dict[str, list[dict[str, Any]]] = {}

    for group_name, sub_modes in groups.items():
        mode_entries: list[dict[str, Any]] = []
        max_slots = len(sub_modes) * len(FACTIONS_ORDER)

        for p in players:
            p_modes = p.get("modes", {})
            all_active_elos: list[int] = []
            per_faction_lists: dict[str, list[int]] = {f: [] for f in FACTIONS_ORDER}
            submode_elos: dict[str, int] = {}
            wins_mode = 0
            losses_mode = 0
            last_match_mode = 0

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
                        last_match_mode = max(last_match_mode, int(st.get("lastmatchdate", 0)))

            if not all_active_elos:
                continue

            faction_elos: dict[str, int] = {
                fac: int(round(sum(vals) / len(vals)))
                for fac, vals in per_faction_lists.items()
                if vals
            }
            avg_elo = round(sum(all_active_elos) / len(all_active_elos), 1)
            max_mode_elo = max(all_active_elos)

            mode_entries.append(
                {
                    "profile_id": int(p["profile_id"]),
                    "alias": str(p["alias"]),
                    "steam_id": str(p.get("steam_id", "")),
                    "mode": group_name,
                    "sub_modes": list(sub_modes),
                    "avg_elo": avg_elo,
                    "max_mode_elo": max_mode_elo,
                    "active_factions_count": len(faction_elos),
                    "active_rankings_count": len(all_active_elos),
                    "max_rankings_slots": max_slots,
                    "faction_elos": faction_elos,
                    "submode_elos": submode_elos,
                    "wins": wins_mode,
                    "losses": losses_mode,
                    "last_match_date": last_match_mode,
                    "coh3stats_url": f"https://coh3stats.com/players/{p['profile_id']}",
                }
            )

        mode_entries.sort(
            key=lambda x: (
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
) -> list[dict[str, Any]]:
    """
    Seleciona os Top N colocados brasileiros de cada modo ('1v1', '2v2', 'Team Games')
    e retorna a lista consolidada sem duplicatas para o config.json.
    """
    consolidated: dict[int, dict[str, Any]] = {}

    for mode, entries in rankings_by_mode.items():
        for item in entries[:top_n]:
            pid = item["profile_id"]
            if pid not in consolidated:
                consolidated[pid] = {
                    "profile_id": pid,
                    "alias": item["alias"],
                    "steam_id": item["steam_id"],
                    "placements": [],
                    "best_avg_elo": item["avg_elo"],
                }
            rec = consolidated[pid]
            rec["placements"].append(f"#{item['br_rank']} {mode} (média {item['avg_elo']:.1f})")
            if item["avg_elo"] > rec["best_avg_elo"]:
                rec["best_avg_elo"] = item["avg_elo"]

    ordered = sorted(consolidated.values(), key=lambda x: -x["best_avg_elo"])
    return ordered


def export_merged_top_rankings(
    rankings_by_mode: dict[str, list[dict[str, Any]]],
    top_n: int,
    json_path: Path,
    csv_path: Path,
) -> None:
    """Exporta as tabelas de estudo dos Top N brasileiros por modo (1v1, 2v2 e Team Games)."""
    trimmed = {mode: entries[:top_n] for mode, entries in rankings_by_mode.items()}
    unique_players = build_top_tracked_players(rankings_by_mode, top_n=top_n)

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
                "profile_id",
                "alias",
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
                        pid_int,
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



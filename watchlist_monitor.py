"""
Monitor privado da Watchlist Histórica (CoH1/CoH2 → CoH3) e auditoria de banimentos/griefing.

REGRAS DE SEGURANÇA E PRIVACIDADE:
- Somente-leitura nas APIs públicas da Relic (CoH2/CoH3) e SQLite local (`matches.db`).
- NUNCA posta em webhooks do Discord nem abre GitHub Issues públicas.
- Destinado exclusivamente a auditorias privadas (CLI local / relatórios no Antigravity).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sqlite3
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from security import (
    build_no_redirect_https_opener,
    read_bounded_http_body,
    strip_unsafe_chars,
    validate_https_endpoint,
)

DEFAULT_WATCHLIST_PATH = Path(__file__).resolve().parent / "historical_watchlist.json"
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "coh3_br_matches.db"
STEAM_ID64_VALID_RE = re.compile(r"^7656119\d{10}$")
ALLOWED_RELIC_HOSTS: frozenset[str] = frozenset({"coh3-api.reliclink.com"})
ALLOWED_STEAM_HOSTS: frozenset[str] = frozenset({"steamcommunity.com"})
_STEAM_HTML_PATH_RE = re.compile(r"^/profiles/7656119\d{10}/?$")
_HTML_BAN_BLOCK_RE = re.compile(r'class="profile_ban_status"[^>]*>(.*?)</div>\s*</div>', re.S | re.I)
_HTML_GAME_BANS_RE = re.compile(r"(\d+)\s+game\s+ban(?:s)?\s+on\s+record", re.I)
_HTML_VAC_BANS_RE = re.compile(r"(\d+)\s+VAC\s+ban(?:s)?\s+on\s+record", re.I)
_HTML_DAYS_SINCE_BAN_RE = re.compile(r"(\d[\d,]*)\s+day\(s\)\s+since\s+last\s+ban", re.I)


def load_watchlist(path: Path = DEFAULT_WATCHLIST_PATH) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    entries = doc.get("entries") if isinstance(doc, dict) else []
    return [dict(e) for e in entries if isinstance(e, dict) and STEAM_ID64_VALID_RE.fullmatch(str(e.get("steam_id") or ""))]


def parse_steam_ban_banner(html_body: str) -> dict[str, Any]:
    """Extrai Game Bans, VAC Bans e dias desde o último banimento do HTML público/privado da Steam."""
    body = str(html_body or "")
    out: dict[str, Any] = {
        "has_ban": False,
        "game_bans": 0,
        "vac_bans": 0,
        "days_since_last_ban": -1,
        "ban_summary": "",
    }
    if not body or "profile_ban_status" not in body:
        return out
    bm = _HTML_BAN_BLOCK_RE.search(body)
    block = bm.group(1) if bm else body[body.find("profile_ban_status") : body.find("profile_ban_status") + 900]
    clean = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", block)).strip()
    clean = re.sub(r"\|\s*Info", "", clean).strip()
    gm = _HTML_GAME_BANS_RE.search(clean)
    vm = _HTML_VAC_BANS_RE.search(clean)
    dm = _HTML_DAYS_SINCE_BAN_RE.search(clean)
    if gm:
        out["game_bans"] = int(gm.group(1))
    if vm:
        out["vac_bans"] = int(vm.group(1))
    if dm:
        out["days_since_last_ban"] = int(dm.group(1).replace(",", ""))
    out["has_ban"] = bool(out["game_bans"] > 0 or out["vac_bans"] > 0)
    if out["has_ban"]:
        out["ban_summary"] = strip_unsafe_chars(clean)[:180]
    return out


def summarize_relic_coh3_stat(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Resume a resposta de `getPersonalStat` da Relic CoH3 para uma conta da watchlist."""
    if not isinstance(payload, dict):
        return {"has_coh3_profile": False}
    sgs = payload.get("statGroups") or []
    lbs = payload.get("leaderboardStats") or []
    member: dict[str, Any] | None = None
    for sg in sgs:
        if isinstance(sg, dict) and sg.get("type") == 1 and sg.get("members"):
            member = sg["members"][0]
            break
    if member is None and sgs and isinstance(sgs[0], dict) and sgs[0].get("members"):
        member = sgs[0]["members"][0]
    if not isinstance(member, dict):
        return {"has_coh3_profile": False}

    total_games = 0
    total_wins = 0
    total_losses = 0
    total_drops = 0
    min_elo: int | None = None
    max_elo: int | None = None
    worst_streak = 0
    last_ts = 0
    for lb in lbs:
        if not isinstance(lb, dict):
            continue
        w = max(0, int(lb.get("wins", 0) or 0))
        l = max(0, int(lb.get("losses", 0) or 0))
        g = w + l
        total_games += g
        total_wins += w
        total_losses += l
        total_drops += max(0, int(lb.get("drops", 0) or 0))
        st = int(lb.get("streak", 0) or 0)
        if st < worst_streak:
            worst_streak = st
        lmd = int(lb.get("lastmatchdate", 0) or 0)
        if lmd > last_ts:
            last_ts = lmd
        raw_r = lb.get("rating")
        if raw_r is not None and g >= 5:
            ri = int(raw_r)
            min_elo = ri if min_elo is None else min(min_elo, ri)
            max_elo = ri if max_elo is None else max(max_elo, ri)

    last_iso = (
        datetime.datetime.fromtimestamp(last_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
        if last_ts > 0
        else "never"
    )
    drop_rate = round(total_drops / total_games, 4) if total_games > 0 else 0.0
    tanking_flags: list[str] = []
    if min_elo is not None and min_elo < 0:
        tanking_flags.append(f"elo_negativo ({min_elo})")
    elif min_elo is not None and min_elo < 600 and total_games >= 100:
        tanking_flags.append(f"elo_tanking ({min_elo})")
    if total_games >= 80 and (drop_rate >= 0.04 or total_drops >= 50):
        tanking_flags.append(f"drops_cronicos ({total_drops} / {drop_rate * 100:.1f}%)")
    if worst_streak <= -12:
        tanking_flags.append(f"streak_extrema ({worst_streak})")

    return {
        "has_coh3_profile": True,
        "coh3_profile_id": int(member.get("profile_id", 0) or 0),
        "current_alias": strip_unsafe_chars(str(member.get("alias") or "")),
        "country": str(member.get("country") or "").lower(),
        "total_games": total_games,
        "wins": total_wins,
        "losses": total_losses,
        "total_drops": total_drops,
        "drop_rate": drop_rate,
        "min_elo": min_elo,
        "max_elo": max_elo,
        "worst_streak": worst_streak,
        "last_match_ts": last_ts,
        "last_match_date": last_iso,
        "tanking_flags": tanking_flags,
    }


def query_local_veteran_encounters(db_path: Path, coh3_profile_id: int) -> list[dict[str, Any]]:
    """Consulta no SQLite local (`nemesis_matches`) se o alvo já enfrentou Veteranos monitorados desde 2023."""
    if not coh3_profile_id or not db_path.is_file() or db_path.is_symlink():
        return []
    try:
        with sqlite3.connect(str(db_path), timeout=5) as con:
            rows = con.execute(
                """
                SELECT tracked_profile_id,
                       COUNT(*) AS games,
                       SUM(CASE WHEN win = 1 THEN 1 ELSE 0 END) AS vet_wins,
                       MAX(completion_time) AS last_ts
                FROM nemesis_matches
                WHERE opponent_profile_id = ?
                GROUP BY tracked_profile_id
                ORDER BY games DESC
                LIMIT 15
                """,
                (int(coh3_profile_id),),
            ).fetchall()
        return [
            {
                "tracked_profile_id": int(r[0]),
                "games": int(r[1]),
                "veteran_wins": int(r[2] or 0),
                "last_ts": int(r[3] or 0),
            }
            for r in rows
        ]
    except Exception:
        return []


def audit_watchlist(
    entries: list[dict[str, Any]],
    *,
    db_path: Path = DEFAULT_DB_PATH,
    check_steam_bans: bool = False,
    relic_fetcher: Any = None,
    steam_html_fetcher: Any = None,
) -> dict[str, Any]:
    """Executa auditoria completa (somente-leitura) da Watchlist privada CoH1/CoH2 → CoH3."""
    opener = build_no_redirect_https_opener()

    def _default_relic(sid: str) -> dict[str, Any] | None:
        qs = urllib.parse.urlencode({"title": "coh3", "profile_names": json.dumps([f"/steam/{sid}"])})
        url = f"https://coh3-api.reliclink.com/community/leaderboard/getPersonalStat?{qs}"
        validate_https_endpoint(url, ALLOWED_RELIC_HOSTS, path_prefix="/community/leaderboard/", allow_query=True)
        req = urllib.request.Request(url, headers={"User-Agent": "CoH3-BR-Watchlist-Audit/1.0"})
        try:
            with opener.open(req, timeout=10) as resp:
                raw = read_bounded_http_body(resp, 524_288)
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return None

    def _default_steam_html(sid: str) -> str:
        url = f"https://steamcommunity.com/profiles/{sid}/"
        validate_https_endpoint(url, ALLOWED_STEAM_HOSTS, path_prefix="/profiles/", path_regex=_STEAM_HTML_PATH_RE)
        req = urllib.request.Request(url, headers={"User-Agent": "CoH3-BR-Watchlist-Audit/1.0"})
        try:
            with opener.open(req, timeout=10) as resp:
                raw = read_bounded_http_body(resp, 262_144)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    fetch_relic = relic_fetcher or _default_relic
    fetch_html = steam_html_fetcher or _default_steam_html

    report_items: list[dict[str, Any]] = []
    alerts: list[str] = []
    for entry in entries:
        sid = str(entry.get("steam_id") or "").strip()
        label = str(entry.get("label") or sid)
        prev_pid = entry.get("coh3_profile_id")
        coh3 = summarize_relic_coh3_stat(fetch_relic(sid))
        ban_info = parse_steam_ban_banner(fetch_html(sid)) if check_steam_bans else {"has_ban": False}
        pid_now = int(coh3.get("coh3_profile_id") or prev_pid or 0)
        encounters = query_local_veteran_encounters(db_path, pid_now) if pid_now else []

        entry_alerts: list[str] = []
        if coh3.get("has_coh3_profile"):
            if prev_pid is None:
                entry_alerts.append(
                    f"NOVO PERFIL CoH3 ATIVADO: {label} criou perfil CoH3 #{pid_now} como '{coh3.get('current_alias')}' ({coh3.get('total_games')} jogos)."
                )
            elif entry.get("category") == "dormant_coh2_alt_watch" and int(coh3.get("total_games", 0)) > 0:
                entry_alerts.append(
                    f"CONTA CoH2 DORMENTE ATIVADA NO CoH3: {label} (#{pid_now}) agora tem {coh3.get('total_games')} partidas!"
                )
            if coh3.get("tanking_flags"):
                entry_alerts.append(
                    f"GRIEFING/TANKING ATIVO ({label} #{pid_now}): {', '.join(coh3['tanking_flags'])}."
                )
            if ban_info.get("has_ban"):
                entry_alerts.append(
                    f"BAN STEAM EM CONTA ATIVA NO CoH3 ({label} #{pid_now}): {ban_info.get('ban_summary')}."
                )
        alerts.extend(entry_alerts)
        report_items.append(
            {
                "label": label,
                "category": entry.get("category") or "",
                "steam_id": sid,
                "coh1_profile_id": entry.get("coh1_profile_id"),
                "coh2_profile_id": entry.get("coh2_profile_id"),
                "coh3_status": coh3,
                "steam_ban_status": ban_info,
                "veteran_encounters_since_2023": encounters,
                "alerts": entry_alerts,
            }
        )

    return {
        "generated_at_utc": datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checked_entries": len(report_items),
        "alerts_count": len(alerts),
        "alerts": alerts,
        "entries": report_items,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditoria privada da Watchlist histórica CoH1/CoH2 -> CoH3.")
    parser.add_argument("--watchlist", type=Path, default=DEFAULT_WATCHLIST_PATH)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--check-steam-bans", action="store_true", help="Verifica banner público/privado de Game/VAC bans na Steam.")
    args = parser.parse_args()
    entries = load_watchlist(args.watchlist)
    report = audit_watchlist(entries, db_path=args.db, check_steam_bans=args.check_steam_bans)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

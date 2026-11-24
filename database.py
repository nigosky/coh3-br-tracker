"""Persistência SQLite otimizada e segura para jogadores monitorados, partidas e cache de avatares."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from relic_api import AUTOMATCH_MODES, STEAM_ID64_VALID_RE, clean_map_name

PENDING_DISCORD_MARKER = "PENDING"
SEEDED_DISCORD_MARKER = "SEEDED"
PRUNED_DISCORD_MARKER = "PRUNED"


class MatchDatabase:
    """Gerencia o catálogo local SQLite com conexões reutilizáveis thread-local e transações atômicas."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if self.db_path.is_symlink():
            raise RuntimeError(f"Caminho do banco SQLite não pode ser symlink: {self.db_path}")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._all_conns_lock = threading.Lock()
        self._all_conns: list[sqlite3.Connection] = []
        self._init_schema()

    def __enter__(self) -> MatchDatabase:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def _connect(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA synchronous = NORMAL")
        # journal_mode=DELETE garante que 100% dos dados fiquem no arquivo único coh3_br_matches.db (compatível com Git)
        conn.execute("PRAGMA journal_mode = DELETE")
        self._local.conn = conn
        with self._all_conns_lock:
            self._all_conns.append(conn)
        return conn

    def close(self) -> None:
        """Fecha todas as conexões abertas de forma limpa (garantindo flush antes de commits Git)."""
        with self._all_conns_lock:
            conns = list(self._all_conns)
            self._all_conns.clear()
        self._local.conn = None
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass

    def _init_schema(self) -> None:
        conn = self._connect()
        with conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tracked_players (
                    profile_id INTEGER PRIMARY KEY,
                    alias TEXT NOT NULL,
                    original_alias TEXT DEFAULT '',
                    steam_id TEXT DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    baseline_synced INTEGER NOT NULL DEFAULT 0,
                    added_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS recorded_matches (
                    match_id INTEGER NOT NULL,
                    tracked_profile_id INTEGER NOT NULL,
                    tracked_alias TEXT NOT NULL,
                    tracked_steam_id TEXT DEFAULT '',
                    tracked_faction TEXT NOT NULL,
                    tracked_faction_short TEXT NOT NULL,
                    win INTEGER NOT NULL,
                    resulttype INTEGER NOT NULL,
                    mode TEXT NOT NULL,
                    matchtype_id INTEGER NOT NULL,
                    map_raw TEXT NOT NULL,
                    map_clean TEXT NOT NULL,
                    start_time INTEGER NOT NULL,
                    completion_time INTEGER NOT NULL,
                    duration_sec INTEGER NOT NULL,
                    old_elo INTEGER,
                    new_elo INTEGER,
                    allies_json TEXT NOT NULL,
                    opponents_json TEXT NOT NULL,
                    counters_json TEXT NOT NULL,
                    has_replay INTEGER NOT NULL DEFAULT 0,
                    coh3stats_url TEXT NOT NULL,
                    discord_message_id TEXT,
                    recorded_at INTEGER NOT NULL,
                    PRIMARY KEY (match_id, tracked_profile_id)
                );

                CREATE INDEX IF NOT EXISTS idx_matches_completion
                    ON recorded_matches (completion_time DESC);

                CREATE INDEX IF NOT EXISTS idx_matches_pid_comp
                    ON recorded_matches (tracked_profile_id, completion_time DESC);

                CREATE TABLE IF NOT EXISTS bot_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS player_avatars (
                    steam_id TEXT PRIMARY KEY,
                    profile_id INTEGER NOT NULL DEFAULT 0,
                    avatar_url TEXT NOT NULL,
                    png_blob BLOB NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_avatars_pid
                    ON player_avatars (profile_id);

                CREATE TABLE IF NOT EXISTS discord_ephemeral_messages (
                    message_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    sent_at INTEGER NOT NULL,
                    pruned_at INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_ephemeral_prune
                    ON discord_ephemeral_messages (pruned_at, sent_at);

                CREATE TABLE IF NOT EXISTS nemesis_matches (
                    tracked_profile_id INTEGER NOT NULL,
                    opponent_profile_id INTEGER NOT NULL,
                    match_id INTEGER NOT NULL,
                    completion_time INTEGER NOT NULL,
                    utc_day INTEGER NOT NULL,
                    win INTEGER NOT NULL,
                    mode TEXT DEFAULT '',
                    opponent_alias TEXT DEFAULT '',
                    opponent_country TEXT DEFAULT '',
                    PRIMARY KEY (tracked_profile_id, opponent_profile_id, match_id)
                );

                CREATE INDEX IF NOT EXISTS idx_nemesis_all_pair_day
                    ON nemesis_matches (tracked_profile_id, opponent_profile_id, utc_day);
                """
            )
            existing_match_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(recorded_matches)").fetchall()
            }
            if "tracked_steam_id" not in existing_match_cols:
                conn.execute("ALTER TABLE recorded_matches ADD COLUMN tracked_steam_id TEXT DEFAULT ''")
            if "battlegroups_json" not in existing_match_cols:
                conn.execute("ALTER TABLE recorded_matches ADD COLUMN battlegroups_json TEXT DEFAULT ''")
            if "smurf_alerts_json" not in existing_match_cols:
                conn.execute("ALTER TABLE recorded_matches ADD COLUMN smurf_alerts_json TEXT DEFAULT ''")

            existing_player_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(tracked_players)").fetchall()
            }
            if "original_alias" not in existing_player_cols:
                conn.execute("ALTER TABLE tracked_players ADD COLUMN original_alias TEXT DEFAULT ''")

            self._ensure_nemesis_all_modes_backfill(conn)
            self._sync_sibling_match_metadata(conn)

    @staticmethod
    def _sync_sibling_match_metadata(conn: sqlite3.Connection) -> None:
        """
        Sincroniza `battlegroups_json`, `smurf_alerts_json` e Snowflake `discord_message_id` entre
        linhas irmãs do mesmo `match_id` (evita loop infinito de PATCH quando um novo Veterano é
        semeado em uma partida que já possuía Battlegroups/Snowflake gravados em outro jogador).
        """
        conn.execute(
            """
            UPDATE recorded_matches
            SET battlegroups_json = (
                SELECT s.battlegroups_json
                FROM recorded_matches s
                WHERE s.match_id = recorded_matches.match_id
                  AND COALESCE(s.battlegroups_json, '') != ''
                LIMIT 1
            )
            WHERE COALESCE(battlegroups_json, '') = ''
              AND EXISTS (
                  SELECT 1
                  FROM recorded_matches s
                  WHERE s.match_id = recorded_matches.match_id
                    AND COALESCE(s.battlegroups_json, '') != ''
              )
            """
        )
        conn.execute(
            """
            UPDATE recorded_matches
            SET smurf_alerts_json = (
                SELECT s.smurf_alerts_json
                FROM recorded_matches s
                WHERE s.match_id = recorded_matches.match_id
                  AND COALESCE(s.smurf_alerts_json, '') != ''
                LIMIT 1
            )
            WHERE COALESCE(smurf_alerts_json, '') = ''
              AND EXISTS (
                  SELECT 1
                  FROM recorded_matches s
                  WHERE s.match_id = recorded_matches.match_id
                    AND COALESCE(s.smurf_alerts_json, '') != ''
              )
            """
        )
        conn.execute(
            """
            UPDATE recorded_matches
            SET discord_message_id = (
                SELECT s.discord_message_id
                FROM recorded_matches s
                WHERE s.match_id = recorded_matches.match_id
                  AND s.discord_message_id IS NOT NULL
                  AND length(s.discord_message_id) >= 15
                  AND s.discord_message_id NOT GLOB '*[^0-9]*'
                LIMIT 1
            )
            WHERE discord_message_id = ?
              AND EXISTS (
                  SELECT 1
                  FROM recorded_matches s
                  WHERE s.match_id = recorded_matches.match_id
                    AND s.discord_message_id IS NOT NULL
                    AND length(s.discord_message_id) >= 15
                    AND s.discord_message_id NOT GLOB '*[^0-9]*'
              )
            """,
            (SEEDED_DISCORD_MARKER,),
        )

    @staticmethod
    def _extract_automatch_steam_opponents(
        mode: str,
        tracked_profile_id: int,
        opponents: Any,
    ) -> list[tuple[int, str, str]]:
        """Retorna lista `[(opponent_profile_id, opponent_alias, opponent_country), ...]` para partidas Automatch (1v1 a 4v4) Steam."""
        if str(mode or "").strip() not in AUTOMATCH_MODES:
            return []
        if not isinstance(opponents, list) or not opponents:
            return []
        out: list[tuple[int, str, str]] = []
        seen_pids: set[int] = set()
        t_pid = int(tracked_profile_id or 0)
        for opp in opponents:
            if not isinstance(opp, dict):
                continue
            opp_pid = int(opp.get("profile_id", 0) or 0)
            if opp_pid <= 0 or opp_pid == t_pid or opp_pid in seen_pids:
                continue
            if "steam_id" in opp:
                raw_sid = str(opp.get("steam_id") or "").strip()
                clean_sid = raw_sid.replace("/steam/", "").strip()
                # Quando o campo steam_id está presente (registros novos), exige SteamID64 válido (Steam-only)
                if not STEAM_ID64_VALID_RE.fullmatch(clean_sid):
                    continue
            seen_pids.add(opp_pid)
            opp_alias = str(opp.get("alias") or "").strip()[:80]
            opp_country = str(opp.get("country") or "").strip().lower()[:4]
            out.append((opp_pid, opp_alias, opp_country))
        return out

    def _ensure_nemesis_all_modes_backfill(self, conn: sqlite3.Connection) -> None:
        """Popula `nemesis_matches` uma única vez com todo o histórico Automatch (1v1, 2v2, 3v3, 4v4)."""
        row = conn.execute("SELECT value FROM bot_state WHERE key = 'nemesis_all_modes_backfilled_v1'").fetchone()
        if row and str(row["value"]) == "1":
            return

        # Migra quaisquer registros previamente salvos na tabela legada nemesis_1v1_matches (se presente)
        legacy_tbl = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nemesis_1v1_matches'"
        ).fetchone()
        if legacy_tbl is not None:
            conn.execute(
                """
                INSERT OR IGNORE INTO nemesis_matches (
                    tracked_profile_id, opponent_profile_id, match_id, completion_time,
                    utc_day, win, mode, opponent_alias, opponent_country
                )
                SELECT tracked_profile_id, opponent_profile_id, match_id, completion_time,
                       utc_day, win, '1v1', opponent_alias, opponent_country
                FROM nemesis_1v1_matches
                """
            )

        placeholders = ",".join("?" for _ in AUTOMATCH_MODES)
        existing_auto = conn.execute(
            f"""
            SELECT match_id, tracked_profile_id, mode, win, completion_time, opponents_json
            FROM recorded_matches
            WHERE mode IN ({placeholders})
              AND opponents_json IS NOT NULL
              AND opponents_json != ''
              AND opponents_json != '[]'
            """,
            tuple(AUTOMATCH_MODES),
        ).fetchall()

        to_insert: list[tuple[int, int, int, int, int, int, str, str, str]] = []
        for r in existing_auto:
            tracked_pid = int(r["tracked_profile_id"] or 0)
            ct = int(r["completion_time"] or 0)
            mid = int(r["match_id"] or 0)
            mode_str = str(r["mode"] or "")
            if tracked_pid <= 0 or ct <= 0 or mid <= 0:
                continue
            try:
                opps = json.loads(r["opponents_json"] or "[]")
            except Exception:
                continue
            extracted = self._extract_automatch_steam_opponents(mode_str, tracked_pid, opps)
            for opp_pid, opp_alias, opp_country in extracted:
                to_insert.append(
                    (
                        tracked_pid,
                        opp_pid,
                        mid,
                        ct,
                        ct // 86400,
                        1 if int(r["win"] or 0) else 0,
                        mode_str,
                        opp_alias,
                        opp_country,
                    )
                )

        if to_insert:
            conn.executemany(
                """
                INSERT OR IGNORE INTO nemesis_matches (
                    tracked_profile_id, opponent_profile_id, match_id, completion_time,
                    utc_day, win, mode, opponent_alias, opponent_country
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                to_insert,
            )
        conn.execute(
            """
            INSERT INTO bot_state (key, value) VALUES ('nemesis_all_modes_backfilled_v1', '1')
            ON CONFLICT(key) DO UPDATE SET value = '1'
            """
        )

    def sync_tracked_players(self, players_cfg: list[dict[str, Any]]) -> None:
        """Sincroniza em lote único a lista de jogadores monitorados do config.json."""
        now = int(time.time())
        active_ids: set[int] = set()
        rows_to_upsert: list[tuple[int, str, str, str, int]] = []

        for item in players_cfg:
            pid = int(item["profile_id"])
            active_ids.add(pid)
            alias = str(item.get("alias") or f"Player {pid}")
            orig_alias = str(item.get("original_alias") or alias)
            steam_id = str(item.get("steam_id") or "")
            rows_to_upsert.append((pid, alias, orig_alias, steam_id, now))

        conn = self._connect()
        with conn:
            if rows_to_upsert:
                conn.executemany(
                    """
                    INSERT INTO tracked_players (profile_id, alias, original_alias, steam_id, active, baseline_synced, added_at)
                    VALUES (?, ?, ?, ?, 1, 0, ?)
                    ON CONFLICT(profile_id) DO UPDATE SET
                        alias = CASE
                            WHEN excluded.alias = excluded.original_alias
                                 AND excluded.original_alias != ''
                                 AND substr(tracked_players.alias, 1, length(excluded.original_alias) + 3) = (excluded.original_alias || '* (')
                            THEN tracked_players.alias
                            ELSE excluded.alias
                        END,
                        original_alias = CASE
                            WHEN excluded.original_alias != '' THEN excluded.original_alias
                            ELSE tracked_players.original_alias
                        END,
                        steam_id = CASE
                            WHEN excluded.steam_id != '' THEN excluded.steam_id
                            ELSE tracked_players.steam_id
                        END,
                        baseline_synced = CASE
                            WHEN tracked_players.active = 0 THEN 0
                            ELSE tracked_players.baseline_synced
                        END,
                        active = 1
                    """,
                    rows_to_upsert,
                )
                placeholders = ",".join("?" for _ in active_ids)
                conn.execute(
                    f"UPDATE tracked_players SET active = 0 WHERE profile_id NOT IN ({placeholders})",
                    tuple(active_ids),
                )
            else:
                conn.execute("UPDATE tracked_players SET active = 0")

    def get_active_players(self) -> list[dict[str, Any]]:
        rows = self._connect().execute(
            "SELECT * FROM tracked_players WHERE active = 1 ORDER BY alias COLLATE NOCASE"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_baseline_synced(
        self,
        profile_id: int,
        alias: str | None = None,
        steam_id: str | None = None,
    ) -> None:
        conn = self._connect()
        clean_sid = str(steam_id or "").strip()
        with conn:
            conn.execute(
                """
                UPDATE tracked_players
                SET baseline_synced = 1,
                    alias = COALESCE(NULLIF(?, ''), alias),
                    steam_id = CASE
                        WHEN COALESCE(steam_id, '') = '' AND ? != '' THEN ?
                        ELSE steam_id
                    END
                WHERE profile_id = ?
                """,
                (alias or "", clean_sid, clean_sid, int(profile_id)),
            )

    def get_player_match_ids(self, tracked_profile_id: int, match_ids: list[int]) -> set[int]:
        """Retorna em uma única consulta quais match_ids da lista já estão gravados para o jogador."""
        if not match_ids:
            return set()
        clean_ids = [int(m) for m in match_ids]
        placeholders = ",".join("?" for _ in clean_ids)
        rows = self._connect().execute(
            f"SELECT match_id FROM recorded_matches WHERE tracked_profile_id = ? AND match_id IN ({placeholders})",
            (int(tracked_profile_id), *clean_ids),
        ).fetchall()
        return {int(r["match_id"]) for r in rows}

    def get_player_latest_match_info(self, tracked_profile_id: int) -> dict[str, Any] | None:
        """Retorna metadados resumidos da última partida catalogada para o jogador (uso na 4ª checagem Radar)."""
        pid = int(tracked_profile_id or 0)
        if pid <= 0:
            return None
        row = self._connect().execute(
            """
            SELECT match_id, completion_time, discord_message_id, recorded_at, map_clean, mode
            FROM recorded_matches
            WHERE tracked_profile_id = ?
            ORDER BY completion_time DESC, match_id DESC
            LIMIT 1
            """,
            (pid,),
        ).fetchone()
        if not row:
            return None
        msg_id = str(row["discord_message_id"] or "").strip()
        return {
            "match_id": int(row["match_id"]),
            "completion_time": int(row["completion_time"] or 0),
            "discord_message_id": msg_id,
            "is_delivered_snowflake": len(msg_id) >= 15 and msg_id.isdigit(),
            "recorded_at": int(row["recorded_at"] or 0),
            "map_clean": str(row["map_clean"] or ""),
            "mode": str(row["mode"] or ""),
        }

    def insert_match(self, match: dict[str, Any], discord_message_id: str | None = None) -> bool:
        """Grava partida atomicamente com INSERT OR IGNORE (sem race condition). Retorna True se foi inédita."""
        now = int(time.time())
        mid = int(match["match_id"])
        bg_raw = match.get("battlegroups")
        bg_json = (
            json.dumps({str(k): v for k, v in bg_raw.items()}, ensure_ascii=False, separators=(",", ":"))
            if isinstance(bg_raw, dict)
            else ""
        )
        smurf_raw = match.get("smurf_alerts")
        smurf_json = (
            json.dumps([a for a in smurf_raw if isinstance(a, dict)], ensure_ascii=False, separators=(",", ":"))
            if isinstance(smurf_raw, list) and smurf_raw
            else ""
        )
        eff_msg_id = discord_message_id
        conn = self._connect()
        with conn:
            if not bg_json or not smurf_json or eff_msg_id == SEEDED_DISCORD_MARKER:
                sib_rows = conn.execute(
                    """
                    SELECT battlegroups_json, smurf_alerts_json, discord_message_id
                    FROM recorded_matches
                    WHERE match_id = ?
                    """,
                    (mid,),
                ).fetchall()
                for srow in sib_rows:
                    if not bg_json and str(srow["battlegroups_json"] or "").strip():
                        bg_json = str(srow["battlegroups_json"])
                    if not smurf_json and str(srow["smurf_alerts_json"] or "").strip():
                        smurf_json = str(srow["smurf_alerts_json"])
                    if eff_msg_id == SEEDED_DISCORD_MARKER:
                        smid = str(srow["discord_message_id"] or "").strip()
                        if len(smid) >= 15 and smid.isdigit():
                            eff_msg_id = smid
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO recorded_matches (
                    match_id, tracked_profile_id, tracked_alias, tracked_steam_id, tracked_faction,
                    tracked_faction_short, win, resulttype, mode, matchtype_id,
                    map_raw, map_clean, start_time, completion_time, duration_sec,
                    old_elo, new_elo, allies_json, opponents_json, counters_json,
                    has_replay, coh3stats_url, discord_message_id, recorded_at,
                    battlegroups_json, smurf_alerts_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mid,
                    int(match["tracked_profile_id"]),
                    str(match["tracked_alias"]),
                    str(match.get("tracked_steam_id") or ""),
                    str(match["tracked_faction"]),
                    str(match["tracked_faction_short"]),
                    1 if match["win"] else 0,
                    int(match["resulttype"]),
                    str(match["mode"]),
                    int(match["matchtype_id"]),
                    str(match["map_raw"]),
                    str(match["map_clean"]),
                    int(match["start_time"]),
                    int(match["completion_time"]),
                    int(match["duration_sec"]),
                    match.get("old_elo"),
                    match.get("new_elo"),
                    json.dumps(match["allies"], ensure_ascii=False, separators=(",", ":")),
                    json.dumps(match["opponents"], ensure_ascii=False, separators=(",", ":")),
                    "{}",
                    1 if match.get("has_replay") else 0,
                    str(match["coh3stats_url"]),
                    eff_msg_id,
                    now,
                    bg_json,
                    smurf_json,
                ),
            )
            mode_str = str(match.get("mode") or "")
            extracted_opps = self._extract_automatch_steam_opponents(
                mode_str,
                int(match["tracked_profile_id"]),
                match.get("opponents"),
            )
            if extracted_opps:
                ct_val = int(match["completion_time"])
                if ct_val > 0:
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO nemesis_matches (
                            tracked_profile_id, opponent_profile_id, match_id, completion_time,
                            utc_day, win, mode, opponent_alias, opponent_country
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                int(match["tracked_profile_id"]),
                                opp_pid,
                                int(match["match_id"]),
                                ct_val,
                                ct_val // 86400,
                                1 if match["win"] else 0,
                                mode_str,
                                opp_alias,
                                opp_country,
                            )
                            for opp_pid, opp_alias, opp_country in extracted_opps
                        ],
                    )
        return cur.rowcount > 0

    def get_nemesis_status(
        self,
        tracked_profile_ids: list[int],
        opponent_profile_id: int,
        up_to_completion_time: int,
        up_to_match_id: int,
        current_opponent_alias: str = "",
        current_opponent_steam_id: str = "",
    ) -> dict[str, Any] | None:
        """
        Avalia a condição de Nemesis em TODOS os modos Automatch (1v1, 2v2, 3v3, 4v4) em tempo real:
        - Apenas partidas Automatch entre jogadores Steam.
        - Trigger: enfrentar o mesmo oponente >= 2 vezes no mesmo dia (UTC).
        - Após o trigger, todas as partidas Automatch contra esse oponente entram na contagem acumulada.
        - Salva o alias do oponente da última partida.
        """
        clean_tracked = [int(p) for p in dict.fromkeys(tracked_profile_ids or []) if int(p) > 0]
        opp_pid = int(opponent_profile_id or 0)
        up_ct = int(up_to_completion_time or 0)
        up_mid = int(up_to_match_id or 0)
        if not clean_tracked or opp_pid <= 0 or up_ct <= 0 or up_mid <= 0:
            return None
        if opp_pid in clean_tracked:
            return None

        clean_opp_sid = str(current_opponent_steam_id or "").replace("/steam/", "").strip()
        if clean_opp_sid and not STEAM_ID64_VALID_RE.fullmatch(clean_opp_sid):
            return None

        placeholders = ",".join("?" for _ in clean_tracked)
        rows = self._connect().execute(
            f"""
            SELECT match_id, completion_time, utc_day, win, mode, opponent_alias, opponent_country
            FROM nemesis_matches
            WHERE tracked_profile_id IN ({placeholders})
              AND opponent_profile_id = ?
              AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
            ORDER BY completion_time ASC, match_id ASC
            """,
            (*clean_tracked, opp_pid, up_ct, up_ct, up_mid),
        ).fetchall()

        if len(rows) < 2:
            return None

        # Deduplica por match_id preservando ordem cronológica (cobre contas secundárias mescladas)
        unique_games: list[dict[str, Any]] = []
        seen_mids: set[int] = set()
        for r in rows:
            mid = int(r["match_id"])
            if mid in seen_mids:
                continue
            seen_mids.add(mid)
            unique_games.append(dict(r))

        if len(unique_games) < 2:
            return None

        day_counts: dict[int, int] = {}
        for g in unique_games:
            d = int(g["utc_day"])
            day_counts[d] = day_counts.get(d, 0) + 1

        trigger_days = [d for d, cnt in day_counts.items() if cnt >= 2]
        if not trigger_days:
            return None

        first_trigger_day = min(trigger_days)
        cur_utc_day = up_ct // 86400
        same_day_games = int(day_counts.get(cur_utc_day, 0))
        is_new_trigger = bool(first_trigger_day == cur_utc_day and same_day_games == 2)

        wins = sum(1 for g in unique_games if int(g["win"] or 0) != 0)
        total = len(unique_games)
        losses = total - wins
        latest_alias = (current_opponent_alias or "").strip() or str(unique_games[-1].get("opponent_alias") or "").strip()
        modes_seen = sorted({str(g.get("mode") or "") for g in unique_games if g.get("mode")})

        return {
            "triggered": True,
            "is_new_trigger": is_new_trigger,
            "tracked_profile_id": clean_tracked[0],
            "opponent_profile_id": opp_pid,
            "opponent_alias": latest_alias,
            "wins": wins,
            "losses": losses,
            "total": total,
            "diff": wins - losses,
            "win_rate": round((wins * 100.0) / total, 1) if total > 0 else 0.0,
            "same_day_games": same_day_games,
            "trigger_utc_day": first_trigger_day,
            "modes": modes_seen,
        }

    def insert_nemesis_matches_batch(
        self,
        rows: list[tuple[int, int, int, int, int, int, str, str, str]],
    ) -> int:
        """
        Insere em lote (idempotente via INSERT OR IGNORE) confrontos históricos Automatch Steam
        na tabela `nemesis_matches`, usada pelo backfill histórico desde o lançamento/Open Data 2023.
        Cada tupla: `(tracked_profile_id, opponent_profile_id, match_id, completion_time, utc_day, win, mode, opponent_alias, opponent_country)`.
        """
        if not rows:
            return 0
        valid_rows = [
            (
                int(tpid),
                int(opid),
                int(mid),
                int(ct),
                int(uday),
                1 if int(win) else 0,
                str(mode)[:24],
                str(oalias or "")[:80],
                str(octry or "").strip().lower()[:4],
            )
            for (tpid, opid, mid, ct, uday, win, mode, oalias, octry) in rows
            if int(tpid) > 0 and int(opid) > 0 and int(tpid) != int(opid) and int(mid) > 0 and int(ct) > 0 and str(mode) in AUTOMATCH_MODES
        ]
        if not valid_rows:
            return 0
        conn = self._connect()
        before = int(conn.execute("SELECT COUNT(*) FROM nemesis_matches").fetchone()[0] or 0)
        with conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO nemesis_matches (
                    tracked_profile_id, opponent_profile_id, match_id, completion_time,
                    utc_day, win, mode, opponent_alias, opponent_country
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                valid_rows,
            )
        after = int(conn.execute("SELECT COUNT(*) FROM nemesis_matches").fetchone()[0] or 0)
        return max(0, after - before)

    def get_nemesis_coverage_summary(self) -> dict[str, Any]:
        """Retorna estatísticas resumidas de cobertura histórica da tabela `nemesis_matches`."""
        conn = self._connect()
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_rows,
                   COUNT(DISTINCT match_id) AS unique_matches,
                   COUNT(DISTINCT tracked_profile_id) AS tracked_players,
                   MIN(completion_time) AS min_ct,
                   MAX(completion_time) AS max_ct
            FROM nemesis_matches
            """
        ).fetchone()
        active_rivals = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT tracked_profile_id, opponent_profile_id
                FROM nemesis_matches
                GROUP BY tracked_profile_id, opponent_profile_id, utc_day
                HAVING COUNT(*) >= 2
            )
            """
        ).fetchone()
        distinct_nemesis_pairs = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT DISTINCT tracked_profile_id, opponent_profile_id
                FROM (
                    SELECT tracked_profile_id, opponent_profile_id
                    FROM nemesis_matches
                    GROUP BY tracked_profile_id, opponent_profile_id, utc_day
                    HAVING COUNT(*) >= 2
                )
            )
            """
        ).fetchone()
        return {
            "total_rows": int(row["total_rows"] or 0) if row else 0,
            "unique_matches": int(row["unique_matches"] or 0) if row else 0,
            "tracked_players": int(row["tracked_players"] or 0) if row else 0,
            "min_completion_time": int(row["min_ct"] or 0) if row else 0,
            "max_completion_time": int(row["max_ct"] or 0) if row else 0,
            "trigger_day_events": int(active_rivals[0] or 0) if active_rivals else 0,
            "distinct_nemesis_pairs": int(distinct_nemesis_pairs[0] or 0) if distinct_nemesis_pairs else 0,
        }

    def update_matches_discord_id_batch(self, records: list[dict[str, Any]], message_id: str) -> None:
        """Atualiza o discord_message_id de todos os registros agrupados da mesma partida em uma transação."""
        if not records or not message_id:
            return
        conn = self._connect()
        with conn:
            conn.executemany(
                "UPDATE recorded_matches SET discord_message_id = ? WHERE match_id = ? AND tracked_profile_id = ?",
                [(str(message_id), int(r["match_id"]), int(r["tracked_profile_id"])) for r in records],
            )

    def update_match_battlegroups(
        self,
        match_id: int,
        battlegroups: dict[int, dict[str, str]] | dict[str, dict[str, str]],
    ) -> int:
        """Persiste o mapa `{profile_id: {'key': ..., 'name': ...}}` em todas as linhas da partida."""
        mid = int(match_id or 0)
        if mid <= 0:
            return 0
        payload = json.dumps(
            {str(k): v for k, v in (battlegroups or {}).items() if isinstance(v, dict)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "UPDATE recorded_matches SET battlegroups_json = ? WHERE match_id = ?",
                (payload, mid),
            )
        return int(cur.rowcount or 0)

    def update_match_smurf_alerts(
        self,
        match_id: int,
        alerts: list[dict[str, Any]],
    ) -> int:
        """Persiste a lista de alertas forenses de smurf em todas as linhas da partida (preservada em PATCHes)."""
        mid = int(match_id or 0)
        if mid <= 0:
            return 0
        clean_alerts = [a for a in (alerts or []) if isinstance(a, dict)]
        payload = (
            json.dumps(clean_alerts, ensure_ascii=False, separators=(",", ":"))
            if clean_alerts
            else ""
        )
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "UPDATE recorded_matches SET smurf_alerts_json = ? WHERE match_id = ?",
                (payload, mid),
            )
        return int(cur.rowcount or 0)

    def get_recent_matches_missing_battlegroups(
        self,
        max_age_sec: int = 259200,
        limit: int = 10,
        exclude_match_ids: set[int] | list[int] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retorna registros de partidas recentes (Automatch e Personalizadas/Custom, excluindo Co-Op vs IA)
        já postadas no Discord (Snowflake válido) cujos Battlegroups ainda não foram indexados no cohdb.com,
        para enriquecimento e PATCH retroativo.
        """
        safe_limit = max(1, min(int(limit), 30))
        cutoff = int(time.time()) - max(600, int(max_age_sec))
        excluded = sorted({int(m) for m in (exclude_match_ids or []) if int(m or 0) > 0})
        exclude_sql = ""
        params: list[Any] = [cutoff]
        if excluded:
            ex_ph = ",".join("?" for _ in excluded)
            exclude_sql = f"\n              AND rm.match_id NOT IN ({ex_ph})"
            params.extend(excluded)
        params.append(safe_limit)
        conn = self._connect()
        mid_rows = conn.execute(
            f"""
            SELECT rm.match_id, MAX(rm.completion_time) AS latest_ct
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.mode IN ('1v1', '2v2', 'Team Games (3v3)', 'Team Games (4v4)', 'Custom')
              AND rm.completion_time >= ?{exclude_sql}
            GROUP BY rm.match_id
            HAVING MAX(CASE WHEN COALESCE(rm.battlegroups_json, '') != '' THEN 1 ELSE 0 END) = 0
               AND MAX(
                   CASE
                       WHEN rm.discord_message_id IS NOT NULL
                            AND length(rm.discord_message_id) >= 15
                            AND rm.discord_message_id NOT GLOB '*[^0-9]*'
                       THEN 1
                       ELSE 0
                   END
               ) = 1
            ORDER BY latest_ct DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        mids = [int(r["match_id"]) for r in mid_rows]
        if not mids:
            return []
        placeholders = ",".join("?" for _ in mids)
        rows = conn.execute(
            f"""
            SELECT rm.*,
                   COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                   COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.match_id IN ({placeholders})
            ORDER BY rm.completion_time DESC, rm.match_id DESC
            """,
            mids,
        ).fetchall()
        return [self._row_to_match_dict(r) for r in rows]

    def get_recent_posted_matches(
        self,
        max_age_sec: int = 259200,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Retorna todas as linhas ativas das partidas recentes (<= max_age_sec) já postadas no Discord
        (com Snowflake válido), para atualização retroativa silenciosa quando um Veterano ou Smurf
        é adicionado ou renomeado no roster compartilhado.
        """
        safe_limit = max(1, min(int(limit), 100))
        cutoff = int(time.time()) - max(600, int(max_age_sec))
        conn = self._connect()
        mid_rows = conn.execute(
            """
            SELECT rm.match_id, MAX(rm.completion_time) AS latest_ct
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.completion_time >= ?
              AND rm.discord_message_id IS NOT NULL
              AND length(rm.discord_message_id) >= 15
              AND rm.discord_message_id NOT GLOB '*[^0-9]*'
            GROUP BY rm.match_id
            ORDER BY latest_ct DESC
            LIMIT ?
            """,
            (cutoff, safe_limit),
        ).fetchall()
        mids = [int(r["match_id"]) for r in mid_rows]
        if not mids:
            return []
        placeholders = ",".join("?" for _ in mids)
        rows = conn.execute(
            f"""
            SELECT rm.*,
                   COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                   COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.match_id IN ({placeholders})
            ORDER BY rm.completion_time DESC, rm.match_id DESC
            """,
            mids,
        ).fetchall()
        return [self._row_to_match_dict(r) for r in rows]

    def update_match_participants_metadata(
        self,
        match_id: int,
        tracked_profile_id: int,
        tracked_alias: str,
        allies: list[dict[str, Any]],
        opponents: list[dict[str, Any]],
    ) -> int:
        """Atualiza `tracked_alias`, `allies_json` e `opponents_json` após atualização retroativa de roster/smurf."""
        mid = int(match_id or 0)
        pid = int(tracked_profile_id or 0)
        if mid <= 0 or pid <= 0:
            return 0
        conn = self._connect()
        with conn:
            cur = conn.execute(
                """
                UPDATE recorded_matches
                SET tracked_alias = ?, allies_json = ?, opponents_json = ?
                WHERE match_id = ? AND tracked_profile_id = ?
                """,
                (
                    str(tracked_alias or ""),
                    json.dumps(allies or [], ensure_ascii=False, separators=(",", ":")),
                    json.dumps(opponents or [], ensure_ascii=False, separators=(",", ":")),
                    mid,
                    pid,
                ),
            )
        return int(cur.rowcount or 0)

    @staticmethod
    def _row_to_match_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["tracked_steam_id"] = d.pop("resolved_steam_id", "") or d.get("tracked_steam_id", "")
        disp_alias = d.pop("resolved_display_alias", "")
        if disp_alias:
            d["tracked_alias"] = disp_alias
        d["win"] = bool(d["win"])
        d["has_replay"] = bool(d["has_replay"])
        d["allies"] = json.loads(d.pop("allies_json") or "[]")
        d["opponents"] = json.loads(d.pop("opponents_json") or "[]")
        raw_bg = str(d.pop("battlegroups_json", "") or "").strip()
        d["battlegroups_checked"] = bool(raw_bg != "")
        if raw_bg:
            try:
                parsed_bg = json.loads(raw_bg)
                d["battlegroups"] = parsed_bg if isinstance(parsed_bg, dict) else {}
            except Exception:
                d["battlegroups"] = {}
        else:
            d["battlegroups"] = {}
        raw_smurf = str(d.pop("smurf_alerts_json", "") or "").strip()
        if raw_smurf:
            try:
                parsed_smurf = json.loads(raw_smurf)
                d["smurf_alerts"] = parsed_smurf if isinstance(parsed_smurf, list) else []
            except Exception:
                d["smurf_alerts"] = []
        else:
            d["smurf_alerts"] = []
        d.pop("counters_json", None)
        d["counters"] = {}
        return d

    def get_recent_recorded_matches(
        self,
        limit: int = 15,
        only_active_players: bool = True,
        min_recorded_at: int = 0,
        min_completion_time: int = 0,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        min_ts = max(0, int(min_recorded_at or 0))
        min_ct = max(0, int(min_completion_time or 0))
        where_parts: list[str] = []
        params: list[Any] = []
        if only_active_players:
            join_clause = "JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id"
            where_parts.append("tp.active = 1")
        else:
            join_clause = "LEFT JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id"
        if min_ts > 0:
            where_parts.append("rm.recorded_at >= ?")
            params.append(min_ts)
            where_parts.append("COALESCE(rm.discord_message_id, '') != ?")
            params.append(SEEDED_DISCORD_MARKER)
        if min_ct > 0:
            where_parts.append("CASE WHEN rm.completion_time > 0 THEN rm.completion_time ELSE rm.recorded_at END >= ?")
            params.append(min_ct)
        where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        params.append(safe_limit)
        rows = self._connect().execute(
            f"""
            SELECT rm.*,
                   COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                   COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
            FROM recorded_matches rm
            {join_clause}
            {where_clause}
            ORDER BY rm.completion_time DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        return [self._row_to_match_dict(r) for r in rows]

    def get_pending_matches(
        self,
        max_age_sec: int = 21600,
        limit: int = 30,
    ) -> list[dict[str, Any]]:
        """Recupera partidas recentes marcadas como PENDING (falha transitória no Discord), evitando duplicatas."""
        safe_limit = max(1, min(int(limit), 200))
        cutoff = int(time.time()) - max(60, int(max_age_sec))
        conn = self._connect()

        # Autocorrija registros PENDING cujo match_id já recebeu Snowflake válido via outro jogador monitorado
        with conn:
            conn.execute(
                """
                UPDATE recorded_matches
                SET discord_message_id = (
                    SELECT s.discord_message_id
                    FROM recorded_matches s
                    WHERE s.match_id = recorded_matches.match_id
                      AND s.discord_message_id IS NOT NULL
                      AND length(s.discord_message_id) >= 15
                      AND s.discord_message_id NOT GLOB '*[^0-9]*'
                    LIMIT 1
                )
                WHERE discord_message_id = ?
                  AND EXISTS (
                    SELECT 1
                    FROM recorded_matches s
                    WHERE s.match_id = recorded_matches.match_id
                      AND s.discord_message_id IS NOT NULL
                      AND length(s.discord_message_id) >= 15
                      AND s.discord_message_id NOT GLOB '*[^0-9]*'
                  )
                """,
                (PENDING_DISCORD_MARKER,),
            )

        rows = conn.execute(
            """
            SELECT rm.*,
                   COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                   COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.discord_message_id = ?
              AND rm.recorded_at >= ?
            ORDER BY rm.completion_time ASC
            LIMIT ?
            """,
            (PENDING_DISCORD_MARKER, cutoff, safe_limit),
        ).fetchall()
        return [self._row_to_match_dict(r) for r in rows]

    def count_pending_matches(self, max_age_sec: int = 21600) -> int:
        cutoff = int(time.time()) - max(60, int(max_age_sec))
        row = self._connect().execute(
            """
            SELECT COUNT(DISTINCT rm.match_id) AS cnt
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.discord_message_id = ?
              AND rm.recorded_at >= ?
            """,
            (PENDING_DISCORD_MARKER, cutoff),
        ).fetchone()
        return int(row["cnt"]) if row else 0

    def get_match_delivery_map(self, match_ids: list[int]) -> dict[int, dict[str, Any]]:
        """
        Retorna mapa de entrega no Discord por match_id para auditoria cruzada:
        - snowflake: Snowflake válido caso QUALQUER linha da partida já tenha sido confirmada no Discord
        - handled_non_live: True se QUALQUER linha foi marcada como PRUNED ou SEEDED
        - rows: {tracked_profile_id: (discord_message_id, recorded_at)}
        """
        clean_ids = sorted({int(mid) for mid in (match_ids or []) if int(mid) > 0})
        if not clean_ids:
            return {}

        result: dict[int, dict[str, Any]] = {}
        conn = self._connect()
        for idx in range(0, len(clean_ids), 400):
            chunk = clean_ids[idx : idx + 400]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"""
                SELECT match_id, tracked_profile_id, discord_message_id, recorded_at
                FROM recorded_matches
                WHERE match_id IN ({placeholders})
                """,
                chunk,
            ).fetchall()
            for row in rows:
                mid = int(row["match_id"])
                pid = int(row["tracked_profile_id"])
                msg_id = str(row["discord_message_id"] or "").strip()
                rec_at = int(row["recorded_at"] or 0)
                entry = result.setdefault(
                    mid,
                    {"snowflake": None, "handled_non_live": False, "rows": {}},
                )
                entry["rows"][pid] = (msg_id, rec_at)
                if len(msg_id) >= 15 and msg_id.isdigit():
                    if not entry["snowflake"]:
                        entry["snowflake"] = msg_id
                elif msg_id in (PRUNED_DISCORD_MARKER, SEEDED_DISCORD_MARKER):
                    entry["handled_non_live"] = True
        return result

    def requeue_undelivered_match(self, match_id: int, tracked_profile_id: int | None = None) -> bool:
        """
        Promove partida(s) já registrada(s) sem entrega confirmada no Discord (NULL, vazia ou PENDING expirada)
        para a fila PENDING ativa, garantindo que nunca reenvie partidas já confirmadas, PRUNED ou SEEDED.
        """
        mid = int(match_id)
        if mid <= 0:
            return False

        now = int(time.time())
        conn = self._connect()
        where_pid = ""
        params: list[Any] = [PENDING_DISCORD_MARKER, now, mid]
        if tracked_profile_id is not None:
            pid = int(tracked_profile_id)
            if pid <= 0:
                return False
            where_pid = "AND tracked_profile_id = ?"
            params.append(pid)
        params.extend([PENDING_DISCORD_MARKER, PRUNED_DISCORD_MARKER, SEEDED_DISCORD_MARKER])

        with conn:
            cur = conn.execute(
                f"""
                UPDATE recorded_matches
                SET discord_message_id = ?, recorded_at = ?
                WHERE match_id = ?
                  {where_pid}
                  AND (
                    discord_message_id IS NULL
                    OR discord_message_id = ''
                    OR discord_message_id = ?
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM recorded_matches s
                    WHERE s.match_id = recorded_matches.match_id
                      AND (
                        (s.discord_message_id IS NOT NULL
                         AND length(s.discord_message_id) >= 15
                         AND s.discord_message_id NOT GLOB '*[^0-9]*')
                        OR s.discord_message_id IN (?, ?)
                      )
                  )
                """,
                params,
            )
        return cur.rowcount > 0

    def get_latest_recorded_match_ts(self, only_active_players: bool = True) -> int:
        """Retorna o maior `completion_time` registrado no banco para detectar períodos prolongados sem partidas."""
        conn = self._connect()
        if only_active_players:
            row = conn.execute(
                """
                SELECT MAX(rm.completion_time) AS latest_ct
                FROM recorded_matches rm
                JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
                WHERE tp.active = 1
                """
            ).fetchone()
        else:
            row = conn.execute("SELECT MAX(completion_time) AS latest_ct FROM recorded_matches").fetchone()
        return int(row["latest_ct"] or 0) if row else 0

    def get_latest_match_ts_by_player(self, profile_ids: list[int] | None = None) -> dict[int, int]:
        """Retorna `{tracked_profile_id: MAX(completion_time)}` em uma única consulta para auditoria contra getPersonalStat."""
        conn = self._connect()
        if profile_ids is not None:
            clean_pids = sorted({int(p) for p in profile_ids if int(p) > 0})
            if not clean_pids:
                return {}
            placeholders = ",".join("?" for _ in clean_pids)
            rows = conn.execute(
                f"""
                SELECT tracked_profile_id, MAX(completion_time) AS latest_ct
                FROM recorded_matches
                WHERE tracked_profile_id IN ({placeholders})
                GROUP BY tracked_profile_id
                """,
                clean_pids,
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT tracked_profile_id, MAX(completion_time) AS latest_ct
                FROM recorded_matches
                GROUP BY tracked_profile_id
                """
            ).fetchall()
        return {int(r["tracked_profile_id"]): int(r["latest_ct"] or 0) for r in rows}

    def get_undelivered_recent_match_ids(
        self,
        min_completion_time: int,
        pending_max_age_sec: int = 21600,
        limit: int = 30,
        now_ts: int | None = None,
    ) -> list[int]:
        """
        Retorna `match_id`s dentro da janela ativa (`completion_time >= min_completion_time`) que estão
        gravados no SQLite sem entrega confirmada no Discord (NULL, vazio ou PENDING expirado) e sem
        nenhum registro irmão já confirmado (Snowflake), PRUNED ou SEEDED.
        """
        min_ct = max(0, int(min_completion_time or 0))
        safe_limit = max(1, min(int(limit), 100))
        now = int(now_ts) if now_ts is not None else int(time.time())
        expired_pending_cutoff = now - max(60, int(pending_max_age_sec))
        rows = self._connect().execute(
            """
            SELECT DISTINCT rm.match_id, MAX(rm.completion_time) AS latest_ct
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.completion_time >= ?
              AND (
                rm.discord_message_id IS NULL
                OR rm.discord_message_id = ''
                OR (rm.discord_message_id = ? AND rm.recorded_at < ?)
              )
              AND NOT EXISTS (
                SELECT 1
                FROM recorded_matches s
                WHERE s.match_id = rm.match_id
                  AND (
                    (s.discord_message_id IS NOT NULL
                     AND length(s.discord_message_id) >= 15
                     AND s.discord_message_id NOT GLOB '*[^0-9]*')
                    OR s.discord_message_id IN (?, ?)
                  )
              )
            GROUP BY rm.match_id
            ORDER BY latest_ct ASC
            LIMIT ?
            """,
            (
                min_ct,
                PENDING_DISCORD_MARKER,
                expired_pending_cutoff,
                PRUNED_DISCORD_MARKER,
                SEEDED_DISCORD_MARKER,
                safe_limit,
            ),
        ).fetchall()
        return [int(r["match_id"]) for r in rows]

    def record_ephemeral_message(
        self,
        message_id: str,
        kind: str,
        sent_at: int | None = None,
    ) -> None:
        """Registra Snowflake de cards temporários (movimentação, novo Top 20, teste) para limpeza após 72h."""
        clean_id = (message_id or "").strip()
        if not clean_id or len(clean_id) < 15 or not clean_id.isdigit():
            return
        ts = int(sent_at) if sent_at is not None else int(time.time())
        conn = self._connect()
        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO discord_ephemeral_messages (message_id, kind, sent_at, pruned_at)
                VALUES (?, ?, ?, NULL)
                """,
                (clean_id, str(kind)[:32], ts),
            )

    def get_prunable_discord_messages(
        self,
        max_age_sec: int = 72 * 3600,
        exclude_message_ids: set[str] | None = None,
        limit: int = 80,
        now_ts: int | None = None,
    ) -> list[tuple[str, str]]:
        """Retorna lista (message_id, origem) de mensagens do Discord com mais de max_age_sec para limpeza (apenas no canal)."""
        safe_limit = max(1, min(int(limit), 200))
        now = int(now_ts) if now_ts is not None else int(time.time())
        cutoff = now - max(3600, int(max_age_sec))
        excluded = {str(x).strip() for x in (exclude_message_ids or set()) if x}
        conn = self._connect()

        candidates: list[tuple[int, str, str]] = []
        seen_ids: set[str] = set()

        match_rows = conn.execute(
            """
            SELECT discord_message_id,
                   MAX(CASE WHEN completion_time > 0 THEN completion_time ELSE recorded_at END) AS effective_ts
            FROM recorded_matches
            WHERE discord_message_id IS NOT NULL
              AND length(discord_message_id) >= 15
              AND discord_message_id NOT GLOB '*[^0-9]*'
            GROUP BY discord_message_id
            HAVING MAX(CASE WHEN completion_time > 0 THEN completion_time ELSE recorded_at END) <= ?
            ORDER BY effective_ts ASC
            LIMIT ?
            """,
            (cutoff, safe_limit),
        ).fetchall()
        for r in match_rows:
            mid = str(r["discord_message_id"])
            if mid not in excluded and mid not in seen_ids:
                seen_ids.add(mid)
                candidates.append((int(r["effective_ts"]), mid, "match"))

        eph_rows = conn.execute(
            """
            SELECT message_id, kind, sent_at
            FROM discord_ephemeral_messages
            WHERE pruned_at IS NULL
              AND sent_at <= ?
            ORDER BY sent_at ASC
            LIMIT ?
            """,
            (cutoff, safe_limit),
        ).fetchall()
        for r in eph_rows:
            mid = str(r["message_id"])
            if mid not in excluded and mid not in seen_ids:
                seen_ids.add(mid)
                candidates.append((int(r["sent_at"]), mid, str(r["kind"])))

        candidates.sort(key=lambda item: item[0])
        return [(mid, kind) for _, mid, kind in candidates[:safe_limit]]

    def mark_discord_message_pruned(self, message_id: str) -> None:
        """Marca a mensagem como limpa no canal sem remover o histórico de partidas do SQLite."""
        clean_id = (message_id or "").strip()
        if not clean_id:
            return
        now = int(time.time())
        conn = self._connect()
        with conn:
            conn.execute(
                "UPDATE recorded_matches SET discord_message_id = ? WHERE discord_message_id = ?",
                (PRUNED_DISCORD_MARKER, clean_id),
            )
            conn.execute(
                "UPDATE discord_ephemeral_messages SET pruned_at = ? WHERE message_id = ?",
                (now, clean_id),
            )

    def get_all_active_discord_message_ids(self, include_summary: bool = True) -> list[tuple[str, str]]:
        """Retorna todas as mensagens ativas do bot/webhook no Discord para limpeza total do canal."""
        conn = self._connect()
        result: list[tuple[str, str]] = []
        seen: set[str] = set()

        match_rows = conn.execute(
            """
            SELECT discord_message_id, MAX(recorded_at) AS latest_ts
            FROM recorded_matches
            WHERE discord_message_id IS NOT NULL
              AND length(discord_message_id) >= 15
              AND discord_message_id NOT GLOB '*[^0-9]*'
            GROUP BY discord_message_id
            ORDER BY latest_ts ASC
            """
        ).fetchall()
        for r in match_rows:
            mid = str(r["discord_message_id"])
            if mid not in seen:
                seen.add(mid)
                result.append((mid, "match"))

        eph_rows = conn.execute(
            """
            SELECT message_id, kind
            FROM discord_ephemeral_messages
            WHERE pruned_at IS NULL
            ORDER BY sent_at ASC
            """
        ).fetchall()
        for r in eph_rows:
            mid = str(r["message_id"])
            if mid not in seen:
                seen.add(mid)
                result.append((mid, str(r["kind"])))

        if include_summary:
            summary_id = (self.get_state("summary_message_id") or "").strip()
            if summary_id and len(summary_id) >= 15 and summary_id.isdigit() and summary_id not in seen:
                seen.add(summary_id)
                result.append((summary_id, "summary_panel"))

        return result

    def reset_discord_channel_state(self, now_ts: int | None = None) -> None:
        """Reinicia o estado visual do canal Discord do zero sem apagar o histórico deduplicado em SQLite."""
        now = int(now_ts) if now_ts is not None else int(time.time())
        conn = self._connect()
        with conn:
            conn.execute(
                """
                UPDATE recorded_matches
                SET discord_message_id = ?
                WHERE discord_message_id IS NOT NULL
                  AND (
                      discord_message_id = ?
                      OR (length(discord_message_id) >= 15 AND discord_message_id NOT GLOB '*[^0-9]*')
                  )
                """,
                (PRUNED_DISCORD_MARKER, PENDING_DISCORD_MARKER),
            )
            conn.execute(
                "UPDATE discord_ephemeral_messages SET pruned_at = ? WHERE pruned_at IS NULL",
                (now,),
            )
            conn.execute(
                "DELETE FROM bot_state WHERE key IN ('summary_message_id', 'ranking_snapshot_v5', 'ranking_last_deltas_v5')"
            )
            conn.execute(
                "INSERT INTO bot_state (key, value) VALUES ('display_since_ts', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(now),),
            )
            conn.execute(
                "INSERT INTO bot_state (key, value) VALUES ('summary_needs_refresh', '1') ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )

    def get_cached_avatar(
        self,
        steam_id: str = "",
        profile_id: int = 0,
        max_age_sec: int = 7 * 86400,
    ) -> bytes | None:
        now = int(time.time())
        conn = self._connect()
        row = None
        if steam_id:
            row = conn.execute(
                "SELECT png_blob, updated_at FROM player_avatars WHERE steam_id = ?",
                (steam_id,),
            ).fetchone()
        if row is None and profile_id > 0:
            row = conn.execute(
                "SELECT png_blob, updated_at FROM player_avatars WHERE profile_id = ? ORDER BY updated_at DESC LIMIT 1",
                (int(profile_id),),
            ).fetchone()
        if not row or (now - int(row["updated_at"])) > max_age_sec:
            return None
        return bytes(row["png_blob"])

    def save_cached_avatar(
        self,
        steam_id: str,
        avatar_url: str,
        png_blob: bytes,
        profile_id: int = 0,
    ) -> None:
        if not steam_id or not png_blob or len(png_blob) > 131_072:
            return
        now = int(time.time())
        conn = self._connect()
        with conn:
            conn.execute(
                """
                INSERT INTO player_avatars (steam_id, profile_id, avatar_url, png_blob, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(steam_id) DO UPDATE SET
                    profile_id = CASE WHEN excluded.profile_id > 0 THEN excluded.profile_id ELSE player_avatars.profile_id END,
                    avatar_url = excluded.avatar_url,
                    png_blob = excluded.png_blob,
                    updated_at = excluded.updated_at
                """,
                (steam_id, int(profile_id), avatar_url[:512], sqlite3.Binary(png_blob), now),
            )

    def prune_expired_avatars(self, max_age_sec: int = 30 * 86400) -> int:
        cutoff = int(time.time()) - max_age_sec
        conn = self._connect()
        with conn:
            cur = conn.execute("DELETE FROM player_avatars WHERE updated_at < ?", (cutoff,))
        return cur.rowcount

    def get_steam_id_map(self) -> dict[int, str]:
        rows = self._connect().execute(
            "SELECT profile_id, steam_id FROM tracked_players WHERE steam_id != ''"
        ).fetchall()
        return {int(r["profile_id"]): str(r["steam_id"]) for r in rows}

    def get_state(self, key: str) -> str | None:
        row = self._connect().execute(
            "SELECT value FROM bot_state WHERE key = ?",
            (key,),
        ).fetchone()
        return str(row["value"]) if row else None

    def set_state(self, key: str, value: str) -> None:
        conn = self._connect()
        with conn:
            conn.execute(
                """
                INSERT INTO bot_state (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_weekly_summary_stats(
        self,
        now_ts: int | None = None,
        window_days: int = 7,
        merged_map: dict[int, int] | None = None,
    ) -> dict[str, Any]:
        """
        Agrega estatísticas dos últimos `window_days` dias (padrão 7 dias) dos jogadores monitorados ativos,
        fundindo contas secundárias vinculadas (ex.: gabe44arg -> É o Gabe) para o Resumo Semanal.
        """
        now = int(now_ts) if now_ts is not None else int(time.time())
        days = max(1, min(int(window_days), 30))
        since_ts = now - days * 86400
        merge_lookup = {int(k): int(v) for k, v in (merged_map or {}).items() if int(k) > 0 and int(v) > 0}

        conn = self._connect()
        player_meta_rows = conn.execute(
            "SELECT profile_id, alias, original_alias, steam_id FROM tracked_players WHERE active = 1"
        ).fetchall()
        meta_by_pid: dict[int, dict[str, Any]] = {
            int(r["profile_id"]): {
                "profile_id": int(r["profile_id"]),
                "alias": str(r["alias"] or r["original_alias"] or f"Jogador {r['profile_id']}"),
                "steam_id": str(r["steam_id"] or ""),
            }
            for r in player_meta_rows
        }

        rows = conn.execute(
            """
            SELECT rm.match_id, rm.tracked_profile_id, rm.tracked_alias, rm.tracked_steam_id,
                   rm.tracked_faction_short, rm.win, rm.mode, rm.map_raw, rm.map_clean,
                   rm.completion_time, rm.duration_sec, rm.old_elo, rm.new_elo,
                   COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_alias,
                   COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id
            FROM recorded_matches rm
            JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
            WHERE tp.active = 1
              AND rm.completion_time >= ?
              AND rm.completion_time <= ?
            ORDER BY rm.completion_time ASC, rm.match_id ASC
            """,
            (since_ts, now + 3600),
        ).fetchall()

        unique_matches: set[int] = set()
        match_sides_seen: dict[int, set[bool]] = {}
        map_counts: dict[str, list[int]] = {}       # map_clean -> [unique_games, wins]
        faction_counts: dict[str, list[int]] = {}   # faction_short -> [rows, wins]
        per_player: dict[int, dict[str, Any]] = {}
        seen_canonical_match: set[tuple[int, int]] = set()
        seen_map_match: set[tuple[str, int]] = set()

        for r in rows:
            mid = int(r["match_id"])
            raw_pid = int(r["tracked_profile_id"])
            canon_pid = merge_lookup.get(raw_pid, raw_pid)
            win_bool = bool(r["win"])

            unique_matches.add(mid)
            match_sides_seen.setdefault(mid, set()).add(win_bool)

            fac = str(r["tracked_faction_short"] or "N/D")
            f_slot = faction_counts.setdefault(fac, [0, 0])
            f_slot[0] += 1
            if win_bool:
                f_slot[1] += 1

            raw_map = str(r["map_raw"] or "").strip()
            m_clean = clean_map_name(raw_map) if raw_map else str(r["map_clean"] or "Mapa Desconhecido")
            m_slot = map_counts.setdefault(m_clean, [0, 0])
            if (m_clean, mid) not in seen_map_match:
                seen_map_match.add((m_clean, mid))
                m_slot[0] += 1
            if win_bool:
                m_slot[1] += 1

            if (canon_pid, mid) in seen_canonical_match:
                continue
            seen_canonical_match.add((canon_pid, mid))

            meta = meta_by_pid.get(canon_pid) or {
                "profile_id": canon_pid,
                "alias": str(r["resolved_alias"] or f"Jogador {canon_pid}"),
                "steam_id": str(r["resolved_steam_id"] or ""),
            }
            rec = per_player.setdefault(
                canon_pid,
                {
                    "profile_id": canon_pid,
                    "alias": meta["alias"],
                    "steam_id": meta["steam_id"],
                    "games": 0,
                    "wins": 0,
                    "losses": 0,
                    "net_elo_delta": 0,
                    "ranked_games": 0,
                    "cur_streak": 0,
                    "best_win_streak": 0,
                    "peak_new_elo": 0,
                },
            )
            rec["games"] += 1
            if win_bool:
                rec["wins"] += 1
                rec["cur_streak"] += 1
                if rec["cur_streak"] > rec["best_win_streak"]:
                    rec["best_win_streak"] = rec["cur_streak"]
            else:
                rec["losses"] += 1
                rec["cur_streak"] = 0

            old_e = r["old_elo"]
            new_e = r["new_elo"]
            if old_e is not None and new_e is not None and int(old_e) > 0 and int(new_e) > 0:
                rec["net_elo_delta"] += int(new_e) - int(old_e)
                rec["ranked_games"] += 1
                if int(new_e) > rec["peak_new_elo"]:
                    rec["peak_new_elo"] = int(new_e)

        players_list: list[dict[str, Any]] = []
        for p in per_player.values():
            g = int(p["games"])
            w = int(p["wins"])
            p["win_rate"] = round((w * 100.0) / g, 1) if g > 0 else 0.0
            players_list.append(p)

        players_by_activity = sorted(
            players_list,
            key=lambda x: (-x["games"], -x["wins"], -x["net_elo_delta"], x["alias"].lower()),
        )

        elo_climbers = sorted(
            [p for p in players_list if p["ranked_games"] > 0 and p["net_elo_delta"] > 0],
            key=lambda x: (-x["net_elo_delta"], -x["wins"], -x["win_rate"]),
        )
        top_elo_climber = elo_climbers[0] if elo_climbers else None

        streak_leaders = sorted(
            [p for p in players_list if p["best_win_streak"] >= 2],
            key=lambda x: (-x["best_win_streak"], -x["wins"], -x["win_rate"]),
        )
        top_streak_player = streak_leaders[0] if streak_leaders else None

        winrate_leaders = sorted(
            [p for p in players_list if p["games"] >= 5],
            key=lambda x: (-x["win_rate"], -x["wins"], -x["net_elo_delta"]),
        )
        top_winrate_player = winrate_leaders[0] if winrate_leaders else None

        top_map = None
        if map_counts:
            best_m_name, best_m_vals = max(map_counts.items(), key=lambda kv: (kv[1][0], kv[1][1]))
            top_map = {"map_clean": best_m_name, "games": best_m_vals[0], "br_wins": best_m_vals[1]}

        top_faction = None
        if faction_counts:
            best_f_name, best_f_vals = max(faction_counts.items(), key=lambda kv: (kv[1][0], kv[1][1]))
            f_wr = int(round((best_f_vals[1] * 100.0) / best_f_vals[0])) if best_f_vals[0] > 0 else 0
            top_faction = {
                "faction_short": best_f_name,
                "picks": best_f_vals[0],
                "wins": best_f_vals[1],
                "win_rate": f_wr,
            }

        br_duels_count = sum(1 for sides in match_sides_seen.values() if True in sides and False in sides)

        return {
            "since_ts": since_ts,
            "until_ts": now,
            "window_days": days,
            "unique_matches_count": len(unique_matches),
            "active_players_with_games": len(players_list),
            "br_duels_count": br_duels_count,
            "most_active_player": players_by_activity[0] if players_by_activity else None,
            "top_elo_climber": top_elo_climber,
            "top_streak_player": top_streak_player,
            "top_winrate_player": top_winrate_player,
            "top_map": top_map,
            "top_faction": top_faction,
            "leaderboard": players_by_activity[:10],
        }

    def run_periodic_maintenance(
        self,
        now_ts: int | None = None,
        json_retention_days: int = 30,
        ephemeral_retention_days: int = 30,
        avatar_retention_days: int = 30,
    ) -> dict[str, int]:
        """
        Compactação inteligente e segura do SQLite (preservando 100% da deduplicação `match_id` por anos):
        1. Esvazia `allies_json`, `opponents_json` e `counters_json` de partidas já encerradas há mais de `json_retention_days`
           que não estejam `PENDING` (mantém todos os IDs, resultados, ELOs e timestamps intactos para estatísticas e anti-duplicação).
        2. Remove avatares expirados e registros efêmeros antigos já podados.
        3. Executa `VACUUM` + `PRAGMA optimize` desfragmentando o arquivo `.db` versionado no Git.
        """
        now = int(now_ts) if now_ts is not None else int(time.time())
        json_cutoff = now - max(14, int(json_retention_days)) * 86400
        eph_cutoff = now - max(7, int(ephemeral_retention_days)) * 86400

        size_before = self.db_path.stat().st_size if self.db_path.is_file() else 0
        conn = self._connect()

        with conn:
            cur_json = conn.execute(
                """
                UPDATE recorded_matches
                SET allies_json = '[]',
                    opponents_json = '[]',
                    counters_json = '{}'
                WHERE completion_time < ?
                  AND COALESCE(discord_message_id, '') != ?
                  AND (allies_json != '[]' OR opponents_json != '[]' OR counters_json != '{}')
                """,
                (json_cutoff, PENDING_DISCORD_MARKER),
            )
            compacted_rows = int(cur_json.rowcount or 0)

            cur_eph = conn.execute(
                """
                DELETE FROM discord_ephemeral_messages
                WHERE pruned_at IS NOT NULL
                  AND pruned_at < ?
                """,
                (eph_cutoff,),
            )
            purged_ephemeral = int(cur_eph.rowcount or 0)

            backfill_row = conn.execute(
                "SELECT value FROM bot_state WHERE key = 'nemesis_all_modes_backfilled_v1'"
            ).fetchone()
            if backfill_row and str(backfill_row["value"]) == "1":
                conn.execute("DROP TABLE IF EXISTS nemesis_1v1_matches")

        purged_avatars = int(self.prune_expired_avatars(max_age_sec=max(7, int(avatar_retention_days)) * 86400) or 0)

        # VACUUM exige estar fora de transação explícita em SQLite
        old_iso = conn.isolation_level
        try:
            conn.isolation_level = None
            conn.execute("VACUUM")
            conn.execute("PRAGMA optimize")
        finally:
            conn.isolation_level = old_iso

        size_after = self.db_path.stat().st_size if self.db_path.is_file() else 0
        return {
            "compacted_match_rows": compacted_rows,
            "purged_ephemeral_rows": purged_ephemeral,
            "purged_avatars": purged_avatars,
            "bytes_before": size_before,
            "bytes_after": size_after,
            "bytes_saved": max(0, size_before - size_after),
        }

    def refresh_recorded_map_names(self) -> int:
        """Atualiza map_clean das partidas já catalogadas com o dicionário oficial de nomes de mapas CoH3."""
        conn = self._connect()
        distinct_rows = conn.execute(
            "SELECT DISTINCT map_raw, map_clean FROM recorded_matches WHERE map_raw != ''"
        ).fetchall()
        updates: list[tuple[str, str, str]] = []
        for r in distinct_rows:
            raw = str(r["map_raw"] or "")
            cur_clean = str(r["map_clean"] or "")
            official_clean = clean_map_name(raw)
            if official_clean and official_clean != cur_clean:
                updates.append((official_clean, raw, cur_clean))

        if not updates:
            return 0

        updated_rows = 0
        with conn:
            for new_clean, raw, old_clean in updates:
                cur = conn.execute(
                    "UPDATE recorded_matches SET map_clean = ? WHERE map_raw = ? AND map_clean = ?",
                    (new_clean, raw, old_clean),
                )
                updated_rows += int(cur.rowcount or 0)
        return updated_rows



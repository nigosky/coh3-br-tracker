"""Persistência SQLite otimizada e segura para jogadores monitorados, partidas e cache de avatares."""

from __future__ import annotations

import json
import math
import sqlite3
import threading
import time
from datetime import datetime, timezone
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

                CREATE INDEX IF NOT EXISTS idx_nemesis_all_opp
                    ON nemesis_matches (opponent_profile_id, tracked_profile_id);

                CREATE INDEX IF NOT EXISTS idx_recorded_tracked_comp
                    ON recorded_matches (tracked_profile_id, completion_time);

                CREATE TABLE IF NOT EXISTS kryptonite_matches (
                    tracked_profile_id INTEGER NOT NULL,
                    match_id INTEGER NOT NULL,
                    completion_time INTEGER NOT NULL,
                    win INTEGER NOT NULL,
                    mode TEXT DEFAULT '',
                    map_clean TEXT DEFAULT '',
                    allies_json TEXT DEFAULT '[]',
                    enemy_bgs_json TEXT DEFAULT '',
                    PRIMARY KEY (tracked_profile_id, match_id)
                );

                CREATE INDEX IF NOT EXISTS idx_kryptonite_tracked_comp
                    ON kryptonite_matches (tracked_profile_id, completion_time);
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

            existing_krypt_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(kryptonite_matches)").fetchall()
            }
            if "enemy_bgs_json" not in existing_krypt_cols:
                conn.execute("ALTER TABLE kryptonite_matches ADD COLUMN enemy_bgs_json TEXT DEFAULT ''")

            existing_player_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(tracked_players)").fetchall()
            }
            if "original_alias" not in existing_player_cols:
                conn.execute("ALTER TABLE tracked_players ADD COLUMN original_alias TEXT DEFAULT ''")

            self._ensure_nemesis_all_modes_backfill(conn)
            self._ensure_kryptonite_backfill(conn)
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

    @staticmethod
    def _extract_compact_ally_pids(tracked_profile_id: int, allies: Any) -> list[int]:
        """Extrai lista ordenada e deduplicada de `profile_id` de aliados humanos (aceita dicts ou ints)."""
        tpid = int(tracked_profile_id or 0)
        if not isinstance(allies, list) or not allies:
            return []
        out: set[int] = set()
        for a in allies:
            if isinstance(a, dict):
                ap = int(a.get("profile_id", 0) or 0)
            elif isinstance(a, (int, float)) or (isinstance(a, str) and a.strip().isdigit()):
                ap = int(a)
            else:
                ap = 0
            if ap > 0 and ap != tpid:
                out.add(ap)
        return sorted(out)

    @staticmethod
    def _extract_enemy_bg_tokens(opponents: Any, battlegroups: Any) -> list[str]:
        """Extrai tokens canônicos únicos de Battlegroups do time adversário para persistência permanente."""
        if not isinstance(opponents, list) or not isinstance(battlegroups, dict) or not battlegroups:
            return []
        seen: set[str] = set()
        for o in opponents:
            if not isinstance(o, dict):
                continue
            opid = int(o.get("profile_id", 0) or 0)
            if opid <= 0:
                continue
            bg_ent = battlegroups.get(str(opid)) or battlegroups.get(opid)
            if not isinstance(bg_ent, dict):
                continue
            bk = str(bg_ent.get("key") or "").strip().lower()
            bn = str(bg_ent.get("name") or "").strip()
            tok = bk or bn.casefold()
            if tok:
                seen.add(tok)
        return sorted(seen)

    def _ensure_kryptonite_backfill(self, conn: sqlite3.Connection) -> None:
        """
        Popula `kryptonite_matches` uma única vez a partir de todas as partidas Automatch PvP em `recorded_matches`
        (preservando mapa, aliados compactos e Battlegroups inimigos permanentemente mesmo após compactação de 30d).
        """
        row = conn.execute("SELECT value FROM bot_state WHERE key = 'kryptonite_local_backfilled_v1'").fetchone()
        if row and str(row["value"]) == "1":
            return

        placeholders = ",".join("?" for _ in AUTOMATCH_MODES)
        existing = conn.execute(
            f"""
            SELECT match_id, tracked_profile_id, mode, win, completion_time,
                   map_clean, map_raw, allies_json, opponents_json, battlegroups_json
            FROM recorded_matches
            WHERE mode IN ({placeholders})
            """,
            tuple(AUTOMATCH_MODES),
        ).fetchall()

        to_upsert: list[tuple[int, int, int, int, str, str, str, str]] = []
        for r in existing:
            tpid = int(r["tracked_profile_id"] or 0)
            mid = int(r["match_id"] or 0)
            ct = int(r["completion_time"] or 0)
            mode_str = str(r["mode"] or "")
            if tpid <= 0 or mid <= 0 or ct <= 0 or mode_str not in AUTOMATCH_MODES:
                continue
            mclean = str(r["map_clean"] or "").strip() or clean_map_name(str(r["map_raw"] or "")).strip()
            try:
                allies_parsed = json.loads(r["allies_json"] or "[]")
            except Exception:
                allies_parsed = []
            ally_pids = self._extract_compact_ally_pids(tpid, allies_parsed)

            enemy_bgs: list[str] = []
            if str(r["battlegroups_json"] or "").strip() not in ("", "{}", "null"):
                try:
                    opps_parsed = json.loads(r["opponents_json"] or "[]")
                    bgs_parsed = json.loads(r["battlegroups_json"] or "{}")
                    enemy_bgs = self._extract_enemy_bg_tokens(opps_parsed, bgs_parsed)
                except Exception:
                    enemy_bgs = []

            to_upsert.append(
                (
                    tpid,
                    mid,
                    ct,
                    1 if int(r["win"] or 0) else 0,
                    mode_str[:24],
                    mclean[:96],
                    json.dumps(ally_pids, separators=(",", ":")),
                    json.dumps(enemy_bgs, ensure_ascii=False, separators=(",", ":")) if enemy_bgs else "",
                )
            )

        if to_upsert:
            conn.executemany(
                """
                INSERT INTO kryptonite_matches (
                    tracked_profile_id, match_id, completion_time, win, mode, map_clean, allies_json, enemy_bgs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tracked_profile_id, match_id) DO UPDATE SET
                    enemy_bgs_json = CASE
                        WHEN COALESCE(kryptonite_matches.enemy_bgs_json, '') = '' AND excluded.enemy_bgs_json != ''
                        THEN excluded.enemy_bgs_json
                        ELSE kryptonite_matches.enemy_bgs_json
                    END,
                    allies_json = CASE
                        WHEN COALESCE(kryptonite_matches.allies_json, '[]') IN ('', '[]') AND excluded.allies_json != '[]'
                        THEN excluded.allies_json
                        ELSE kryptonite_matches.allies_json
                    END
                """,
                to_upsert,
            )

        conn.execute(
            """
            INSERT INTO bot_state (key, value) VALUES ('kryptonite_local_backfilled_v1', '1')
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
            if mode_str in AUTOMATCH_MODES:
                ct_val = int(match["completion_time"] or 0)
                tpid_int = int(match["tracked_profile_id"] or 0)
                if ct_val > 0 and tpid_int > 0 and mid > 0:
                    mclean = str(match.get("map_clean") or "").strip() or clean_map_name(str(match.get("map_raw") or "")).strip()
                    ally_pids = self._extract_compact_ally_pids(tpid_int, match.get("allies"))
                    enemy_bgs = self._extract_enemy_bg_tokens(match.get("opponents"), match.get("battlegroups"))
                    conn.execute(
                        """
                        INSERT INTO kryptonite_matches (
                            tracked_profile_id, match_id, completion_time, win, mode, map_clean, allies_json, enemy_bgs_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(tracked_profile_id, match_id) DO UPDATE SET
                            enemy_bgs_json = CASE
                                WHEN COALESCE(kryptonite_matches.enemy_bgs_json, '') = '' AND excluded.enemy_bgs_json != ''
                                THEN excluded.enemy_bgs_json
                                ELSE kryptonite_matches.enemy_bgs_json
                            END,
                            allies_json = CASE
                                WHEN COALESCE(kryptonite_matches.allies_json, '[]') IN ('', '[]') AND excluded.allies_json != '[]'
                                THEN excluded.allies_json
                                ELSE kryptonite_matches.allies_json
                            END
                        """,
                        (
                            tpid_int,
                            mid,
                            ct_val,
                            1 if match["win"] else 0,
                            mode_str[:24],
                            mclean[:96],
                            json.dumps(ally_pids, separators=(",", ":")),
                            json.dumps(enemy_bgs, ensure_ascii=False, separators=(",", ":")) if enemy_bgs else "",
                        ),
                    )
        return cur.rowcount > 0

    # Limiares simétricos de domínio recorrente no histórico completo CoH3 (2023+) — Nêmesis e Freguês
    RIVALRY_ZERO_OPP_MIN_GAMES: int = 4   # 0V-4D (Nêmesis) ou 4V-0D (Freguês)
    RIVALRY_MIN_TOTAL_GAMES: int = 5      # Ex.: 1V-4D / 4V-1D, 2V-5D / 5V-2D, 3V-6D / 6V-3D
    RIVALRY_MIN_DIFF: int = 3             # Diferença mínima de 3 vitórias a favor do lado dominante
    RIVALRY_MIN_DOMINANT_WR: float = 65.0 # >= 65% de aproveitamento do lado dominante (<= 35% do dominado)

    @classmethod
    def is_rivalry_dominant(cls, dominant_wins: int, underdog_wins: int) -> bool:
        """
        Critério simétrico de domínio recorrente ao longo de TODO o histórico CoH3 (2023+):
        - Invicto dominante: 0 derrotas e >= 4 vitórias (ex.: 4V-0D / 0V-4D); OU
        - Domínio sustentado: >= 5 confrontos, saldo >= 3 e >= 65% WR do lado dominante
          (ex.: 4V-1D, 5V-2D, 6V-3D, 8V-4D, 13V-7D).
        Vale ao longo de toda a história do jogo (2023+), sem exigir 2+ jogos no mesmo dia.
        """
        dom = max(0, int(dominant_wins))
        und = max(0, int(underdog_wins))
        tot = dom + und
        if tot <= 0 or dom <= und:
            return False
        if und == 0 and dom >= cls.RIVALRY_ZERO_OPP_MIN_GAMES:
            return True
        return (
            tot >= cls.RIVALRY_MIN_TOTAL_GAMES
            and (dom - und) >= cls.RIVALRY_MIN_DIFF
            and (dom * 100.0 / tot) >= cls.RIVALRY_MIN_DOMINANT_WR
        )

    @classmethod
    def is_nemesis_record(cls, wins: int, losses: int) -> bool:
        """True quando o Veterano apanha regularmente deste adversário no histórico CoH3 (2023+)."""
        return cls.is_rivalry_dominant(losses, wins)

    @classmethod
    def is_fregues_record(cls, wins: int, losses: int) -> bool:
        """True quando o adversário apanha regularmente do Veterano no histórico CoH3 (2023+)."""
        return cls.is_rivalry_dominant(wins, losses)

    def _get_head_to_head_rivalry_status(
        self,
        *,
        kind: str,
        tracked_profile_ids: list[int],
        opponent_profile_id: int,
        up_to_completion_time: int,
        up_to_match_id: int,
        current_opponent_alias: str = "",
        current_opponent_steam_id: str = "",
    ) -> dict[str, Any] | None:
        """
        Avalia em tempo real a condição simétrica de Nêmesis ('nemesis') ou Freguês ('fregues')
        em TODOS os modos Automatch (1v1, 2v2, 3v3, 4v4) ao longo de TODO o histórico CoH3 (2023+):
        - Apenas partidas Automatch entre jogadores Steam (tabela permanente `nemesis_matches`).
        - Não depende de enfrentar o oponente 2+ vezes em um único dia UTC.
        - `kind='nemesis'`: o Veterano apanha regularmente do adversário (`is_nemesis_record`).
        - `kind='fregues'`: o adversário apanha regularmente do Veterano (`is_fregues_record`).
        - `is_new_trigger=True` somente na partida exata em que o par cruza o limiar pela 1ª vez.
        """
        if kind not in ("nemesis", "fregues"):
            raise ValueError(f"Tipo de rivalidade inválido: {kind}")

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

        if len(rows) < self.RIVALRY_ZERO_OPP_MIN_GAMES:
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

        total = len(unique_games)
        if total < self.RIVALRY_ZERO_OPP_MIN_GAMES:
            return None

        wins = sum(1 for g in unique_games if int(g["win"] or 0) != 0)
        losses = total - wins
        predicate = self.is_nemesis_record if kind == "nemesis" else self.is_fregues_record
        if not predicate(wins, losses):
            return None

        # Identifica a 1ª partida cronológica em que o par atingiu o critério (NOVO NEMESIS / NOVO FREGUÊS)
        first_trigger_idx: int | None = None
        run_w = 0
        run_l = 0
        for idx, g in enumerate(unique_games):
            if int(g["win"] or 0) != 0:
                run_w += 1
            else:
                run_l += 1
            if predicate(run_w, run_l):
                first_trigger_idx = idx
                break

        if first_trigger_idx is None:
            return None

        first_trigger_game = unique_games[first_trigger_idx]
        first_trigger_day = int(first_trigger_game["utc_day"])
        is_new_trigger = bool(
            first_trigger_idx == total - 1 and int(first_trigger_game["match_id"]) == up_mid
        )

        cur_utc_day = up_ct // 86400
        same_day_games = sum(1 for g in unique_games if int(g["utc_day"]) == cur_utc_day)

        win_streak = 0
        loss_streak = 0
        for g in reversed(unique_games):
            if int(g["win"] or 0) != 0:
                if loss_streak > 0:
                    break
                win_streak += 1
            else:
                if win_streak > 0:
                    break
                loss_streak += 1

        first_ct = int(unique_games[0].get("completion_time") or 0)
        since_year = datetime.fromtimestamp(first_ct, tz=timezone.utc).year if first_ct > 0 else 0
        latest_alias = (current_opponent_alias or "").strip() or str(unique_games[-1].get("opponent_alias") or "").strip()
        modes_seen = sorted({str(g.get("mode") or "") for g in unique_games if g.get("mode")})

        return {
            "triggered": True,
            "kind": kind,
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
            "first_match_time": first_ct,
            "since_year": since_year,
            "win_streak": win_streak,
            "loss_streak": loss_streak,
            "modes": modes_seen,
        }

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
        Avalia a condição de Nêmesis em TODOS os modos Automatch (1v1, 2v2, 3v3, 4v4) ao longo de
        todo o histórico CoH3 (2023+): adversário de quem o Veterano apanha regularmente.
        """
        return self._get_head_to_head_rivalry_status(
            kind="nemesis",
            tracked_profile_ids=tracked_profile_ids,
            opponent_profile_id=opponent_profile_id,
            up_to_completion_time=up_to_completion_time,
            up_to_match_id=up_to_match_id,
            current_opponent_alias=current_opponent_alias,
            current_opponent_steam_id=current_opponent_steam_id,
        )

    def get_fregues_status(
        self,
        tracked_profile_ids: list[int],
        opponent_profile_id: int,
        up_to_completion_time: int,
        up_to_match_id: int,
        current_opponent_alias: str = "",
        current_opponent_steam_id: str = "",
    ) -> dict[str, Any] | None:
        """
        Avalia a condição de Freguês (oposto exato do Nêmesis) em TODOS os modos Automatch (1v1, 2v2, 3v3, 4v4)
        ao longo de todo o histórico CoH3 (2023+): adversário que apanha regularmente do Veterano.
        """
        return self._get_head_to_head_rivalry_status(
            kind="fregues",
            tracked_profile_ids=tracked_profile_ids,
            opponent_profile_id=opponent_profile_id,
            up_to_completion_time=up_to_completion_time,
            up_to_match_id=up_to_match_id,
            current_opponent_alias=current_opponent_alias,
            current_opponent_steam_id=current_opponent_steam_id,
        )

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

    def insert_kryptonite_matches_batch(
        self,
        rows: list[tuple[Any, ...]],
    ) -> int:
        """
        Insere em lote (idempotente via INSERT OR IGNORE / upsert de BGs) metadados compactos de partidas
        Automatch PvP na tabela `kryptonite_matches` (mapa, aliados compactos e BGs inimigos) desde o
        lançamento do CoH3 (2023+). Aceita tuplas de 7 ou 8 elementos:
        `(tracked_profile_id, match_id, completion_time, win, mode, map_clean, allies_json[, enemy_bgs_json])`.
        """
        if not rows:
            return 0
        valid_rows: list[tuple[int, int, int, int, str, str, str, str]] = []
        for raw_row in rows:
            if len(raw_row) < 7:
                continue
            tpid, mid, ct, win, mode, mclean, allies_j = raw_row[:7]
            enemy_bgs_j = raw_row[7] if len(raw_row) >= 8 else ""
            tpid_i = int(tpid)
            mid_i = int(mid)
            ct_i = int(ct)
            mode_s = str(mode)
            if tpid_i <= 0 or mid_i <= 0 or ct_i <= 0 or mode_s not in AUTOMATCH_MODES:
                continue
            # Normaliza aliados em lista compacta de inteiros quando vier em JSON de dicts ou ints
            compact_allies_j = "[]"
            if isinstance(allies_j, list):
                compact_allies_j = json.dumps(self._extract_compact_ally_pids(tpid_i, allies_j), separators=(",", ":"))
            else:
                raw_aj = str(allies_j or "[]").strip()
                if raw_aj and raw_aj != "[]":
                    try:
                        parsed_a = json.loads(raw_aj)
                        compact_allies_j = json.dumps(
                            self._extract_compact_ally_pids(tpid_i, parsed_a), separators=(",", ":")
                        )
                    except Exception:
                        compact_allies_j = "[]"
            valid_rows.append(
                (
                    tpid_i,
                    mid_i,
                    ct_i,
                    1 if int(win) else 0,
                    mode_s[:24],
                    str(mclean or "").strip()[:96],
                    compact_allies_j[:1024],
                    str(enemy_bgs_j or "").strip()[:512],
                )
            )
        if not valid_rows:
            return 0
        conn = self._connect()
        before = int(conn.execute("SELECT COUNT(*) FROM kryptonite_matches").fetchone()[0] or 0)
        with conn:
            conn.executemany(
                """
                INSERT INTO kryptonite_matches (
                    tracked_profile_id, match_id, completion_time, win, mode, map_clean, allies_json, enemy_bgs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tracked_profile_id, match_id) DO UPDATE SET
                    enemy_bgs_json = CASE
                        WHEN COALESCE(kryptonite_matches.enemy_bgs_json, '') = '' AND excluded.enemy_bgs_json != ''
                        THEN excluded.enemy_bgs_json
                        ELSE kryptonite_matches.enemy_bgs_json
                    END,
                    allies_json = CASE
                        WHEN COALESCE(kryptonite_matches.allies_json, '[]') IN ('', '[]') AND excluded.allies_json != '[]'
                        THEN excluded.allies_json
                        ELSE kryptonite_matches.allies_json
                    END
                """,
                valid_rows,
            )
        after = int(conn.execute("SELECT COUNT(*) FROM kryptonite_matches").fetchone()[0] or 0)
        return max(0, after - before)

    # Limiares estatísticos estritos para caracterizar fraqueza FLAGRANTE ('Criptonita') no histórico completo (2023+)
    _KRYPTONITE_FLAGRANT_RULES: dict[str, dict[str, float]] = {
        "map":         {"zero_win_l": 6, "min_n": 10, "min_diff": 6, "max_wr": 36.0, "max_p": 0.045, "min_drop": 14.0},
        "battlegroup": {"zero_win_l": 5, "min_n": 8,  "min_diff": 5, "max_wr": 30.0, "max_p": 0.030, "min_drop": 12.0},
        "nemesis":     {"zero_win_l": 5, "min_n": 6,  "min_diff": 5, "max_wr": 30.0, "max_p": 0.040, "min_drop": 0.0},
        "opponent":    {"zero_win_l": 6, "min_n": 8,  "min_diff": 6, "max_wr": 25.0, "max_p": 0.020, "min_drop": 0.0},
        "partner":     {"zero_win_l": 6, "min_n": 10, "min_diff": 6, "max_wr": 36.0, "max_p": 0.025, "min_drop": 13.0},
    }

    @staticmethod
    def _binomial_le_prob(wins: int, total: int, p: float = 0.5) -> float:
        """Calcula P(X <= wins) exata sob Binomial(total, p) para filtrar ruído de amostra pequena."""
        n = int(total)
        k = int(wins)
        if n <= 0 or k < 0 or k >= n:
            return 1.0
        prob = min(0.99, max(0.01, float(p)))
        if prob == 0.5:
            acc = 0.0
            for i in range(k + 1):
                acc += math.ldexp(math.comb(n, i), -n)
            return min(1.0, acc)
        log_p = math.log(prob)
        log_q = math.log(1.0 - prob)
        log_nf = math.lgamma(n + 1)
        acc = 0.0
        for i in range(k + 1):
            lp = log_nf - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * log_p + (n - i) * log_q
            acc += math.exp(lp)
        return min(1.0, acc)

    @classmethod
    def is_flagrant_kryptonite(
        cls,
        wins: int,
        losses: int,
        *,
        kind: str = "map",
        career_wr_pct: float = 50.0,
    ) -> bool:
        """
        Critério estatístico estrito para disparar Criptonita APENAS quando a fraqueza é FLAGRANTE:
        - Rejeita ruído de amostra pequena (ex.: 1V-4D, 2V-4D, 0V-4D);
        - Combina volume mínimo, saldo negativo mínimo (`losses - wins`), WR% máximo, significância
          binomial unilateral contra a linha de base do próprio Veterano e queda mínima em pontos percentuais
          (para Mapa, BG e Parceiro) para evitar falsos positivos em contas com WR geral baixo.
        """
        w = max(0, int(wins))
        l = max(0, int(losses))
        tot = w + l
        if tot <= 0 or l <= w:
            return False
        rule = cls._KRYPTONITE_FLAGRANT_RULES.get(kind, cls._KRYPTONITE_FLAGRANT_RULES["map"])
        if w == 0 and l >= int(rule["zero_win_l"]):
            return True
        wr_pct = (w * 100.0) / tot
        diff = l - w
        if tot < int(rule["min_n"]) or diff < int(rule["min_diff"]) or wr_pct > float(rule["max_wr"]):
            return False
        base_wr = min(85.0, max(35.0, float(career_wr_pct)))
        base_p = min(0.50, max(0.35, base_wr / 100.0))
        if cls._binomial_le_prob(w, tot, base_p) > float(rule["max_p"]):
            return False
        min_drop = float(rule.get("min_drop", 0.0))
        if min_drop > 0.0 and wr_pct > 15.0 and (base_wr - wr_pct) < min_drop:
            return False
        return True

    @classmethod
    def _is_kryptonite_weakness(
        cls,
        wins: int,
        losses: int,
        *,
        max_wr_pct: float = 35.0,
        kind: str = "",
        career_wr_pct: float = 50.0,
    ) -> bool:
        """Wrapper compatível que delega para o critério estrito `is_flagrant_kryptonite`."""
        eff_kind = kind or ("map" if float(max_wr_pct) >= 32.0 else "opponent")
        return cls.is_flagrant_kryptonite(wins, losses, kind=eff_kind, career_wr_pct=career_wr_pct)

    @staticmethod
    def _compute_loss_streak(outcomes: dict[int, tuple[int, int]]) -> int:
        """Conta a sequência atual de derrotas seguidas (do jogo mais recente para trás). `outcomes`: `{mid: (ct, win)}`."""
        ordered = sorted(outcomes.items(), key=lambda kv: (kv[1][0], kv[0]), reverse=True)
        streak = 0
        for _mid, (_ct, win_flag) in ordered:
            if int(win_flag) == 0:
                streak += 1
            else:
                break
        return streak

    def get_kryptonite_status(
        self,
        tracked_profile_ids: list[int] | set[int],
        up_to_completion_time: int,
        up_to_match_id: int,
        *,
        current_win: bool = False,
        current_map_clean: str = "",
        current_map_raw: str = "",
        current_enemy_battlegroups: list[tuple[str, str]] | None = None,
        current_opponents: list[dict[str, Any]] | None = None,
        current_allies: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """
        Avalia em cascata estrita se uma DERROTA Automatch PvP de um Veterano expõe uma 'Criptonita' FLAGRANTE
        considerando TODO o histórico do jogo desde o lançamento (2023+) e cruzado com o sistema Nêmesis:
          1. Mapa específico (2023+ em `kryptonite_matches` ∪ `recorded_matches`);
          2. Battlegroup inimigo específico (permanente em `kryptonite_matches.enemy_bgs_json` ∪ `recorded_matches`);
          3. Adversário / Nêmesis específico (2023+ em `nemesis_matches`, cruzado com trigger Nêmesis);
          4. Parceiro / aliado específico em último caso (2023+ em `kryptonite_matches` ∪ `recorded_matches`).
        Retorna apenas o nível mais prioritário acionado (ou None se a derrota não for flagrante).
        """
        if current_win:
            return None
        clean_pids = sorted({int(p) for p in tracked_profile_ids if int(p) > 0})
        ct = int(up_to_completion_time or 0)
        mid = int(up_to_match_id or 0)
        if not clean_pids or ct <= 0 or mid <= 0:
            return None

        pid_set = set(clean_pids)
        pid_ph = ",".join("?" for _ in clean_pids)
        mode_ph = ",".join("?" for _ in AUTOMATCH_MODES)
        mode_params = tuple(AUTOMATCH_MODES)
        conn = self._connect()

        # Linha de base de carreira Automatch do Veterano desde o lançamento (2023+)
        career_row = conn.execute(
            f"""
            SELECT COUNT(*) AS n, COALESCE(SUM(win), 0) AS w
            FROM (
                SELECT match_id, MAX(win) AS win
                FROM (
                    SELECT match_id, win
                    FROM kryptonite_matches
                    WHERE tracked_profile_id IN ({pid_ph})
                      AND mode IN ({mode_ph})
                      AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                    UNION ALL
                    SELECT match_id, win
                    FROM recorded_matches
                    WHERE tracked_profile_id IN ({pid_ph})
                      AND mode IN ({mode_ph})
                      AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                )
                GROUP BY match_id
            )
            """,
            (*clean_pids, *mode_params, ct, ct, mid, *clean_pids, *mode_params, ct, ct, mid),
        ).fetchone()
        career_n = int(career_row["n"] or 0) if career_row else 0
        career_w = int(career_row["w"] or 0) if career_row else 0
        career_wr_pct = round((career_w * 100.0) / career_n, 1) if career_n >= 20 else 50.0

        # Pré-carrega o histórico completo 2023+ contra os oponentes atuais e cruza com o sistema Nêmesis
        opp_alias_by_pid: dict[int, str] = {}
        for o in (current_opponents or ()):
            if not isinstance(o, dict):
                continue
            opid = int(o.get("profile_id", 0) or 0)
            if opid > 0 and opid not in pid_set:
                opp_alias_by_pid[opid] = str(o.get("alias") or "").strip() or f"ID #{opid}"

        opp_outcomes: dict[int, dict[int, tuple[int, int]]] = {op: {} for op in opp_alias_by_pid}
        opp_day_counts: dict[int, dict[int, int]] = {op: {} for op in opp_alias_by_pid}
        if opp_alias_by_pid:
            opp_pids = sorted(opp_alias_by_pid.keys())
            opp_ph = ",".join("?" for _ in opp_pids)
            nem_rows = conn.execute(
                f"""
                SELECT opponent_profile_id, match_id, completion_time, utc_day, win
                FROM nemesis_matches
                WHERE tracked_profile_id IN ({pid_ph})
                  AND opponent_profile_id IN ({opp_ph})
                  AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                """,
                (*clean_pids, *opp_pids, ct, ct, mid),
            ).fetchall()
            for r in nem_rows:
                op = int(r["opponent_profile_id"])
                rm_mid = int(r["match_id"])
                if op in opp_outcomes and rm_mid not in opp_outcomes[op]:
                    rm_ct = int(r["completion_time"] or 0)
                    rm_win = 1 if int(r["win"] or 0) else 0
                    opp_outcomes[op][rm_mid] = (rm_ct, rm_win)
                    ud = int(r["utc_day"] or (rm_ct // 86400))
                    opp_day_counts[op][ud] = opp_day_counts[op].get(ud, 0) + 1

        cur_utc_day = ct // 86400
        active_nemesis_info: dict[int, dict[str, Any]] = {}
        dominant_nemesis_cross: dict[str, Any] | None = None
        dom_nem_rank: tuple[int, int, int] = (-1, -1, -1)
        for op, oalias in opp_alias_by_pid.items():
            out_map = opp_outcomes[op]
            if mid not in out_map:
                out_map[mid] = (ct, 0)
                opp_day_counts[op][cur_utc_day] = opp_day_counts[op].get(cur_utc_day, 0) + 1
            else:
                out_map[mid] = (ct, 0)
            ow = sum(1 for _c, wv in out_map.values() if wv == 1)
            ol = len(out_map) - ow
            is_nem = self.is_nemesis_record(ow, ol)
            if is_nem:
                is_flag_nem = self.is_flagrant_kryptonite(ow, ol, kind="nemesis", career_wr_pct=career_wr_pct)
                info = {
                    "opponent_profile_id": op,
                    "opponent_alias": oalias,
                    "wins": ow,
                    "losses": ol,
                    "total": ow + ol,
                    "same_day_games": int(opp_day_counts[op].get(cur_utc_day, 0)),
                    "is_flagrant": is_flag_nem,
                    "loss_streak": self._compute_loss_streak(out_map),
                }
                active_nemesis_info[op] = info
                if ol > ow:
                    rk = (1 if is_flag_nem else 0, ol - ow, ol)
                    if rk > dom_nem_rank:
                        dom_nem_rank = rk
                        dominant_nemesis_cross = info

        def _build_result(
            *,
            priority: int,
            kind: str,
            label: str,
            wins: int,
            losses: int,
            loss_streak: int = 0,
            bg_key: str = "",
            target_profile_id: int = 0,
            is_nemesis: bool = False,
            nemesis_same_day_games: int = 0,
            attach_nemesis_cross: bool = False,
        ) -> dict[str, Any]:
            tot = wins + losses
            res: dict[str, Any] = {
                "triggered": True,
                "priority": priority,
                "kind": kind,
                "label": str(label).strip(),
                "bg_key": str(bg_key or "").strip(),
                "target_profile_id": int(target_profile_id or 0),
                "wins": wins,
                "losses": losses,
                "total": tot,
                "diff": wins - losses,
                "win_rate": round((wins * 100.0) / tot, 1) if tot > 0 else 0.0,
                "career_win_rate": career_wr_pct,
                "loss_streak": int(loss_streak or 0),
                "is_nemesis": bool(is_nemesis),
                "nemesis_same_day_games": int(nemesis_same_day_games or 0),
                "flagrant_nemesis_opp_pids": sorted(
                    op_id for op_id, ninfo in active_nemesis_info.items() if ninfo.get("is_flagrant")
                ),
            }
            if attach_nemesis_cross and dominant_nemesis_cross is not None:
                res["nemesis_cross"] = dict(dominant_nemesis_cross)
            return res

        # ------------------------------------------------------------------
        # Prioridade 1: MAPA (histórico completo desde 2023)
        # ------------------------------------------------------------------
        disp_map = str(current_map_clean or "").strip() or clean_map_name(str(current_map_raw or "")).strip()
        norm_map = disp_map.casefold()
        if norm_map:
            map_outcomes: dict[int, tuple[int, int]] = {}
            km_rows = conn.execute(
                f"""
                SELECT match_id, completion_time, win, map_clean
                FROM kryptonite_matches
                WHERE tracked_profile_id IN ({pid_ph})
                  AND mode IN ({mode_ph})
                  AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                """,
                (*clean_pids, *mode_params, ct, ct, mid),
            ).fetchall()
            for r in km_rows:
                rm_disp = str(r["map_clean"] or "").strip()
                if rm_disp.casefold() == norm_map:
                    map_outcomes[int(r["match_id"])] = (int(r["completion_time"] or 0), 1 if int(r["win"] or 0) else 0)

            rec_rows = conn.execute(
                f"""
                SELECT match_id, completion_time, win, map_clean, map_raw
                FROM recorded_matches
                WHERE tracked_profile_id IN ({pid_ph})
                  AND mode IN ({mode_ph})
                  AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                """,
                (*clean_pids, *mode_params, ct, ct, mid),
            ).fetchall()
            for r in rec_rows:
                rm_mid = int(r["match_id"])
                if rm_mid in map_outcomes:
                    continue
                rm_disp = str(r["map_clean"] or "").strip() or clean_map_name(str(r["map_raw"] or "")).strip()
                if rm_disp.casefold() == norm_map:
                    map_outcomes[rm_mid] = (int(r["completion_time"] or 0), 1 if int(r["win"] or 0) else 0)

            map_outcomes[mid] = (ct, 0)
            m_wins = sum(1 for _c, wv in map_outcomes.values() if wv == 1)
            m_losses = len(map_outcomes) - m_wins
            if self.is_flagrant_kryptonite(m_wins, m_losses, kind="map", career_wr_pct=career_wr_pct):
                return _build_result(
                    priority=1,
                    kind="map",
                    label=disp_map,
                    wins=m_wins,
                    losses=m_losses,
                    loss_streak=self._compute_loss_streak(map_outcomes),
                    attach_nemesis_cross=True,
                )

        # ------------------------------------------------------------------
        # Prioridade 2: BATTLEGROUP INIMIGO (permanente em kryptonite_matches + recorded_matches)
        # ------------------------------------------------------------------
        target_bgs: dict[str, tuple[str, str]] = {}
        name_to_canon: dict[str, str] = {}
        for raw_k, raw_n in (current_enemy_battlegroups or ()):
            bk = str(raw_k or "").strip().lower()
            bn = str(raw_n or "").strip()
            canon = bk or bn.casefold()
            if canon and canon not in target_bgs:
                target_bgs[canon] = (bk, bn or bk)
                if bn:
                    name_to_canon[bn.casefold()] = canon

        if target_bgs:
            bg_outcomes: dict[str, dict[int, tuple[int, int]]] = {c: {} for c in target_bgs}

            km_bg_rows = conn.execute(
                f"""
                SELECT match_id, completion_time, win, enemy_bgs_json
                FROM kryptonite_matches
                WHERE tracked_profile_id IN ({pid_ph})
                  AND mode IN ({mode_ph})
                  AND COALESCE(enemy_bgs_json, '') NOT IN ('', '[]', 'null')
                  AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                """,
                (*clean_pids, *mode_params, ct, ct, mid),
            ).fetchall()
            for r in km_bg_rows:
                try:
                    toks = json.loads(r["enemy_bgs_json"] or "[]")
                except Exception:
                    continue
                if not isinstance(toks, list):
                    continue
                rm_mid = int(r["match_id"])
                rm_ct = int(r["completion_time"] or 0)
                rm_win = 1 if int(r["win"] or 0) else 0
                for raw_tok in toks:
                    tl = str(raw_tok or "").strip().lower()
                    matched_c = tl if tl in target_bgs else name_to_canon.get(tl, "")
                    if matched_c:
                        bg_outcomes[matched_c][rm_mid] = (rm_ct, rm_win)

            bg_rows = conn.execute(
                f"""
                SELECT match_id, completion_time, win, opponents_json, battlegroups_json
                FROM recorded_matches
                WHERE tracked_profile_id IN ({pid_ph})
                  AND mode IN ({mode_ph})
                  AND COALESCE(battlegroups_json, '') NOT IN ('', '{{}}', 'null')
                  AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                """,
                (*clean_pids, *mode_params, ct, ct, mid),
            ).fetchall()
            for r in bg_rows:
                try:
                    opps_parsed = json.loads(r["opponents_json"] or "[]")
                    bgs_parsed = json.loads(r["battlegroups_json"] or "{}")
                except Exception:
                    continue
                if not isinstance(opps_parsed, list) or not isinstance(bgs_parsed, dict):
                    continue
                rm_mid = int(r["match_id"])
                rm_ct = int(r["completion_time"] or 0)
                rm_win = 1 if int(r["win"] or 0) else 0
                seen_in_match: set[str] = set()
                for o in opps_parsed:
                    if not isinstance(o, dict):
                        continue
                    opid_str = str(int(o.get("profile_id", 0) or 0))
                    bg_entry = bgs_parsed.get(opid_str)
                    if not isinstance(bg_entry, dict):
                        continue
                    ebk = str(bg_entry.get("key") or "").strip().lower()
                    ebn = str(bg_entry.get("name") or "").strip()
                    ecanon = ebk or ebn.casefold()
                    if ecanon in target_bgs:
                        seen_in_match.add(ecanon)
                    elif ebn and ebn.casefold() in name_to_canon:
                        seen_in_match.add(name_to_canon[ebn.casefold()])
                for c in seen_in_match:
                    if rm_mid not in bg_outcomes[c]:
                        bg_outcomes[c][rm_mid] = (rm_ct, rm_win)

            best_bg: dict[str, Any] | None = None
            best_bg_rank: tuple[int, int, float] = (-1, -1, -1.0)
            for canon, (bk, bn) in target_bgs.items():
                out_map = bg_outcomes[canon]
                out_map[mid] = (ct, 0)
                bw = sum(1 for _c, wv in out_map.values() if wv == 1)
                bl = len(out_map) - bw
                if self.is_flagrant_kryptonite(bw, bl, kind="battlegroup", career_wr_pct=career_wr_pct):
                    wr = (bw * 100.0) / (bw + bl)
                    rank_key = (bl - bw, bl, -wr)
                    if rank_key > best_bg_rank:
                        best_bg_rank = rank_key
                        best_bg = _build_result(
                            priority=2,
                            kind="battlegroup",
                            label=bn,
                            bg_key=bk,
                            wins=bw,
                            losses=bl,
                            loss_streak=self._compute_loss_streak(out_map),
                            attach_nemesis_cross=True,
                        )
            if best_bg is not None:
                return best_bg

        # ------------------------------------------------------------------
        # Prioridade 3: ADVERSÁRIO / NÊMESIS ESPECÍFICO (histórico completo desde 2023)
        # ------------------------------------------------------------------
        if opp_alias_by_pid:
            best_opp: dict[str, Any] | None = None
            best_opp_rank: tuple[int, int, int, float] = (-1, -1, -1, -1.0)
            for op, oalias in opp_alias_by_pid.items():
                out_map = opp_outcomes[op]
                out_map[mid] = (ct, 0)
                ow = sum(1 for _c, wv in out_map.values() if wv == 1)
                ol = len(out_map) - ow
                nem_info = active_nemesis_info.get(op)
                is_nem = nem_info is not None
                eff_kind = "nemesis" if is_nem else "opponent"
                if self.is_flagrant_kryptonite(ow, ol, kind=eff_kind, career_wr_pct=career_wr_pct):
                    wr = (ow * 100.0) / (ow + ol)
                    rank_key = (1 if is_nem else 0, ol - ow, ol, -wr)
                    if rank_key > best_opp_rank:
                        best_opp_rank = rank_key
                        best_opp = _build_result(
                            priority=3,
                            kind=eff_kind,
                            label=oalias,
                            target_profile_id=op,
                            wins=ow,
                            losses=ol,
                            loss_streak=self._compute_loss_streak(out_map),
                            is_nemesis=is_nem,
                            nemesis_same_day_games=int(nem_info.get("same_day_games", 0)) if nem_info else 0,
                        )
            if best_opp is not None:
                return best_opp

        # ------------------------------------------------------------------
        # Prioridade 4 (último caso): PARCEIRO / ALIADO ESPECÍFICO (desde 2023)
        # ------------------------------------------------------------------
        ally_alias_by_pid: dict[int, str] = {}
        for a in (current_allies or ()):
            if not isinstance(a, dict):
                continue
            apid = int(a.get("profile_id", 0) or 0)
            if apid > 0 and apid not in pid_set:
                ally_alias_by_pid[apid] = str(a.get("alias") or "").strip() or f"ID #{apid}"

        if ally_alias_by_pid:
            ally_target_set = set(ally_alias_by_pid.keys())
            ally_outcomes: dict[int, dict[int, tuple[int, int]]] = {ap: {} for ap in ally_target_set}

            for table_name in ("kryptonite_matches", "recorded_matches"):
                a_rows = conn.execute(
                    f"""
                    SELECT match_id, completion_time, win, allies_json
                    FROM {table_name}
                    WHERE tracked_profile_id IN ({pid_ph})
                      AND mode IN ({mode_ph})
                      AND COALESCE(allies_json, '[]') NOT IN ('', '[]')
                      AND (completion_time < ? OR (completion_time = ? AND match_id <= ?))
                    """,
                    (*clean_pids, *mode_params, ct, ct, mid),
                ).fetchall()
                for r in a_rows:
                    try:
                        allies_parsed = json.loads(r["allies_json"] or "[]")
                    except Exception:
                        continue
                    if not isinstance(allies_parsed, list):
                        continue
                    rm_mid = int(r["match_id"])
                    rm_ct = int(r["completion_time"] or 0)
                    rm_win = 1 if int(r["win"] or 0) else 0
                    for al in allies_parsed:
                        if isinstance(al, dict):
                            apid = int(al.get("profile_id", 0) or 0)
                        elif isinstance(al, (int, float)) or (isinstance(al, str) and al.strip().isdigit()):
                            apid = int(al)
                        else:
                            apid = 0
                        if apid in ally_target_set and rm_mid not in ally_outcomes[apid]:
                            ally_outcomes[apid][rm_mid] = (rm_ct, rm_win)

            best_ally: dict[str, Any] | None = None
            best_ally_rank: tuple[int, int, float] = (-1, -1, -1.0)
            for ap, aalias in ally_alias_by_pid.items():
                out_map = ally_outcomes[ap]
                out_map[mid] = (ct, 0)
                aw = sum(1 for _c, wv in out_map.values() if wv == 1)
                al_l = len(out_map) - aw
                if self.is_flagrant_kryptonite(aw, al_l, kind="partner", career_wr_pct=career_wr_pct):
                    wr = (aw * 100.0) / (aw + al_l)
                    rank_key = (al_l - aw, al_l, -wr)
                    if rank_key > best_ally_rank:
                        best_ally_rank = rank_key
                        best_ally = _build_result(
                            priority=4,
                            kind="partner",
                            label=aalias,
                            target_profile_id=ap,
                            wins=aw,
                            losses=al_l,
                            loss_streak=self._compute_loss_streak(out_map),
                            attach_nemesis_cross=True,
                        )
            if best_ally is not None:
                return best_ally

        return None

    def get_kryptonite_coverage_summary(self) -> dict[str, Any]:
        """Retorna estatísticas resumidas de cobertura histórica da tabela `kryptonite_matches` (2023+)."""
        conn = self._connect()
        row = conn.execute(
            """
            SELECT COUNT(*) AS total_rows,
                   COUNT(DISTINCT match_id) AS unique_matches,
                   COUNT(DISTINCT tracked_profile_id) AS tracked_players,
                   SUM(CASE WHEN COALESCE(enemy_bgs_json, '') NOT IN ('', '[]', 'null') THEN 1 ELSE 0 END) AS rows_with_bg,
                   MIN(completion_time) AS min_ct,
                   MAX(completion_time) AS max_ct
            FROM kryptonite_matches
            """
        ).fetchone()
        return {
            "total_rows": int(row["total_rows"] or 0) if row else 0,
            "unique_matches": int(row["unique_matches"] or 0) if row else 0,
            "tracked_players": int(row["tracked_players"] or 0) if row else 0,
            "rows_with_bg": int(row["rows_with_bg"] or 0) if row else 0,
            "min_completion_time": int(row["min_ct"] or 0) if row else 0,
            "max_completion_time": int(row["max_ct"] or 0) if row else 0,
        }

    def get_nemesis_coverage_summary(self) -> dict[str, Any]:
        """Retorna estatísticas resumidas de cobertura histórica (2023+) da tabela `nemesis_matches` (Nêmesis e Freguês)."""
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
        z_min = self.RIVALRY_ZERO_OPP_MIN_GAMES
        t_min = self.RIVALRY_MIN_TOTAL_GAMES
        d_min = self.RIVALRY_MIN_DIFF
        wr_min = self.RIVALRY_MIN_DOMINANT_WR
        rivalry_pairs = conn.execute(
            """
            SELECT
                COALESCE(SUM(CASE
                    WHEN (w = 0 AND l >= ?) OR (tot >= ? AND (l - w) >= ? AND (l * 100.0 / tot) >= ?)
                    THEN 1 ELSE 0 END), 0) AS nem_pairs,
                COALESCE(SUM(CASE
                    WHEN (l = 0 AND w >= ?) OR (tot >= ? AND (w - l) >= ? AND (w * 100.0 / tot) >= ?)
                    THEN 1 ELSE 0 END), 0) AS freg_pairs
            FROM (
                SELECT tracked_profile_id,
                       opponent_profile_id,
                       SUM(CASE WHEN win != 0 THEN 1 ELSE 0 END) AS w,
                       SUM(CASE WHEN win = 0 THEN 1 ELSE 0 END) AS l,
                       COUNT(*) AS tot
                FROM nemesis_matches
                GROUP BY tracked_profile_id, opponent_profile_id
            )
            """,
            (z_min, t_min, d_min, wr_min, z_min, t_min, d_min, wr_min),
        ).fetchone()
        return {
            "total_rows": int(row["total_rows"] or 0) if row else 0,
            "unique_matches": int(row["unique_matches"] or 0) if row else 0,
            "tracked_players": int(row["tracked_players"] or 0) if row else 0,
            "min_completion_time": int(row["min_ct"] or 0) if row else 0,
            "max_completion_time": int(row["max_ct"] or 0) if row else 0,
            "trigger_day_events": int(active_rivals[0] or 0) if active_rivals else 0,
            "distinct_nemesis_pairs": int(rivalry_pairs["nem_pairs"] or 0) if rivalry_pairs else 0,
            "distinct_fregues_pairs": int(rivalry_pairs["freg_pairs"] or 0) if rivalry_pairs else 0,
        }

    def get_tracked_pids_who_faced_opponent(self, opponent_profile_id: int) -> set[int]:
        """
        Retorna todos os `tracked_profile_id` que já enfrentaram `opponent_profile_id` em qualquer
        partida Automatch histórica registrada em `nemesis_matches` (desde 2023-06-30).
        Usado como desqualificador absoluto na detecção de smurfs ("Um Smurf nunca enfrenta a conta original").
        """
        opp_pid = int(opponent_profile_id or 0)
        if opp_pid <= 0:
            return set()
        rows = self._connect().execute(
            "SELECT DISTINCT tracked_profile_id FROM nemesis_matches WHERE opponent_profile_id = ?",
            (opp_pid,),
        ).fetchall()
        return {int(r[0]) for r in rows if int(r[0] or 0) > 0}

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
        """Persiste o mapa `{profile_id: {'key': ..., 'name': ...}}` em todas as linhas da partida e sincroniza `enemy_bgs_json` em `kryptonite_matches`."""
        mid = int(match_id or 0)
        if mid <= 0:
            return 0
        norm_bgs = {str(k): v for k, v in (battlegroups or {}).items() if isinstance(v, dict)}
        payload = json.dumps(norm_bgs, ensure_ascii=False, separators=(",", ":"))
        conn = self._connect()
        with conn:
            cur = conn.execute(
                "UPDATE recorded_matches SET battlegroups_json = ? WHERE match_id = ?",
                (payload, mid),
            )
            if norm_bgs:
                rec_rows = conn.execute(
                    "SELECT tracked_profile_id, mode, opponents_json FROM recorded_matches WHERE match_id = ?",
                    (mid,),
                ).fetchall()
                for r in rec_rows:
                    if str(r["mode"] or "") not in AUTOMATCH_MODES:
                        continue
                    try:
                        opps_parsed = json.loads(r["opponents_json"] or "[]")
                    except Exception:
                        continue
                    enemy_bgs = self._extract_enemy_bg_tokens(opps_parsed, norm_bgs)
                    if enemy_bgs:
                        conn.execute(
                            "UPDATE kryptonite_matches SET enemy_bgs_json = ? WHERE tracked_profile_id = ? AND match_id = ?",
                            (
                                json.dumps(enemy_bgs, ensure_ascii=False, separators=(",", ":")),
                                int(r["tracked_profile_id"]),
                                mid,
                            ),
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



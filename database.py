"""Persistência SQLite otimizada e segura para jogadores monitorados, partidas e cache de avatares."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

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
                """
            )
            existing_match_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(recorded_matches)").fetchall()
            }
            if "tracked_steam_id" not in existing_match_cols:
                conn.execute("ALTER TABLE recorded_matches ADD COLUMN tracked_steam_id TEXT DEFAULT ''")

            existing_player_cols = {
                str(r["name"]) for r in conn.execute("PRAGMA table_info(tracked_players)").fetchall()
            }
            if "original_alias" not in existing_player_cols:
                conn.execute("ALTER TABLE tracked_players ADD COLUMN original_alias TEXT DEFAULT ''")

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
                        alias = excluded.alias,
                        original_alias = CASE
                            WHEN excluded.original_alias != '' THEN excluded.original_alias
                            ELSE tracked_players.original_alias
                        END,
                        steam_id = CASE
                            WHEN excluded.steam_id != '' THEN excluded.steam_id
                            ELSE tracked_players.steam_id
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
        with conn:
            conn.execute(
                """
                UPDATE tracked_players
                SET baseline_synced = 1,
                    alias = COALESCE(NULLIF(?, ''), alias),
                    steam_id = COALESCE(NULLIF(?, ''), steam_id)
                WHERE profile_id = ?
                """,
                (alias or "", steam_id or "", int(profile_id)),
            )

    def match_exists(self, match_id: int, tracked_profile_id: int) -> bool:
        row = self._connect().execute(
            "SELECT 1 FROM recorded_matches WHERE match_id = ? AND tracked_profile_id = ?",
            (int(match_id), int(tracked_profile_id)),
        ).fetchone()
        return row is not None

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

    def insert_match(self, match: dict[str, Any], discord_message_id: str | None = None) -> bool:
        """Grava partida atomicamente com INSERT OR IGNORE (sem race condition). Retorna True se foi inédita."""
        now = int(time.time())
        conn = self._connect()
        with conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO recorded_matches (
                    match_id, tracked_profile_id, tracked_alias, tracked_steam_id, tracked_faction,
                    tracked_faction_short, win, resulttype, mode, matchtype_id,
                    map_raw, map_clean, start_time, completion_time, duration_sec,
                    old_elo, new_elo, allies_json, opponents_json, counters_json,
                    has_replay, coh3stats_url, discord_message_id, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(match["match_id"]),
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
                    discord_message_id,
                    now,
                ),
            )
        return cur.rowcount > 0

    def update_match_discord_id(self, match_id: int, tracked_profile_id: int, message_id: str) -> None:
        conn = self._connect()
        with conn:
            conn.execute(
                "UPDATE recorded_matches SET discord_message_id = ? WHERE match_id = ? AND tracked_profile_id = ?",
                (str(message_id), int(match_id), int(tracked_profile_id)),
            )

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
        d.pop("counters_json", None)
        d["counters"] = {}
        return d

    def get_recent_recorded_matches(
        self,
        limit: int = 15,
        only_active_players: bool = True,
        min_recorded_at: int = 0,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        min_ts = max(0, int(min_recorded_at or 0))
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
        limit: int = 40,
    ) -> list[tuple[str, str]]:
        """Retorna lista (message_id, origem) de mensagens do Discord com mais de max_age_sec para limpeza."""
        safe_limit = max(1, min(int(limit), 200))
        cutoff = int(time.time()) - max(3600, int(max_age_sec))
        excluded = {str(x).strip() for x in (exclude_message_ids or set()) if x}
        conn = self._connect()

        candidates: list[tuple[int, str, str]] = []
        seen_ids: set[str] = set()

        match_rows = conn.execute(
            """
            SELECT discord_message_id, MAX(recorded_at) AS latest_ts
            FROM recorded_matches
            WHERE discord_message_id IS NOT NULL
              AND length(discord_message_id) >= 15
              AND discord_message_id NOT GLOB '*[^0-9]*'
            GROUP BY discord_message_id
            HAVING MAX(recorded_at) <= ?
            ORDER BY latest_ts ASC
            LIMIT ?
            """,
            (cutoff, safe_limit),
        ).fetchall()
        for r in match_rows:
            mid = str(r["discord_message_id"])
            if mid not in excluded and mid not in seen_ids:
                seen_ids.add(mid)
                candidates.append((int(r["latest_ts"]), mid, "match"))

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

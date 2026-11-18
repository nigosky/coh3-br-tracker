"""Persistência SQLite para jogadores escolhidos e partidas catalogadas."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class MatchDatabase:
    """Gerencia o catálogo local de partidas e estado da mensagem fixada no Discord."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tracked_players (
                    profile_id INTEGER PRIMARY KEY,
                    alias TEXT NOT NULL,
                    steam_id TEXT DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    baseline_synced INTEGER NOT NULL DEFAULT 0,
                    added_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS recorded_matches (
                    match_id INTEGER NOT NULL,
                    tracked_profile_id INTEGER NOT NULL,
                    tracked_alias TEXT NOT NULL,
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
                """
            )
            try:
                conn.execute("ALTER TABLE recorded_matches ADD COLUMN tracked_steam_id TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tracked_players ADD COLUMN original_alias TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass

    def sync_tracked_players(self, players_cfg: list[dict[str, Any]]) -> None:
        """Sincroniza a lista de jogadores monitorados do config.json com a tabela tracked_players."""
        now = int(time.time())
        active_ids: set[int] = set()
        with self._connect() as conn:
            for item in players_cfg:
                pid = int(item["profile_id"])
                active_ids.add(pid)
                alias = str(item.get("alias") or f"Player {pid}")
                orig_alias = str(item.get("original_alias") or alias)
                steam_id = str(item.get("steam_id") or "")
                conn.execute(
                    """
                    INSERT INTO tracked_players (profile_id, alias, original_alias, steam_id, active, baseline_synced, added_at)
                    VALUES (?, ?, ?, ?, 1, 0, ?)
                    ON CONFLICT(profile_id) DO UPDATE SET
                        alias = excluded.alias,
                        original_alias = CASE
                            WHEN excluded.original_alias != '' THEN excluded.original_alias
                            ELSE tracked_players.original_alias
                        END,
                        steam_id = CASE WHEN excluded.steam_id != '' THEN excluded.steam_id ELSE tracked_players.steam_id END,
                        active = 1
                    """,
                    (pid, alias, orig_alias, steam_id, now),
                )
            if active_ids:
                placeholders = ",".join("?" for _ in active_ids)
                conn.execute(
                    f"UPDATE tracked_players SET active = 0 WHERE profile_id NOT IN ({placeholders})",
                    tuple(active_ids),
                )
            else:
                conn.execute("UPDATE tracked_players SET active = 0")

    def get_active_players(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tracked_players WHERE active = 1 ORDER BY alias COLLATE NOCASE"
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_baseline_synced(self, profile_id: int, alias: str | None = None, steam_id: str | None = None) -> None:
        with self._connect() as conn:
            if alias and steam_id:
                conn.execute(
                    "UPDATE tracked_players SET baseline_synced = 1, alias = ?, steam_id = ? WHERE profile_id = ?",
                    (alias, steam_id, profile_id),
                )
            elif alias:
                conn.execute(
                    "UPDATE tracked_players SET baseline_synced = 1, alias = ? WHERE profile_id = ?",
                    (alias, profile_id),
                )
            else:
                conn.execute(
                    "UPDATE tracked_players SET baseline_synced = 1 WHERE profile_id = ?",
                    (profile_id,),
                )

    def match_exists(self, match_id: int, tracked_profile_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM recorded_matches WHERE match_id = ? AND tracked_profile_id = ?",
                (match_id, tracked_profile_id),
            ).fetchone()
        return row is not None

    def insert_match(self, match: dict[str, Any], discord_message_id: str | None = None) -> bool:
        """Grava uma partida caso ainda não exista. Retorna True se foi inserida agora."""
        if self.match_exists(match["match_id"], match["tracked_profile_id"]):
            return False

        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO recorded_matches (
                    match_id, tracked_profile_id, tracked_alias, tracked_steam_id, tracked_faction,
                    tracked_faction_short, win, resulttype, mode, matchtype_id,
                    map_raw, map_clean, start_time, completion_time, duration_sec,
                    old_elo, new_elo, allies_json, opponents_json, counters_json,
                    has_replay, coh3stats_url, discord_message_id, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    match["match_id"],
                    match["tracked_profile_id"],
                    match["tracked_alias"],
                    str(match.get("tracked_steam_id") or ""),
                    match["tracked_faction"],
                    match["tracked_faction_short"],
                    1 if match["win"] else 0,
                    match["resulttype"],
                    match["mode"],
                    match["matchtype_id"],
                    match["map_raw"],
                    match["map_clean"],
                    match["start_time"],
                    match["completion_time"],
                    match["duration_sec"],
                    match["old_elo"],
                    match["new_elo"],
                    json.dumps(match["allies"], ensure_ascii=False),
                    json.dumps(match["opponents"], ensure_ascii=False),
                    "{}",
                    1 if match["has_replay"] else 0,
                    match["coh3stats_url"],
                    discord_message_id,
                    now,
                ),
            )
        return True

    def update_match_discord_id(self, match_id: int, tracked_profile_id: int, message_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE recorded_matches SET discord_message_id = ? WHERE match_id = ? AND tracked_profile_id = ?",
                (message_id, match_id, tracked_profile_id),
            )

    def get_recent_recorded_matches(
        self,
        limit: int = 15,
        only_active_players: bool = True,
    ) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if only_active_players:
                rows = conn.execute(
                    """
                    SELECT rm.*,
                           COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                           COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
                    FROM recorded_matches rm
                    JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
                    WHERE tp.active = 1
                    ORDER BY rm.completion_time DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT rm.*,
                           COALESCE(NULLIF(rm.tracked_steam_id, ''), tp.steam_id, '') AS resolved_steam_id,
                           COALESCE(NULLIF(tp.alias, ''), rm.tracked_alias) AS resolved_display_alias
                    FROM recorded_matches rm
                    LEFT JOIN tracked_players tp ON tp.profile_id = rm.tracked_profile_id
                    ORDER BY rm.completion_time DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

        results: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["tracked_steam_id"] = d.pop("resolved_steam_id", "") or d.get("tracked_steam_id", "")
            disp_alias = d.pop("resolved_display_alias", "")
            if disp_alias:
                d["tracked_alias"] = disp_alias
            d["win"] = bool(d["win"])
            d["has_replay"] = bool(d["has_replay"])
            d["allies"] = json.loads(d.pop("allies_json"))
            d["opponents"] = json.loads(d.pop("opponents_json"))
            d["counters"] = json.loads(d.pop("counters_json"))
            results.append(d)
        return results

    def get_cached_avatar(self, steam_id: str = "", profile_id: int = 0, max_age_sec: int = 7 * 86400) -> bytes | None:
        now = int(time.time())
        with self._connect() as conn:
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
        if not row:
            return None
        if (now - int(row["updated_at"])) > max_age_sec:
            return None
        return bytes(row["png_blob"])

    def save_cached_avatar(self, steam_id: str, avatar_url: str, png_blob: bytes, profile_id: int = 0) -> None:
        if not steam_id or not png_blob:
            return
        now = int(time.time())
        with self._connect() as conn:
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
                (steam_id, int(profile_id), avatar_url, sqlite3.Binary(png_blob), now),
            )

    def get_steam_id_map(self) -> dict[int, str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT profile_id, steam_id FROM tracked_players WHERE steam_id != ''"
            ).fetchall()
        return {int(r["profile_id"]): str(r["steam_id"]) for r in rows}

    def get_state(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM bot_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO bot_state (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

#!/usr/bin/env python3
"""Testes da política de retenção de 72h no canal Discord preservando 100% do histórico em SQLite."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import monitor
from database import MatchDatabase, PENDING_DISCORD_MARKER, PRUNED_DISCORD_MARKER


def _sample_match(
    match_id: int,
    profile_id: int,
    completion_time: int,
    *,
    win: bool = True,
    old_elo: int = 1400,
    new_elo: int = 1420,
    opponent_pid: int = 999001,
) -> dict[str, Any]:
    return {
        "match_id": match_id,
        "tracked_profile_id": profile_id,
        "tracked_steam_id": "76561197963172584",
        "tracked_alias": "Chacineiro",
        "tracked_faction": "Wehrmacht",
        "tracked_faction_short": "Wehr",
        "win": win,
        "resulttype": 1 if win else 0,
        "mode": "1v1",
        "matchtype_id": 1,
        "map_raw": "twin_beaches_2p_mkii",
        "map_clean": "Twin Beaches",
        "start_time": completion_time - 900,
        "completion_time": completion_time,
        "duration_sec": 900,
        "old_elo": old_elo,
        "new_elo": new_elo,
        "allies": [
            {
                "profile_id": profile_id,
                "steam_id": "76561197963172584",
                "alias": "Chacineiro",
                "faction": "Wehrmacht",
                "faction_short": "Wehr",
                "country": "br",
                "old_elo": old_elo,
                "new_elo": new_elo,
            }
        ],
        "opponents": [
            {
                "profile_id": opponent_pid,
                "steam_id": "76561198000000123",
                "alias": "RivalTest",
                "faction": "US Forces",
                "faction_short": "USF",
                "country": "us",
                "old_elo": 1410,
                "new_elo": 1390,
            }
        ],
        "counters": {},
        "has_replay": False,
        "coh3stats_url": f"https://coh3stats.com/matches/{match_id}?profileIDs=[{profile_id}]",
    }


class _FakeDiscord:
    is_configured = True

    def __init__(self) -> None:
        self.deleted_ids: list[str] = []
        self.sent_match_ids: list[int] = []
        self.summary_calls: list[list[int]] = []

    def verify_webhook(self) -> dict[str, str]:
        return {"id": "1", "channel_id": "2", "name": "Test"}

    def delete_message(self, message_id: str, protected_message_id: str | None = None) -> bool:
        if protected_message_id and message_id == protected_message_id:
            return False
        self.deleted_ids.append(message_id)
        return True

    def send_match_card(self, grp: dict[str, Any]) -> str:
        mid = int(grp["match_id"])
        self.sent_match_ids.append(mid)
        return f"15729990000000{mid:05d}"

    def upsert_summary_message(
        self,
        matches: list[dict[str, Any]],
        tracked_players: list[dict[str, Any]],
        existing_message_id: str | None,
        custom_players: list[dict[str, Any]] | None = None,
        recreate_message: bool = False,
    ) -> str:
        self.summary_calls.append([int(m["match_id"]) for m in matches])
        return existing_message_id or "1572747709675475054"


class TestDiscord72hRetention(unittest.TestCase):
    def test_prunes_by_completion_time_and_preserves_history_for_weekly_and_nemesis(self) -> None:
        now_ts = 1_795_500_000
        old_ct = now_ts - (73 * 3600)
        old_ct_2 = now_ts - (72 * 3600 + 60)
        recent_ct = now_ts - (10 * 3600)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            with MatchDatabase(db_path) as db:
                db.sync_tracked_players(
                    [
                        {
                            "profile_id": 79327,
                            "alias": "Chacineiro",
                            "original_alias": "Chacineiro",
                            "steam_id": "76561197963172584",
                        }
                    ]
                )
                db.set_state("summary_message_id", "1572747709675475054")

                # Duas partidas antigas (>72h por completion_time), mesmo com recorded_at recente (simulando recuperação tardia)
                self.assertTrue(db.insert_match(_sample_match(101, 79327, old_ct, win=True), discord_message_id="1572700000000000101"))
                self.assertTrue(db.insert_match(_sample_match(102, 79327, old_ct_2, win=False), discord_message_id="1572700000000000102"))
                # Partida recente (<72h) deve permanecer no canal
                self.assertTrue(db.insert_match(_sample_match(103, 79327, recent_ct, win=True), discord_message_id="1572700000000000103"))
                # Mensagem efêmera legada (lobby_alert) >72h também deve ser limpa
                db.record_ephemeral_message("1572700000000000999", kind="lobby_alert", sent_at=now_ts - 75 * 3600)
                # Simula recorded_at recente nas partidas antigas (recuperadas pela 3ª checagem)
                with db._connect() as conn:
                    conn.execute("UPDATE recorded_matches SET recorded_at = ? WHERE match_id IN (101, 102)", (now_ts - 12 * 3600,))

                fake_discord = _FakeDiscord()
                pruned = monitor.prune_old_discord_messages(db, fake_discord, retention_hours=72, now_ts=now_ts)

                self.assertEqual(pruned, 3)
                self.assertEqual(
                    set(fake_discord.deleted_ids),
                    {"1572700000000000101", "1572700000000000102", "1572700000000000999"},
                )
                self.assertNotIn("1572700000000000103", fake_discord.deleted_ids)
                self.assertNotIn("1572747709675475054", fake_discord.deleted_ids)

                # Todas as 3 partidas permanecem intactas no SQLite (apenas marcadas como PRUNED)
                delivery = db.get_match_delivery_map([101, 102, 103])
                self.assertTrue(delivery[101]["handled_non_live"])
                self.assertTrue(delivery[102]["handled_non_live"])
                self.assertEqual(delivery[103]["snowflake"], "1572700000000000103")

                # Boletim Semanal (7 dias) continua contabilizando 100% das partidas podadas do canal
                weekly = db.get_weekly_summary_stats(now_ts=now_ts, window_days=7)
                self.assertEqual(weekly["unique_matches_count"], 3)
                self.assertEqual(weekly["most_active_player"]["games"], 3)
                self.assertEqual(weekly["most_active_player"]["wins"], 2)

                # Nemesis continua enxergando confrontos mesmo após a limpeza do Discord
                nem = db.get_nemesis_status(
                    tracked_profile_ids=[79327],
                    opponent_profile_id=999001,
                    up_to_completion_time=recent_ct,
                    up_to_match_id=103,
                )
                self.assertIsNotNone(nem)
                self.assertEqual(nem["total"], 3)

                # Painel Fixado com filtro de 72h exibe apenas a partida dentro da janela
                panel_72h = db.get_recent_recorded_matches(
                    limit=15,
                    only_active_players=True,
                    min_completion_time=now_ts - 72 * 3600,
                )
                self.assertEqual([int(m["match_id"]) for m in panel_72h], [103])

                # Histórico completo no SQLite sem min_completion_time mantém todas as 3 partidas
                all_hist = db.get_recent_recorded_matches(limit=15, only_active_players=True)
                self.assertEqual(len(all_hist), 3)

    def test_run_cycle_archives_over_72h_matches_without_posting_to_discord(self) -> None:
        now_ts = 1_795_500_000
        old_ct = now_ts - (80 * 3600)
        pending_expired_ct = now_ts - (74 * 3600)
        live_ct = now_ts - (2 * 3600)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            db_path = tmp_dir / "test.db"
            cfg_path = tmp_dir / "config.json"
            player_entry = {
                "profile_id": 79327,
                "alias": "Chacineiro",
                "original_alias": "Chacineiro",
                "steam_id": "76561197963172584",
                "is_custom": True,
                "is_core_roster": True,
            }
            cfg_path.write_text(
                json.dumps(
                    {
                        "discord_webhook_url": monitor.SAFE_WEBHOOK_PLACEHOLDER,
                        "sqlite_db_path": str(db_path),
                        "discord_cleanup_hours": 72,
                        "custom_players": [player_entry],
                        "tracked_players": [player_entry],
                    }
                ),
                encoding="utf-8",
            )

            with MatchDatabase(db_path) as db:
                db.sync_tracked_players([player_entry])
                db.mark_baseline_synced(79327, "Chacineiro", steam_id="76561197963172584")
                # Partida pendente que expirou >72h antes de ser enviada
                db.insert_match(
                    _sample_match(201, 79327, pending_expired_ct, win=True),
                    discord_message_id=PENDING_DISCORD_MARKER,
                )
                with db._connect() as conn:
                    conn.execute("UPDATE recorded_matches SET recorded_at = ? WHERE match_id = 201", (now_ts - 3600,))

            fake_discord = _FakeDiscord()

            class _FakeRelic:
                def fetch_player_recent_matches(self, **kwargs: Any) -> list[dict[str, Any]]:
                    return [
                        _sample_match(202, 79327, old_ct, win=False),
                        _sample_match(203, 79327, live_ct, win=True),
                    ]

            with (
                mock.patch.object(monitor, "DiscordWebhookClient", return_value=fake_discord),
                mock.patch.object(monitor, "refresh_core_br_roster", return_value=None),
                mock.patch.object(monitor, "ensure_core_roster_in_config", return_value=False),
                mock.patch.object(monitor, "maybe_post_weekly_summary", return_value=None),
                mock.patch.object(monitor, "maybe_run_db_maintenance", return_value=None),
                mock.patch.object(monitor.time, "time", return_value=now_ts),
                mock.patch.object(monitor.time, "sleep", return_value=None),
            ):
                monitor.run_cycle(
                    config_path=cfg_path,
                    relic=_FakeRelic(),  # type: ignore[arg-type]
                    is_oneshot=True,
                    enable_third_check=False,
                    enable_fourth_check=False,
                    enable_battlegroups=False,
                )

            # Apenas a partida #203 (<72h) foi postada no Discord; #201 e #202 ficaram arquivadas no SQLite
            self.assertEqual(fake_discord.sent_match_ids, [203])
            self.assertTrue(fake_discord.summary_calls)
            self.assertEqual(fake_discord.summary_calls[-1], [203])

            with MatchDatabase(db_path) as db:
                delivery = db.get_match_delivery_map([201, 202, 203])
                self.assertEqual(delivery[201]["rows"][79327][0], PRUNED_DISCORD_MARKER)
                self.assertEqual(delivery[202]["rows"][79327][0], PRUNED_DISCORD_MARKER)
                self.assertIsNotNone(delivery[203]["snowflake"])
                weekly = db.get_weekly_summary_stats(now_ts=now_ts, window_days=7)
                self.assertEqual(weekly["unique_matches_count"], 3)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Testes da 5ª checagem automática — Auditoria de Silêncio (Quiet-Period Deep Audit)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import monitor
from database import MatchDatabase, PENDING_DISCORD_MARKER, PRUNED_DISCORD_MARKER


def _make_match(
    match_id: int,
    profile_id: int,
    completion_time: int,
    *,
    alias: str = "Chacineiro",
    steam_id: str = "76561197963172584",
) -> dict[str, Any]:
    return {
        "match_id": match_id,
        "tracked_profile_id": profile_id,
        "tracked_steam_id": steam_id,
        "tracked_alias": alias,
        "tracked_faction": "Wehrmacht",
        "tracked_faction_short": "Wehr",
        "win": True,
        "resulttype": 1,
        "mode": "1v1",
        "matchtype_id": 1,
        "map_raw": "twin_beaches_2p_mkii",
        "map_clean": "Twin Beaches",
        "start_time": completion_time - 900,
        "completion_time": completion_time,
        "duration_sec": 900,
        "old_elo": 1450,
        "new_elo": 1470,
        "allies": [
            {
                "profile_id": profile_id,
                "steam_id": steam_id,
                "alias": alias,
                "faction": "Wehrmacht",
                "faction_short": "Wehr",
                "country": "br",
                "old_elo": 1450,
                "new_elo": 1470,
            }
        ],
        "opponents": [
            {
                "profile_id": 888001,
                "steam_id": "76561198000000888",
                "alias": "Oponente",
                "faction": "US Forces",
                "faction_short": "USF",
                "country": "us",
                "old_elo": 1440,
                "new_elo": 1420,
            }
        ],
        "counters": {},
        "has_replay": False,
        "coh3stats_url": f"https://coh3stats.com/matches/{match_id}?profileIDs=[{profile_id}]",
    }


class TestQuietPeriodDeepAudit(unittest.TestCase):
    def test_skips_when_silence_below_threshold_or_within_cooldown(self) -> None:
        now_ts = 1_795_536_000  # 2026-11-24 16:00:00 UTC
        players = [
            {
                "profile_id": 79327,
                "alias": "Chacineiro",
                "original_alias": "Chacineiro",
                "steam_id": "76561197963172584",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            with MatchDatabase(Path(tmp) / "test.db") as db:
                db.sync_tracked_players(players)
                # Partida há apenas 1h -> não deve disparar auditoria de silêncio (threshold 3h)
                db.insert_match(_make_match(5001, 79327, now_ts - 3600), discord_message_id="1573000000000005001")

                fake_relic = mock.MagicMock()
                res = monitor.run_quiet_period_deep_audit(
                    db=db,
                    relic=fake_relic,
                    coh3stats=None,
                    synced_players=players,
                    newly_finished=[],
                    only_automatch=False,
                    roster_maps=({}, {}),
                    recovery_min_completion_ts=now_ts - 72 * 3600,
                    live_marker=PENDING_DISCORD_MARKER,
                    now_ts=now_ts,
                )
                self.assertFalse(res["ran"])
                fake_relic.fetch_players_latest_stat_timestamps.assert_not_called()

    def test_recovers_missed_match_via_personalstat_coh3stats_and_sqlite_scan(self) -> None:
        now_ts = 1_795_536_000  # 2026-11-24 16:00:00 UTC (>= 04:00 UTC)
        old_ct = now_ts - 5 * 3600  # 5h de silêncio no banco
        missed_relic_ct = now_ts - 2 * 3600
        missed_c3s_ct = now_ts - 26 * 3600
        undelivered_ct = now_ts - 6 * 3600
        pruned_ct = now_ts - 12 * 3600

        players = [
            {
                "profile_id": 79327,
                "alias": "Chacineiro",
                "original_alias": "Chacineiro",
                "steam_id": "76561197963172584",
            },
            {
                "profile_id": 3895,
                "alias": "Liquid",
                "original_alias": "Liquid",
                "steam_id": "76561197986271242",
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            with MatchDatabase(Path(tmp) / "test.db") as db:
                db.sync_tracked_players(players)
                # Última partida entregue há 5h (Liquid) e há 12h (Chacineiro já PRUNED)
                db.insert_match(
                    _make_match(6001, 3895, old_ct, alias="Liquid", steam_id="76561197986271242"),
                    discord_message_id="1573000000000006001",
                )
                db.insert_match(
                    _make_match(6002, 79327, pruned_ct),
                    discord_message_id=PRUNED_DISCORD_MARKER,
                )
                # Partida gravada no SQLite com discord_message_id=NULL dentro da janela de 72h (nunca entregue!)
                db.insert_match(
                    _make_match(6003, 79327, undelivered_ct),
                    discord_message_id=None,
                )

                class _FakeRelic:
                    races = {}
                    match_types = {}

                    def fetch_players_latest_stat_timestamps(self, pls: list[dict[str, Any]]) -> dict[int, int]:
                        return {
                            # Chacineiro tem partida mais nova (+10h acima de old db_ct) -> divergente!
                            79327: missed_relic_ct + 1,
                            # Liquid tem apenas +1s de drift normal da Relic -> NÃO deve gerar falso positivo
                            3895: old_ct + 1,
                        }

                    def fetch_player_recent_matches(self, profile_id: int, **kwargs: Any) -> list[dict[str, Any]]:
                        if profile_id == 79327:
                            return [_make_match(6004, 79327, missed_relic_ct)]
                        return []

                    def fetch_recent_matches_direct_batch(self, players: list[dict[str, Any]], **kwargs: Any) -> tuple[dict[int, list[dict[str, Any]]], int]:
                        return ({}, 0)

                class _FakeCoh3Stats:
                    def fetch_open_data_days_matches(self, **kwargs: Any) -> tuple[dict[int, list[dict[str, Any]]], list[int], int, int]:
                        days = kwargs.get("day_timestamps") or []
                        return (
                            {
                                3895: [
                                    _make_match(6005, 3895, missed_c3s_ct, alias="Liquid", steam_id="76561197986271242"),
                                    # Partida #6002 já PRUNED nunca pode ser reenviada
                                    _make_match(6002, 79327, pruned_ct),
                                ]
                            },
                            list(days),
                            500,
                            0,
                        )

                newly: list[dict[str, Any]] = []
                with mock.patch.object(monitor.time, "sleep", return_value=None):
                    res = monitor.run_quiet_period_deep_audit(
                        db=db,
                        relic=_FakeRelic(),  # type: ignore[arg-type]
                        coh3stats=_FakeCoh3Stats(),  # type: ignore[arg-type]
                        synced_players=players,
                        newly_finished=newly,
                        only_automatch=False,
                        roster_maps=({}, {}),
                        recovery_min_completion_ts=now_ts - 72 * 3600,
                        live_marker=PENDING_DISCORD_MARKER,
                        expected_custom_count=2,
                        now_ts=now_ts,
                    )

                self.assertTrue(res["ran"])
                self.assertEqual(res["stat_ok_accounts"], 2)
                # Apenas Chacineiro divergiu (+1s do Liquid ignorado!)
                self.assertEqual(res["divergent_accounts"], 1)
                self.assertEqual(res["rechecked_accounts"], 1)
                self.assertTrue(res["coh3stats_reaudited"])
                # #6004 (Relic PersonalStat) + #6005 (coh3stats Open Data) + #6003 (SQLite NULL) = 3 recuperadas
                self.assertEqual(res["recovered_unique"], 3)
                self.assertEqual(res["sqlite_requeued"], 1)

                delivery = db.get_match_delivery_map([6001, 6002, 6003, 6004, 6005])
                self.assertEqual(delivery[6001]["snowflake"], "1573000000000006001")
                self.assertTrue(delivery[6002]["handled_non_live"])
                self.assertEqual(delivery[6003]["rows"][79327][0], PENDING_DISCORD_MARKER)
                self.assertEqual(delivery[6004]["rows"][79327][0], PENDING_DISCORD_MARKER)
                self.assertEqual(delivery[6005]["rows"][3895][0], PENDING_DISCORD_MARKER)

                # Dentro do cooldown de 3h, a próxima chamada não roda novamente
                res_again = monitor.run_quiet_period_deep_audit(
                    db=db,
                    relic=_FakeRelic(),  # type: ignore[arg-type]
                    coh3stats=_FakeCoh3Stats(),  # type: ignore[arg-type]
                    synced_players=players,
                    newly_finished=[],
                    only_automatch=False,
                    roster_maps=({}, {}),
                    recovery_min_completion_ts=now_ts - 72 * 3600,
                    live_marker=PENDING_DISCORD_MARKER,
                    now_ts=now_ts + 1800,
                )
                self.assertFalse(res_again["ran"])


if __name__ == "__main__":
    unittest.main()

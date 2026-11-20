"""Testes unitários do consumo da base única compartilhada (`players_roster.json`) no Tracker."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import monitor
import relic_api


class TestTrackerSharedRoster(unittest.TestCase):
    def tearDown(self) -> None:
        relic_api.CORE_BR_ROSTER[:] = [dict(r) for r in relic_api.FALLBACK_CORE_BR_ROSTER]

    def test_parse_shared_roster_ignores_manual_other_br_and_keeps_us_country(self) -> None:
        payload = {
            "schema_version": 1,
            "veteranos": [
                {"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro", "country": "br"},
                {"profile_id": 366826, "steam_id": "76561198014985380", "original_alias": "Lem22", "country": "us"},
                {"profile_id": 975688, "steam_id": "76561197994245218", "original_alias": "Kefbr", "in_ranking": False},
            ],
            "manual_other_br": [
                {"profile_id": 33487, "steam_id": "76561197995712470", "original_alias": "Generick", "country": "us"},
            ],
        }
        parsed = relic_api.parse_shared_roster_payload(payload)
        pids = [int(r["profile_id"]) for r in parsed]
        self.assertEqual(pids, [79327, 366826, 975688])
        self.assertNotIn(33487, pids)
        lem = next(r for r in parsed if r["profile_id"] == 366826)
        self.assertEqual(lem.get("country"), "us")

    def test_fetch_shared_roster_blocks_untrusted_urls(self) -> None:
        for bad_url in (
            "http://raw.githubusercontent.com/nigosky/coh3-br-lobby-radar/main/players_roster.json",
            "https://evil.com/nigosky/coh3-br-lobby-radar/main/players_roster.json",
            "https://raw.githubusercontent.com/attacker/repo/main/players_roster.json",
        ):
            with self.assertRaises(ValueError):
                relic_api.fetch_shared_roster(url=bad_url)

    def test_ensure_core_roster_syncs_additions_country_updates_and_removals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rp = Path(td) / "players_roster.json"
            rp.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "veteranos": [
                            {"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro", "country": "br"},
                            {"profile_id": 366826, "steam_id": "76561198014985380", "original_alias": "Lem22", "country": "us"},
                            {"profile_id": 999111, "steam_id": "76561198000999111", "original_alias": "NovoVet", "country": "pt"},
                        ],
                        "manual_other_br": [],
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(relic_api.refresh_core_br_roster(local_path=rp))

            cfg = {
                "monitor_only_custom_matches": True,
                "leaderboard_refresh_minutes": 15,
                "custom_players": [
                    {
                        "profile_id": 79327,
                        "steam_id": "76561197963172584",
                        "original_alias": "Chacineiro",
                        "alias": "Chacineiro",
                        "is_core_roster": True,
                    },
                    {
                        "profile_id": 366826,
                        "steam_id": "76561198014985380",
                        "original_alias": "Lem22",
                        "alias": "Lem22",
                        "is_core_roster": True,
                    },
                    {
                        "profile_id": 555000,
                        "steam_id": "76561198000555000",
                        "original_alias": "RemovidoDaBase",
                        "alias": "RemovidoDaBase",
                        "is_core_roster": True,
                    },
                    {
                        "profile_id": 777000,
                        "steam_id": "76561198000777000",
                        "original_alias": "ConvidadoLocalExtra",
                        "alias": "ConvidadoLocalExtra",
                    },
                ],
            }
            self.assertTrue(monitor.ensure_core_roster_in_config(cfg))
            by_pid = {int(c["profile_id"]): c for c in cfg["custom_players"]}
            self.assertIn(999111, by_pid)
            self.assertEqual(by_pid[999111].get("country"), "pt")
            self.assertEqual(by_pid[366826].get("country"), "us")
            self.assertNotIn(555000, by_pid, "Jogador core removido da base compartilhada deve sair de custom_players.")
            self.assertIn(777000, by_pid, "Convidado local não-core deve permanecer preservado.")
            # Idempotente na segunda chamada
            self.assertFalse(monitor.ensure_core_roster_in_config(cfg))

    def test_format_bound_display_alias_marks_nick_changes_with_asterisk_and_respects_pin_alias(self) -> None:
        # Mudança inédita preserva nick anterior com asterisco '*'
        self.assertEqual(
            relic_api.format_bound_display_alias("NovoNick", "Chacineiro"),
            "Chacineiro* (NovoNick)",
        )
        # Idempotente e atualiza formato antigo sem asterisco
        self.assertEqual(
            relic_api.format_bound_display_alias("Chacineiro* (NovoNick)", "Chacineiro"),
            "Chacineiro* (NovoNick)",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias("Chacineiro (NovoNick)", "Chacineiro"),
            "Chacineiro* (NovoNick)",
        )
        # Gabe com nick conhecido "É o Gabe" -> exibe simplesmente "Gabe"
        self.assertEqual(
            relic_api.format_bound_display_alias("É o Gabe", "Gabe", ["É o Gabe", "Gabe"]),
            "Gabe",
        )
        # arc com pin_alias=True -> SEMPRE "arc", independente do nick atual
        self.assertEqual(
            relic_api.format_bound_display_alias("geladeira velha", "arc", pin_alias=True),
            "arc",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias("QualquerNickNovo123", "arc", pin_alias=True),
            "arc",
        )


if __name__ == "__main__":
    unittest.main()

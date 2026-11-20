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
        # Chacineiro smurf com show_smurf_alias=True -> SEMPRE "Chacineiro* (NomeDaSmurf)", mesmo constando em known_aliases
        smurf_known = ["TacticalForceConcentration", "Charles Bronson", "Lord Charles Bronson", "Charles Broson", "Chacineiro"]
        self.assertEqual(
            relic_api.format_bound_display_alias("Charles Bronson", "Chacineiro", smurf_known, show_smurf_alias=True),
            "Chacineiro* (Charles Bronson)",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias(
                "TacticalForceConcentration", "Chacineiro", smurf_known, show_smurf_alias=True
            ),
            "Chacineiro* (TacticalForceConcentration)",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias(
                "Chacineiro* (Charles Bronson)", "Chacineiro", smurf_known, show_smurf_alias=True
            ),
            "Chacineiro* (Charles Bronson)",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias("Chacineiro", "Chacineiro", smurf_known, show_smurf_alias=True),
            "Chacineiro",
        )

    def test_chacineiro_smurf_keeps_main_avatar_and_displays_asterisk_smurf_name(self) -> None:
        import io
        from PIL import Image
        import card_renderer
        from database import MatchDatabase

        # 1. Mesmo quando players_roster.json remoto ainda não lista #1333418, _merge_local_smurf_fallbacks preserva a smurf
        remote_without_smurf = [
            {"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro"},
            {"profile_id": 991764, "steam_id": "76561198115923932", "original_alias": "SaNgar [BR]"},
        ]
        merged = relic_api._merge_local_smurf_fallbacks(remote_without_smurf)
        pids = [int(r["profile_id"]) for r in merged]
        self.assertEqual(pids, [79327, 1333418, 991764])
        smurf_row = next(r for r in merged if r["profile_id"] == 1333418)
        self.assertTrue(smurf_row.get("show_smurf_alias"))
        self.assertEqual(smurf_row.get("merged_into_profile_id"), 79327)
        self.assertEqual(smurf_row.get("merged_into_steam_id"), "76561197963172584")

        # 2. Mesmo quando players_roster.json remoto traz #1333418 com known_aliases (formato do Ranking),
        # parse_shared_roster_payload ativa show_smurf_alias=True automaticamente para o Tracker
        parsed_with_smurf = relic_api.parse_shared_roster_payload(
            {
                "schema_version": 1,
                "veteranos": [
                    {"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro", "country": "br"},
                    {
                        "profile_id": 1333418,
                        "steam_id": "76561198698969876",
                        "original_alias": "Chacineiro",
                        "country": "br",
                        "merged_into_profile_id": 79327,
                        "merged_into_steam_id": "76561197963172584",
                        "known_aliases": ["TacticalForceConcentration", "Charles Bronson", "Chacineiro"],
                    },
                ],
            }
        )
        smurf_parsed = next(r for r in parsed_with_smurf if r["profile_id"] == 1333418)
        self.assertTrue(smurf_parsed.get("show_smurf_alias"))

        # 3. Enriquecimento da partida + extração do card + avatar:
        # mantém avatar da conta principal (76561197963172584) e exibe "Chacineiro* (Charles Bronson)"
        roster_maps = relic_api.build_roster_lookup_maps()
        sample_match = {
            "match_id": 999888777,
            "tracked_profile_id": 1333418,
            "tracked_steam_id": "76561198698969876",
            "tracked_alias": "Charles Bronson",
            "tracked_faction": "Wehrmacht",
            "mode": "1v1",
            "map_raw": "faymonville",
            "map_clean": "Faymonville",
            "result": "Vitória",
            "duration_sec": 1200,
            "completion_time": 1_800_000_000,
            "old_elo": 1520,
            "new_elo": 1536,
            "allies": [],
            "opponents": [
                {
                    "profile_id": 555001,
                    "alias": "Rival_US",
                    "steam_id": "76561198000012345",
                    "country": "us",
                    "faction": "US Forces",
                    "old_elo": 1510,
                    "new_elo": 1494,
                }
            ],
        }
        relic_api.enrich_match_with_roster(sample_match, roster_maps)
        self.assertEqual(sample_match["tracked_alias"], "Chacineiro* (Charles Bronson)")
        self.assertEqual(sample_match["tracked_steam_id"], "76561197963172584")

        axis_p, allies_p = card_renderer.extract_axis_and_allies_players({"records": [sample_match], "primary": sample_match})
        self.assertEqual(len(axis_p), 1)
        self.assertEqual(axis_p[0]["alias"], "Chacineiro* (Charles Bronson)")
        self.assertEqual(axis_p[0]["steam_id"], "76561197963172584")
        self.assertEqual(len(allies_p), 1)

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "smurf_avatar.db")
            # Salva avatar VERDE para a conta principal (79327) e VERMELHO para a smurf (1333418)
            buf_main = io.BytesIO()
            Image.new("RGBA", (64, 64), (20, 220, 40, 255)).save(buf_main, format="PNG")
            buf_smurf = io.BytesIO()
            Image.new("RGBA", (64, 64), (220, 20, 20, 255)).save(buf_smurf, format="PNG")
            db.save_cached_avatar("76561197963172584", "https://avatars.steamstatic.com/main.jpg", buf_main.getvalue(), profile_id=79327)
            db.save_cached_avatar("76561198698969876", "https://avatars.steamstatic.com/smurf.jpg", buf_smurf.getvalue(), profile_id=1333418)

            ap = card_renderer.SteamAvatarProvider(db, allow_network=False)
            # Mesmo consultando diretamente pelo profile_id/steam_id da smurf, retorna o avatar VERDE da conta principal!
            self.assertEqual(ap.resolve_steam_id(profile_id=1333418, steam_id="76561198698969876"), "76561197963172584")
            av = ap.get_circular_avatar(size=40, profile_id=1333418, steam_id="76561198698969876", alias="Chacineiro* (Charles Bronson)")
            r, g, b, _ = av.getpixel((20, 20))
            self.assertGreater(g, 180, f"Avatar deveria vir da conta principal (verde), mas recebeu RGB=({r},{g},{b}).")
            self.assertLess(r, 80)
            db.close()


if __name__ == "__main__":
    unittest.main()

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
        relic_api.MANUAL_OTHER_BR_DISPLAY[:] = [dict(r) for r in relic_api.FALLBACK_MANUAL_OTHER_BR_DISPLAY]

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

    def test_unmerged_smurfs_keep_own_avatar_and_pinned_display_name(self) -> None:
        import io
        from PIL import Image
        import card_renderer
        from database import MatchDatabase

        # 1. Roster padrão tem 48 Veteranos independentes (0 mescladas) + 176 perfis de exibição passiva (158 Monitorados + 18 Emigrados em Outros BR)
        self.assertEqual(len(relic_api.CORE_BR_ROSTER), 48)
        self.assertEqual(len(relic_api.MANUAL_OTHER_BR_DISPLAY), 176)
        self.assertEqual(relic_api.TRACKER_SMURF_DISPLAY_PIDS, frozenset())
        self.assertEqual(relic_api.LOCAL_MERGED_ACCOUNT_FALLBACKS, ())
        by_pid = {int(r["profile_id"]): r for r in relic_api.CORE_BR_ROSTER}
        other_by_pid = {int(r["profile_id"]): r for r in relic_api.MANUAL_OTHER_BR_DISPLAY}
        self.assertIn(1119784, by_pid)
        self.assertEqual(by_pid[1119784]["original_alias"], "Tracker")
        self.assertEqual(by_pid[1119784]["steam_id"], "76561198000067932")
        self.assertNotIn(1076221, by_pid)
        self.assertIn(1076221, other_by_pid)
        self.assertEqual(other_by_pid[1076221]["original_alias"], "Lucielle (Smurf: Colossus)")
        self.assertEqual(other_by_pid[1076221].get("smurf_of"), "Colossus")
        self.assertIn(164152, other_by_pid)
        self.assertEqual(other_by_pid[164152]["original_alias"], "Sgt.Yoda")
        self.assertFalse(other_by_pid[164152].get("smurf_of"))
        for mon_pid, mon_alias in (
            (941524, "Colossus"),
            (40833, "Tokai Teio"),
            (991551, "Caveira-."),
            (667564, "Friedhelm Winter"),
            (357310, "Sleeping Sheep"),
            (845669, "PH0BB05"),
            (17169, "Guh"),
            (71299, "Bruno.s"),
            (13516, "Pax Xavier youtube"),
            (970468, "Московский метро"),
            (649535, "pensss"),
            (765837, "Southland"),
            (87314, "Pedro Jedi"),
            (1156831, "DAk120"),
            (3888, "Pepe Popo"),
        ):
            self.assertIn(mon_pid, other_by_pid)
            self.assertEqual(other_by_pid[mon_pid]["original_alias"], mon_alias)
        for exp_pid, exp_alias, exp_ctry in (
            (212034, "XAPA KENTE", "ca"),
            (7448, "icewarp", "za"),
            (33487, "Generick", "us"),
            (91827, "[★General★] Apollo", "au"),
            (263517, "Angel of Death", "jp"),
            (29737, "PABLO FLEXCOBAR", "ar"),
            (999940, "Warmech11", "py"),
            (110593, "Ethan Hunt", "us"),
            (1304336, "V.I.T.O.X", "us"),
            (1168460, "Nonô", "ca"),
            (11033, "Coka", "jp"),
            (24963, "Eduardo A.", "sa"),
        ):
            self.assertIn(exp_pid, other_by_pid)
            self.assertEqual(other_by_pid[exp_pid]["original_alias"], exp_alias)
            self.assertEqual(other_by_pid[exp_pid].get("country"), exp_ctry)
        self.assertTrue(all(not r.get("merged_into_profile_id") for r in relic_api.CORE_BR_ROSTER))
        self.assertTrue(all(not r.get("merged_into_steam_id") for r in relic_api.CORE_BR_ROSTER))

        expected_vet_smurfs = {
            1333418: ("76561198698969876", "Charles Bronson (Smurf: Chacineiro)"),
            557890: ("76561199538846112", "gabe44arg (Smurf: Gabe)"),
            1423426: ("76561199482388323", "geladeira velha (Smurf: arc)"),
            1487738: ("76561198602236177", "Državljan H (Smurf: arc)"),
            1482961: ("76561199886227102", "Vog (Smurf: arc)"),
            917917: ("76561198287157768", "arc (Smurf: arc)"),
            1160699: ("76561199814547622", "Bubebolos (Smurf: arc)"),
            918241: ("76561199794093952", "Faint (Smurf: arc)"),
            1390350: ("76561198089278659", "TearsInTheRain (Smurf: Chacineiro)"),
        }
        for spid, (expected_sid, expected_alias) in expected_vet_smurfs.items():
            self.assertIn(spid, by_pid)
            self.assertEqual(by_pid[spid]["steam_id"], expected_sid)
            self.assertEqual(by_pid[spid]["original_alias"], expected_alias)
            self.assertTrue(by_pid[spid].get("pin_alias"))
            self.assertFalse(by_pid[spid].get("show_smurf_alias"))
            self.assertTrue(by_pid[spid].get("smurf_of"))

        self.assertNotIn(462597, by_pid)
        self.assertIn(462597, other_by_pid)
        self.assertEqual(other_by_pid[462597]["steam_id"], "76561198133760614")
        self.assertEqual(other_by_pid[462597]["original_alias"], "General Winter")

        expected_pinned_other = {
            1297821: ("76561198722284920", "General Winter (Smurf: General Winter)"),
            1318162: ("76561198708550887", "General Winter (Smurf: General Winter)"),
            509690: ("76561198053226112", "Alekel"),
            1297853: ("76561198721980631", "Shadow (Smurf: Alekel)"),
            844225: ("76561198009000654", "『V』SKOBADARK"),
            1297804: ("76561198723667226", "Leite Moço (Smurf: 『V』SKOBADARK)"),
            1076221: ("76561198815935562", "Lucielle (Smurf: Colossus)"),
        }
        for gpid, (expected_sid, expected_alias) in expected_pinned_other.items():
            self.assertNotIn(gpid, by_pid)
            self.assertIn(gpid, other_by_pid)
            self.assertEqual(other_by_pid[gpid]["steam_id"], expected_sid)
            self.assertEqual(other_by_pid[gpid]["original_alias"], expected_alias)
            self.assertTrue(other_by_pid[gpid].get("pin_alias"))

        # Verifica parser retrocompatível (`monitorados` + `outros_br_emigrados` + `manual_other_br`)
        parsed_mon = relic_api.parse_shared_manual_other_br_payload(
            {
                "schema_version": 1,
                "veteranos": [],
                "monitorados": [
                    {"profile_id": 164152, "steam_id": "76561198029749621", "original_alias": "Sgt.Yoda", "country": "br"},
                ],
                "outros_br_emigrados": [
                    {"profile_id": 33487, "steam_id": "76561197995712470", "original_alias": "Generick", "country": "us"},
                ],
                "manual_other_br": [
                    {"profile_id": 33487, "steam_id": "76561197995712470", "original_alias": "Generick", "country": "us"},
                ],
            }
        )
        self.assertEqual([int(r["profile_id"]) for r in parsed_mon], [164152, 33487])
        self.assertEqual(parsed_mon[1].get("country"), "us")

        # 2. Enriquecimento da partida + extração do card + avatar independente:
        # Veteranos (#1333418 e #1390350) mantêm nome fixo e is_br_roster=True;
        # Outros BR (#1297853 Alekel smurf e #1297804 SKOBADARK smurf) exibem rótulo fixo SEM badge de Veterano!
        roster_maps = relic_api.build_roster_lookup_maps()
        sample_match = {
            "match_id": 999888777,
            "tracked_profile_id": 1333418,
            "tracked_steam_id": "76561198698969876",
            "tracked_alias": "QualquerNickSteamNovo",
            "tracked_faction": "Wehrmacht",
            "mode": "2v2",
            "map_raw": "faymonville",
            "map_clean": "Faymonville",
            "win": True,
            "result": "Vitória",
            "duration_sec": 1200,
            "completion_time": 1_800_000_000,
            "old_elo": 1520,
            "new_elo": 1536,
            "allies": [
                {
                    "profile_id": 1390350,
                    "alias": "OutroNickQualquer",
                    "steam_id": "76561198089278659",
                    "country": "br",
                    "faction": "DAK",
                    "old_elo": 1510,
                    "new_elo": 1525,
                }
            ],
            "opponents": [
                {
                    "profile_id": 1297853,
                    "alias": "Shadow",
                    "steam_id": "76561198721980631",
                    "country": "br",
                    "faction": "US Forces",
                    "old_elo": 1430,
                    "new_elo": 1415,
                },
                {
                    "profile_id": 1297804,
                    "alias": "Leite Moço",
                    "steam_id": "76561198723667226",
                    "country": "br",
                    "faction": "British Forces",
                    "old_elo": 1520,
                    "new_elo": 1505,
                },
            ],
        }
        relic_api.enrich_match_with_roster(sample_match, roster_maps)
        self.assertEqual(sample_match["tracked_alias"], "Charles Bronson (Smurf: Chacineiro)")
        self.assertEqual(sample_match["tracked_steam_id"], "76561198698969876")
        self.assertTrue(sample_match.get("is_br_roster"))
        self.assertEqual(sample_match["allies"][0]["alias"], "TearsInTheRain (Smurf: Chacineiro)")
        self.assertTrue(sample_match["allies"][0].get("is_br_roster"))
        self.assertEqual(sample_match["opponents"][0]["alias"], "Shadow (Smurf: Alekel)")
        self.assertFalse(sample_match["opponents"][0].get("is_br_roster"))
        self.assertEqual(sample_match["opponents"][1]["alias"], "Leite Moço (Smurf: 『V』SKOBADARK)")
        self.assertFalse(sample_match["opponents"][1].get("is_br_roster"))

        axis_p, allies_p = card_renderer.extract_axis_and_allies_players({"records": [sample_match], "primary": sample_match})
        self.assertEqual(len(axis_p), 2)
        self.assertEqual(axis_p[0]["alias"], "Charles Bronson (Smurf: Chacineiro)")
        self.assertTrue(axis_p[0]["is_br_roster"])
        self.assertEqual(axis_p[1]["alias"], "TearsInTheRain (Smurf: Chacineiro)")
        self.assertTrue(axis_p[1]["is_br_roster"])
        self.assertEqual(len(allies_p), 2)
        self.assertEqual(allies_p[0]["alias"], "Shadow (Smurf: Alekel)")
        self.assertFalse(allies_p[0]["is_br_roster"])
        self.assertEqual(allies_p[1]["alias"], "Leite Moço (Smurf: 『V』SKOBADARK)")
        self.assertFalse(allies_p[1]["is_br_roster"])
        self.assertFalse(card_renderer._is_br_veteranos_duel([sample_match], axis_p, allies_p))

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "smurf_avatar.db")
            buf_main = io.BytesIO()
            Image.new("RGBA", (64, 64), (20, 220, 40, 255)).save(buf_main, format="PNG")
            buf_smurf = io.BytesIO()
            Image.new("RGBA", (64, 64), (220, 20, 20, 255)).save(buf_smurf, format="PNG")
            db.save_cached_avatar("76561197963172584", "https://avatars.steamstatic.com/main.jpg", buf_main.getvalue(), profile_id=79327)
            db.save_cached_avatar("76561198698969876", "https://avatars.steamstatic.com/smurf.jpg", buf_smurf.getvalue(), profile_id=1333418)

            ap = card_renderer.SteamAvatarProvider(db, allow_network=False)
            self.assertEqual(ap.resolve_steam_id(profile_id=1333418, steam_id="76561198698969876"), "76561198698969876")
            av = ap.get_circular_avatar(size=40, profile_id=1333418, steam_id="76561198698969876", alias="Charles Bronson (Smurf: Chacineiro)")
            r, g, b, _ = av.getpixel((20, 20))
            self.assertGreater(r, 180, f"Avatar da conta desmembrada deveria ser o próprio (vermelho), mas recebeu RGB=({r},{g},{b}).")
            self.assertLess(g, 80)

            # Renderização completa do card com Veteranos + Alekel/SKOBADARK smurfs funciona sem erros
            png_bytes = card_renderer.render_single_match_card_png(
                {"records": [sample_match], "primary": sample_match},
                avatar_provider=ap,
            )
            self.assertTrue(png_bytes.startswith(b"\x89PNG"))
            db.close()

    def test_ensure_core_roster_strips_stale_merge_fields_on_unmerge(self) -> None:
        cfg = {
            "custom_players": [
                {
                    "profile_id": 1333418,
                    "steam_id": "76561198698969876",
                    "original_alias": "Chacineiro",
                    "alias": "Chacineiro* (Charles Bronson)",
                    "is_core_roster": True,
                    "merged_into_profile_id": 79327,
                    "merged_into_steam_id": "76561197963172584",
                    "show_smurf_alias": True,
                }
            ]
        }
        self.assertTrue(monitor.ensure_core_roster_in_config(cfg))
        by_pid = {int(c["profile_id"]): c for c in cfg["custom_players"]}
        entry = by_pid[1333418]
        self.assertEqual(entry["original_alias"], "Charles Bronson (Smurf: Chacineiro)")
        self.assertEqual(entry["alias"], "Charles Bronson (Smurf: Chacineiro)")
        self.assertTrue(entry.get("pin_alias"))
        self.assertNotIn("merged_into_profile_id", entry)
        self.assertNotIn("merged_into_steam_id", entry)
        self.assertNotIn("show_smurf_alias", entry)
        self.assertFalse(monitor.ensure_core_roster_in_config(cfg))

    def test_db_sync_preserves_formatted_alias_and_resets_baseline_on_reactivation(self) -> None:
        from database import MatchDatabase

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "smurf_sync.db")
            players_cfg = [
                {
                    "profile_id": 79327,
                    "alias": "Chacineiro",
                    "original_alias": "Chacineiro",
                    "steam_id": "76561197963172584",
                },
                {
                    "profile_id": 1333418,
                    "alias": "Charles Bronson (Chacineiro)",
                    "original_alias": "Charles Bronson (Chacineiro)",
                    "steam_id": "76561198698969876",
                },
                {
                    "profile_id": 1297821,
                    "alias": "Smurf 1 (General Winter)",
                    "original_alias": "Smurf 1 (General Winter)",
                    "steam_id": "76561198722284920",
                },
            ]
            db.sync_tracked_players(players_cfg)
            db.mark_baseline_synced(79327, "Chacineiro* (NickNovo)")
            db.mark_baseline_synced(1333418, "Charles Bronson (Chacineiro)", steam_id="76561197963172584")
            db.mark_baseline_synced(1297821, "Smurf 1 (General Winter)")

            # Desativa #1297821 removendo da lista ativa
            db.sync_tracked_players(players_cfg[:2])
            row_ch = next(p for p in db.get_active_players() if int(p["profile_id"]) == 79327)
            row_cb = next(p for p in db.get_active_players() if int(p["profile_id"]) == 1333418)
            self.assertEqual(row_ch["alias"], "Chacineiro* (NickNovo)")
            self.assertEqual(row_ch["baseline_synced"], 1)
            self.assertEqual(row_cb["steam_id"], "76561198698969876")
            self.assertEqual(row_cb["alias"], "Charles Bronson (Chacineiro)")
            self.assertEqual(row_cb["baseline_synced"], 1)

            # Ao reativar #1297821, baseline_synced volta a 0 (evita flood de partidas antigas no Discord)
            db.sync_tracked_players(players_cfg)
            active_map = {int(p["profile_id"]): p for p in db.get_active_players()}
            self.assertEqual(active_map[79327]["baseline_synced"], 1)
            self.assertEqual(active_map[1333418]["baseline_synced"], 1)
            self.assertEqual(active_map[1297821]["baseline_synced"], 0)
            self.assertEqual(active_map[1297821]["alias"], "Smurf 1 (General Winter)")
            db.close()

    def test_smurf_of_nick_change_without_pin_alias_and_retroactive_card_patch(self) -> None:
        import time
        from database import MatchDatabase

        # 1. Ao baixar players_roster.json (smurf_of='arc', pin_alias=False), preserva smurf_of
        #    e formata troca de nick como '<NovoNick> (Smurf: arc)' (nunca '... (Smurf: arc)* (NovoNick)')!
        parsed = relic_api.parse_shared_roster_payload(
            {
                "schema_version": 1,
                "veteranos": [
                    {
                        "profile_id": 1487738,
                        "steam_id": "76561198602236177",
                        "original_alias": "Državljan H (Smurf: arc)",
                        "smurf_of": "arc",
                        "country": "br",
                        "known_aliases": ["Državljan H", "Državljan H (arc)", "Državljan H (Smurf: arc)"],
                    },
                    {
                        "profile_id": 1482961,
                        "steam_id": "76561199886227102",
                        "original_alias": "Vog (Smurf: arc)",
                        "smurf_of": "arc",
                        "country": "br",
                        "known_aliases": ["Vog", "Vog (arc)", "Vog (Smurf: arc)"],
                    },
                ],
            }
        )
        by_pid = {int(r["profile_id"]): r for r in parsed}
        self.assertEqual(by_pid[1487738].get("smurf_of"), "arc")
        self.assertEqual(by_pid[1482961].get("smurf_of"), "arc")
        self.assertFalse(by_pid[1487738].get("pin_alias"))

        self.assertEqual(
            relic_api.format_bound_display_alias(
                "Državljan H",
                "Državljan H (Smurf: arc)",
                ["Državljan H"],
                pin_alias=False,
                smurf_of="arc",
            ),
            "Državljan H (Smurf: arc)",
        )
        self.assertEqual(
            relic_api.format_bound_display_alias(
                "NovoDisfarceArc",
                "Vog (Smurf: arc)",
                ["Vog"],
                pin_alias=False,
                smurf_of="arc",
            ),
            "NovoDisfarceArc (Smurf: arc)",
        )

        # 2. Card já postado antes da promoção de Državljan H é atualizado silenciosamente via PATCH
        #    com preservação de Battlegroups e idempotência na 2ª execução!
        now_ts = int(time.time()) - 1800
        patched_calls: list[tuple[str, dict]] = []

        class _FakeDiscord:
            is_configured = True

            def edit_match_card(self, message_id: str, grp: dict) -> str:
                patched_calls.append((message_id, grp))
                return message_id

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "retro_roster.db")
            db.sync_tracked_players(
                [
                    {
                        "profile_id": 1022333,
                        "alias": "gaules",
                        "original_alias": "gaules",
                        "steam_id": "76561198264285149",
                    },
                    {
                        "profile_id": 1487738,
                        "alias": "Državljan H (Smurf: arc)",
                        "original_alias": "Državljan H (Smurf: arc)",
                        "steam_id": "76561198602236177",
                    },
                ]
            )
            match_before = {
                "match_id": 92725814,
                "tracked_profile_id": 1022333,
                "tracked_alias": "gaules",
                "tracked_steam_id": "76561198264285149",
                "tracked_faction": "DAK",
                "tracked_faction_short": "DAK",
                "win": True,
                "resulttype": 1,
                "mode": "Team Games (3v3)",
                "matchtype_id": 3,
                "map_raw": "gazala",
                "map_clean": "Gazala Landing Ground",
                "start_time": now_ts - 600,
                "completion_time": now_ts,
                "duration_sec": 600,
                "old_elo": 1407,
                "new_elo": 1420,
                "allies": [
                    {
                        "profile_id": 1487738,
                        "alias": "Državljan H",
                        "steam_id": "76561198602236177",
                        "country": "br",
                        "faction": "Wehrmacht",
                    }
                ],
                "opponents": [
                    {
                        "profile_id": 90823,
                        "alias": "Superboy",
                        "steam_id": "76561198000090823",
                        "country": "ca",
                        "faction": "British Forces",
                    }
                ],
                "has_replay": True,
                "coh3stats_url": "https://coh3stats.com/players/1022333/matches/92725814",
                "battlegroups": {
                    "1022333": {"key": "panzerjager_kommand_ak", "name": "Panzerjäger Kommand"},
                    "1487738": {"key": "terror_ger", "name": "Terror"},
                },
            }
            db.insert_match(match_before, discord_message_id="1574624180224266240")
            # Linha irmã SEEDED sem BG herda Snowflake e BG automaticamente!
            match_sibling = dict(match_before)
            match_sibling["tracked_profile_id"] = 1487738
            match_sibling["tracked_alias"] = "Državljan H (Smurf: arc)"
            match_sibling["tracked_steam_id"] = "76561198602236177"
            match_sibling["battlegroups"] = None
            db.insert_match(match_sibling, discord_message_id="SEEDED")

            roster_maps = relic_api.build_roster_lookup_maps()
            patched = monitor.refresh_recent_cards_after_roster_changes(
                db=db,
                discord=_FakeDiscord(),  # type: ignore[arg-type]
                roster_maps=roster_maps,
                max_age_sec=72 * 3600,
            )
            self.assertEqual(patched, 1)
            self.assertEqual(len(patched_calls), 1)
            msg_id, patched_grp = patched_calls[0]
            self.assertEqual(msg_id, "1574624180224266240")
            gaules_rec = next(r for r in patched_grp["records"] if int(r["tracked_profile_id"]) == 1022333)
            self.assertEqual(gaules_rec["allies"][0]["alias"], "Državljan H (Smurf: arc)")
            self.assertEqual(gaules_rec["battlegroups"]["1487738"]["key"], "terror_ger")

            # Segunda chamada sem mudança de roster -> 0 PATCHes (idempotente)
            patched_again = monitor.refresh_recent_cards_after_roster_changes(
                db=db,
                discord=_FakeDiscord(),  # type: ignore[arg-type]
                roster_maps=roster_maps,
                max_age_sec=72 * 3600,
            )
            self.assertEqual(patched_again, 0)
            db.close()


if __name__ == "__main__":
    unittest.main()

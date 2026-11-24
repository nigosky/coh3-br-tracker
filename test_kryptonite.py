import io
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image

import card_renderer
import monitor
from database import MatchDatabase


def _make_match(
    match_id: int,
    tpid: int,
    *,
    alias: str = "Bineto",
    win: bool = False,
    mode: str = "Team Games (4v4)",
    map_clean: str = "Torrente Ruins",
    map_raw: str = "torrente_8p",
    completion_time: int = 1_795_000_000,
    opponents: list[dict] | None = None,
    allies: list[dict] | None = None,
    battlegroups: dict | None = None,
) -> dict:
    return {
        "match_id": match_id,
        "tracked_profile_id": tpid,
        "tracked_steam_id": f"76561198000{tpid:06d}",
        "tracked_alias": alias,
        "tracked_faction": "Wehrmacht",
        "tracked_faction_short": "Wehr",
        "win": win,
        "resulttype": 1 if win else 0,
        "mode": mode,
        "matchtype_id": 23 if "4v4" in mode else (20 if mode == "1v1" else 22),
        "map_raw": map_raw,
        "map_clean": map_clean,
        "start_time": completion_time - 1200,
        "completion_time": completion_time,
        "duration_sec": 1200,
        "old_elo": 1350,
        "new_elo": 1362 if win else 1338,
        "elo_delta": 12 if win else -12,
        "allies": allies if allies is not None else [],
        "opponents": opponents if opponents is not None else [{"profile_id": 9001, "alias": "EnemyOne", "steam_id": "76561198000009001", "country": "de", "faction": "US Forces", "faction_short": "USF", "old_elo": 1350, "new_elo": 1362, "elo_delta": 12}],
        "counters": {},
        "has_replay": False,
        "coh3stats_url": f"https://coh3stats.com/players/{tpid}",
        "battlegroups": battlegroups or {},
    }


class TestKryptoniteFeature(unittest.TestCase):
    def _new_db(self) -> tuple[tempfile.TemporaryDirectory, MatchDatabase]:
        td = tempfile.TemporaryDirectory()
        db = MatchDatabase(Path(td.name) / "test.db")
        return td, db

    def test_victory_and_non_automatch_never_trigger_kryptonite(self) -> None:
        td, db = self._new_db()
        self.addCleanup(td.cleanup)
        tpid = 110078
        for i in range(7):
            db.insert_match(_make_match(100 + i, tpid, win=False, map_clean="Torrente Ruins", completion_time=1_790_000_000 + i * 3600))

        # Vitória no mapa fraco -> NÃO dispara Criptonita
        win_m = _make_match(200, tpid, win=True, map_clean="Torrente Ruins", completion_time=1_790_100_000)
        db.insert_match(win_m)
        grp_win = {"match_id": 200, "primary": win_m, "records": [win_m]}
        self.assertEqual(monitor.enrich_group_with_kryptonite(db, grp_win), [])
        self.assertNotIn("kryptonite", grp_win)

        # Derrota em Custom / Co-Op vs IA -> NÃO dispara Criptonita
        for bad_mode in ("Custom", "Co-Op vs IA"):
            cust_m = _make_match(201, tpid, win=False, mode=bad_mode, map_clean="Torrente Ruins", completion_time=1_790_200_000)
            grp_cust = {"match_id": 201, "primary": cust_m, "records": [cust_m]}
            self.assertEqual(monitor.enrich_group_with_kryptonite(db, grp_cust), [])

    def test_strict_four_tier_cascade_and_nemesis_cross_link(self) -> None:
        td, db = self._new_db()
        self.addCleanup(td.cleanup)
        tpid = 110078
        opp_nem = {"profile_id": 88001, "alias": "Reakly", "steam_id": "76561198000088001", "country": "us", "faction": "US Forces", "faction_short": "USF"}
        opp_plain = {"profile_id": 88002, "alias": "QuietFoe", "steam_id": "76561198000088002", "country": "de", "faction": "US Forces", "faction_short": "USF"}
        ally = {"profile_id": 55693, "alias": "Alface aka BinhoBiceps", "steam_id": "76561197996817129", "country": "br", "faction": "Wehrmacht", "faction_short": "Wehr"}
        bgs = {"88001": {"key": "italian_coastal_ger", "name": "Italian Coastal"}}

        # Semeia fraqueza flagrante simultânea nos 4 níveis:
        # - Reakly enfrentado 2x no mesmo dia UTC (i=0,1) -> Nêmesis ativo!
        # - QuietFoe enfrentado sempre em dias UTC distintos (5 dias diferentes -> NÃO é Nêmesis)
        base_ts = 1_790_000_000
        for i in range(5):
            ts_i = base_ts + (1800 if i == 1 else i * 86400)
            opps_i = [opp_nem] if i == 1 else [opp_nem, opp_plain]
            m = _make_match(
                1000 + i,
                tpid,
                win=False,
                map_clean="Torrente Ruins",
                completion_time=ts_i,
                opponents=opps_i,
                allies=[ally],
                battlegroups=bgs,
            )
            db.insert_match(m)
        # 5º jogo em dia UTC distinto contra QuietFoe (total 5 antes de cur3b -> 6 com cur3b, sempre 1 jogo/dia)
        db.insert_match(
            _make_match(
                1005,
                tpid,
                win=False,
                map_clean="Faymonville",
                completion_time=base_ts + 5 * 86400,
                opponents=[opp_plain],
                allies=[],
                battlegroups={},
            )
        )

        # 1) Tudo qualifica -> Prioridade 1 (MAPA) vence (0V-6D) e carrega nemesis_cross + marca Nêmesis como is_kryptonite!
        cur1 = _make_match(2001, tpid, win=False, map_clean="Torrente Ruins", completion_time=base_ts + 7 * 86400, opponents=[opp_nem], allies=[ally], battlegroups=bgs)
        db.insert_match(cur1)
        grp1 = {"match_id": 2001, "primary": cur1, "records": [cur1]}
        nems1 = monitor.enrich_group_with_nemesis(db, grp1)
        self.assertEqual(len(nems1), 1)
        k1 = monitor.enrich_group_with_kryptonite(db, grp1)
        self.assertEqual(len(k1), 1)
        self.assertEqual(k1[0]["kind"], "map")
        self.assertEqual(k1[0]["label"], "Torrente Ruins")
        self.assertEqual((k1[0]["wins"], k1[0]["losses"]), (0, 6))
        self.assertEqual(k1[0]["loss_streak"], 6)
        self.assertIsInstance(k1[0].get("nemesis_cross"), dict)
        self.assertEqual(k1[0]["nemesis_cross"]["opponent_alias"], "Reakly")
        self.assertTrue(nems1[0].get("is_kryptonite"))

        # 2) Mapa neutro -> cai para Prioridade 2 (BATTLEGROUP inimigo) ainda com combo +Nêmesis!
        cur2 = _make_match(2002, tpid, win=False, map_clean="Twin Beaches", completion_time=base_ts + 8 * 86400, opponents=[opp_nem], allies=[ally], battlegroups=bgs)
        grp2 = {"match_id": 2002, "primary": cur2, "records": [cur2]}
        monitor.enrich_group_with_nemesis(db, grp2)
        k2 = monitor.enrich_group_with_kryptonite(db, grp2)
        self.assertEqual(len(k2), 1)
        self.assertEqual(k2[0]["kind"], "battlegroup")
        self.assertEqual(k2[0]["label"], "Italian Coastal")
        self.assertEqual(k2[0]["bg_key"], "italian_coastal_ger")
        self.assertIsInstance(k2[0].get("nemesis_cross"), dict)

        # 3a) Mapa neutro + sem BG + Nêmesis ativo -> Prioridade 3 como kind='nemesis' (priorizado sobre rival não-Nêmesis)
        cur3 = _make_match(2003, tpid, win=False, map_clean="Twin Beaches", completion_time=base_ts + 9 * 86400, opponents=[opp_plain, opp_nem], allies=[ally], battlegroups={})
        grp3 = {"match_id": 2003, "primary": cur3, "records": [cur3]}
        nems3 = monitor.enrich_group_with_nemesis(db, grp3)
        k3 = monitor.enrich_group_with_kryptonite(db, grp3)
        self.assertEqual(len(k3), 1)
        self.assertEqual(k3[0]["kind"], "nemesis")
        self.assertTrue(k3[0]["is_nemesis"])
        self.assertEqual(k3[0]["label"], "Reakly")
        self.assertTrue(nems3[0].get("is_kryptonite"))

        # 3b) Mapa neutro + sem BG + apenas rival NÃO-Nêmesis (0V-6D em dias separados) -> Prioridade 3 como kind='opponent'
        cur3b = _make_match(2004, tpid, win=False, map_clean="Twin Beaches", completion_time=base_ts + 10 * 86400, opponents=[opp_plain], allies=[ally], battlegroups={})
        grp3b = {"match_id": 2004, "primary": cur3b, "records": [cur3b]}
        k3b = monitor.enrich_group_with_kryptonite(db, grp3b)
        self.assertEqual(len(k3b), 1)
        self.assertEqual(k3b[0]["kind"], "opponent")
        self.assertFalse(k3b[0]["is_nemesis"])
        self.assertEqual(k3b[0]["label"], "QuietFoe")

        # 4) Mapa neutro + sem BG + oponente novo -> cai para Prioridade 4 (PARCEIRO, 0V-6D!)
        new_opp = {"profile_id": 99999, "alias": "RandomGuy", "steam_id": "76561198000099999", "country": "de", "faction": "US Forces", "faction_short": "USF"}
        cur4 = _make_match(2005, tpid, win=False, map_clean="Twin Beaches", completion_time=base_ts + 11 * 86400, opponents=[new_opp], allies=[ally], battlegroups={})
        grp4 = {"match_id": 2005, "primary": cur4, "records": [cur4]}
        k4 = monitor.enrich_group_with_kryptonite(db, grp4)
        self.assertEqual(len(k4), 1)
        self.assertEqual(k4[0]["kind"], "partner")
        self.assertEqual(k4[0]["label"], "Alface aka BinhoBiceps")

        # 5) Simula PATCH retroativo quando o cohdb descobre o BG depois -> sobe automaticamente de Parceiro para BG!
        cur4["battlegroups"] = {"99999": {"key": "italian_coastal_ger", "name": "Italian Coastal"}}
        k4_patched = monitor.enrich_group_with_kryptonite(db, grp4)
        self.assertEqual(len(k4_patched), 1)
        self.assertEqual(k4_patched[0]["kind"], "battlegroup")
        self.assertEqual(k4_patched[0]["label"], "Italian Coastal")

    def test_flagrant_statistical_gate_dedup_and_compaction_resilience(self) -> None:
        td, db = self._new_db()
        self.addCleanup(td.cleanup)
        tpid = 26910

        # Critério estrito 'flagrante': rejeita ruído de amostra pequena (0V-4D, 1V-4D, 1V-5D, 2V-4D, 2V-6D)
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(0, 4, kind="map"))
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(1, 5, kind="map"))
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(2, 4, kind="map"))
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(2, 6, kind="nemesis"))
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(1, 4, kind="partner"))

        # Rejeita WR moderado de jogador que já tem WR geral baixo (ex.: 34% no mapa vs 40% na carreira -> apenas -6pp)
        self.assertFalse(MatchDatabase.is_flagrant_kryptonite(15, 29, kind="map", career_wr_pct=40.0))
        # Aceita o MESMO 15V-29D (34.1% WR) para jogador de 53.5% na carreira (-19.4pp, p=0.024 -> FLAGRANTE!)
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(15, 29, kind="map", career_wr_pct=53.5))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(2, 15, kind="map", career_wr_pct=49.8))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(0, 6, kind="map"))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(0, 5, kind="battlegroup"))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(2, 10, kind="nemesis"))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(2, 21, kind="nemesis", career_wr_pct=61.2))
        self.assertTrue(MatchDatabase.is_flagrant_kryptonite(8, 29, kind="partner", career_wr_pct=52.2))

        # Histórico via tabela kryptonite_matches + deduplicação com recorded_matches (formato compacto [ally_pid])
        inserted = db.insert_kryptonite_matches_batch(
            [
                (tpid, 3001, 1_700_000_000, 0, "Team Games (3v3)", "Oasis Depot", "[55693]"),
                (tpid, 3002, 1_700_010_000, 0, "Team Games (3v3)", "Oasis Depot", "[55693]"),
                (tpid, 3003, 1_700_020_000, 0, "Team Games (3v3)", "Oasis Depot", "[55693]"),
                (tpid, 3004, 1_700_030_000, 0, "Team Games (3v3)", "Oasis Depot", "[55693]"),
                (tpid, 3005, 1_700_040_000, 0, "Team Games (3v3)", "Oasis Depot", "[55693]"),
            ]
        )
        self.assertEqual(inserted, 5)
        # Duplicata do match 3005 em recorded_matches NÃO pode contar duas vezes
        db.insert_match(_make_match(3005, tpid, alias="nigo_BR ᵀᴹ", win=False, mode="Team Games (3v3)", map_clean="Oasis Depot", completion_time=1_700_040_000))
        # Derrota 3006 completa exatamente 0V-6D (não 0V-7D!)
        res = db.get_kryptonite_status(
            tracked_profile_ids=[tpid],
            up_to_completion_time=1_700_050_000,
            up_to_match_id=3006,
            current_win=False,
            current_map_clean="Oasis Depot",
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["kind"], "map")
        self.assertEqual((res["wins"], res["losses"], res["total"]), (0, 6, 6))

        # Dois inimigos usando o mesmo BG na mesma partida devem contar apenas 1 jogo!
        opp1 = {"profile_id": 7001, "alias": "E1", "country": "de", "faction": "Wehrmacht", "faction_short": "Wehr"}
        opp2 = {"profile_id": 7002, "alias": "E2", "country": "de", "faction": "Wehrmacht", "faction_short": "Wehr"}
        double_bg = {
            "7001": {"key": "terror_ger", "name": "Terror"},
            "7002": {"key": "terror_ger", "name": "Terror"},
        }
        old_ts = 1_710_000_000
        for j in range(4):
            db.insert_match(_make_match(4001 + j, tpid, win=False, mode="2v2", map_clean=f"Map{j}", completion_time=old_ts + j * 3600, opponents=[opp1, opp2]))
            # Atualiza BG retroativamente via update_match_battlegroups -> deve gravar enemy_bgs_json permanente!
            db.update_match_battlegroups(4001 + j, double_bg)

        # Apenas 3 jogos (4001, 4002 + 4099) ainda não devem inflar para 6 nem disparar
        res_bg_too_few = db.get_kryptonite_status(
            tracked_profile_ids=[tpid],
            up_to_completion_time=old_ts + 2 * 3600,
            up_to_match_id=4099,
            current_win=False,
            current_map_clean="Twin Beaches",
            current_enemy_battlegroups=[("terror_ger", "Terror")],
        )
        self.assertIsNone(res_bg_too_few)

        # Compactação de 30 dias limpa opponents_json/allies_json de recorded_matches, mas kryptonite_matches preserva BGs!
        db.run_periodic_maintenance(now_ts=old_ts + 60 * 86400, json_retention_days=30)
        res_bg_after_compact = db.get_kryptonite_status(
            tracked_profile_ids=[tpid],
            up_to_completion_time=old_ts + 60 * 86400,
            up_to_match_id=4100,
            current_win=False,
            current_map_clean="Twin Beaches",
            current_enemy_battlegroups=[("terror_ger", "Terror")],
        )
        self.assertIsNotNone(res_bg_after_compact)
        self.assertEqual(res_bg_after_compact["kind"], "battlegroup")
        self.assertEqual((res_bg_after_compact["wins"], res_bg_after_compact["losses"]), (0, 5))

        cov = db.get_kryptonite_coverage_summary()
        self.assertGreaterEqual(cov["total_rows"], 9)
        self.assertGreaterEqual(cov["rows_with_bg"], 4)

    def test_card_renderer_kryptonite_heights_nemesis_synergy_and_victory_guard(self) -> None:
        provider = card_renderer.SteamAvatarProvider(db=None, allow_network=False)
        m = _make_match(5001, 110078, alias="Bineto", win=False, mode="2v2", map_clean="Torrente Ruins")

        base_png = card_renderer.render_single_match_card_png({"match_id": 5001, "primary": m, "records": [m]}, provider)
        base_h = Image.open(io.BytesIO(base_png)).size[1]

        k_map = {
            "triggered": True,
            "priority": 1,
            "kind": "map",
            "label": "Torrente Ruins",
            "bg_key": "",
            "wins": 2,
            "losses": 15,
            "total": 17,
            "win_rate": 11.8,
            "loss_streak": 5,
            "tracked_profile_id": 110078,
            "tracked_alias": "Bineto",
            "nemesis_cross": {"opponent_profile_id": 9001, "opponent_alias": "EnemyOne", "wins": 2, "losses": 10},
        }
        k_nem = {
            "triggered": True,
            "priority": 3,
            "kind": "nemesis",
            "is_nemesis": True,
            "label": "EnemyOne",
            "bg_key": "",
            "wins": 2,
            "losses": 10,
            "total": 12,
            "win_rate": 16.7,
            "loss_streak": 4,
            "tracked_profile_id": 31145,
            "tracked_alias": "vonMises",
        }

        one_k_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m, "records": [m], "kryptonite": k_map, "kryptonite_list": [k_map]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(one_k_png)).size[1], base_h + 42)

        two_k_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m, "records": [m], "kryptonite": k_map, "kryptonite_list": [k_map, k_nem]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(two_k_png)).size[1], base_h + 74)

        # Empilhamento completo: Nemesis com is_kryptonite=True (42) + Criptonita (42) + Alerta Smurf (56)
        nem = {
            "triggered": True,
            "is_new_trigger": True,
            "is_kryptonite": True,
            "wins": 2,
            "losses": 10,
            "total": 12,
            "win_rate": 16.7,
            "same_day_games": 2,
            "opponent_profile_id": 9001,
            "opponent_alias": "EnemyOne",
            "tracked_profile_id": 110078,
            "tracked_alias": "Bineto",
        }
        smurf = {
            "opponent_profile_id": 9001,
            "opponent_alias": "EnemyOne",
            "suspected_main_alias": "Chacineiro",
            "probability_pct": 86,
            "confidence_tier": "Muito Alta",
            "top_reasons": ["Family Sharing", "APM Δ=2.1"],
        }
        stacked_png = card_renderer.render_single_match_card_png(
            {
                "match_id": 5001,
                "primary": m,
                "records": [m],
                "nemesis": nem,
                "nemesis_list": [nem],
                "kryptonite": k_nem,
                "kryptonite_list": [k_nem],
                "smurf_alerts": [smurf],
            },
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(stacked_png)).size[1], base_h + 42 + 42 + 56)

        # Garantia visual: em card de VITÓRIA, mesmo com dict kryptonite injetado, NÃO renderiza faixa CRIPTONITA!
        m_win = dict(m, win=True, resulttype=1)
        win_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m_win, "records": [m_win], "kryptonite": k_map, "kryptonite_list": [k_map]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(win_png)).size[1], base_h)

        # Em partida Custom, Criptonita NÃO deve ser renderizada no card
        m_custom = dict(m, mode="Custom")
        custom_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m_custom, "records": [m_custom], "kryptonite": k_map, "kryptonite_list": [k_map]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(custom_png)).size[1], base_h)


if __name__ == "__main__":
    unittest.main()

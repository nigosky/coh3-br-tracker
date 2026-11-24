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
        for i in range(5):
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

    def test_strict_four_tier_cascade_map_then_bg_then_opponent_then_partner(self) -> None:
        td, db = self._new_db()
        self.addCleanup(td.cleanup)
        tpid = 110078
        opp = {"profile_id": 88001, "alias": "Reakly", "steam_id": "76561198000088001", "country": "us", "faction": "US Forces", "faction_short": "USF"}
        ally = {"profile_id": 55693, "alias": "Alface aka BinhoBiceps", "steam_id": "76561197996817129", "country": "br", "faction": "Wehrmacht", "faction_short": "Wehr"}
        bgs = {"88001": {"key": "italian_coastal_ger", "name": "Italian Coastal"}}

        # Semeia fraqueza simultânea em TODOS os 4 níveis (0V-4D antes da partida atual)
        for i in range(4):
            m = _make_match(
                1000 + i,
                tpid,
                win=False,
                map_clean="Torrente Ruins",
                completion_time=1_790_000_000 + i * 3600,
                opponents=[opp],
                allies=[ally],
                battlegroups=bgs,
            )
            db.insert_match(m)

        # 1) Tudo qualifica -> Prioridade 1 (MAPA) vence
        cur1 = _make_match(2001, tpid, win=False, map_clean="Torrente Ruins", completion_time=1_790_500_000, opponents=[opp], allies=[ally], battlegroups=bgs)
        db.insert_match(cur1)
        grp1 = {"match_id": 2001, "primary": cur1, "records": [cur1]}
        k1 = monitor.enrich_group_with_kryptonite(db, grp1)
        self.assertEqual(len(k1), 1)
        self.assertEqual(k1[0]["kind"], "map")
        self.assertEqual(k1[0]["label"], "Torrente Ruins")
        self.assertEqual((k1[0]["wins"], k1[0]["losses"]), (0, 5))

        # 2) Mapa neutro (sem fraqueza) -> cai para Prioridade 2 (BATTLEGROUP inimigo)
        cur2 = _make_match(2002, tpid, win=False, map_clean="Twin Beaches", completion_time=1_790_600_000, opponents=[opp], allies=[ally], battlegroups=bgs)
        grp2 = {"match_id": 2002, "primary": cur2, "records": [cur2]}
        k2 = monitor.enrich_group_with_kryptonite(db, grp2)
        self.assertEqual(len(k2), 1)
        self.assertEqual(k2[0]["kind"], "battlegroup")
        self.assertEqual(k2[0]["label"], "Italian Coastal")
        self.assertEqual(k2[0]["bg_key"], "italian_coastal_ger")

        # 3) Mapa neutro + sem BG inimigo -> cai para Prioridade 3 (ADVERSÁRIO)
        cur3 = _make_match(2003, tpid, win=False, map_clean="Twin Beaches", completion_time=1_790_700_000, opponents=[opp], allies=[ally], battlegroups={})
        grp3 = {"match_id": 2003, "primary": cur3, "records": [cur3]}
        k3 = monitor.enrich_group_with_kryptonite(db, grp3)
        self.assertEqual(len(k3), 1)
        self.assertEqual(k3[0]["kind"], "opponent")
        self.assertEqual(k3[0]["label"], "Reakly")
        self.assertEqual(k3[0]["losses"], 6)

        # 4) Mapa neutro + sem BG + adversário novo (1 jogo só) -> cai para Prioridade 4 (PARCEIRO!)
        new_opp = {"profile_id": 99999, "alias": "RandomGuy", "steam_id": "76561198000099999", "country": "de", "faction": "US Forces", "faction_short": "USF"}
        cur4 = _make_match(2004, tpid, win=False, map_clean="Twin Beaches", completion_time=1_790_800_000, opponents=[new_opp], allies=[ally], battlegroups={})
        grp4 = {"match_id": 2004, "primary": cur4, "records": [cur4]}
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

    def test_thresholds_dedup_and_kryptonite_history_table(self) -> None:
        td, db = self._new_db()
        self.addCleanup(td.cleanup)
        tpid = 26910

        # 0V-3D não dispara (abaixo de 4 derrotas); 0V-4D dispara!
        self.assertFalse(MatchDatabase._is_kryptonite_weakness(0, 3, max_wr_pct=35.0))
        self.assertTrue(MatchDatabase._is_kryptonite_weakness(0, 4, max_wr_pct=35.0))
        self.assertFalse(MatchDatabase._is_kryptonite_weakness(1, 3, max_wr_pct=35.0))
        self.assertTrue(MatchDatabase._is_kryptonite_weakness(1, 4, max_wr_pct=35.0))
        self.assertFalse(MatchDatabase._is_kryptonite_weakness(2, 3, max_wr_pct=35.0))  # 40% > 35%
        self.assertTrue(MatchDatabase._is_kryptonite_weakness(2, 4, max_wr_pct=35.0))   # 33.3% <= 35%
        self.assertFalse(MatchDatabase._is_kryptonite_weakness(2, 4, max_wr_pct=30.0))  # 33.3% > 30% (rival/parceiro)
        self.assertTrue(MatchDatabase._is_kryptonite_weakness(3, 7, max_wr_pct=30.0))   # 30.0% <= 30%

        # Histórico via tabela kryptonite_matches + deduplicação com recorded_matches
        inserted = db.insert_kryptonite_matches_batch(
            [
                (tpid, 3001, 1_780_000_000, 0, "Team Games (3v3)", "Oasis Depot", "[]"),
                (tpid, 3002, 1_780_010_000, 0, "Team Games (3v3)", "Oasis Depot", "[]"),
                (tpid, 3003, 1_780_020_000, 0, "Team Games (3v3)", "Oasis Depot", "[]"),
            ]
        )
        self.assertEqual(inserted, 3)
        # Duplicata do match 3003 em recorded_matches NÃO pode contar duas vezes
        db.insert_match(_make_match(3003, tpid, alias="nigo_BR ᵀᴹ", win=False, mode="Team Games (3v3)", map_clean="Oasis Depot", completion_time=1_780_020_000))
        # Derrota 3004 completa exatamente 0V-4D (não 0V-5D!)
        cur = _make_match(3004, tpid, alias="nigo_BR ᵀᴹ", win=False, mode="Team Games (3v3)", map_clean="Oasis Depot", completion_time=1_780_050_000)
        res = db.get_kryptonite_status(
            tracked_profile_ids=[tpid],
            up_to_completion_time=1_780_050_000,
            up_to_match_id=3004,
            current_win=False,
            current_map_clean="Oasis Depot",
        )
        self.assertIsNotNone(res)
        self.assertEqual(res["kind"], "map")
        self.assertEqual((res["wins"], res["losses"], res["total"]), (0, 4, 4))

        # Dois inimigos usando o mesmo BG na mesma partida devem contar apenas 1 jogo!
        opp1 = {"profile_id": 7001, "alias": "E1", "country": "de", "faction": "Wehrmacht", "faction_short": "Wehr"}
        opp2 = {"profile_id": 7002, "alias": "E2", "country": "de", "faction": "Wehrmacht", "faction_short": "Wehr"}
        double_bg = {
            "7001": {"key": "terror_ger", "name": "Terror"},
            "7002": {"key": "terror_ger", "name": "Terror"},
        }
        db.insert_match(_make_match(4001, tpid, win=False, mode="2v2", map_clean="Semois", completion_time=1_781_000_000, opponents=[opp1, opp2], battlegroups=double_bg))
        db.insert_match(_make_match(4002, tpid, win=False, mode="2v2", map_clean="Semois", completion_time=1_781_010_000, opponents=[opp1, opp2], battlegroups=double_bg))
        res_bg_too_few = db.get_kryptonite_status(
            tracked_profile_ids=[tpid],
            up_to_completion_time=1_781_020_000,
            up_to_match_id=4003,
            current_win=False,
            current_map_clean="Twin Beaches",
            current_enemy_battlegroups=[("terror_ger", "Terror")],
        )
        # Apenas 3 jogos (4001, 4002, 4003) -> não deve inflar para 6 nem disparar ainda!
        self.assertIsNone(res_bg_too_few)

    def test_card_renderer_kryptonite_heights_and_stacking(self) -> None:
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
            "wins": 3,
            "losses": 7,
            "total": 10,
            "win_rate": 30.0,
            "tracked_profile_id": 110078,
            "tracked_alias": "Bineto",
        }
        k_bg = {
            "triggered": True,
            "priority": 2,
            "kind": "battlegroup",
            "label": "Italian Coastal",
            "bg_key": "italian_coastal_ger",
            "wins": 2,
            "losses": 6,
            "total": 8,
            "win_rate": 25.0,
            "tracked_profile_id": 31145,
            "tracked_alias": "vonMises",
        }

        one_k_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m, "records": [m], "kryptonite": k_map, "kryptonite_list": [k_map]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(one_k_png)).size[1], base_h + 42)

        two_k_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m, "records": [m], "kryptonite": k_map, "kryptonite_list": [k_map, k_bg]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(two_k_png)).size[1], base_h + 74)

        # Empilhamento completo: Nemesis (42) + Criptonita (42) + Alerta Smurf (56)
        nem = {
            "triggered": True,
            "is_new_trigger": True,
            "wins": 1,
            "losses": 4,
            "total": 5,
            "win_rate": 20.0,
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
                "kryptonite": k_bg,
                "kryptonite_list": [k_bg],
                "smurf_alerts": [smurf],
            },
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(stacked_png)).size[1], base_h + 42 + 42 + 56)

        # Em partida Custom, Criptonita NÃO deve ser renderizada no card
        m_custom = dict(m, mode="Custom")
        custom_png = card_renderer.render_single_match_card_png(
            {"match_id": 5001, "primary": m_custom, "records": [m_custom], "kryptonite": k_map, "kryptonite_list": [k_map]},
            provider,
        )
        self.assertEqual(Image.open(io.BytesIO(custom_png)).size[1], base_h)


if __name__ == "__main__":
    unittest.main()

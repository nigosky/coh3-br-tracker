"""Testes unitários da regra oficial de 1v1 Nemesis (trigger 2x/dia UTC, Steam-only e card gráfico)."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from PIL import Image

import card_renderer
from database import MatchDatabase
from monitor import enrich_group_with_nemesis


def _make_match(
    match_id: int,
    tracked_pid: int,
    tracked_alias: str,
    opp_pid: int,
    opp_alias: str,
    opp_steam_id: str,
    completion_time: int,
    win: bool,
    mode: str = "1v1",
) -> dict:
    return {
        "match_id": match_id,
        "tracked_profile_id": tracked_pid,
        "tracked_alias": tracked_alias,
        "tracked_steam_id": "76561198070545853",
        "tracked_faction": "US Forces",
        "tracked_faction_short": "USF",
        "win": win,
        "resulttype": 1 if win else 0,
        "mode": mode,
        "matchtype_id": 20 if mode == "1v1" else 21,
        "map_raw": "angoville_farms_2p",
        "map_clean": "Angoville Farms",
        "start_time": completion_time - 900,
        "completion_time": completion_time,
        "duration_sec": 900,
        "old_elo": 1400,
        "new_elo": 1414 if win else 1386,
        "allies": [],
        "opponents": [
            {
                "profile_id": opp_pid,
                "alias": opp_alias,
                "steam_id": opp_steam_id,
                "country": "de",
                "faction": "Wehrmacht",
                "faction_short": "Wehr",
                "old_elo": 1410,
                "new_elo": 1396 if win else 1424,
                "elo_delta": -14 if win else 14,
            }
        ],
        "has_replay": True,
        "coh3stats_url": f"https://coh3stats.com/matches/{match_id}",
    }


class TestNemesis1v1(unittest.TestCase):
    def test_trigger_requires_two_games_same_utc_day_and_persists_afterwards(self) -> None:
        day_base = 20_000 * 86400  # 00:00 UTC exato
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "nemesis.db")
            opp_sid = "76561198000011111"

            # Dia 1: 1 jogo -> não dispara Nemesis
            m1 = _make_match(101, 900358, "Margheriti", 777001, "RivalOldNick", opp_sid, day_base + 3600, True)
            db.insert_match(m1)
            self.assertIsNone(
                db.get_1v1_nemesis_status([900358], 777001, m1["completion_time"], m1["match_id"], "RivalOldNick", opp_sid)
            )

            # Dia 2 (outro dia UTC): 1 jogo -> ainda 1 jogo por dia UTC -> NÃO dispara Nemesis!
            m2 = _make_match(102, 900358, "Margheriti", 777001, "RivalMidNick", opp_sid, day_base + 86400 + 3600, False)
            db.insert_match(m2)
            self.assertIsNone(
                db.get_1v1_nemesis_status([900358], 777001, m2["completion_time"], m2["match_id"], "RivalMidNick", opp_sid)
            )

            # Dia 2 (MESMO dia UTC): 2º jogo no dia -> DISPARA NOVO NEMESIS e conta TODOS os 1v1!
            m3 = _make_match(103, 900358, "Margheriti", 777001, "RivalNewNick", opp_sid, day_base + 86400 + 7200, True)
            db.insert_match(m3)
            st3 = db.get_1v1_nemesis_status([900358], 777001, m3["completion_time"], m3["match_id"], "RivalNewNick", opp_sid)
            self.assertIsNotNone(st3)
            assert st3 is not None
            self.assertTrue(st3["triggered"])
            self.assertTrue(st3["is_new_trigger"])
            self.assertEqual(st3["wins"], 2)
            self.assertEqual(st3["losses"], 1)
            self.assertEqual(st3["total"], 3)
            self.assertEqual(st3["same_day_games"], 2)
            self.assertEqual(st3["opponent_alias"], "RivalNewNick")

            # Dia 5 (após trigger): 4º jogo -> continua contando como NEMESIS ATIVO e atualiza alias
            m4 = _make_match(104, 900358, "Margheriti", 777001, "RivalLatest", opp_sid, day_base + 4 * 86400 + 1800, False)
            db.insert_match(m4)
            st4 = db.get_1v1_nemesis_status([900358], 777001, m4["completion_time"], m4["match_id"], "RivalLatest", opp_sid)
            self.assertIsNotNone(st4)
            assert st4 is not None
            self.assertTrue(st4["triggered"])
            self.assertFalse(st4["is_new_trigger"])
            self.assertEqual((st4["wins"], st4["losses"], st4["total"]), (2, 2, 4))
            self.assertEqual(st4["same_day_games"], 1)
            self.assertEqual(st4["opponent_alias"], "RivalLatest")

            # Compactação de 30 dias em recorded_matches NÃO perde histórico Nemesis
            db.run_periodic_maintenance(now_ts=day_base + 40 * 86400, json_retention_days=14)
            st4_after = db.get_1v1_nemesis_status([900358], 777001, m4["completion_time"], m4["match_id"], "RivalLatest", opp_sid)
            self.assertIsNotNone(st4_after)
            assert st4_after is not None
            self.assertEqual(st4_after["total"], 4)

    def test_non_steam_and_team_games_are_ignored(self) -> None:
        day_base = 20_005 * 86400
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "nemesis_filter.db")
            # Oponente sem SteamID64 válido -> ignorado (Only Steam players are tracked)
            for idx in range(2):
                m = _make_match(200 + idx, 900358, "Margheriti", 888001, "ConsolePlayer", "", day_base + idx * 1200, True)
                db.insert_match(m)
            self.assertIsNone(db.get_1v1_nemesis_status([900358], 888001, day_base + 2400, 201))

            # Partida 2v2 -> ignorada
            for idx in range(2):
                m = _make_match(300 + idx, 900358, "Margheriti", 888002, "SteamOpp", "76561198000022222", day_base + idx * 1200, True, mode="2v2")
                db.insert_match(m)
            self.assertIsNone(db.get_1v1_nemesis_status([900358], 888002, day_base + 2400, 301))

    def test_card_renderer_adds_nemesis_footer_bar_height(self) -> None:
        day_base = 20_010 * 86400
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "nemesis_card.db")
            ap = card_renderer.SteamAvatarProvider(db, allow_network=False)
            opp_sid = "76561198000033333"
            m1 = _make_match(401, 900358, "Margheriti", 777009, "Hans_DE", opp_sid, day_base + 1000, True)
            m2 = _make_match(402, 900358, "Margheriti", 777009, "Hans_DE", opp_sid, day_base + 2500, False)
            db.insert_match(m1)
            db.insert_match(m2)

            grp_plain = {"match_id": 401, "primary": dict(m1), "records": [dict(m1)]}
            self.assertIsNone(enrich_group_with_nemesis(db, grp_plain))
            im_plain = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_plain, ap)))

            grp_nem = {"match_id": 402, "primary": dict(m2), "records": [dict(m2)]}
            nem = enrich_group_with_nemesis(db, grp_nem)
            self.assertIsNotNone(nem)
            im_nem = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_nem, ap)))

            self.assertEqual(im_plain.width, 940)
            self.assertEqual(im_nem.width, 940)
            self.assertEqual(im_nem.height - im_plain.height, 42)


if __name__ == "__main__":
    unittest.main()

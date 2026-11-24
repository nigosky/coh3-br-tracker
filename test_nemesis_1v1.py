"""Testes unitários das regras vitalícias (2023+) de Nêmesis e Freguês em todos os modos Automatch e card gráfico."""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path

from PIL import Image

import card_renderer
from database import MatchDatabase
from monitor import enrich_group_with_fregues, enrich_group_with_nemesis


def _make_match(
    match_id: int,
    tracked_pid: int,
    tracked_alias: str,
    opponents: list[tuple[int, str, str]],
    completion_time: int,
    win: bool,
    mode: str = "1v1",
    allies: list[tuple[int, str, str]] | None = None,
) -> dict:
    mt_map = {"1v1": 20, "2v2": 21, "Team Games (3v3)": 22, "Team Games (4v4)": 23, "Custom": 0}
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
        "matchtype_id": mt_map.get(mode, 20),
        "map_raw": "angoville_farms_2p",
        "map_clean": "Angoville Farms",
        "start_time": completion_time - 900,
        "completion_time": completion_time,
        "duration_sec": 900,
        "old_elo": 1400,
        "new_elo": 1414 if win else 1386,
        "allies": [
            {
                "profile_id": pid,
                "alias": al,
                "steam_id": sid,
                "country": "br",
                "faction": "British Forces",
                "faction_short": "UKF",
                "old_elo": 1390,
                "new_elo": 1404 if win else 1376,
                "elo_delta": 14 if win else -14,
            }
            for pid, al, sid in (allies or [])
        ],
        "opponents": [
            {
                "profile_id": opp_pid,
                "alias": opp_alias,
                "steam_id": opp_sid,
                "country": "de",
                "faction": "Wehrmacht",
                "faction_short": "Wehr",
                "old_elo": 1410,
                "new_elo": 1396 if win else 1424,
                "elo_delta": -14 if win else 14,
            }
            for opp_pid, opp_alias, opp_sid in opponents
        ],
        "has_replay": True,
        "coh3stats_url": f"https://coh3stats.com/matches/{match_id}",
    }


class TestNemesisAndFreguesLifetime(unittest.TestCase):
    def test_symmetric_dominance_thresholds_reject_noise_and_balanced_scores(self) -> None:
        # Rejeita amostras pequenas ou confrontos equilibrados (mesmo jogando várias vezes no mesmo dia)
        for w, l in [(0, 1), (0, 2), (0, 3), (1, 1), (1, 2), (2, 1), (1, 3), (3, 1), (2, 4), (4, 2), (3, 5), (5, 3), (10, 15), (15, 10)]:
            self.assertFalse(MatchDatabase.is_nemesis_record(w, l), f"Nemesis não deve disparar em {w}V-{l}D")
            self.assertFalse(MatchDatabase.is_fregues_record(w, l), f"Freguês não deve disparar em {w}V-{l}D")

        # Aceita domínio recorrente real em Nêmesis (Veterano apanhando) e Freguês (adversário apanhando)
        for dom, und in [(4, 0), (5, 0), (4, 1), (5, 1), (5, 2), (6, 3), (8, 4), (10, 5), (13, 7), (15, 4), (21, 2)]:
            self.assertTrue(MatchDatabase.is_nemesis_record(und, dom), f"Nemesis deveria disparar em {und}V-{dom}D")
            self.assertFalse(MatchDatabase.is_fregues_record(und, dom), f"Freguês nunca pode coexistir em {und}V-{dom}D")
            self.assertTrue(MatchDatabase.is_fregues_record(dom, und), f"Freguês deveria disparar em {dom}V-{und}D")
            self.assertFalse(MatchDatabase.is_nemesis_record(dom, und), f"Nemesis nunca pode coexistir em {dom}V-{und}D")

    def test_nemesis_and_fregues_work_across_years_without_same_day_requirement(self) -> None:
        # Confrontos espaçados ao longo de 2023, 2024, 2025 e 2026 (NUNCA 2 jogos no mesmo dia!)
        ts_2023 = 1_690_000_000  # Jul/2023
        ts_2024 = 1_715_000_000  # Mai/2024
        ts_2025 = 1_745_000_000  # Abr/2025
        ts_2026_a = 1_775_000_000  # Abr/2026
        ts_2026_b = 1_795_000_000  # Nov/2026

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "rivalry.db")
            nem_sid = "76561198000011111"
            freg_sid = "76561198000022222"

            # 1) NÊMESIS ao longo de 4 anos e 4 modos diferentes (0V-4D sem NENHUM dia repetido!)
            nem_schedule = [
                (101, ts_2023, False, "2v2", "Algoz2023"),
                (102, ts_2024, False, "Team Games (3v3)", "Algoz2024"),
                (103, ts_2025, False, "Team Games (4v4)", "Algoz2025"),
                (104, ts_2026_a, False, "1v1", "Algoz2026"),
                (105, ts_2026_b, True, "2v2", "AlgozAtual"),
            ]
            for idx, (mid, ts, win_flag, mode, nick) in enumerate(nem_schedule):
                m = _make_match(mid, 900358, "Margheriti", [(777001, nick, nem_sid)], ts, win_flag, mode=mode)
                db.insert_match(m)
                st_nem = db.get_nemesis_status([900358], 777001, ts, mid, nick, nem_sid)
                st_freg = db.get_fregues_status([900358], 777001, ts, mid, nick, nem_sid)
                self.assertIsNone(st_freg)
                if idx < 3:
                    # 0V-1D, 0V-2D, 0V-3D -> ainda não atinge domínio recorrente
                    self.assertIsNone(st_nem)
                elif idx == 3:
                    # 4ª derrota (0V-4D, 1 jogo por ano!) -> DISPARA NOVO NEMESIS!
                    self.assertIsNotNone(st_nem)
                    assert st_nem is not None
                    self.assertTrue(st_nem["triggered"])
                    self.assertEqual(st_nem["kind"], "nemesis")
                    self.assertTrue(st_nem["is_new_trigger"])
                    self.assertEqual((st_nem["wins"], st_nem["losses"], st_nem["total"]), (0, 4, 4))
                    self.assertEqual(st_nem["same_day_games"], 1)
                    self.assertEqual(st_nem["since_year"], 2023)
                    self.assertEqual(st_nem["loss_streak"], 4)
                    self.assertEqual(st_nem["opponent_alias"], "Algoz2026")
                    self.assertEqual(st_nem["modes"], ["1v1", "2v2", "Team Games (3v3)", "Team Games (4v4)"])
                else:
                    # 5º jogo: Veterano finalmente vence (1V-4D, 20% WR) -> continua NEMESIS ativo (não mais NOVO)
                    self.assertIsNotNone(st_nem)
                    assert st_nem is not None
                    self.assertTrue(st_nem["triggered"])
                    self.assertFalse(st_nem["is_new_trigger"])
                    self.assertEqual((st_nem["wins"], st_nem["losses"], st_nem["total"]), (1, 4, 5))
                    self.assertEqual(st_nem["loss_streak"], 0)
                    self.assertEqual(st_nem["win_streak"], 1)
                    self.assertEqual(st_nem["opponent_alias"], "AlgozAtual")

            # 2) FREGUÊS ao longo de 4 anos (1V-0D -> 1V-1D -> 2V-1D -> 3V-1D -> 4V-1D -> 5V-1D)
            freg_schedule = [
                (201, ts_2023, True, "1v1", "FregOld"),
                (202, ts_2024, False, "2v2", "FregMid"),
                (203, ts_2025, True, "Team Games (3v3)", "Freg2025"),
                (204, ts_2026_a, True, "Team Games (4v4)", "Freg2026"),
                (205, ts_2026_b, True, "2v2", "FregNovo"),
                (206, ts_2026_b + 86400, True, "1v1", "FregAtual"),
            ]
            for idx, (mid, ts, win_flag, mode, nick) in enumerate(freg_schedule):
                m = _make_match(mid, 900358, "Margheriti", [(777002, nick, freg_sid)], ts, win_flag, mode=mode)
                db.insert_match(m)
                st_nem = db.get_nemesis_status([900358], 777002, ts, mid, nick, freg_sid)
                st_freg = db.get_fregues_status([900358], 777002, ts, mid, nick, freg_sid)
                self.assertIsNone(st_nem)
                if idx < 4:
                    # Até 3V-1D (4 jogos, saldo +2) -> ainda não dispara Freguês
                    self.assertIsNone(st_freg)
                elif idx == 4:
                    # 4V-1D (5 jogos, saldo +3, 80% WR) -> DISPARA NOVO FREGUÊS!
                    self.assertIsNotNone(st_freg)
                    assert st_freg is not None
                    self.assertTrue(st_freg["triggered"])
                    self.assertEqual(st_freg["kind"], "fregues")
                    self.assertTrue(st_freg["is_new_trigger"])
                    self.assertEqual((st_freg["wins"], st_freg["losses"], st_freg["total"]), (4, 1, 5))
                    self.assertEqual(st_freg["since_year"], 2023)
                    self.assertEqual(st_freg["win_streak"], 3)
                    self.assertEqual(st_freg["opponent_alias"], "FregNovo")
                else:
                    # 5V-1D (6 jogos, 83.3% WR, 4V seg.) -> continua FREGUÊS ativo (is_new_trigger=False)
                    self.assertIsNotNone(st_freg)
                    assert st_freg is not None
                    self.assertTrue(st_freg["triggered"])
                    self.assertFalse(st_freg["is_new_trigger"])
                    self.assertEqual((st_freg["wins"], st_freg["losses"], st_freg["total"]), (5, 1, 6))
                    self.assertEqual(st_freg["win_streak"], 4)
                    self.assertEqual(st_freg["opponent_alias"], "FregAtual")

            # Compactação de recorded_matches NÃO apaga histórico de Nêmesis nem de Freguês
            db.run_periodic_maintenance(now_ts=ts_2026_b + 60 * 86400, json_retention_days=14)
            st_nem_after = db.get_nemesis_status([900358], 777001, ts_2026_b, 105, "AlgozAtual", nem_sid)
            st_freg_after = db.get_fregues_status([900358], 777002, ts_2026_b + 86400, 206, "FregAtual", freg_sid)
            self.assertIsNotNone(st_nem_after)
            self.assertIsNotNone(st_freg_after)
            assert st_nem_after is not None and st_freg_after is not None
            self.assertEqual(st_nem_after["total"], 5)
            self.assertEqual(st_freg_after["total"], 6)

    def test_non_steam_and_custom_games_are_ignored_for_both_nemesis_and_fregues(self) -> None:
        day_base = 20_005 * 86400
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "rivalry_filter.db")
            # Oponente sem SteamID64 válido -> ignorado (Steam-only)
            for idx in range(5):
                m = _make_match(200 + idx, 900358, "Margheriti", [(888001, "ConsolePlayer", "")], day_base + idx * 86400, True, mode="2v2")
                db.insert_match(m)
            self.assertIsNone(db.get_fregues_status([900358], 888001, day_base + 5 * 86400, 204))
            self.assertIsNone(db.get_nemesis_status([900358], 888001, day_base + 5 * 86400, 204))

            # Partida Custom -> ignorada tanto para Nêmesis quanto para Freguês
            for idx in range(5):
                m = _make_match(300 + idx, 900358, "Margheriti", [(888002, "CustomFriend", "76561198000022222")], day_base + idx * 86400, False, mode="Custom")
                db.insert_match(m)
            self.assertIsNone(db.get_nemesis_status([900358], 888002, day_base + 5 * 86400, 304))
            self.assertIsNone(db.get_fregues_status([900358], 888002, day_base + 5 * 86400, 304))

    def test_card_renderer_nemesis_and_fregues_heights_stacking_and_distinct_colors(self) -> None:
        day_base = 20_010 * 86400
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "rivalry_card.db")
            ap = card_renderer.SteamAvatarProvider(db, allow_network=False)
            opps_2v2 = [
                (777009, "Hans_DE", "76561198000033333"),
                (777010, "Fritz_DE", "76561198000033334"),
            ]
            ally_2v2 = [(79327, "Chacineiro", "76561197963172584")]

            # 4 derrotas em dias separados contra ambos os oponentes -> ambos viram NÊMESIS (0V-4D)
            last_nem_m = None
            for idx in range(4):
                m = _make_match(401 + idx, 900358, "Margheriti", opps_2v2, day_base + idx * 86400, False, mode="2v2", allies=ally_2v2)
                db.insert_match(m)
                last_nem_m = m
            assert last_nem_m is not None

            m_first = _make_match(401, 900358, "Margheriti", opps_2v2, day_base, False, mode="2v2", allies=ally_2v2)
            grp_plain = {"match_id": 401, "primary": dict(m_first), "records": [dict(m_first)]}
            self.assertEqual(enrich_group_with_nemesis(db, grp_plain), [])
            self.assertEqual(enrich_group_with_fregues(db, grp_plain), [])
            im_plain = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_plain, ap)))

            # Em #404, AMBOS os oponentes viraram Nêmesis -> faixa dupla (+74px)
            grp_nem_2 = {"match_id": 404, "primary": dict(last_nem_m), "records": [dict(last_nem_m)]}
            nems = enrich_group_with_nemesis(db, grp_nem_2)
            fregs_empty = enrich_group_with_fregues(db, grp_nem_2)
            self.assertEqual(len(nems), 2)
            self.assertEqual(fregs_empty, [])
            im_nem_2 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_nem_2, ap)))
            self.assertEqual(im_nem_2.height - im_plain.height, 74)

            # Com 1 único rival Nêmesis -> faixa simples (+42px)
            grp_nem_1 = {
                "match_id": 404,
                "primary": dict(last_nem_m, nemesis=nems[0], nemesis_list=[nems[0]]),
                "records": [dict(last_nem_m, nemesis=nems[0], nemesis_list=[nems[0]])],
                "nemesis": nems[0],
                "nemesis_list": [nems[0]],
            }
            im_nem_1 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_nem_1, ap)))
            self.assertEqual(im_nem_1.height - im_plain.height, 42)

            # Agora 4 vitórias de Chacineiro em dias separados contra os mesmos 2 oponentes -> ambos viram FREGUÊS!
            last_freg_m = None
            for idx in range(4):
                mf = _make_match(
                    501 + idx,
                    79327,
                    "Chacineiro",
                    opps_2v2,
                    day_base + (10 + idx) * 86400,
                    True,
                    mode="2v2",
                    allies=[(900358, "Margheriti", "76561198070545853")],
                )
                db.insert_match(mf)
                last_freg_m = mf
            assert last_freg_m is not None

            grp_freg_2 = {"match_id": 504, "primary": dict(last_freg_m), "records": [dict(last_freg_m)]}
            fregs = enrich_group_with_fregues(db, grp_freg_2)
            self.assertEqual(len(fregs), 2)
            self.assertTrue(all(f["is_new_trigger"] for f in fregs))
            im_freg_2 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_freg_2, ap)))
            self.assertEqual(im_freg_2.height - im_plain.height, 74)

            grp_freg_1 = {
                "match_id": 504,
                "primary": dict(last_freg_m, fregues=fregs[0], fregues_list=[fregs[0]]),
                "records": [dict(last_freg_m, fregues=fregs[0], fregues_list=[fregs[0]])],
                "fregues": fregs[0],
                "fregues_list": [fregs[0]],
            }
            im_freg_1 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_freg_1, ap)))
            self.assertEqual(im_freg_1.height - im_plain.height, 42)

            # Empilhamento simultâneo Nêmesis (+42) + Freguês (+42) e verificação de cores claramente distintas!
            grp_both = {
                "match_id": 504,
                "primary": dict(last_freg_m),
                "records": [dict(last_freg_m)],
                "nemesis": nems[0],
                "nemesis_list": [nems[0]],
                "fregues": fregs[0],
                "fregues_list": [fregs[0]],
            }
            im_both = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_both, ap)))
            self.assertEqual(im_both.height - im_plain.height, 42 + 42)

            # Verifica a faixa lateral esquerda (x=4): Nemesis é carmesim (R alto, G/B baixos)
            # e Freguês é turquesa/teal (G e B altos, R baixo) -> impossível confundir!
            nem_left_px = im_both.getpixel((4, im_plain.height + 20))
            freg_left_px = im_both.getpixel((4, im_plain.height + 42 + 20))
            self.assertGreater(nem_left_px[0], 180)
            self.assertLess(nem_left_px[1], 90)
            self.assertLess(freg_left_px[0], 80)
            self.assertGreater(freg_left_px[1], 160)
            self.assertGreater(freg_left_px[2], 150)

            # Em partida Custom, nem Nêmesis nem Freguês são renderizados no card
            m_custom = dict(last_freg_m, mode="Custom")
            im_custom = Image.open(
                io.BytesIO(
                    card_renderer.render_single_match_card_png(
                        {
                            "match_id": 504,
                            "primary": m_custom,
                            "records": [m_custom],
                            "nemesis_list": [nems[0]],
                            "fregues_list": [fregs[0]],
                        },
                        ap,
                    )
                )
            )
            self.assertEqual(im_custom.height, im_plain.height)

    def test_insert_nemesis_matches_batch_and_open_data_backfill_since_2023(self) -> None:
        from monitor import NEMESIS_OPEN_DATA_EARLIEST_DATE, backfill_nemesis_history_from_open_data

        class _FakeCoh3Stats:
            def __init__(self) -> None:
                self.called_days: list[int] = []

            def fetch_open_data_day_matches(
                self,
                day_utc_midnight_ts: int,
                players: list[dict[str, object]],
                only_automatch: bool = False,
                roster_maps: object = None,
                retries: int = 2,
            ) -> tuple[dict[int, list[dict[str, object]]], str, int]:
                self.called_days.append(day_utc_midnight_ts)
                # Dia 2023-06-30 (1688083200): 4 derrotas contra Rival2023 (Nêmesis) e 4 vitórias contra Fregues2023 (Freguês)
                if day_utc_midnight_ts == 1688083200:
                    matches_day = []
                    for i in range(4):
                        matches_day.append(
                            {
                                "match_id": 1001 + i,
                                "mode": "1v1",
                                "completion_time": 1688086800 + i * 1800,
                                "win": False,
                                "opponents": [
                                    {
                                        "profile_id": 999999,
                                        "alias": "Rival2023",
                                        "steam_id": "76561198000999999",
                                        "country": "de",
                                    }
                                ],
                            }
                        )
                        matches_day.append(
                            {
                                "match_id": 2001 + i,
                                "mode": "2v2",
                                "completion_time": 1688099000 + i * 1800,
                                "win": True,
                                "opponents": [
                                    {
                                        "profile_id": 888888,
                                        "alias": "Fregues2023",
                                        "steam_id": "76561198000888888",
                                        "country": "us",
                                    }
                                ],
                            }
                        )
                    return {79327: matches_day}, "ok", 5000
                return {}, "not_published", 0

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "nemesis_backfill.db")
            fake = _FakeCoh3Stats()
            players = [{"profile_id": 79327, "steam_id": "76561197963172584", "original_alias": "Chacineiro", "alias": "Chacineiro"}]
            # Solicita desde 2023-02-23 (lançamento CoH3): função deve clampar para 2023-06-30 automaticamente
            res = backfill_nemesis_history_from_open_data(
                db,
                players,
                coh3stats=fake,  # type: ignore[arg-type]
                start_date="2023-02-23",
                end_date="2023-07-01",
                max_workers=1,
            )
            self.assertEqual(res["start_date"], NEMESIS_OPEN_DATA_EARLIEST_DATE)
            self.assertEqual(res["end_date"], "2023-07-01")
            self.assertEqual(res["days_requested"], 2)
            self.assertEqual(res["days_ok"], 1)
            self.assertEqual(res["days_not_published"], 1)
            self.assertEqual(res["nemesis_rows_inserted"], 8)

            # Reexecução deve ser 100% idempotente (0 linhas duplicadas)
            res2 = backfill_nemesis_history_from_open_data(
                db,
                players,
                coh3stats=fake,  # type: ignore[arg-type]
                start_date="2023-06-30",
                end_date="2023-07-01",
                max_workers=1,
            )
            self.assertEqual(res2["nemesis_rows_inserted"], 0)
            cov = db.get_nemesis_coverage_summary()
            self.assertEqual(cov["total_rows"], 8)
            self.assertEqual(cov["unique_matches"], 8)
            self.assertEqual(cov["distinct_nemesis_pairs"], 1)
            self.assertEqual(cov["distinct_fregues_pairs"], 1)

            # Partida em 2026 já herda o histórico completo desde junho/2023 para Nêmesis E Freguês!
            status_nem_2026 = db.get_nemesis_status(
                [79327],
                999999,
                up_to_completion_time=1_795_000_000,
                up_to_match_id=99_999_999,
                current_opponent_alias="Rival2023NewNick",
                current_opponent_steam_id="76561198000999999",
            )
            self.assertIsNotNone(status_nem_2026)
            assert status_nem_2026 is not None
            self.assertTrue(status_nem_2026["triggered"])
            self.assertEqual((status_nem_2026["wins"], status_nem_2026["losses"], status_nem_2026["total"]), (0, 4, 4))
            self.assertEqual(status_nem_2026["since_year"], 2023)
            self.assertEqual(status_nem_2026["opponent_alias"], "Rival2023NewNick")

            status_freg_2026 = db.get_fregues_status(
                [79327],
                888888,
                up_to_completion_time=1_795_000_000,
                up_to_match_id=99_999_999,
                current_opponent_alias="Fregues2023NewNick",
                current_opponent_steam_id="76561198000888888",
            )
            self.assertIsNotNone(status_freg_2026)
            assert status_freg_2026 is not None
            self.assertTrue(status_freg_2026["triggered"])
            self.assertEqual((status_freg_2026["wins"], status_freg_2026["losses"], status_freg_2026["total"]), (4, 0, 4))
            self.assertEqual(status_freg_2026["since_year"], 2023)
            self.assertEqual(status_freg_2026["opponent_alias"], "Fregues2023NewNick")


if __name__ == "__main__":
    unittest.main()

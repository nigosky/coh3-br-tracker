#!/usr/bin/env python3
"""Testes da rotina de Battlegroups (cohdb.com): partidas Custom, Automatch, Smurfs do Chacineiro e backoff 72h."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import card_renderer as cr
from database import MatchDatabase
from discord_notifier import group_matches_by_id
from monitor import (
    _bg_retry_cooldown_seconds,
    _load_bg_retry_state,
    _save_bg_retry_state,
    enrich_group_with_battlegroups,
    pre_post_double_check_battlegroups,
)
from relic_api import CohDBClient, is_battlegroup_eligible_mode


class _FakeCohDBClient:
    def __init__(
        self,
        responses: dict[int, dict[int, dict[str, str]] | None | list[dict[int, dict[str, str]] | None]],
    ) -> None:
        self.is_circuit_open = False
        self.responses = dict(responses)
        self.calls: list[dict[str, object]] = []
        self.player_invalidations = 0
        self.match_invalidations: list[list[int] | None] = []
        self._call_counts: dict[int, int] = {}

    def invalidate_player_cache(self, profile_ids: list[int] | None = None) -> None:
        self.player_invalidations += 1

    def invalidate_match_cache(self, match_ids: list[int] | None = None) -> None:
        self.match_invalidations.append(list(match_ids) if match_ids is not None else None)

    def fetch_match_battlegroups(
        self,
        match_id: int,
        tracked_profile_ids: list[int],
        expected_map_clean: str = "",
        max_replay_probes: int = 8,
        fallback_profile_ids: list[int] | None = None,
        expected_duration_sec: int = 0,
        expected_opponent_aliases: list[str] | None = None,
    ) -> dict[int, dict[str, str]] | None:
        idx = self._call_counts.get(match_id, 0)
        self._call_counts[match_id] = idx + 1
        self.calls.append(
            {
                "match_id": match_id,
                "tracked_profile_ids": list(tracked_profile_ids),
                "expected_map_clean": expected_map_clean,
                "fallback_profile_ids": list(fallback_profile_ids or []),
                "expected_duration_sec": expected_duration_sec,
                "expected_opponent_aliases": list(expected_opponent_aliases or []),
            }
        )
        raw_resp = self.responses.get(match_id)
        if isinstance(raw_resp, list):
            if not raw_resp:
                return None
            return raw_resp[min(idx, len(raw_resp) - 1)]
        return raw_resp


def _sample_match(
    match_id: int,
    pid: int,
    alias: str,
    steam_id: str,
    *,
    mode: str = "Custom",
    matchtype_id: int = 0,
    map_clean: str = "Operation Eindhoven",
    completion_time: int | None = None,
    duration_sec: int = 1200,
    faction: str = "Wehrmacht",
    faction_short: str = "Wehr",
    allies: list[dict[str, object]] | None = None,
    opponents: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    now_ts = int(completion_time or time.time())
    dur = max(1, int(duration_sec))
    return {
        "match_id": match_id,
        "tracked_profile_id": pid,
        "tracked_alias": alias,
        "tracked_steam_id": steam_id,
        "tracked_faction": faction,
        "tracked_faction_short": faction_short,
        "win": True,
        "resulttype": 1,
        "mode": mode,
        "matchtype_id": matchtype_id,
        "map_raw": "eindhoven",
        "map_clean": map_clean,
        "start_time": now_ts - dur,
        "completion_time": now_ts,
        "duration_sec": dur,
        "old_elo": 1500,
        "new_elo": 1515,
        "allies": allies or [],
        "opponents": opponents or [],
        "counters": {},
        "has_replay": True,
        "coh3stats_url": f"https://coh3stats.com/players/{pid}/matches/{match_id}",
    }


class TestBattlegroupsCustomAndSmurfs(unittest.TestCase):
    def test_mode_eligibility_allows_automatch_and_custom_but_blocks_coop_ai(self) -> None:
        for ok_mode in ("1v1", "2v2", "Team Games (3v3)", "Team Games (4v4)", "Custom", "Personalizada"):
            self.assertTrue(is_battlegroup_eligible_mode(ok_mode), ok_mode)
        for bad_mode in ("Co-Op vs IA", "Skirmish vs AI", ""):
            self.assertFalse(is_battlegroup_eligible_mode(bad_mode), bad_mode)

    def test_cohdb_client_parses_beyond_12_rows_and_probes_up_to_8_participants(self) -> None:
        client = CohDBClient(min_interval_sec=0.15)
        rows_html_15 = "".join(
            f'<tr data-href="/replays/{9000 + i}"><td>2v2</td><td>{"Gabes Gap" if i == 14 else "Semois"}</td><td>21:30</td></tr>'
            for i in range(15)
        )
        replay_html = (
            "<title>cohdb – Match 92483920</title>"
            '<div data-player-card><a href="/players/79327">Chacineiro</a>'
            '<img src="/assets/races/german/battlegroups/terror_ger-abc123.webp">'
            "Battlegroup</div><div>Terror</div></div>"
            '<div data-player-card><a href="/players/1390350">TearsInTheRain</a>'
            '<img src="/assets/races/american/battlegroups/special_weapons_us-def456.webp">'
            "Battlegroup</div><div>Heavy Weapons</div></div>"
        )

        def fake_fetch(path: str, _regex: object) -> str | None:
            if path in (
                "/players/55693/matches",
                "/players/639157/matches",
                "/players/1001/matches",
                "/players/1002/matches",
                "/players/1003/matches",
                "/players/1004/matches",
                "/players/1005/matches",
            ):
                return "<table></table>"
            if path == "/players/79327/matches":
                return f"<table>{rows_html_15}</table>"
            if path == "/replays/9014":
                return replay_html
            return None

        with mock.patch.object(client, "_fetch_canonical_html", side_effect=fake_fetch):
            bgs = client.fetch_match_battlegroups(
                match_id=92483920,
                tracked_profile_ids=[55693, 639157],
                fallback_profile_ids=[1001, 1002, 1003, 1004, 1005, 79327],
                expected_map_clean="Gabès Gap",
            )

        self.assertIsNotNone(bgs)
        assert bgs is not None
        self.assertEqual(bgs[79327]["key"], "terror_ger")
        self.assertEqual(bgs[1390350]["key"], "special_weapons_us")

    def test_cohdb_client_matches_by_duration_and_opponent_and_rejects_broken_html(self) -> None:
        client = CohDBClient(min_interval_sec=0.15)
        # Mapa na linha difere do map_clean, mas duração (25:36 vs 1550s) e oponente casam além da 5ª linha
        rows_html = "".join(
            f'<tr data-href="/replays/{8000 + i}"><td>1v1</td><td>Other Map</td><td>OtherOpp</td><td>12:00</td></tr>'
            for i in range(6)
        ) + '<tr data-href="/replays/8099"><td>1v1</td><td>Bologna Classic</td><td>J3x</td><td>25:36</td></tr>'

        broken_html = "<title>cohdb – Match 92705800</title><div>Loading error / truncated</div>"
        valid_empty_html = (
            "<title>cohdb – Match 92718398</title>"
            '<div data-player-card><a href="/players/5292">nub</a>'
            "<div>Battlegroup</div><div>None</div></div>"
            '<div data-player-card><a href="/players/639157">Itaperuna</a>'
            "<div>Battlegroup</div><div>None</div></div>"
        )
        valid_bg_html = (
            "<title>cohdb – Match 92705800</title>"
            '<div data-player-card><a href="/players/79327">Chacineiro</a>'
            '<img src="/assets/races/american/battlegroups/armored_us-abc123.webp">'
            "<div>Battlegroup</div><div>Armored</div></div>"
            '<div data-player-card><a href="/players/6219">J3x</a>'
            '<img src="/assets/races/german/battlegroups/luftwaffe_ger-abc123.webp">'
            "<div>Battlegroup</div><div>Luftwaffe</div></div>"
        )

        # 1) HTML truncado/sem blocos de Battlegroup NÃO deve retornar '{}' nem envenenar cache
        def fake_fetch_broken(path: str, _regex: object) -> str | None:
            if path == "/players/79327/matches":
                return f"<table>{rows_html}</table>"
            if path == "/replays/8099":
                return broken_html
            return "<table></table>"

        with mock.patch.object(client, "_fetch_canonical_html", side_effect=fake_fetch_broken):
            res_broken = client.fetch_match_battlegroups(
                match_id=92705800,
                tracked_profile_ids=[79327],
                expected_map_clean="Bologna",
                expected_duration_sec=1550,
                expected_opponent_aliases=["J3x"],
                max_replay_probes=2,
            )
        self.assertIsNone(res_broken)
        self.assertNotIn(92705800, client._match_bg_cache)

        # 2) Após correção do HTML, duração + oponente encontram o replay 8099 na 1ª sonda mesmo com 6 linhas novas acima
        def fake_fetch_ok(path: str, _regex: object) -> str | None:
            if path == "/players/79327/matches":
                return f"<table>{rows_html}</table>"
            if path == "/replays/8099":
                return valid_bg_html
            return "<table></table>"

        with mock.patch.object(client, "_fetch_canonical_html", side_effect=fake_fetch_ok):
            res_ok = client.fetch_match_battlegroups(
                match_id=92705800,
                tracked_profile_ids=[79327],
                expected_map_clean="Unknown Map Name",
                expected_duration_sec=1550,
                expected_opponent_aliases=["J3x"],
                max_replay_probes=2,
            )
        self.assertIsNotNone(res_ok)
        assert res_ok is not None
        self.assertEqual(res_ok[79327]["key"], "armored_us")
        self.assertEqual(res_ok[6219]["key"], "luftwaffe_ger")

        # 3) Página válida com 2 player cards e Battlegroup -> None retorna '{}' legitimamente
        client_empty = CohDBClient(min_interval_sec=0.15)
        with mock.patch.object(
            client_empty,
            "_fetch_canonical_html",
            side_effect=lambda p, _r: (
                '<table><tr data-href="/replays/7758660"><td>1v1</td><td>Road to Tunis</td><td>10:54</td></tr></table>'
                if p == "/players/639157/matches"
                else (valid_empty_html if p == "/replays/7758660" else None)
            ),
        ):
            res_empty = client_empty.fetch_match_battlegroups(
                match_id=92718398,
                tracked_profile_ids=[639157],
                expected_map_clean="Road to Tunis",
                expected_duration_sec=667,
            )
        self.assertEqual(res_empty, {})

    def test_pre_post_double_check_and_suspicious_empty_guard(self) -> None:
        now_ts = int(time.time())
        with tempfile.TemporaryDirectory() as tmpdir:
            db = MatchDatabase(Path(tmpdir) / "double_check.db")
            db.sync_tracked_players(
                [
                    {"profile_id": 79327, "alias": "Chacineiro", "steam_id": "76561197963172584"},
                    {"profile_id": 639157, "alias": "Itaperuna", "steam_id": "76561198000000639"},
                ]
            )
            # Partida 1: Custom longa que só aparece na 2ª passada pré-envio -> card sai JÁ COM BG!
            m_delayed = _sample_match(
                92719373,
                79327,
                "Chacineiro",
                "76561197963172584",
                mode="Custom",
                matchtype_id=0,
                map_clean="Campbell's Convoy",
                completion_time=now_ts - 60,
                duration_sec=1536,
            )
            # Partida 2: Automatch longa (>=8m) que devolve {} suspeito na 1ª passada e BGs reais na 2ª passada!
            m_suspect_recovers = _sample_match(
                92719901,
                79327,
                "Chacineiro",
                "76561197963172584",
                mode="1v1",
                matchtype_id=20,
                map_clean="Bologna",
                completion_time=now_ts - 90,
                duration_sec=1400,
            )
            # Partida 3: Automatch longa (>=8m) genuinamente sem BG nas 2 passadas -> só grava '{}' após dupla confirmação!
            m_confirmed_empty = _sample_match(
                92718398,
                639157,
                "Itaperuna",
                "76561198000000639",
                mode="1v1",
                matchtype_id=20,
                map_clean="Road to Tunis",
                completion_time=now_ts - 120,
                duration_sec=667,
            )
            # Partida 4: Drop precoce (<8m, 3 min) sem BG -> grava '{}' logo na 1ª passada sem reter!
            m_early_drop = _sample_match(
                92719999,
                639157,
                "Itaperuna",
                "76561198000000639",
                mode="1v1",
                matchtype_id=20,
                map_clean="Semois",
                completion_time=now_ts - 180,
                duration_sec=180,
            )

            for m in (m_delayed, m_suspect_recovers, m_confirmed_empty, m_early_drop):
                db.insert_match(m, discord_message_id="PENDING")

            # Verifica primeiro isoladamente que uma partida longa >=8m com {} NÃO é gravada na 1ª chamada
            single_fake = _FakeCohDBClient({92719901: {}})
            grp_single = group_matches_by_id([dict(m_suspect_recovers)])[0]
            ok1, has1 = enrich_group_with_battlegroups(db, single_fake, grp_single, allow_commit_empty_long=False)  # type: ignore[arg-type]
            self.assertFalse(ok1)
            self.assertFalse(has1)
            self.assertTrue(grp_single.get("_bg_empty_suspect"))
            row_check = db._connect().execute(
                "SELECT battlegroups_json FROM recorded_matches WHERE match_id = 92719901"
            ).fetchone()
            self.assertEqual(row_check["battlegroups_json"], "")

            # Agora executa o fluxo completo pre_post_double_check_battlegroups nas 4 partidas juntas
            fake_cohdb = _FakeCohDBClient(
                {
                    92719373: [None, {79327: {"key": "terror_ger", "name": "Terror"}}],
                    92719901: [{}, {79327: {"key": "armored_us", "name": "Armored"}}],
                    92718398: [{}, {}],
                    92719999: [{}],
                }
            )
            groups = group_matches_by_id([m_delayed, m_suspect_recovers, m_confirmed_empty, m_early_drop])
            status, enriched_cnt, checked_mids = pre_post_double_check_battlegroups(
                db=db,
                cohdb=fake_cohdb,  # type: ignore[arg-type]
                grouped_to_send=groups,
                retry_wait_sec=0.0,
            )

            self.assertEqual(enriched_cnt, 2)
            self.assertEqual(status[92719373], (True, True))
            self.assertEqual(status[92719901], (True, True))
            self.assertEqual(status[92718398], (True, False))
            self.assertEqual(status[92719999], (True, False))
            self.assertEqual(checked_mids, {92719373, 92719901, 92718398, 92719999})
            self.assertEqual(fake_cohdb.player_invalidations, 1)
            self.assertEqual(fake_cohdb.match_invalidations, [[92719901, 92718398]])
            # Partida curta <8m (92719999) só foi consultada 1 vez; as 3 que precisaram de dupla checagem, 2 vezes!
            self.assertEqual(fake_cohdb._call_counts[92719999], 1)
            self.assertEqual(fake_cohdb._call_counts[92719373], 2)
            self.assertEqual(fake_cohdb._call_counts[92719901], 2)
            self.assertEqual(fake_cohdb._call_counts[92718398], 2)

            # Confirma persistência no SQLite
            saved_rows = {
                int(r["match_id"]): r["battlegroups_json"]
                for r in db._connect().execute(
                    "SELECT match_id, battlegroups_json FROM recorded_matches"
                ).fetchall()
            }
            self.assertIn("terror_ger", saved_rows[92719373])
            self.assertIn("armored_us", saved_rows[92719901])
            self.assertEqual(saved_rows[92718398], "{}")
            self.assertEqual(saved_rows[92719999], "{}")

            # Se todas as partidas já forem confirmadas na 1ª passada (ex.: drop <8m), NÃO dispara espera nem 2ª passada
            m_fast_only = _sample_match(
                92719998,
                639157,
                "Itaperuna",
                "76561198000000639",
                mode="1v1",
                matchtype_id=20,
                map_clean="Semois",
                completion_time=now_ts - 60,
                duration_sec=150,
            )
            db.insert_match(m_fast_only, discord_message_id="PENDING")
            fast_cohdb = _FakeCohDBClient({92719998: {}})
            with mock.patch("monitor.time.sleep") as mock_sleep:
                st_fast, enr_fast, _ = pre_post_double_check_battlegroups(
                    db=db,
                    cohdb=fast_cohdb,  # type: ignore[arg-type]
                    grouped_to_send=group_matches_by_id([m_fast_only]),
                    retry_wait_sec=25.0,
                )
            self.assertEqual(st_fast[92719998], (True, False))
            self.assertEqual(enr_fast, 0)
            self.assertEqual(fast_cohdb.player_invalidations, 0)
            mock_sleep.assert_not_called()

    def test_custom_and_smurfs_enrichment_db_query_and_card_rendering(self) -> None:
        now_ts = int(time.time())
        with tempfile.TemporaryDirectory() as tmpdir:
            db = MatchDatabase(Path(tmpdir) / "test.db")
            db.sync_tracked_players(
                [
                    {"profile_id": 79327, "alias": "Chacineiro", "steam_id": "76561197963172584"},
                    {"profile_id": 1333418, "alias": "Charles Bronson (Smurf: Chacineiro)", "steam_id": "76561198698969876"},
                    {"profile_id": 1390350, "alias": "TearsInTheRain (Smurf: Chacineiro)", "steam_id": "76561198089278659"},
                ]
            )

            custom_m = _sample_match(
                92483920,
                79327,
                "Chacineiro",
                "76561197963172584",
                mode="Custom",
                matchtype_id=0,
                completion_time=now_ts - 48 * 3600,
                opponents=[{"profile_id": 6557, "alias": "Dragoness", "faction": "US Forces", "old_elo": 1480, "new_elo": 1465}],
            )
            smurf_m = _sample_match(
                92691540,
                1390350,
                "TearsInTheRain (Smurf: Chacineiro)",
                "76561198089278659",
                mode="1v1",
                matchtype_id=20,
                map_clean="Road to Tunis",
                completion_time=now_ts - 3600,
                faction="US Forces",
                faction_short="USF",
                opponents=[{"profile_id": 431797, "alias": "`", "faction": "Afrikakorps", "old_elo": 1719, "new_elo": 1696}],
            )
            coop_m = _sample_match(
                92581416,
                1333418,
                "Charles Bronson (Smurf: Chacineiro)",
                "76561198698969876",
                mode="Co-Op vs IA",
                matchtype_id=5,
                completion_time=now_ts - 3600,
            )

            for m, msg_id in (
                (custom_m, "1573881814089605131"),
                (smurf_m, "1574495198384365598"),
                (coop_m, "1574110691449774280"),
            ):
                db.insert_match(m, discord_message_id=msg_id)

            # Query 72h deve retornar Custom e Automatch, mas excluir Co-Op vs IA
            missing = db.get_recent_matches_missing_battlegroups(max_age_sec=72 * 3600, limit=10)
            missing_mids = {int(r["match_id"]) for r in missing}
            self.assertEqual(missing_mids, {92483920, 92691540})

            # exclude_match_ids deve filtrar partidas em cooldown
            missing_filtered = db.get_recent_matches_missing_battlegroups(
                max_age_sec=72 * 3600,
                limit=10,
                exclude_match_ids={92691540},
            )
            self.assertEqual({int(r["match_id"]) for r in missing_filtered}, {92483920})

            fake_cohdb = _FakeCohDBClient(
                {
                    92483920: {
                        79327: {"key": "terror_ger", "name": "Terror"},
                        6557: {"key": "spec_ops_us", "name": "Special Operations"},
                    },
                    92691540: {
                        1390350: {"key": "special_weapons_us", "name": "Heavy Weapons"},
                        431797: {"key": "combined_arms_ak", "name": "Italian Combined Arms"},
                    },
                }
            )

            for grp in group_matches_by_id(missing):
                checked_ok, has_bg = enrich_group_with_battlegroups(db, fake_cohdb, grp)  # type: ignore[arg-type]
                self.assertTrue(checked_ok)
                self.assertTrue(has_bg)
                axis_p, allies_p = cr.extract_axis_and_allies_players(grp)
                all_bg_keys = {p["profile_id"]: p["battlegroup_key"] for p in axis_p + allies_p}
                if grp["match_id"] == 92483920:
                    self.assertEqual(all_bg_keys[79327], "terror_ger")
                    self.assertEqual(all_bg_keys[6557], "spec_ops_us")
                elif grp["match_id"] == 92691540:
                    self.assertEqual(all_bg_keys[1390350], "special_weapons_us")
                    self.assertEqual(all_bg_keys[431797], "combined_arms_ak")

            # Co-Op vs IA nunca deve disparar consulta ao cohdb
            coop_grp = group_matches_by_id([coop_m])[0]
            checked_coop, has_coop_bg = enrich_group_with_battlegroups(db, fake_cohdb, coop_grp)  # type: ignore[arg-type]
            self.assertFalse(checked_coop)
            self.assertFalse(has_coop_bg)
            self.assertEqual(len(fake_cohdb.calls), 2)

            # Após enriquecimento, nenhuma partida deve restar pendente
            self.assertEqual(db.get_recent_matches_missing_battlegroups(max_age_sec=72 * 3600, limit=10), [])

    def test_retry_backoff_tiers_and_state_persistence(self) -> None:
        self.assertEqual(_bg_retry_cooldown_seconds(600, has_replay=True), 0)
        self.assertEqual(_bg_retry_cooldown_seconds(3600, has_replay=True), 900)
        self.assertEqual(_bg_retry_cooldown_seconds(20000, has_replay=True), 900)
        self.assertEqual(_bg_retry_cooldown_seconds(100000, has_replay=True), 1800)
        self.assertEqual(_bg_retry_cooldown_seconds(200000, has_replay=True), 3600)
        self.assertEqual(_bg_retry_cooldown_seconds(3600, has_replay=False), 7200)

        now_ts = 1_800_000_000
        with tempfile.TemporaryDirectory() as tmpdir:
            db = MatchDatabase(Path(tmpdir) / "state.db")
            _save_bg_retry_state(
                db,
                {
                    92705800: now_ts - 600,
                    92704541: now_ts - 3600,
                    11111111: now_ts - 90 * 3600,  # expirada (>72h)
                },
                now_ts=now_ts,
                max_age_sec=72 * 3600,
            )
            loaded = _load_bg_retry_state(db, now_ts=now_ts, max_age_sec=72 * 3600)
            self.assertEqual(loaded, {92705800: now_ts - 600, 92704541: now_ts - 3600})

    def test_sibling_row_inherits_battlegroups_and_never_loops_missing_query(self) -> None:
        now_ts = int(time.time()) - 1800
        with tempfile.TemporaryDirectory() as tmpdir:
            db = MatchDatabase(Path(tmpdir) / "sibling_bg.db")
            db.sync_tracked_players(
                [
                    {"profile_id": 1022333, "alias": "gaules", "original_alias": "gaules", "steam_id": "76561198264285149"},
                    {"profile_id": 1487738, "alias": "Državljan H (Smurf: arc)", "original_alias": "Državljan H (Smurf: arc)", "steam_id": "76561198602236177"},
                ]
            )
            m1 = _sample_match(92726139, 1022333, "gaules", "76561198264285149", mode="Team Games (3v3)", matchtype_id=3, completion_time=now_ts)
            m1["battlegroups"] = {"1022333": {"key": "panzerjager_kommand_ak", "name": "Panzerjäger Kommand"}}
            db.insert_match(m1, discord_message_id="1574633088313721042")

            # Novo Veterano inserido depois sem BGs na memória -> herda BGs da linha irmã e não entra em loop infinito!
            m2 = _sample_match(92726139, 1487738, "Državljan H (Smurf: arc)", "76561198602236177", mode="Team Games (3v3)", matchtype_id=3, completion_time=now_ts)
            db.insert_match(m2, discord_message_id="1574633088313721042")

            self.assertEqual(db.get_recent_matches_missing_battlegroups(max_age_sec=72 * 3600, limit=10), [])
            db.close()


if __name__ == "__main__":
    unittest.main()

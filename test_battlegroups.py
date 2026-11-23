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
)
from relic_api import CohDBClient, is_battlegroup_eligible_mode


class _FakeCohDBClient:
    def __init__(self, responses: dict[int, dict[int, dict[str, str]] | None]) -> None:
        self.is_circuit_open = False
        self.responses = dict(responses)
        self.calls: list[dict[str, object]] = []

    def fetch_match_battlegroups(
        self,
        match_id: int,
        tracked_profile_ids: list[int],
        expected_map_clean: str = "",
        max_replay_probes: int = 6,
        fallback_profile_ids: list[int] | None = None,
    ) -> dict[int, dict[str, str]] | None:
        self.calls.append(
            {
                "match_id": match_id,
                "tracked_profile_ids": list(tracked_profile_ids),
                "expected_map_clean": expected_map_clean,
                "fallback_profile_ids": list(fallback_profile_ids or []),
            }
        )
        return self.responses.get(match_id)


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
    faction: str = "Wehrmacht",
    faction_short: str = "Wehr",
    allies: list[dict[str, object]] | None = None,
    opponents: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    now_ts = int(completion_time or time.time())
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
        "start_time": now_ts - 1200,
        "completion_time": now_ts,
        "duration_sec": 1200,
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

    def test_cohdb_client_parses_beyond_12_rows_and_probes_up_to_4_tracked_players(self) -> None:
        client = CohDBClient(min_interval_sec=0.15)
        rows_html_15 = "".join(
            f'<tr data-href="/replays/{9000 + i}"><td>2v2</td><td>{"Gabes Gap" if i == 14 else "Semois"}</td></tr>'
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
            if path in ("/players/55693/matches", "/players/639157/matches"):
                return "<table></table>"
            if path == "/players/79327/matches":
                return f"<table>{rows_html_15}</table>"
            if path == "/replays/9014":
                return replay_html
            return None

        with mock.patch.object(client, "_fetch_canonical_html", side_effect=fake_fetch):
            bgs = client.fetch_match_battlegroups(
                match_id=92483920,
                tracked_profile_ids=[55693, 639157, 79327, 366826],
                expected_map_clean="Gabès Gap",
            )

        self.assertIsNotNone(bgs)
        assert bgs is not None
        self.assertEqual(bgs[79327]["key"], "terror_ger")
        self.assertEqual(bgs[1390350]["key"], "special_weapons_us")

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
        self.assertEqual(_bg_retry_cooldown_seconds(20000, has_replay=True), 2700)
        self.assertEqual(_bg_retry_cooldown_seconds(100000, has_replay=True), 7200)
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


if __name__ == "__main__":
    unittest.main()

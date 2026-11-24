import unittest
from pathlib import Path

import watchlist_monitor as wm


class TestWatchlistMonitor(unittest.TestCase):
    def test_load_private_historical_watchlist_contains_all_targets(self) -> None:
        entries = wm.load_watchlist(wm.DEFAULT_WATCHLIST_PATH)
        by_sid = {e["steam_id"]: e for e in entries}
        self.assertIn("76561197995394193", by_sid)  # Alcoólatra
        self.assertIn("76561197995130555", by_sid)  # Siririca
        self.assertIn("76561198091708083", by_sid)  # Xampoo
        self.assertIn("76561197983811816", by_sid)  # glowing (alt CoH2 dormente)

    def test_parse_steam_ban_banner_game_and_vac(self) -> None:
        html = (
            '<div class="profile_ban_status"><div class="profile_ban">1 game ban on record | Info</div>'
            '22 day(s) since last ban</div></div>'
        )
        res = wm.parse_steam_ban_banner(html)
        self.assertTrue(res["has_ban"])
        self.assertEqual(res["game_bans"], 1)
        self.assertEqual(res["vac_bans"], 0)
        self.assertEqual(res["days_since_last_ban"], 22)

    def test_audit_watchlist_flags_new_coh3_activation_tanking_and_steam_ban(self) -> None:
        entries = [
            {
                "label": "Alcoólatra",
                "category": "historical_coh1_coh2_troll",
                "steam_id": "76561197995394193",
                "coh3_profile_id": None,
            },
            {
                "label": "Xampoo",
                "category": "historical_coh1_coh2_troll",
                "steam_id": "76561198091708083",
                "coh3_profile_id": 2834,
            },
            {
                "label": "glowing",
                "category": "dormant_coh2_alt_watch",
                "steam_id": "76561197983811816",
                "coh3_profile_id": 1148379,
            },
        ]

        def fake_relic(sid: str):
            if sid == "76561197995394193":
                return {
                    "statGroups": [{"id": 1, "type": 1, "members": [{"profile_id": 1500001, "alias": "NovoNickAlc", "country": "br"}]}],
                    "leaderboardStats": [{"wins": 3, "losses": 2, "rating": 1050, "drops": 0, "streak": 1, "lastmatchdate": 1795500000}],
                }
            if sid == "76561198091708083":
                return {
                    "statGroups": [{"id": 2, "type": 1, "members": [{"profile_id": 2834, "alias": "Xampoo - ☭", "country": "br"}]}],
                    "leaderboardStats": [{"wins": 1441, "losses": 2708, "rating": -2588, "drops": 98, "streak": -20, "lastmatchdate": 1794900000}],
                }
            if sid == "76561197983811816":
                return {
                    "statGroups": [{"id": 3, "type": 1, "members": [{"profile_id": 1148379, "alias": "glowing", "country": "br"}]}],
                    "leaderboardStats": [{"wins": 4, "losses": 1, "rating": 1180, "drops": 0, "streak": 3, "lastmatchdate": 1795500000}],
                }
            return None

        def fake_html(sid: str) -> str:
            if sid == "76561198091708083":
                return '<div class="profile_ban_status"><div class="profile_ban">1 game ban on record | Info</div>5 day(s) since last ban</div></div>'
            return ""

        rep = wm.audit_watchlist(
            entries,
            db_path=Path("/nonexistent/matches.db"),
            check_steam_bans=True,
            relic_fetcher=fake_relic,
            steam_html_fetcher=fake_html,
        )
        self.assertEqual(rep["checked_entries"], 3)
        joined = "\n".join(rep["alerts"])
        self.assertIn("NOVO PERFIL CoH3 ATIVADO", joined)
        self.assertIn("GRIEFING/TANKING ATIVO", joined)
        self.assertIn("BAN STEAM EM CONTA ATIVA NO CoH3", joined)
        self.assertIn("CONTA CoH2 DORMENTE ATIVADA NO CoH3", joined)

    def test_query_local_veteran_encounters_reads_nemesis_matches_schema(self) -> None:
        import sqlite3
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            db_p = Path(td) / "test.db"
            with sqlite3.connect(str(db_p)) as con:
                con.execute(
                    """
                    CREATE TABLE nemesis_matches (
                        tracked_profile_id INTEGER NOT NULL,
                        opponent_profile_id INTEGER NOT NULL,
                        match_id INTEGER NOT NULL,
                        completion_time INTEGER NOT NULL,
                        utc_day INTEGER NOT NULL,
                        win INTEGER NOT NULL,
                        mode TEXT DEFAULT '',
                        opponent_alias TEXT DEFAULT '',
                        opponent_country TEXT DEFAULT '',
                        PRIMARY KEY (tracked_profile_id, opponent_profile_id, match_id)
                    )
                    """
                )
                con.execute(
                    "INSERT INTO nemesis_matches VALUES (59864, 2834, 1001, 1750000000, 20250, 1, '4v4', 'Xampoo', 'br')"
                )
                con.execute(
                    "INSERT INTO nemesis_matches VALUES (59864, 2834, 1002, 1760000000, 20366, 0, '4v4', 'Xampoo', 'br')"
                )
            rows = wm.query_local_veteran_encounters(db_p, 2834)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["tracked_profile_id"], 59864)
            self.assertEqual(rows[0]["games"], 2)
            self.assertEqual(rows[0]["veteran_wins"], 1)
            self.assertEqual(rows[0]["last_ts"], 1760000000)


if __name__ == "__main__":
    unittest.main()

"""Testes unitários do alerta em tempo real de possíveis smurfs BR no Tracker (critérios multi-gênero, card PNG, Discord e SQLite)."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from PIL import Image

import card_renderer
import discord_notifier
import monitor
import smurf_alert as sa
from database import MatchDatabase
from security import HttpsOnlySchemeHandler, StrictNoRedirectHandler


def _make_raw_relic_match(
    mid: int,
    st: int,
    ct: int,
    pid: int,
    *,
    race_id: int = 137123,
    matchtype_id: int = 1,
    win: int = 1,
    old_elo: int = 1520,
    new_elo: int = 1545,
    ally_pids: list[int] | None = None,
    opp_pids: list[int] | None = None,
    counters: dict[str, Any] | None = None,
    cosmetic_ids: list[int] | None = None,
) -> dict[str, Any]:
    reports = [
        {
            "profile_id": pid,
            "teamid": 0,
            "race_id": race_id,
            "resulttype": win,
            "counters": json.dumps(counters) if isinstance(counters, dict) else (counters or ""),
        }
    ]
    for ap in ally_pids or []:
        reports.append({"profile_id": ap, "teamid": 0, "race_id": 129494, "resulttype": win, "counters": ""})
    for op in opp_pids or [990000 + mid]:
        reports.append({"profile_id": op, "teamid": 1, "race_id": 197345, "resulttype": 0 if win else 1, "counters": ""})

    items = [
        {"profile_id": pid, "itemdefinition_id": cid, "metadata": '{"eslot":"10"}'}
        for cid in (cosmetic_ids or [])
    ]
    return {
        "id": mid,
        "matchtype_id": matchtype_id,
        "startgametime": st,
        "completiontime": ct,
        "matchhistoryreportresults": reports,
        "matchhistorymember": [{"profile_id": pid, "oldrating": old_elo, "newrating": new_elo}],
        "matchhistoryitems": items,
    }


def _make_recorded_match(
    match_id: int,
    tracked_pid: int,
    tracked_alias: str,
    opponents: list[dict[str, Any]],
    *,
    completion_time: int = 1_800_000_000,
    mode: str = "1v1",
    allies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "match_id": match_id,
        "tracked_profile_id": tracked_pid,
        "tracked_alias": tracked_alias,
        "tracked_steam_id": "76561198070545853",
        "tracked_faction": "US Forces",
        "tracked_faction_short": "USF",
        "win": False,
        "resulttype": 0,
        "mode": mode,
        "matchtype_id": 20 if mode == "1v1" else 21,
        "map_raw": "angoville_farms_2p",
        "map_clean": "Angoville Farms",
        "start_time": completion_time - 1100,
        "completion_time": completion_time,
        "duration_sec": 1100,
        "old_elo": 1580,
        "new_elo": 1564,
        "allies": list(allies or []),
        "opponents": list(opponents),
        "has_replay": True,
        "coh3stats_url": f"https://coh3stats.com/players/{tracked_pid}/matches/{match_id}",
    }


class _FakeOSINTClient(sa.SteamProfileOSINTClient):
    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        super().__init__(pace_delay_sec=0.0, allow_network=False)
        self._fake = dict(responses)

    def fetch_profile_osint(self, steam_id: str) -> dict[str, Any]:
        sid = str(steam_id or "").replace("/steam/", "").strip()
        return dict(self._fake.get(sid) or {})


class _FakeRelicClient:
    def __init__(
        self,
        stats_by_pid: dict[int, dict[str, Any]],
        raw_histories: dict[int, dict[str, Any]],
    ) -> None:
        self._stats = dict(stats_by_pid)
        self._raw = dict(raw_histories)

    def get_cached_raw_histories(self) -> dict[int, dict[str, Any]]:
        return dict(self._raw)

    def fetch_raw_match_history(self, profile_id: int) -> dict[str, Any] | None:
        return self._raw.get(int(profile_id))

    def fetch_profile_summary_stats(self, profile_ids: list[int]) -> dict[int, dict[str, Any]]:
        return {int(p): dict(self._stats[int(p)]) for p in profile_ids if int(p) in self._stats}


class TestRealTimeSmurfAlerts(unittest.TestCase):
    def test_disguised_foreign_flag_smurf_detected_persisted_and_hydrated_for_patch(self) -> None:
        # Veterano Margheriti (#900358) enfrenta oponente "HansFakeDE" (#1_950_111, bandeira "de"),
        # que na verdade é smurf disfarçada do Veterano brasileiro #79327 (Chacineiro):
        # - Steam XML revela "Curitiba, Brazil" + mesmo avatar customizado SHA-1
        # - APM quase idêntico + 6 eixos Combat DNA idênticos + dias alternados (dormancy swap) + +180 ELO rápido
        base_t = 1_799_000_000  # ~20h BRT
        dna_c = {"gt": 1200, "totalcmds": 1700, "abil": 54, "ekills": 90, "edeaths": 62, "dmgdone": 4800, "pcap": 24, "inactperiod": 48, "sqkill": 5, "sqlost": 2}
        dna_m = {"gt": 1200, "totalcmds": 1710, "abil": 55, "ekills": 88, "edeaths": 61, "dmgdone": 4900, "pcap": 25, "inactperiod": 47, "sqkill": 5, "sqlost": 2}

        opp_pid = 1_950_111
        opp_sid = "76561199950000111"
        main_pid = 79327
        main_sid = "76561198014114284"

        opp_matches = [
            _make_raw_relic_match(
                1000 + i,
                base_t + (i * 2) * 86400,
                base_t + (i * 2) * 86400 + 1200,
                opp_pid,
                race_id=137123,
                win=1,
                old_elo=1450 + i * 25,
                new_elo=1475 + i * 25,
                counters=dna_c,
                cosmetic_ids=list(range(1, 32)),
            )
            for i in range(8)
        ]
        main_matches = [
            _make_raw_relic_match(
                2000 + i,
                base_t + (i * 2 + 1) * 86400,
                base_t + (i * 2 + 1) * 86400 + 1200,
                main_pid,
                race_id=129494,  # Facção diferente! Cross-faction disguise!
                win=1 if i % 2 == 0 else 0,
                old_elo=1660,
                new_elo=1670,
                counters=dna_m,
            )
            for i in range(8)
        ]

        raw_histories = {
            opp_pid: {
                "profiles": [{"profile_id": opp_pid, "name": f"/steam/{opp_sid}", "alias": "HansFakeDE", "country": "de"}],
                "matchHistoryStats": opp_matches,
            },
            main_pid: {
                "profiles": [{"profile_id": main_pid, "name": f"/steam/{main_sid}", "alias": "Chacineiro", "country": "br"}],
                "matchHistoryStats": main_matches,
            },
        }
        stats = {
            opp_pid: {
                "profile_id": opp_pid,
                "steam_id": opp_sid,
                "alias": "HansFakeDE",
                "country": "de",
                "max_elo": 1650,
                "total_matches": 82,
                "total_wins": 60,
                "total_losses": 22,
                "mode_elo_max": {"1v1": 1650, "2v2": 1410},
            }
        }
        shared_av = "11223344556677889900aabbccddeeff11223344"
        osint = _FakeOSINTClient(
            {
                opp_sid: {
                    "ok": True,
                    "is_private": False,
                    "member_since_year": 2026,
                    "location": "Curitiba, Brazil",
                    "is_br_location": True,
                    "avatar_hash": shared_av,
                    "is_default_avatar": False,
                },
                main_sid: {
                    "ok": True,
                    "is_private": False,
                    "member_since_year": 2012,
                    "location": "Curitiba, Brazil",
                    "is_br_location": True,
                    "avatar_hash": shared_av,
                    "is_default_avatar": False,
                },
            }
        )
        relic = _FakeRelicClient(stats, raw_histories)
        custom_roster = [
            {"profile_id": 900358, "steam_id": "76561198070545853", "original_alias": "Margheriti", "alias": "Margheriti"},
            {"profile_id": main_pid, "steam_id": main_sid, "original_alias": "Chacineiro", "alias": "Chacineiro"},
        ]

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "smurf_test.db")
            m = _make_recorded_match(
                555001,
                900358,
                "Margheriti",
                [
                    {
                        "profile_id": opp_pid,
                        "alias": "HansFakeDE",
                        "steam_id": opp_sid,
                        "country": "de",
                        "faction": "Wehrmacht",
                        "faction_short": "Wehr",
                        "old_elo": 1625,
                        "new_elo": 1650,
                        "elo_delta": 25,
                    }
                ],
                completion_time=base_t + 20 * 86400,
            )
            db.insert_match(m)
            grp = {"match_id": 555001, "primary": dict(m), "records": [dict(m)]}

            ctx = sa.build_smurf_alert_context(
                db,
                relic,
                custom_players=custom_roster,
                br_community_data={},
                osint_client=osint,
                allow_network=False,
                now_ts=base_t + 20 * 86400,
            )
            alerts = sa.enrich_group_with_smurf_alerts(db, relic, grp, ctx=ctx)
            self.assertEqual(len(alerts), 1)
            al = alerts[0]
            self.assertEqual(al["kind"], "attributed")
            self.assertEqual(al["opponent_profile_id"], opp_pid)
            self.assertEqual(al["suspected_main_profile_id"], main_pid)
            self.assertEqual(al["suspected_main_alias"], "Chacineiro")
            self.assertGreaterEqual(al["probability_pct"], 75)
            self.assertIn("Avatar Steam idêntico", al["top_reasons"])

            # Verifica persistência no SQLite e hidratação automática para PATCH retroativo de Battlegroups!
            reloaded = db.get_recent_recorded_matches(limit=5, only_active_players=False)
            self.assertEqual(len(reloaded), 1)
            self.assertEqual(len(reloaded[0]["smurf_alerts"]), 1)
            self.assertEqual(reloaded[0]["smurf_alerts"][0]["suspected_main_alias"], "Chacineiro")

            # Simula PATCH retroativo de Battlegroups sem perder smurf_alerts!
            captured_payloads: list[dict[str, Any]] = []

            class _FakeDiscord:
                def edit_match_card(self, message_id: str, match_or_group: dict[str, Any]) -> str:
                    captured_payloads.append(discord_notifier.build_match_embed_payload(match_or_group))
                    return message_id

            patch_grp = {"match_id": 555001, "primary": reloaded[0], "records": [reloaded[0]]}
            patched_ok = monitor._patch_match_card_with_battlegroups(
                db,
                _FakeDiscord(),  # type: ignore[arg-type]
                patch_grp,
                "123456789012345678",
                ({}, {}),
            )
            self.assertTrue(patched_ok)
            self.assertEqual(len(captured_payloads), 1)
            self.assertIn("ALERTA SMURF", captured_payloads[0]["content"])
            self.assertIn("Chacineiro", captured_payloads[0]["content"])

    def test_unattributed_br_burner_smurf_triggers_with_sandbagging_and_default_avatar(self) -> None:
        base_t = 1_799_500_000
        opp_pid = 1_960_222
        opp_sid = "76561199960000222"
        # 3 derrotas <4m (sandbagging) + 7 vitórias longas consecutivas (+175 ELO) + avatar '?' + Steam privada + nick PT-BR!
        opp_matches = [
            _make_raw_relic_match(3001 + i, base_t + i * 1000, base_t + i * 1000 + 120, opp_pid, win=0, old_elo=1420, new_elo=1400)
            for i in range(3)
        ] + [
            _make_raw_relic_match(
                3010 + i,
                base_t + 10000 + i * 2000,
                base_t + 10000 + i * 2000 + 1200,
                opp_pid,
                win=1,
                old_elo=1400 + i * 25,
                new_elo=1425 + i * 25,
                cosmetic_ids=list(range(1, 25)),
            )
            for i in range(7)
        ]
        relic = _FakeRelicClient(
            {
                opp_pid: {
                    "profile_id": opp_pid,
                    "steam_id": opp_sid,
                    "alias": "Capivara Veloz",
                    "country": "br",
                    "max_elo": 1575,
                    "total_matches": 64,
                    "total_wins": 48,
                    "total_losses": 16,
                    "mode_elo_max": {"1v1": 1575, "2v2": 1360},
                }
            },
            {
                opp_pid: {
                    "profiles": [{"profile_id": opp_pid, "name": f"/steam/{opp_sid}", "alias": "Capivara Veloz", "country": "br"}],
                    "matchHistoryStats": opp_matches,
                }
            },
        )
        osint = _FakeOSINTClient(
            {
                opp_sid: {
                    "ok": True,
                    "is_private": True,
                    "member_since_year": 2026,
                    "location": "",
                    "is_br_location": False,
                    "avatar_hash": sa.STEAM_DEFAULT_AVATAR_HASH,
                    "is_default_avatar": True,
                }
            }
        )
        custom_roster = [
            {"profile_id": 900358, "steam_id": "76561198070545853", "original_alias": "Margheriti", "alias": "Margheriti"},
        ]

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "burner.db")
            m = _make_recorded_match(
                555002,
                900358,
                "Margheriti",
                [
                    {
                        "profile_id": opp_pid,
                        "alias": "Capivara Veloz",
                        "steam_id": opp_sid,
                        "country": "br",
                        "faction": "Wehrmacht",
                        "faction_short": "Wehr",
                        "old_elo": 1550,
                        "new_elo": 1575,
                        "elo_delta": 25,
                    }
                ],
            )
            db.insert_match(m)
            grp = {"match_id": 555002, "primary": dict(m), "records": [dict(m)]}
            ctx = sa.build_smurf_alert_context(
                db, relic, custom_players=custom_roster, br_community_data={}, osint_client=osint, allow_network=False
            )
            alerts = sa.enrich_group_with_smurf_alerts(db, relic, grp, ctx=ctx)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["kind"], "unattributed_br")
            self.assertEqual(alerts[0]["suspected_main_alias"], "")
            self.assertGreaterEqual(alerts[0]["probability_pct"], 75)

    def test_anti_false_positive_guards_same_match_overlap_veteran_foreign_and_cataloged(self) -> None:
        base_t = 1_799_000_000
        # 1. Veterano consolidado (>900 jogos) -> cacheado como "veteran" e nunca alertado
        vet_opp_pid = 1_970_001
        vet_opp_sid = "76561199970000001"
        relic = _FakeRelicClient(
            {
                vet_opp_pid: {
                    "profile_id": vet_opp_pid,
                    "steam_id": vet_opp_sid,
                    "alias": "OldBRVeteran",
                    "country": "br",
                    "max_elo": 1680,
                    "total_matches": 1450,
                    "total_wins": 800,
                    "total_losses": 650,
                    "mode_elo_max": {"1v1": 1680},
                }
            },
            {},
        )
        custom_roster = [
            {"profile_id": 900358, "steam_id": "76561198070545853", "original_alias": "Margheriti", "alias": "Margheriti"},
            {"profile_id": 79327, "steam_id": "76561198014114284", "original_alias": "Chacineiro", "alias": "Chacineiro"},
            {"profile_id": 1333418, "steam_id": "76561199863274133", "original_alias": "Charles Bronson (Smurf: Chacineiro)", "alias": "Charles Bronson (Smurf: Chacineiro)", "merged_into_profile_id": 79327},
        ]
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "guards.db")
            ctx = sa.build_smurf_alert_context(
                db, relic, custom_players=custom_roster, br_community_data={}, osint_client=_FakeOSINTClient({}), allow_network=False
            )
            # Smurf já catalogada (Charles Bronson) nunca é re-sondada
            self.assertFalse(sa._should_probe_opponent({"profile_id": 1333418, "alias": "Charles Bronson", "country": "br"}, ctx))
            # Veterano confirmado (Chacineiro) nunca é re-sondado
            self.assertFalse(sa._should_probe_opponent({"profile_id": 79327, "alias": "Chacineiro", "country": "br"}, ctx))
            # Estrangeiro antigo normal -> pula sem gastar chamadas HTTP
            self.assertFalse(sa._should_probe_opponent({"profile_id": 120000, "steam_id": "76561198000120000", "alias": "HansNormal", "country": "de", "old_elo": 1600}, ctx))

            m_vet = _make_recorded_match(
                555003,
                900358,
                "Margheriti",
                [{"profile_id": vet_opp_pid, "alias": "OldBRVeteran", "steam_id": vet_opp_sid, "country": "br", "faction": "Wehrmacht", "faction_short": "Wehr", "old_elo": 1680, "new_elo": 1690, "elo_delta": 10}],
            )
            grp_vet = {"match_id": 555003, "primary": m_vet, "records": [m_vet]}
            self.assertEqual(sa.enrich_group_with_smurf_alerts(db, relic, grp_vet, ctx=ctx), [])
            self.assertEqual(ctx.probe_cache[vet_opp_pid]["status"], "veteran")

        # 2. Sobreposição simultânea desqualifica imediatamente
        t_c = sa.PlayerTelemetry(profile_id=1_980_001, intervals=[(base_t, base_t + 1200)])
        t_m = sa.PlayerTelemetry(profile_id=79327, intervals=[(base_t + 300, base_t + 1500)])
        res_ov = sa.score_live_smurf_pair(
            {"profile_id": 1_980_001, "alias": "Chacineiro", "country": "br", "max_elo": 1650, "total_matches": 60},
            {"profile_id": 79327, "alias": "Chacineiro", "country": "br", "max_elo": 1670, "total_matches": 2000},
            t_c,
            t_m,
        )
        self.assertEqual(res_ov["probability_pct"], 0)
        self.assertEqual(res_ov["disqualified_reason"], "sobreposicao_simultanea")

        # 3. Estrangeiro sem vínculo BR é desqualificado mesmo com horários próximos
        t_de = sa.PlayerTelemetry(profile_id=1_980_002, games=8)
        t_br = sa.PlayerTelemetry(profile_id=79327, games=8)
        for k in range(8):
            t_de.hour_counts[22] += 1
            t_br.hour_counts[22] += 1
            t_de.intervals.append((base_t + k * 86400, base_t + k * 86400 + 1000))
            t_br.intervals.append((base_t + k * 86400 + 1600, base_t + k * 86400 + 2600))
        res_de = sa.score_live_smurf_pair(
            {"profile_id": 1_980_002, "alias": "RandomDE", "country": "de", "max_elo": 1600, "total_matches": 90},
            {"profile_id": 79327, "alias": "Chacineiro", "country": "br", "max_elo": 1620, "total_matches": 2000},
            t_de,
            t_br,
        )
        self.assertEqual(res_de["probability_pct"], 0)
        self.assertEqual(res_de["disqualified_reason"], "estrangeiro_sem_vinculo_br")

    def test_discord_payload_sanitization_and_card_png_heights_with_nemesis(self) -> None:
        base_m = _make_recorded_match(
            555010,
            900358,
            "Margheriti",
            [
                {"profile_id": 1_950_501, "alias": "@everyone [Smurf]\u202e", "steam_id": "76561199950000501", "country": "de", "faction": "Wehrmacht", "faction_short": "Wehr", "old_elo": 1600, "new_elo": 1618, "elo_delta": 18},
                {"profile_id": 1_950_502, "alias": "Capivara_BR", "steam_id": "76561199950000502", "country": "br", "faction": "Afrikakorps", "faction_short": "DAK", "old_elo": 1540, "new_elo": 1558, "elo_delta": 18},
            ],
            mode="2v2",
            allies=[{"profile_id": 79327, "alias": "Chacineiro", "steam_id": "76561198014114284", "country": "br", "faction": "British Forces", "faction_short": "UKF", "old_elo": 1620, "new_elo": 1604, "elo_delta": -16}],
        )

        # 1. Partida normal: content continua 100% vazio
        normal_payload = discord_notifier.build_match_embed_payload(base_m)
        self.assertEqual(normal_payload["content"], "")
        self.assertEqual(normal_payload["allowed_mentions"], {"parse": []})

        # 2. Partida com 1 alerta atribuído + 1 não atribuído: content sanitizado, zero menções e sem RLO
        alert_1 = {
            "kind": "attributed",
            "opponent_profile_id": 1_950_501,
            "opponent_alias": "@everyone [Smurf]\u202e",
            "tracked_alias": "Margheriti",
            "suspected_main_profile_id": 462597,
            "suspected_main_alias": "General Winter",
            "probability_pct": 88,
            "confidence_tier": "Muito Alta",
            "top_reasons": ["Avatar Steam idêntico", "APM Δ=1.1", "Combat DNA 86%"],
        }
        alert_2 = {
            "kind": "unattributed_br",
            "opponent_profile_id": 1_950_502,
            "opponent_alias": "Capivara_BR",
            "tracked_alias": "Margheriti",
            "suspected_main_profile_id": 0,
            "suspected_main_alias": "",
            "probability_pct": 76,
            "confidence_tier": "Alta",
            "top_reasons": ["64 jogos em ELO 1575", "Avatar padrão '?'", "Tanking (3x <4m)"],
        }
        grp_1 = {"match_id": 555010, "primary": dict(base_m, smurf_alerts=[alert_1]), "records": [dict(base_m, smurf_alerts=[alert_1])], "smurf_alerts": [alert_1]}
        grp_2 = {"match_id": 555010, "primary": dict(base_m, smurf_alerts=[alert_1, alert_2]), "records": [dict(base_m, smurf_alerts=[alert_1, alert_2])], "smurf_alerts": [alert_1, alert_2]}

        p_alert = discord_notifier.build_match_embed_payload(grp_2)
        self.assertEqual(p_alert["allowed_mentions"], {"parse": []})
        self.assertIn("ALERTA SMURF", p_alert["content"])
        self.assertIn("General Winter", p_alert["content"])
        self.assertIn("smurf BR não identificado", p_alert["content"])
        self.assertIn("\\@everyone", p_alert["content"])
        self.assertNotIn("\u202e", p_alert["content"])

        # 3. Card PNG: +56px (1 alerta), +104px (2 alertas) e empilhamento perfeito com Nemesis (+42px + 56px = +98px)
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "card.db")
            ap = card_renderer.SteamAvatarProvider(db, allow_network=False)
            grp_plain = {"match_id": 555010, "primary": dict(base_m), "records": [dict(base_m)]}
            im_plain = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_plain, ap)))
            im_1 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_1, ap)))
            im_2 = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_2, ap)))
            self.assertEqual(im_1.height - im_plain.height, 56)
            self.assertEqual(im_2.height - im_plain.height, 104)

            nem_entry = {
                "triggered": True,
                "is_new_trigger": True,
                "tracked_profile_id": 900358,
                "tracked_alias": "Margheriti",
                "opponent_profile_id": 1_950_501,
                "opponent_alias": "HansFakeDE",
                "wins": 1,
                "losses": 1,
                "total": 2,
                "win_rate": 50.0,
                "same_day_games": 2,
            }
            grp_both = dict(grp_1, nemesis=nem_entry, nemesis_list=[nem_entry])
            im_both = Image.open(io.BytesIO(card_renderer.render_single_match_card_png(grp_both, ap)))
            self.assertEqual(im_both.height - im_plain.height, 42 + 56)

    def test_steam_osint_client_is_https_only_and_no_redirect(self) -> None:
        client = sa.SteamProfileOSINTClient(allow_network=False)
        handler_types = {type(h) for h in client._opener.handlers}
        self.assertIn(HttpsOnlySchemeHandler, handler_types)
        self.assertIn(StrictNoRedirectHandler, handler_types)

    def test_family_sharing_xml_html_parser_and_live_scoring_boost(self) -> None:
        xml_priv_limited = """<?xml version="1.0" encoding="UTF-8"?>
        <profile>
            <steamID64>76561198722284920</steamID64>
            <privacyState>private</privacyState>
            <isLimitedAccount>1</isLimitedAccount>
        </profile>"""
        parsed_priv = sa.SteamProfileOSINTClient.parse_profile_xml(xml_priv_limited, current_year=2026)
        self.assertTrue(parsed_priv["ok"])
        self.assertTrue(parsed_priv["is_private"])
        self.assertTrue(parsed_priv["is_limited_account"])
        self.assertFalse(parsed_priv["member_since_current_year"])

        xml_pub_yearless = """<?xml version="1.0" encoding="UTF-8"?>
        <profile>
            <steamID64>76561198723667226</steamID64>
            <privacyState>public</privacyState>
            <isLimitedAccount>1</isLimitedAccount>
            <memberSince>March 23</memberSince>
            <customURL><![CDATA[]]></customURL>
        </profile>"""
        parsed_pub = sa.SteamProfileOSINTClient.parse_profile_xml(xml_pub_yearless, current_year=2026)
        self.assertTrue(parsed_pub["is_limited_account"])
        self.assertEqual(parsed_pub["member_since_year"], 2026)
        self.assertTrue(parsed_pub["member_since_current_year"])

        fp = sa.SteamProfileOSINTClient.parse_profile_html_footprint(
            '<span class="friendPlayerLevelNum">0</span>'
            '<a href="https://steamcommunity.com/profiles/76561198723667226/friends/"><span class="profile_count_link_total">4</span></a>'
        )
        self.assertEqual(fp["steam_level"], 0)
        self.assertEqual(fp["friends_count"], 4)

        # Unattributed BR burner com isLimitedAccount=1 + conta criada este ano deve disparar com chip Family Sharing!
        cand = {
            "profile_id": 1_985_001,
            "steam_id": "76561199985000001",
            "alias": "ContaTesteBR",
            "country": "br",
            "max_elo": 1520,
            "total_matches": 60,
            "total_wins": 42,
        }
        tel = sa.PlayerTelemetry(profile_id=1_985_001, games=15, wins=11)
        res_no_fs = sa.score_unattributed_br_burner(cand, tel, cand_osint={})
        res_fs = sa.score_unattributed_br_burner(
            cand,
            tel,
            cand_osint={
                "ok": True,
                "is_limited_account": True,
                "member_since_current_year": True,
                "steam_level": 0,
                "friends_count": 3,
            },
        )
        self.assertFalse(res_no_fs["triggered"])
        self.assertTrue(res_fs["triggered"])
        self.assertGreaterEqual(res_fs["probability_pct"], 80)
        self.assertIn("Family Sharing (conta limitada)", res_fs["top_reasons"])
        self.assertIn("Steam criada este ano", res_fs["top_reasons"])

    def test_regional_br_sa_mm_elo_slope_fake_br_guard_and_historical_nemesis_disqualifier(self) -> None:
        base_t = 1_760_047_200  # 2025-10-09 22:00 UTC = 19:00 BRT (prime time)
        opp_pid = 1_990_001
        opp_sid = "76561199990000001"
        main_pid = 79327
        main_sid = "76561198014114284"

        # 1. Smurf BR sob bandeira 'de' com alta densidade de encontros BR/SA no Automatch + subida rápida (+16 ELO/jogo)
        profiles = [{"profile_id": opp_pid, "name": f"/steam/{opp_sid}", "alias": "StealthDE", "country": "de", "leaderboardregion_id": 1}]
        opp_matches = []
        for i in range(8):
            opid = 880000 + i
            profiles.append(
                {
                    "profile_id": opid,
                    "name": f"/steam/{76561198000000000 + opid}",
                    "alias": f"SAOpp{i}",
                    "country": "br" if i < 4 else "ar",
                    "leaderboardregion_id": sa.SA_LEADERBOARD_REGION_ID,
                }
            )
            opp_matches.append(
                _make_raw_relic_match(
                    9000 + i,
                    base_t + i * 86400,
                    base_t + i * 86400 + 1200,
                    opp_pid,
                    win=1,
                    old_elo=1320 + i * 16,
                    new_elo=1336 + i * 16,
                    opp_pids=[opid],
                    counters={"gt": 1200, "totalcmds": 1700, "abil": 54, "ekills": 80, "edeaths": 50, "dmgdone": 4800, "pcap": 24, "inactperiod": 48, "sqkill": 5, "sqlost": 2},
                )
            )
        opp_tel = sa.PlayerTelemetry(profile_id=opp_pid)
        opp_tel.observe_raw_relic_history({"profiles": profiles, "matchHistoryStats": opp_matches}, known_br_pids={880000, 880001})
        self.assertEqual(opp_tel.regional_observed_games, 8)
        self.assertGreaterEqual(opp_tel.sa_match_rate(), 0.9)
        self.assertGreaterEqual(opp_tel.br_opp_match_rate(), 0.9)

        vel = sa._analyze_skill_velocity_and_tanking(opp_tel, {"max_elo": 1448, "total_matches": 32})
        self.assertGreaterEqual(vel["elo_gain_per_game"], 12.0)
        self.assertTrue(vel["strong_velocity"])

        # Fura guarda estrangeira em unattributed_br_burner via MM BR/SA + ELO/jogo!
        unattr = sa.score_unattributed_br_burner(
            {"profile_id": opp_pid, "steam_id": opp_sid, "alias": "StealthDE", "country": "de", "max_elo": 1448, "total_matches": 32, "total_wins": 25},
            opp_tel,
            cand_osint={"ok": True, "is_limited_account": True},
        )
        self.assertTrue(unattr["triggered"])
        self.assertTrue(any("MM BR/SA" in r for r in unattr["top_reasons"]))

        # 2. Anti-bandeira 'br' falsa: 0% encontros BR/SA e fora do BRT não dispara burner BR!
        fake_tel = sa.PlayerTelemetry(
            profile_id=1_990_002,
            games=16,
            wins=13,
            regional_observed_games=16,
            br_match_count=0,
            sa_match_count=0,
            br_opp_match_count=0,
        )
        for _ in range(16):
            fake_tel.brt_hour_counts[9] += 1  # 0% prime time BRT
        unattr_fake = sa.score_unattributed_br_burner(
            {"profile_id": 1_990_002, "steam_id": "76561199990000002", "alias": "AsianFlagBR", "country": "br", "max_elo": 1520, "total_matches": 55, "total_wins": 42},
            fake_tel,
            cand_osint={"ok": True, "is_limited_account": True},
        )
        self.assertFalse(unattr_fake["triggered"])

        # 3. Desqualificador absoluto histórico (nemesis_matches desde 2023): se o Veterano JÁ enfrentou o oponente no passado,
        # ele NUNCA pode ser apontado como dono da smurf!
        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "hist_confront.db")
            inserted = db.insert_nemesis_matches_batch(
                [(main_pid, opp_pid, 777001, 1_690_000_000, 19560, 1, "1v1", "StealthDE", "de")]
            )
            self.assertEqual(inserted, 1)
            faced_set = db.get_tracked_pids_who_faced_opponent(opp_pid)
            self.assertIn(main_pid, faced_set)

            # Simula cache/avaliação live com main_pid no pool: deve ser desqualificado pelo confronto de 2023!
            main_matches = [
                _make_raw_relic_match(
                    9500 + i,
                    base_t + i * 86400 + 7200,
                    base_t + i * 86400 + 8400,
                    main_pid,
                    win=1,
                    old_elo=1480,
                    new_elo=1490,
                    counters={"gt": 1200, "totalcmds": 1705, "abil": 54, "ekills": 80, "edeaths": 50, "dmgdone": 4800, "pcap": 24, "inactperiod": 48, "sqkill": 5, "sqlost": 2},
                )
                for i in range(8)
            ]
            relic = _FakeRelicClient(
                {opp_pid: {"profile_id": opp_pid, "steam_id": opp_sid, "alias": "StealthDE", "country": "de", "max_elo": 1448, "total_matches": 32, "total_wins": 25}},
                {
                    opp_pid: {"profiles": profiles, "matchHistoryStats": opp_matches},
                    main_pid: {"profiles": [{"profile_id": main_pid, "name": f"/steam/{main_sid}", "alias": "Chacineiro", "country": "br"}], "matchHistoryStats": main_matches},
                },
            )
            ctx = sa.build_smurf_alert_context(
                db,
                relic,
                custom_players=[
                    {"profile_id": 900358, "steam_id": "76561198070545853", "original_alias": "Margheriti"},
                    {"profile_id": main_pid, "steam_id": main_sid, "original_alias": "Chacineiro"},
                ],
                br_community_data={},
                osint_client=_FakeOSINTClient({opp_sid: {"ok": True, "is_limited_account": True}}),
                allow_network=False,
            )
            res_alert = sa._evaluate_opponent_against_br_pool(
                {"profile_id": opp_pid, "alias": "StealthDE", "steam_id": opp_sid, "country": "de", "old_elo": 1432, "new_elo": 1448},
                match_participant_pids={900358, opp_pid},
                tracked_alias="Margheriti",
                relic=relic,
                ctx=ctx,
                db=db,
            )
            # NUNCA atribuído a main_pid (Chacineiro) pois já se enfrentaram em 2023!
            if res_alert is not None:
                self.assertNotEqual(res_alert["suspected_main_profile_id"], main_pid)

    def test_nemesis_fregues_and_kryptonite_sqlite_hydration_and_live_scoring(self) -> None:
        main_pid = 79327
        main_sid = "76561198014114284"
        cand_pid = 1_995_001
        cand_sid = "76561199995001000"
        nem_pid = 550001
        freg_pid = 550002

        with tempfile.TemporaryDirectory() as td:
            db = MatchDatabase(Path(td) / "rk_live.db")
            # Popula histórico permanente 2023+ no SQLite para main_pid (Nêmesis #550001, Freguês #550002 + Criptonitas de mapa/BG)
            nem_rows = []
            # 1V-5D contra Nêmesis #550001 em 3 dias distintos
            for i in range(6):
                nem_rows.append((main_pid, nem_pid, 30000 + i, 1_710_000_000 + i * 86400, 19790 + i, 1 if i == 0 else 0, "1v1", "CarrascoBR", "de"))
            # 6V-1D contra Freguês #550002 em 3 dias distintos
            for i in range(7):
                nem_rows.append((main_pid, freg_pid, 31000 + i, 1_711_000_000 + i * 86400, 19800 + i, 0 if i == 0 else 1, "1v1", "FreguesFixo", "us"))
            db.insert_nemesis_matches_batch(nem_rows)

            krypt_rows = []
            mid_seq = 40000
            for map_name, wins_n, losses_n, bg_key in (
                ("Foggia Airfield", 2, 8, "coastal_ger"),
                ("El Alamein", 2, 7, "coastal_ger"),
                ("Pachino Farmlands", 9, 2, "mechanized_ger"),
                ("Langres", 8, 2, "mechanized_ger"),
            ):
                for j in range(wins_n + losses_n):
                    mid_seq += 1
                    krypt_rows.append(
                        (
                            main_pid,
                            mid_seq,
                            1_720_000_000 + mid_seq * 100,
                            1 if j < wins_n else 0,
                            "1v1",
                            map_name,
                            "[]",
                            json.dumps([bg_key]),
                        )
                    )
            db.insert_kryptonite_matches_batch(krypt_rows)

            # Testa os novos métodos indexados do SQLite diretamente
            fetched_nem = db.get_nemesis_matches_for_opponents({nem_pid, freg_pid})
            self.assertEqual(len(fetched_nem), 13)
            kprof = db.get_kryptonite_profile_by_tracked_pids({main_pid})
            self.assertEqual(kprof[main_pid]["map_wl"]["Foggia Airfield"], [2, 8])
            self.assertEqual(kprof[main_pid]["enemy_bg_wl"]["coastal_ger"], [4, 15])

            # Constrói contexto e hidrata sob demanda a partir do SQLite sem duplicar match_ids
            ctx = sa.build_smurf_alert_context(
                db,
                relic=None,
                custom_players=[{"profile_id": main_pid, "steam_id": main_sid, "original_alias": "Chacineiro"}],
                br_community_data={},
                osint_client=_FakeOSINTClient({}),
                allow_network=False,
            )
            # Pré-carrega 1 confronto já visto (match_id=30000) para provar zero dupla contagem!
            main_tel = ctx.telemetry_by_pid.setdefault(main_pid, sa.PlayerTelemetry(profile_id=main_pid, games=40, wins=21))
            main_tel.record_match_outcome_profile(won=True, ct=1_710_000_000, match_id=30000, enemy_pids=[nem_pid])
            for h in (22, 23, 0, 1):
                main_tel.hour_counts[h] += 8
            main_tel.apm_values.extend([90.0] * 6)

            # Candidata smurf com WR inflado (72%), mesmos Nêmesis/Freguês e mesmas Criptonitas/Facilidades
            cand_tel = sa.PlayerTelemetry(profile_id=cand_pid, games=36, wins=26)
            for h in (22, 23, 0, 1):
                cand_tel.hour_counts[h] += 8
            cand_tel.apm_values.extend([88.5] * 6)
            cand_tel.opp_wl[nem_pid] = [0, 3]
            cand_tel.opp_days[nem_pid] = {20100, 20102}
            cand_tel.opp_wl[freg_pid] = [3, 0]
            cand_tel.opp_days[freg_pid] = {20101, 20103}
            cand_tel.map_wl = {
                "Foggia Airfield": [1, 4],
                "El Alamein": [1, 3],
                "Pachino Farmlands": [8, 0],
                "Langres": [7, 0],
            }
            cand_tel.enemy_bg_wl = {
                "Italian Coastal": [1, 4],
                "Mechanized": [6, 0],
            }

            sa._hydrate_rivalry_kryptonite_for_live_probe(db, cand_tel, ctx)
            self.assertTrue(ctx.kryptonite_hydrated)
            # Match 30000 não foi contado em dobro: continua exatamente 1V-5D!
            self.assertEqual(main_tel.opp_wl[nem_pid], [1, 5])
            self.assertEqual(main_tel.opp_wl[freg_pid], [6, 1])
            self.assertEqual(main_tel.map_wl["Foggia Airfield"], [2, 8])
            self.assertEqual(main_tel.enemy_bg_wl["Italian Coastal"], [4, 15])

            scored = sa.score_live_smurf_pair(
                {"profile_id": cand_pid, "steam_id": cand_sid, "alias": "SmurfLive", "country": "br", "max_elo": 1560, "total_matches": 85},
                {"profile_id": main_pid, "steam_id": main_sid, "alias": "Chacineiro", "country": "br", "max_elo": 1600, "total_matches": 900},
                cand_tel,
                main_tel,
                pid_aliases=ctx.pid_aliases,
            )
            self.assertGreaterEqual(scored["probability_pct"], 65)
            self.assertEqual(scored["rivalry_kryptonite"]["pts"], 16.0)
            self.assertEqual(scored["rivalry_kryptonite"]["shared_nemeses"], 1)
            self.assertEqual(scored["rivalry_kryptonite"]["shared_fregueses"], 1)
            self.assertTrue(any("Nêmesis/Freguês comum" in r for r in scored["top_reasons"]))
            self.assertTrue(any("Criptonitas/Matchups" in r for r in scored["top_reasons"]))

            # Anti-FP: conta com rivalidades invertidas e sem âncoras NUNCA dispara alerta
            inv_tel = sa.PlayerTelemetry(profile_id=1_995_002, games=40, wins=20)
            inv_tel.opp_wl[nem_pid] = [4, 0]
            inv_tel.opp_wl[freg_pid] = [0, 4]
            scored_inv = sa.score_live_smurf_pair(
                {"profile_id": 1_995_002, "steam_id": "76561199995002000", "alias": "InnocentBR", "country": "br", "max_elo": 1560, "total_matches": 140},
                {"profile_id": main_pid, "steam_id": main_sid, "alias": "Chacineiro", "country": "br", "max_elo": 1600, "total_matches": 900},
                inv_tel,
                main_tel,
                pid_aliases=ctx.pid_aliases,
            )
            self.assertLess(scored_inv["rivalry_kryptonite"]["pts"], 0.0)
            self.assertLessEqual(scored_inv["probability_pct"], 34)


if __name__ == "__main__":
    unittest.main()

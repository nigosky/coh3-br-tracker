#!/usr/bin/env python3
"""CLI para gerenciar Ranking (Top 20 + brasileiros via SteamID), convidados extras e testes do Discord v7."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from database import MatchDatabase
from discord_notifier import (
    DiscordWebhookClient,
    build_match_embed_payload,
    build_summary_list_payload,
    format_duration,
    format_elo_compact,
    group_matches_by_id,
)
from monitor import (
    CURRENT_SUMMARY_LAYOUT_VERSION,
    NEMESIS_OPEN_DATA_EARLIEST_DATE,
    backfill_nemesis_history_from_open_data,
    build_tracked_players_from_custom,
    ensure_core_roster_in_config,
    load_config as _load_monitor_config,
    merge_catalog_with_custom_players,
    save_config_file,
)
from relic_api import (
    CORE_BR_ROSTER,
    FACTION_KEY_LABELS,
    RelicAPIClient,
    build_roster_lookup_maps,
    compute_merged_mode_rankings,
    export_players_files,
    fetch_custom_players_stats,
    parse_profile_id_input,
    parse_steam_id_input,
    refresh_core_br_roster,
)
from security import (
    SAFE_WEBHOOK_PLACEHOLDER,
    SECRET_FILE_NAME,
    configure_secure_logging,
    redact_secrets,
    resolve_data_dir,
    resolve_safe_db_path,
    strip_unsafe_chars,
    write_local_secret_webhook,
)

configure_secure_logging(level=logging.INFO, datefmt="%H:%M:%S")
logger = logging.getLogger("coh3_br.manage")

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"


def _data_paths() -> tuple[Path, Path]:
    data_dir = resolve_data_dir(BASE_DIR)
    return data_dir / "jogadores_br_steam.json", data_dir / "jogadores_br_steam.csv"


def load_br_catalog() -> list[dict[str, Any]]:
    """Carrega catálogo local de jogadores brasileiros (respeitando COH3_DATA_DIR quando definido)."""
    data_json, _ = _data_paths()
    candidates = [
        data_json,
        BASE_DIR / "jogadores_br_steam.json",
        BASE_DIR / "br_snapshot.json",
    ]
    seen: set[Path] = set()
    for path in candidates:
        if path in seen or not path.is_file() or path.is_symlink():
            continue
        seen.add(path)
        try:
            return json.loads(path.read_text(encoding="utf-8")).get("players", [])
        except Exception:
            continue
    return []


def load_config() -> dict[str, Any]:
    """Compatível com scripts de inicialização (`from manage import load_config`)."""
    return _load_monitor_config(CONFIG_PATH)


def save_config(cfg: dict[str, Any]) -> None:
    """Salva config.json garantindo remoção incondicional de qualquer URL real de Webhook."""
    save_config_file(CONFIG_PATH, cfg)


def _clamp_int(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(int(value), maximum))


def _rebuild_rankings_and_config(cfg: dict[str, Any], relic: RelicAPIClient, reset_top: bool = False) -> None:
    """Sincroniza tracked_players diretamente a partir do elenco monitorado (Ranking Unificado agora roda em nigosky/coh3-br-ranking)."""
    del relic, reset_top
    ensure_core_roster_in_config(cfg)
    custom_players: list[dict[str, Any]] = list(cfg.get("custom_players") or [])
    cfg["custom_players"] = custom_players
    cfg["tracked_players"] = build_tracked_players_from_custom(custom_players)
    save_config(cfg)

    db_path = resolve_safe_db_path(BASE_DIR, cfg.get("sqlite_db_path"))
    with MatchDatabase(db_path) as db:
        db.sync_tracked_players(cfg["tracked_players"])
        db.set_state("summary_needs_refresh", "1")


def cmd_refresh_br(_args: argparse.Namespace) -> int:
    print("Consultando todas as leaderboards Steam (1v1, 2v2, 3v3, 4v4) na API da Relic (country=br)...")
    client = RelicAPIClient()
    players = client.fetch_brazilian_players()
    players_json_path, players_csv_path = _data_paths()
    export_players_files(players, players_json_path, players_csv_path)
    print(f"Concluído! {len(players)} jogadores brasileiros salvos.")
    return 0


def cmd_add_player(args: argparse.Namespace) -> int:
    """Adiciona jogador(es) extra(s) pelo código Steam (SteamID64/link Steam) ou ID/link do coh3stats.com."""
    raw_tokens: list[str] = []
    for item in args.targets:
        for sub in str(item).replace(",", " ").split():
            if sub.strip():
                raw_tokens.append(sub.strip())

    pids: list[int] = []
    sids: list[str] = []
    for tok in raw_tokens:
        sid = parse_steam_id_input(tok)
        if sid:
            sids.append(sid)
            continue
        pid = parse_profile_id_input(tok)
        if pid:
            pids.append(pid)
            continue
        print(
            f"ERRO: Não foi possível identificar um ID válido em '{strip_unsafe_chars(tok)[:80]}'.\n"
            "Informe o código Steam de 17 dígitos (7656119...), link steamcommunity.com/profiles/... "
            "ou link https://coh3stats.com/players/ID."
        )
        return 1

    relic = RelicAPIClient()
    custom_seed: list[dict[str, Any]] = [{"steam_id": s} for s in sids] + [{"profile_id": p} for p in pids]
    fetched = fetch_custom_players_stats(relic, custom_seed)
    fetched_by_id = {int(p["profile_id"]): p for p in fetched}
    fetched_by_sid = {str(p.get("steam_id") or ""): p for p in fetched if p.get("steam_id")}

    cfg = load_config()
    custom_list: list[dict[str, Any]] = cfg.get("custom_players", [])
    custom_by_id: dict[int, dict[str, Any]] = {
        int(c["profile_id"]): dict(c) for c in custom_list if int(c.get("profile_id", 0)) > 0
    }

    for sid in sids:
        info = fetched_by_sid.get(sid)
        if not info:
            print(f"AVISO: Conta Steam {sid} ainda não possui registro público de CoH3 na API da Relic.")
            continue
        pid = int(info["profile_id"])
        orig_alias = custom_by_id.get(pid, {}).get("original_alias") or info.get("current_alias") or info["alias"]
        custom_by_id[pid] = {
            "profile_id": pid,
            "steam_id": sid,
            "original_alias": orig_alias,
            "alias": info["alias"],
        }
        print(f"[+] Jogador vinculado por SteamID ({sid}): ⭐ {strip_unsafe_chars(info['alias'])} (Relic #{pid})")

    for pid in pids:
        info = fetched_by_id.get(pid)
        if not info:
            matches = relic.fetch_player_recent_matches(pid)
            alias = matches[0]["tracked_alias"] if matches else f"Player {pid}"
            steam_id = matches[0].get("tracked_steam_id", "") if matches else ""
        else:
            alias = info["alias"]
            steam_id = info.get("steam_id", "")

        orig_alias = custom_by_id.get(pid, {}).get("original_alias") or alias
        custom_by_id[pid] = {
            "profile_id": pid,
            "steam_id": steam_id,
            "original_alias": orig_alias,
            "alias": alias,
        }
        print(f"[+] Jogador adicionado e vinculado (Steam {steam_id or 'N/D'}): ⭐ {strip_unsafe_chars(alias)} (Relic #{pid})")

    cfg["custom_players"] = list(custom_by_id.values())
    _rebuild_rankings_and_config(cfg, relic, reset_top=False)
    return 0


def cmd_remove_player(args: argparse.Namespace) -> int:
    """Remove jogador(es) convidado(s) extra(s) (mantendo protegida a lista fixa brasileira)."""
    pids_to_remove: set[int] = set()
    sids_to_remove: set[str] = set()
    for item in args.targets:
        for sub in str(item).replace(",", " ").split():
            sid = parse_steam_id_input(sub)
            if sid:
                sids_to_remove.add(sid)
                continue
            pid = parse_profile_id_input(sub)
            if pid:
                pids_to_remove.add(pid)

    if not pids_to_remove and not sids_to_remove:
        print("ERRO: Informe pelo menos um SteamID64, Relic ID ou link válido do coh3stats.com.")
        return 1

    refresh_core_br_roster()
    live_core_pids = {int(x["profile_id"]) for x in CORE_BR_ROSTER}
    live_core_sids = {str(x["steam_id"]) for x in CORE_BR_ROSTER}
    blocked_core = (pids_to_remove & live_core_pids) or (sids_to_remove & live_core_sids)
    if blocked_core:
        print(
            "AVISO: Jogadores da base compartilhada (players_roster.json em nigosky/coh3-br-lobby-radar) "
            "devem ser removidos via workflow 'Gerenciar Base Compartilhada de Jogadores' para refletir nos 4 sistemas."
        )
        pids_to_remove -= live_core_pids
        sids_to_remove -= live_core_sids
        if not pids_to_remove and not sids_to_remove:
            return 0

    cfg = load_config()
    custom_before = cfg.get("custom_players", [])
    cfg["custom_players"] = [
        c
        for c in custom_before
        if int(c.get("profile_id", 0)) not in pids_to_remove
        and str(c.get("steam_id") or "") not in sids_to_remove
    ]
    cfg["tracked_players"] = [
        p
        for p in cfg.get("tracked_players", [])
        if int(p.get("profile_id", 0)) not in pids_to_remove
        and str(p.get("steam_id") or "") not in sids_to_remove
    ]

    relic = RelicAPIClient()
    _rebuild_rankings_and_config(cfg, relic, reset_top=False)
    print("[-] Lista de jogadores convidados extras atualizada com sucesso.")
    return 0


def cmd_list_br(args: argparse.Namespace) -> int:
    limit = _clamp_int(args.limit, 1, 500)
    players = load_br_catalog()
    if not players:
        cmd_refresh_br(args)
        players = load_br_catalog()

    cfg = load_config()
    selected_ids = {int(p["profile_id"]) for p in cfg.get("tracked_players", [])}

    filtered: list[dict[str, Any]] = []
    query = (args.search or "").strip().lower()
    mode_filter = (args.mode or "").strip().lower()

    for p in players:
        modes = sorted({v["mode"] for v in p.get("modes", {}).values()})
        if mode_filter and mode_filter not in modes:
            continue
        if query and query not in str(p["alias"]).lower() and query != str(p["profile_id"]):
            continue
        filtered.append(p)

    print(f"Total encontrado: {len(filtered)} (mostrando top {min(len(filtered), limit)})\n")
    print(f"{'MON':<4} {'RELIC ID':<10} {'JOGADOR':<26} {'MAX ELO':<8} {'MELHOR MODO':<16} {'V / D':<13} {'MODOS'}")
    print("-" * 96)
    for p in filtered[:limit]:
        mark = "[X]" if int(p["profile_id"]) in selected_ids else "[ ]"
        modes = ",".join(sorted({v["mode"] for v in p.get("modes", {}).values()}))
        vd = f"{p.get('total_wins', 0)}V/{p.get('total_losses', 0)}D"
        alias = strip_unsafe_chars(p["alias"])[:25]
        print(
            f"{mark:<4} {p['profile_id']:<10} {alias:<26} {int(round(p.get('max_elo', 0))):<8} "
            f"{p.get('best_mode', ''):<16} {vd:<13} {modes}"
        )
    return 0


def cmd_selected(_args: argparse.Namespace) -> int:
    cfg = load_config()
    tracked = cfg.get("tracked_players", [])
    print(f"Jogadores brasileiros com partidas monitoradas ({len(tracked)} jogadores vinculados via SteamID):")
    for p in tracked:
        pid = int(p["profile_id"])
        sid = p.get("steam_id") or "N/D"
        orig = strip_unsafe_chars(p.get("original_alias") or p["alias"])
        alias = strip_unsafe_chars(p["alias"])
        print(
            f"  • {alias} [Nick Original: {orig} | Steam: {sid} | Relic: {pid}] -> https://coh3stats.com/players/{pid}"
        )
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    limit = _clamp_int(args.limit, 1, 500)
    cfg = load_config()
    db_path = resolve_safe_db_path(BASE_DIR, cfg.get("sqlite_db_path"))
    with MatchDatabase(db_path) as db:
        matches = db.get_recent_recorded_matches(limit=limit, only_active_players=True)

    if not matches:
        print("Nenhuma partida gravada ainda no SQLite. Rode `python3 monitor.py --once` para sincronizar!")
        return 0

    print(f"Últimas {len(matches)} partidas gravadas dos jogadores monitorados em {db_path.name}:\n")
    for m in matches:
        dt = datetime.fromtimestamp(m["completion_time"]).strftime("%d/%m/%Y %H:%M")
        res = "VITÓRIA" if m["win"] else "DERROTA"
        opps = ", ".join(f"{strip_unsafe_chars(o['alias'])} ({o['faction_short']})" for o in m["opponents"])
        elo = format_elo_compact(m.get("old_elo"), m.get("new_elo"))
        dur = format_duration(m["duration_sec"])
        print(
            f"[{dt}] {res:<7} | {strip_unsafe_chars(m['tracked_alias'])} ({m['tracked_faction_short']}) | "
            f"{m['mode']} • {strip_unsafe_chars(m['map_clean'])} ({dur}) | ELO {elo} | vs {opps}"
        )
    return 0


def cmd_test_discord(args: argparse.Namespace) -> int:
    cfg = load_config()
    db_path = resolve_safe_db_path(BASE_DIR, cfg.get("sqlite_db_path"))
    custom_players = cfg.get("custom_players", [])
    roster_maps = build_roster_lookup_maps(custom_players)
    players_json_path, _ = _data_paths()
    if not players_json_path.is_file():
        players_json_path = BASE_DIR / "jogadores_br_steam.json"

    with MatchDatabase(db_path) as db:
        if not args.dry_run:
            db.sync_tracked_players(cfg.get("tracked_players", []))
        tracked = db.get_active_players() or cfg.get("tracked_players", [])

        matches = db.get_recent_recorded_matches(
            limit=max(40, int(cfg.get("summary_list_size", 15)) * 3),
            only_active_players=True,
        )

        if not matches and tracked and not args.dry_run:
            print("Buscando partidas recentes dos monitorados na API da Relic para montar o teste...")
            client = RelicAPIClient()
            for p in tracked[:4]:
                fetched = client.fetch_player_recent_matches(
                    int(p["profile_id"]),
                    p.get("original_alias") or p["alias"],
                    roster_maps=roster_maps,
                )
                for m in reversed(fetched[:3]):
                    db.insert_match(m)
            matches = db.get_recent_recorded_matches(limit=40, only_active_players=True)

        if not matches:
            print("Nenhuma partida disponível para os jogadores monitorados.")
            return 1

        grouped = group_matches_by_id(matches)
        sample_group = grouped[0]

        sample_opps = sample_group["primary"].get("opponents", [])
        if not args.dry_run and sample_opps and "elo_delta" not in sample_opps[0]:
            try:
                live_client = RelicAPIClient()
                p0 = sample_group["primary"]
                fresh_list = live_client.fetch_player_recent_matches(
                    int(p0["tracked_profile_id"]),
                    str(p0["tracked_alias"]),
                    roster_maps=roster_maps,
                )
                matched_fresh = [fm for fm in fresh_list if int(fm["match_id"]) == int(sample_group["match_id"])]
                if matched_fresh:
                    sample_group = {
                        "match_id": int(sample_group["match_id"]),
                        "primary": matched_fresh[0],
                        "records": matched_fresh,
                    }
            except Exception as exc:
                logger.debug("Falha opcional ao enriquecer amostra de partida: %s", redact_secrets(exc))

        summary_payload = build_summary_list_payload(
            matches,
            tracked,
            cfg.get("bot_username", "CoH3 Brasil Monitor"),
            custom_players=custom_players,
        )
        card_payload = build_match_embed_payload(sample_group, cfg.get("bot_username", "CoH3 Brasil Monitor"))

        if args.dry_run:
            print("=== PAYLOAD 1: PAINEL FIXADO PT-BR (ÚLTIMAS PARTIDAS) ===")
            print(json.dumps(summary_payload, ensure_ascii=False, indent=2))
            print("\n=== PAYLOAD 2: CARD PARTIDA PT-BR ===")
            print(json.dumps(card_payload, ensure_ascii=False, indent=2))
            return 0

        discord = DiscordWebhookClient(
            cfg.get("discord_webhook_url", ""),
            cfg.get("bot_username", "CoH3 Brasil Monitor"),
            db=db,
            catalog_json_path=players_json_path,
        )
        if not discord.is_configured:
            print("ERRO: Configure uma URL válida no Secret DISCORD_WEBHOOK_URL ou via set-webhook (ou use --dry-run).")
            return 1

        summary_id = db.get_state("summary_message_id")
        new_summary_id = discord.upsert_summary_message(
            matches,
            tracked,
            summary_id,
            custom_players=custom_players,
        )
        if new_summary_id:
            db.set_state("summary_message_id", new_summary_id)
            db.set_state("summary_layout_version", CURRENT_SUMMARY_LAYOUT_VERSION)
            print(f"[OK] Painel Fixado PT-BR atualizado no Discord (message_id={new_summary_id}).")

        card_id = discord.send_match_card(sample_group)
        if card_id:
            db.record_ephemeral_message(card_id, kind="test_card")
        print(f"[OK] Card PT-BR da partida #{sample_group['match_id']} enviado ao Discord (message_id={card_id}).")
        return 0


def cmd_rankings(args: argparse.Namespace) -> int:
    top_n = _clamp_int(args.top, 1, 100)
    cfg = load_config()
    custom_players = cfg.get("custom_players", [])
    custom_ids = {int(c["profile_id"]) for c in custom_players if int(c.get("profile_id", 0)) > 0}
    custom_sids = {str(c["steam_id"]) for c in custom_players if c.get("steam_id")}

    players = load_br_catalog()
    relic = RelicAPIClient()
    if not players:
        cmd_refresh_br(args)
        players = load_br_catalog()

    merged_players = merge_catalog_with_custom_players(players, custom_players, relic)
    rankings = compute_merged_mode_rankings(
        merged_players,
        custom_ids=custom_ids,
        custom_steam_ids=custom_sids,
    )
    modes = [args.mode] if args.mode else ["1v1", "2v2", "Team Games"]

    for mode in modes:
        all_entries = rankings.get(mode, [])
        entries = [e for idx, e in enumerate(all_entries) if idx < top_n or e.get("is_custom")]
        mode_pt = "JOGOS EM EQUIPE (3V3 + 4V4)" if mode == "Team Games" else mode.upper()
        print(f"\n=== TOP {top_n} BR + MONITORADOS — {mode_pt} ===")
        print(f"{'POS.':<6} {'RELIC ID':<10} {'JOGADOR':<30} {'MÉDIA ELO':<10} {'ATIVOS':<8} {'ELO POR FACÇÃO'}")
        print("-" * 106)
        for e in entries:
            fac_str = ", ".join(f"{FACTION_KEY_LABELS[f]}: {v}" for f, v in e["faction_elos"].items())
            star = " ⭐" if e.get("is_custom") else ""
            alias = (strip_unsafe_chars(e["alias"])[:25] + star)[:29]
            slots = f"{e['active_rankings_count']}/{e['max_rankings_slots']}"
            print(
                f"{e['br_rank']:02d}º    {e['profile_id']:<10} {alias:<30} {e['avg_elo']:<10.1f} "
                f"{slots:<8} {fac_str}"
            )
    return 0


def cmd_select_top(args: argparse.Namespace) -> int:
    top_n = _clamp_int(args.top, 1, 100)
    cfg = load_config()
    cfg["auto_follow_top_br"] = True
    cfg["top_n_per_mode"] = top_n
    cfg.setdefault("leaderboard_refresh_minutes", 15)
    cfg.setdefault("monitor_only_custom_matches", True)

    relic = RelicAPIClient()
    _rebuild_rankings_and_config(cfg, relic, reset_top=bool(args.reset))
    updated = load_config()
    print(
        f"Ranking Top {top_n} + {len(updated.get('custom_players', []))} monitorados atualizado! "
        f"Partidas monitoradas: {len(updated.get('tracked_players', []))} jogadores."
    )
    return 0


def cmd_set_webhook(args: argparse.Namespace) -> int:
    url = (args.url or "").strip()
    if not url:
        url = getpass.getpass("Cole aqui a URL do Webhook (entrada oculta por segurança): ").strip()

    client = DiscordWebhookClient(url)
    if not client.is_configured:
        print(
            "ERRO: A URL informada não passou na validação estrita de segurança.\n"
            "Formato exigido: https://discord.com/api/webhooks/ID_NUMERICO/TOKEN"
        )
        return 1

    write_local_secret_webhook(BASE_DIR, url)

    cfg = load_config()
    cfg["discord_webhook_url"] = SAFE_WEBHOOK_PLACEHOLDER
    if args.name:
        cfg["bot_username"] = strip_unsafe_chars(args.name)[:60]
    save_config(cfg)
    print(f"[OK] Webhook isolado com permissão restrita (0600) em {SECRET_FILE_NAME} (fora do Git)!")

    if args.test:
        print("Enviando mensagem inicial de teste + Painel Resumo para o seu canal...")
        test_args = argparse.Namespace(dry_run=False)
        return cmd_test_discord(test_args)
    return 0


def cmd_backfill_nemesis(args: argparse.Namespace) -> int:
    """Reconstroi o histórico completo da tabela `nemesis_matches` desde o início do arquivo Open Data (2023-06-30)."""
    refresh_core_br_roster()
    cfg = load_config()
    ensure_core_roster_in_config(cfg)
    tracked_players = build_tracked_players_from_custom(list(cfg.get("custom_players") or []))
    db_path = resolve_safe_db_path(BASE_DIR, cfg.get("sqlite_db_path"))
    since_str = str(args.since or NEMESIS_OPEN_DATA_EARLIEST_DATE).strip()
    until_str = str(args.until or "").strip() or None
    workers = _clamp_int(args.workers, 1, 6)

    def _on_progress(done: int, total: int, inserted: int, scanned: int) -> None:
        print(
            f"  [NEMESIS BACKFILL] {done}/{total} dias | +{inserted} confrontos inseridos | {scanned:,} partidas Open Data varridas",
            flush=True,
        )

    print(
        f"Iniciando backfill histórico de Nemesis ({len(tracked_players)} contas monitoradas | "
        f"de {since_str} até {until_str or 'ontem UTC'} | {workers} workers em streaming)...",
        flush=True,
    )
    with MatchDatabase(db_path) as db:
        db.sync_tracked_players(tracked_players)
        res = backfill_nemesis_history_from_open_data(
            db,
            tracked_players,
            start_date=since_str,
            end_date=until_str,
            max_workers=workers,
            progress_callback=_on_progress,
        )
        if getattr(args, "vacuum", False):
            db._connect().execute("VACUUM")
            cov = db.get_nemesis_coverage_summary()
            kcov = db.get_kryptonite_coverage_summary()
        else:
            cov = res["coverage_after"]
            kcov = res.get("kryptonite_coverage_after") or db.get_kryptonite_coverage_summary()

    min_ct = int(cov.get("min_completion_time", 0) or 0)
    max_ct = int(cov.get("max_completion_time", 0) or 0)
    min_d = datetime.utcfromtimestamp(min_ct).strftime("%Y-%m-%d") if min_ct > 0 else "N/D"
    max_d = datetime.utcfromtimestamp(max_ct).strftime("%Y-%m-%d") if max_ct > 0 else "N/D"
    k_min_ct = int(kcov.get("min_completion_time", 0) or 0)
    k_max_ct = int(kcov.get("max_completion_time", 0) or 0)
    k_min_d = datetime.utcfromtimestamp(k_min_ct).strftime("%Y-%m-%d") if k_min_ct > 0 else "N/D"
    k_max_d = datetime.utcfromtimestamp(k_max_ct).strftime("%Y-%m-%d") if k_max_ct > 0 else "N/D"
    print(
        f"\n[CONCLUÍDO] Dias OK: {res['days_ok']}/{res['days_requested']} (404: {res['days_not_published']}, erros: {res['days_failed']}) | "
        f"Partidas Open Data varridas: {res['matches_scanned']:,} | Novos confrontos Nemesis: +{res['nemesis_rows_inserted']:,} | "
        f"Novas partidas Criptonita: +{res.get('kryptonite_rows_inserted', 0):,}\n"
        f"[COBERTURA NEMESIS/FREGUÊS] Total linhas: {cov['total_rows']:,} | Partidas únicas: {cov['unique_matches']:,} | "
        f"Período: {min_d} .. {max_d} | Pares Nemesis (2023+): {cov['distinct_nemesis_pairs']:,} | "
        f"Pares Freguês (2023+): {cov.get('distinct_fregues_pairs', 0):,}\n"
        f"[COBERTURA CRIPTONITA] Total linhas: {kcov['total_rows']:,} | Partidas únicas: {kcov['unique_matches']:,} | "
        f"Período: {k_min_d} .. {k_max_d} | Partidas com BGs permanentes: {kcov.get('rows_with_bg', 0):,}",
        flush=True,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gerenciador CoH3 Brasil Tracker v7")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("refresh-br", help="Varre todos os modos Steam na API da Relic e atualiza a lista de brasileiros")

    p_rank = sub.add_parser(
        "rankings",
        help="Exibe o Ranking Top 20 + monitorados em 1v1, 2v2 e Jogos em Equipe (3v3+4v4)",
    )
    p_rank.add_argument("--mode", choices=["1v1", "2v2", "Team Games"], help="Modo específico (opcional)")
    p_rank.add_argument("--top", type=int, default=20, help="Quantidade por modo (padrão: 20)")

    p_seltop = sub.add_parser(
        "select-top",
        help="Atualiza config.json e tabelas com o Ranking (Top 20 + monitorados)",
    )
    p_seltop.add_argument("--top", type=int, default=20, help="Quantidade por modo (padrão: 20)")
    p_seltop.add_argument("--reset", action="store_true", help="Reconstrói lista limpa de monitorados")

    p_add = sub.add_parser(
        "add-player",
        help="Adiciona jogador extra via SteamID64, link Steam ou ID/link do coh3stats.com",
    )
    p_add.add_argument("targets", nargs="+", help="SteamID64, links Steam ou links https://coh3stats.com/players/...")

    p_rem = sub.add_parser(
        "remove-player",
        help="Remove jogador convidado extra (mantendo os principais protegidos)",
    )
    p_rem.add_argument("targets", nargs="+", help="SteamID64, links Steam ou links https://coh3stats.com/players/...")

    p_list = sub.add_parser("list-br", help="Exibe a lista geral de jogadores brasileiros encontrados")
    p_list.add_argument("--mode", choices=["1v1", "2v2", "3v3", "4v4"], help="Filtra por leaderboard bruta")
    p_list.add_argument("--search", help="Busca por apelido ou Relic ID")
    p_list.add_argument("--limit", type=int, default=30, help="Quantidade máxima de linhas")

    p_sel = sub.add_parser("select", help="Atalho equivalente a add-player")
    p_sel.add_argument("targets", nargs="+", help="SteamID64 ou links coh3stats")
    p_unsel = sub.add_parser("unselect", help="Atalho equivalente a remove-player")
    p_unsel.add_argument("targets", nargs="+", help="SteamID64 ou links coh3stats")

    sub.add_parser("selected", help="Lista todos os jogadores com partidas monitoradas (vinculados via SteamID)")

    p_hist = sub.add_parser("history", help="Lista no terminal as partidas já gravadas no SQLite")
    p_hist.add_argument("--limit", type=int, default=20)

    p_wh = sub.add_parser("set-webhook", help="Configura a URL do Webhook localmente em .env.secret (chmod 0600)")
    p_wh.add_argument("url", nargs="?", help="URL do Webhook do Discord")
    p_wh.add_argument("--name", help="Nome exibido no canal do Discord")
    p_wh.add_argument("--test", action="store_true", help="Publica o Painel Fixado + 1 Card de teste")

    p_test = sub.add_parser("test-discord", help="Testa o envio do Painel Fixado PT-BR + Card de Partida")
    p_test.add_argument("--dry-run", action="store_true", help="Exibe os JSONs sem enviar HTTP")

    p_bnem = sub.add_parser(
        "backfill-nemesis",
        help="Popula o histórico completo de Nemesis (Automatch Steam) desde 2023-06-30 via COH3 Stats Open Data",
    )
    p_bnem.add_argument("--since", default=NEMESIS_OPEN_DATA_EARLIEST_DATE, help="Data inicial UTC YYYY-MM-DD (mín. 2023-06-30)")
    p_bnem.add_argument("--until", default="", help="Data final UTC YYYY-MM-DD (padrão: ontem UTC)")
    p_bnem.add_argument("--workers", type=int, default=4, help="Workers paralelos de streaming (1..6, padrão: 4)")
    p_bnem.add_argument("--vacuum", action="store_true", help="Executa VACUUM no SQLite ao finalizar")

    args = parser.parse_args()
    dispatch = {
        "refresh-br": cmd_refresh_br,
        "rankings": cmd_rankings,
        "select-top": cmd_select_top,
        "add-player": cmd_add_player,
        "remove-player": cmd_remove_player,
        "select": cmd_add_player,
        "unselect": cmd_remove_player,
        "list-br": cmd_list_br,
        "selected": cmd_selected,
        "history": cmd_history,
        "set-webhook": cmd_set_webhook,
        "test-discord": cmd_test_discord,
        "backfill-nemesis": cmd_backfill_nemesis,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

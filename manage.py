#!/usr/bin/env python3
"""CLI para gerenciar Ranking (Top 20 + 31 brasileiros via SteamID), convidados extras e testes do Discord v5."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
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
    ensure_core_roster_in_config,
    load_cached_rankings,
    merge_catalog_with_custom_players,
)
from relic_api import (
    CORE_BR_ROSTER,
    FACTION_KEY_LABELS,
    RelicAPIClient,
    build_roster_lookup_maps,
    build_top_tracked_players,
    compute_merged_mode_rankings,
    export_merged_top_rankings,
    export_players_files,
    fetch_custom_players_stats,
    parse_profile_id_input,
    parse_steam_id_input,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("coh3_br.manage")

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
SECRET_ENV_PATH = BASE_DIR / ".env.secret"
SAFE_WEBHOOK_PLACEHOLDER = "DEFINA_NOS_SECRETS_DO_GITHUB_DISCORD_WEBHOOK_URL"
PLAYERS_JSON_PATH = BASE_DIR / "jogadores_br_steam.json"
PLAYERS_CSV_PATH = BASE_DIR / "jogadores_br_steam.csv"
SNAPSHOT_FALLBACK_PATH = BASE_DIR / "br_snapshot.json"

CORE_STEAM_IDS = {str(x["steam_id"]) for x in CORE_BR_ROSTER}
CORE_PROFILE_IDS = {int(x["profile_id"]) for x in CORE_BR_ROSTER}


def load_br_catalog() -> list[dict[str, Any]]:
    if PLAYERS_JSON_PATH.exists():
        return json.loads(PLAYERS_JSON_PATH.read_text(encoding="utf-8")).get("players", [])
    if SNAPSHOT_FALLBACK_PATH.exists():
        return json.loads(SNAPSHOT_FALLBACK_PATH.read_text(encoding="utf-8")).get("players", [])
    return []


def _read_local_secret_webhook() -> str:
    if not SECRET_ENV_PATH.exists():
        return ""
    for line in SECRET_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DISCORD_WEBHOOK_URL="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def load_config() -> dict[str, Any]:
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    ensure_core_roster_in_config(cfg)
    env_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    local_secret = _read_local_secret_webhook()
    if env_webhook:
        cfg["discord_webhook_url"] = env_webhook
    elif local_secret:
        cfg["discord_webhook_url"] = local_secret
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db:
        cfg["sqlite_db_path"] = env_db
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    sanitized = dict(cfg)
    raw_wh = str(sanitized.get("discord_webhook_url", ""))
    if "discord.com/api/" in raw_wh or "discordapp.com/api/" in raw_wh:
        sanitized["discord_webhook_url"] = SAFE_WEBHOOK_PLACEHOLDER
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db and sanitized.get("sqlite_db_path") == env_db:
        try:
            disk_db = json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("sqlite_db_path", "./coh3_br_matches.db")
        except Exception:
            disk_db = "./coh3_br_matches.db"
        sanitized["sqlite_db_path"] = disk_db
    CONFIG_PATH.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rebuild_rankings_and_config(cfg: dict[str, Any], relic: RelicAPIClient, reset_top: bool = False) -> None:
    ensure_core_roster_in_config(cfg)
    top_n = int(cfg.get("top_n_per_mode", 20))
    only_custom = bool(cfg.get("monitor_only_custom_matches", True))
    custom_players: list[dict[str, Any]] = cfg.get("custom_players", [])

    base_players = load_br_catalog()
    if not base_players:
        base_players = relic.fetch_brazilian_players()
        export_players_files(base_players, PLAYERS_JSON_PATH, PLAYERS_CSV_PATH)

    merged_players = merge_catalog_with_custom_players(base_players, custom_players, relic)
    custom_ids = {int(cp["profile_id"]) for cp in custom_players if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp["steam_id"]) for cp in custom_players if cp.get("steam_id")}

    rankings = compute_merged_mode_rankings(
        merged_players,
        custom_ids=custom_ids,
        custom_steam_ids=custom_sids,
    )

    json_out = BASE_DIR / f"top{top_n}_br_por_modo.json"
    csv_out = BASE_DIR / f"top{top_n}_br_por_modo.csv"
    export_merged_top_rankings(rankings, top_n, json_out, csv_out, custom_players=custom_players)

    monitored_list = build_top_tracked_players(
        rankings,
        top_n=top_n,
        custom_players=custom_players,
        only_custom=only_custom,
    )
    if only_custom or reset_top:
        merged_by_id: dict[int, dict[str, Any]] = {}
    else:
        merged_by_id = {int(p["profile_id"]): p for p in cfg.get("tracked_players", []) if "profile_id" in p}

    for p in monitored_list:
        pid = int(p["profile_id"])
        rec_p: dict[str, Any] = {
            "profile_id": pid,
            "alias": p["alias"],
            "original_alias": str(p.get("original_alias") or p["alias"]),
            "steam_id": str(p.get("steam_id") or merged_by_id.get(pid, {}).get("steam_id") or ""),
            "placements": p["placements"],
            "is_custom": bool(p.get("is_custom")) or (pid in custom_ids),
        }
        if p.get("merged_into_profile_id"):
            rec_p["merged_into_profile_id"] = int(p["merged_into_profile_id"])
        merged_by_id[pid] = rec_p

    cfg["custom_players"] = custom_players
    cfg["tracked_players"] = list(merged_by_id.values())
    save_config(cfg)

    db_path = (BASE_DIR / cfg.get("sqlite_db_path", "./coh3_br_matches.db")).resolve()
    db = MatchDatabase(db_path)
    db.sync_tracked_players(cfg["tracked_players"])
    db.set_state("rankings_updated_flag", "1")


def cmd_refresh_br(_args: argparse.Namespace) -> int:
    print("Consultando todas as leaderboards Steam (1v1, 2v2, 3v3, 4v4) na API da Relic (country=br)...")
    client = RelicAPIClient()
    players = client.fetch_brazilian_players()
    export_players_files(players, PLAYERS_JSON_PATH, PLAYERS_CSV_PATH)
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
            f"ERRO: Não foi possível identificar um ID válido em '{tok}'.\n"
            "Informe o código Steam de 17 dígitos (7656119...), link steamcommunity.com/profiles/... "
            "ou link https://coh3stats.com/players/ID."
        )
        return 1

    relic = RelicAPIClient()
    fetched = fetch_custom_players_stats(relic, pids, steam_ids=sids)
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
        print(f"[+] Jogador vinculado por SteamID ({sid}): ⭐ {info['alias']} (Relic #{pid})")

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
        print(f"[+] Jogador adicionado e vinculado (Steam {steam_id or 'N/D'}): ⭐ {alias} (Relic #{pid})")

    cfg["custom_players"] = list(custom_by_id.values())
    _rebuild_rankings_and_config(cfg, relic, reset_top=False)
    return 0


def cmd_remove_player(args: argparse.Namespace) -> int:
    """Remove jogador(es) convidado(s) extra(s) (mantendo protegida a lista fixa dos 31 brasileiros)."""
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

    blocked_core = (pids_to_remove & CORE_PROFILE_IDS) or (sids_to_remove & CORE_STEAM_IDS)
    if blocked_core:
        print(
            "AVISO: Os 31 jogadores brasileiros principais fazem parte da lista fixa protegida "
            "e permanecem monitorados automaticamente."
        )
        pids_to_remove -= CORE_PROFILE_IDS
        sids_to_remove -= CORE_STEAM_IDS
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

    print(f"Total encontrado: {len(filtered)} (mostrando top {min(len(filtered), args.limit)})\n")
    print(f"{'MON':<4} {'RELIC ID':<10} {'JOGADOR':<26} {'MAX ELO':<8} {'MELHOR MODO':<16} {'V / D':<13} {'MODOS'}")
    print("-" * 96)
    for p in filtered[: args.limit]:
        mark = "[X]" if int(p["profile_id"]) in selected_ids else "[ ]"
        modes = ",".join(sorted({v["mode"] for v in p.get("modes", {}).values()}))
        vd = f"{p.get('total_wins', 0)}V/{p.get('total_losses', 0)}D"
        alias = str(p["alias"])[:25]
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
        orig = p.get("original_alias") or p["alias"]
        print(
            f"  • {p['alias']} [Nick Original: {orig} | Steam: {sid} | Relic: {pid}] -> https://coh3stats.com/players/{pid}"
        )
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    cfg = load_config()
    db_path = (BASE_DIR / cfg.get("sqlite_db_path", "./coh3_br_matches.db")).resolve()
    db = MatchDatabase(db_path)
    matches = db.get_recent_recorded_matches(limit=args.limit, only_active_players=True)
    if not matches:
        print("Nenhuma partida gravada ainda no SQLite. Rode `python3 monitor.py --once` para sincronizar!")
        return 0

    print(f"Últimas {len(matches)} partidas gravadas dos jogadores monitorados em {db_path.name}:\n")
    for m in matches:
        dt = datetime.fromtimestamp(m["completion_time"]).strftime("%d/%m/%Y %H:%M")
        res = "VITÓRIA" if m["win"] else "DERROTA"
        opps = ", ".join(f"{o['alias']} ({o['faction_short']})" for o in m["opponents"])
        elo = format_elo_compact(m.get("old_elo"), m.get("new_elo"))
        dur = format_duration(m["duration_sec"])
        print(
            f"[{dt}] {res:<7} | {m['tracked_alias']} ({m['tracked_faction_short']}) | "
            f"{m['mode']} • {m['map_clean']} ({dur}) | ELO {elo} | vs {opps}"
        )
    return 0


def cmd_test_discord(args: argparse.Namespace) -> int:
    cfg = load_config()
    db_path = (BASE_DIR / cfg.get("sqlite_db_path", "./coh3_br_matches.db")).resolve()
    db = MatchDatabase(db_path)
    db.sync_tracked_players(cfg.get("tracked_players", []))
    tracked = db.get_active_players()
    top_n = int(cfg.get("top_n_per_mode", 20))
    custom_players = cfg.get("custom_players", [])
    roster_maps = build_roster_lookup_maps(custom_players)

    matches = db.get_recent_recorded_matches(
        limit=max(40, int(cfg.get("summary_list_size", 15)) * 3),
        only_active_players=True,
    )

    if not matches and tracked:
        print("Buscando partidas recentes dos 31 monitorados na API da Relic para montar o teste...")
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

    cached_rankings = load_cached_rankings(BASE_DIR, top_n=top_n)
    grouped = group_matches_by_id(matches)
    sample_group = grouped[0]

    sample_opps = sample_group["primary"].get("opponents", [])
    if sample_opps and "elo_delta" not in sample_opps[0]:
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
        except Exception:
            pass

    summary_payload = build_summary_list_payload(
        matches,
        tracked,
        cfg.get("bot_username", "CoH3 Brasil Monitor"),
        rankings_by_mode=cached_rankings,
        custom_players=custom_players,
    )
    card_payload = build_match_embed_payload(sample_group, cfg.get("bot_username", "CoH3 Brasil Monitor"))

    if args.dry_run:
        print("=== PAYLOAD 1: PAINEL FIXADO PT-BR (RANKING 20+31 + PARTIDAS DOS 31) ===")
        print(json.dumps(summary_payload, ensure_ascii=False, indent=2))
        print("\n=== PAYLOAD 2: CARD PARTIDA PT-BR ===")
        print(json.dumps(card_payload, ensure_ascii=False, indent=2))
        return 0

    discord = DiscordWebhookClient(
        cfg.get("discord_webhook_url", ""),
        cfg.get("bot_username", "CoH3 Brasil Monitor"),
        db=db,
        catalog_json_path=PLAYERS_JSON_PATH,
    )
    if not discord.is_configured:
        print("ERRO: Configure uma URL válida no Secret DISCORD_WEBHOOK_URL ou via set-webhook (ou use --dry-run).")
        return 1

    summary_id = db.get_state("summary_message_id")
    new_summary_id = discord.upsert_summary_message(
        matches,
        tracked,
        summary_id,
        rankings_by_mode=cached_rankings,
        custom_players=custom_players,
        top_n=top_n,
    )
    if new_summary_id:
        db.set_state("summary_message_id", new_summary_id)
        db.set_state("summary_layout_version", CURRENT_SUMMARY_LAYOUT_VERSION)
        print(f"[OK] Painel Fixado PT-BR atualizado no Discord (message_id={new_summary_id}).")

    card_id = discord.send_match_card(sample_group)
    print(f"[OK] Card PT-BR da partida #{sample_group['match_id']} enviado ao Discord (message_id={card_id}).")
    return 0


def cmd_rankings(args: argparse.Namespace) -> int:
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
        entries = [
            e for idx, e in enumerate(all_entries) if idx < args.top or e.get("is_custom")
        ]
        mode_pt = "JOGOS EM EQUIPE (3V3 + 4V4)" if mode == "Team Games" else mode.upper()
        print(f"\n=== TOP {args.top} BR + 31 MONITORADOS — {mode_pt} ===")
        print(f"{'POS.':<6} {'RELIC ID':<10} {'JOGADOR':<30} {'MÉDIA ELO':<10} {'ATIVOS':<8} {'ELO POR FACÇÃO'}")
        print("-" * 106)
        for e in entries:
            fac_str = ", ".join(f"{FACTION_KEY_LABELS[f]}: {v}" for f, v in e["faction_elos"].items())
            star = " ⭐" if e.get("is_custom") else ""
            alias = (e["alias"][:25] + star)[:29]
            slots = f"{e['active_rankings_count']}/{e['max_rankings_slots']}"
            print(
                f"{e['br_rank']:02d}º    {e['profile_id']:<10} {alias:<30} {e['avg_elo']:<10.1f} "
                f"{slots:<8} {fac_str}"
            )
    return 0


def cmd_select_top(args: argparse.Namespace) -> int:
    cfg = load_config()
    cfg["auto_follow_top_br"] = True
    cfg["top_n_per_mode"] = args.top
    cfg.setdefault("leaderboard_refresh_minutes", 20)
    cfg.setdefault("monitor_only_custom_matches", True)

    relic = RelicAPIClient()
    _rebuild_rankings_and_config(cfg, relic, reset_top=bool(args.reset))
    updated = load_config()
    print(
        f"Ranking Top {args.top} + {len(updated.get('custom_players', []))} monitorados atualizado! "
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

    fd = os.open(SECRET_ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as secret_fp:
        secret_fp.write(f"DISCORD_WEBHOOK_URL={url}\n")

    cfg = load_config()
    cfg["discord_webhook_url"] = SAFE_WEBHOOK_PLACEHOLDER
    if args.name:
        cfg["bot_username"] = args.name.strip()
    save_config(cfg)
    print(f"[OK] Webhook isolado com permissão restrita (0600) em {SECRET_ENV_PATH.name} (fora do Git)!")

    if args.test:
        print("Enviando mensagem inicial de teste + Painel Resumo para o seu canal...")
        test_args = argparse.Namespace(dry_run=False)
        return cmd_test_discord(test_args)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gerenciador CoH3 Brasil Tracker v5")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("refresh-br", help="Varre todos os modos Steam na API da Relic e atualiza a lista de brasileiros")

    p_rank = sub.add_parser(
        "rankings",
        help="Exibe o Ranking Top 20 + 31 monitorados em 1v1, 2v2 e Jogos em Equipe (3v3+4v4)",
    )
    p_rank.add_argument("--mode", choices=["1v1", "2v2", "Team Games"], help="Modo específico (opcional)")
    p_rank.add_argument("--top", type=int, default=20, help="Quantidade por modo (padrão: 20)")

    p_seltop = sub.add_parser(
        "select-top",
        help="Atualiza config.json e tabelas com o Ranking (Top 20 + 31) e monitoria dos 31",
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
        help="Remove jogador convidado extra (mantendo os 31 principais protegidos)",
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
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

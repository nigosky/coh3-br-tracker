#!/usr/bin/env python3
"""CLI para listar jogadores brasileiros da API Relic, escolher quem monitorar e testar o Discord."""

from __future__ import annotations

import argparse
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
)
from relic_api import (
    FACTION_KEY_LABELS,
    RelicAPIClient,
    build_top_tracked_players,
    compute_merged_mode_rankings,
    export_merged_top_rankings,
    export_players_files,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("coh3_br.manage")

import getpass
import os

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
SECRET_ENV_PATH = BASE_DIR / ".env.secret"
SAFE_WEBHOOK_PLACEHOLDER = "DEFINA_NOS_SECRETS_DO_GITHUB_DISCORD_WEBHOOK_URL"
PLAYERS_JSON_PATH = BASE_DIR / "jogadores_br_steam.json"
PLAYERS_CSV_PATH = BASE_DIR / "jogadores_br_steam.csv"
SNAPSHOT_FALLBACK_PATH = BASE_DIR / "br_snapshot.json"


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
    CONFIG_PATH.write_text(json.dumps(sanitized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cmd_refresh_br(_args: argparse.Namespace) -> int:
    print("Consultando todas as leaderboards Steam (1v1, 2v2, 3v3, 4v4) na API da Relic (country=br)...")
    client = RelicAPIClient()
    players = client.fetch_brazilian_players()
    export_players_files(players, PLAYERS_JSON_PATH, PLAYERS_CSV_PATH)
    print(f"Concluído! {len(players)} jogadores brasileiros salvos em:")
    print(f"  - {PLAYERS_JSON_PATH}")
    print(f"  - {PLAYERS_CSV_PATH}")
    return 0


def cmd_list_br(args: argparse.Namespace) -> int:
    players = load_br_catalog()
    if not players:
        print("Catálogo local ainda não existe. Executando refresh-br primeiro...")
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


def cmd_select(args: argparse.Namespace) -> int:
    catalog = load_br_catalog()
    by_id = {int(p["profile_id"]): p for p in catalog}
    cfg = load_config()
    tracked = cfg.get("tracked_players", [])
    tracked_by_id = {int(p["profile_id"]): p for p in tracked}

    for target in args.players:
        resolved_id: int | None = None
        resolved_alias: str | None = None

        if target.isdigit():
            resolved_id = int(target)
            if resolved_id in by_id:
                resolved_alias = by_id[resolved_id]["alias"]
            else:
                # Valida direto na API da Relic caso não esteja no top cacheado
                matches = RelicAPIClient().fetch_player_recent_matches(resolved_id)
                resolved_alias = matches[0]["tracked_alias"] if matches else f"Player {resolved_id}"
        else:
            q = target.lower()
            exact = [p for p in catalog if str(p["alias"]).lower() == q]
            partial = [p for p in catalog if q in str(p["alias"]).lower()]
            candidates = exact or partial
            if not candidates:
                print(f"Jogador '{target}' não encontrado na lista BR. Passe o Relic profile_id numérico.")
                continue
            if len(candidates) > 1 and not exact:
                print(f"Mais de um jogador corresponde a '{target}'; especifique o Relic ID:")
                for c in candidates[:8]:
                    print(f"  - {c['profile_id']}: {c['alias']} ({c.get('best_mode', '')} ELO {round(c.get('max_elo', 0))})")
                continue
            resolved_id = int(candidates[0]["profile_id"])
            resolved_alias = str(candidates[0]["alias"])

        tracked_by_id[resolved_id] = {"profile_id": resolved_id, "alias": resolved_alias}
        print(f"[+] Adicionado ao monitoramento: {resolved_alias} (Relic ID {resolved_id})")

    cfg["tracked_players"] = list(tracked_by_id.values())
    save_config(cfg)
    return 0


def cmd_unselect(args: argparse.Namespace) -> int:
    cfg = load_config()
    before = cfg.get("tracked_players", [])
    targets_lower = {t.lower() for t in args.players}
    kept = [
        p
        for p in before
        if str(p["profile_id"]) not in targets_lower and str(p.get("alias", "")).lower() not in targets_lower
    ]
    removed = len(before) - len(kept)
    cfg["tracked_players"] = kept
    save_config(cfg)
    print(f"[-] {removed} jogador(es) removido(s). Restam {len(kept)} monitorados em config.json.")
    return 0


def cmd_selected(_args: argparse.Namespace) -> int:
    cfg = load_config()
    tracked = cfg.get("tracked_players", [])
    print(f"Jogadores brasileiros selecionados em config.json ({len(tracked)}):")
    for p in tracked:
        pid = p["profile_id"]
        print(f"  • {p['alias']} (Relic ID: {pid}) -> https://coh3stats.com/players/{pid}")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    cfg = load_config()
    db_path = (BASE_DIR / cfg.get("sqlite_db_path", "./coh3_br_matches.db")).resolve()
    db = MatchDatabase(db_path)
    matches = db.get_recent_recorded_matches(limit=args.limit, only_active_players=False)
    if not matches:
        print("Nenhuma partida gravada ainda no SQLite. Rode `python3 monitor.py --once` para sincronizar!")
        return 0

    print(f"Últimas {len(matches)} partidas gravadas em {db_path.name}:\n")
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
    matches = db.get_recent_recorded_matches(limit=int(cfg.get("summary_list_size", 15)), only_active_players=True)

    if not matches and tracked:
        print("Buscando partidas recentes na API da Relic para montar o teste...")
        client = RelicAPIClient()
        for p in tracked[:3]:
            fetched = client.fetch_player_recent_matches(int(p["profile_id"]), p["alias"])
            for m in reversed(fetched[:3]):
                db.insert_match(m)
        matches = db.get_recent_recorded_matches(limit=15, only_active_players=True)

    if not matches:
        print("Nenhuma partida disponível para os jogadores selecionados.")
        return 1

    summary_payload = build_summary_list_payload(matches, tracked, cfg.get("bot_username", "CoH3 Brasil Monitor"))
    card_payload = build_match_embed_payload(matches[0], cfg.get("bot_username", "CoH3 Brasil Monitor"))

    if args.dry_run:
        print("=== PAYLOAD 1: MENSAGEM FIXADA (LISTA RESUMO) ===")
        print(json.dumps(summary_payload, ensure_ascii=False, indent=2))
        print("\n=== PAYLOAD 2: CARD WEBHOOK EM TEMPO REAL ===")
        print(json.dumps(card_payload, ensure_ascii=False, indent=2))
        return 0

    discord = DiscordWebhookClient(cfg.get("discord_webhook_url", ""), cfg.get("bot_username", "CoH3 Brasil Monitor"))
    if not discord.is_configured:
        print("ERRO: Configure uma URL válida em 'discord_webhook_url' no config.json (ou use --dry-run).")
        return 1

    summary_id = db.get_state("summary_message_id")
    new_summary_id = discord.upsert_summary_message(matches, tracked, summary_id)
    if new_summary_id:
        db.set_state("summary_message_id", new_summary_id)
        print(f"[OK] Lista Resumo publicada/atualizada no Discord (message_id={new_summary_id}).")

    card_id = discord.send_match_card(matches[0])
    print(f"[OK] Card da última partida (#{matches[0]['match_id']}) enviado ao Discord (message_id={card_id}).")
    return 0


def cmd_rankings(args: argparse.Namespace) -> int:
    players = load_br_catalog()
    if not players:
        cmd_refresh_br(args)
        players = load_br_catalog()

    rankings = compute_merged_mode_rankings(players)
    modes = [args.mode] if args.mode else ["1v1", "2v2", "Team Games"]

    for mode in modes:
        entries = rankings.get(mode, [])[: args.top]
        subtitle = "3v3 + 4v4 mesclados" if mode == "Team Games" else "facções ativas mescladas"
        print(f"\n=== TOP {args.top} BR — {mode.upper()} ({subtitle} pela média simples) ===")
        print(f"{'#':<4} {'RELIC ID':<10} {'JOGADOR':<25} {'MÉDIA ELO':<10} {'ATIVOS':<9} {'ELO MÉDIO POR FACÇÃO'}")
        print("-" * 98)
        for e in entries:
            fac_str = ", ".join(
                f"{FACTION_KEY_LABELS[f]}: {v}" for f, v in e["faction_elos"].items()
            )
            alias = e["alias"][:24]
            slots = f"{e['active_rankings_count']}/{e['max_rankings_slots']}"
            print(
                f"{e['br_rank']:02d}º  {e['profile_id']:<10} {alias:<25} {e['avg_elo']:<10.1f} "
                f"{slots:<9} {fac_str}"
            )
    return 0


def cmd_select_top(args: argparse.Namespace) -> int:
    players = load_br_catalog()
    if not players:
        cmd_refresh_br(args)
        players = load_br_catalog()

    rankings = compute_merged_mode_rankings(players)
    json_out = BASE_DIR / f"top{args.top}_br_por_modo.json"
    csv_out = BASE_DIR / f"top{args.top}_br_por_modo.csv"
    export_merged_top_rankings(rankings, args.top, json_out, csv_out)
    top_unique = build_top_tracked_players(rankings, top_n=args.top)

    cfg = load_config()
    cfg["auto_follow_top_br"] = True
    cfg["top_n_per_mode"] = args.top
    cfg.setdefault("leaderboard_refresh_minutes", 30)
    cfg.setdefault("remove_if_drops_out_of_top", False)

    if args.reset:
        merged_by_id: dict[int, dict[str, Any]] = {}
    else:
        merged_by_id = {int(p["profile_id"]): p for p in cfg.get("tracked_players", [])}

    newly_added = 0
    for p in top_unique:
        pid = p["profile_id"]
        if pid not in merged_by_id:
            newly_added += 1
        merged_by_id[pid] = {
            "profile_id": pid,
            "alias": p["alias"],
            "placements": p["placements"],
        }

    cfg["tracked_players"] = list(merged_by_id.values())
    save_config(cfg)

    print(
        f"Top {args.top} brasileiros por modo (1v1, 2v2 e Team Games) calculados com sucesso!"
    )
    print(
        f"Total seguido em {CONFIG_PATH.name}: {len(cfg['tracked_players'])} jogadores únicos ({newly_added} novos adicionados)."
    )
    print(f"Tabelas de estudo exportadas em:\n  - {csv_out}\n  - {json_out}")
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
        print("Enviando mensagem inicial de teste + Lista Resumo para o seu canal...")
        test_args = argparse.Namespace(dry_run=False)
        return cmd_test_discord(test_args)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Gerenciador CoH3 Brasil Tracker")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("refresh-br", help="Varre todos os modos Steam na API da Relic e atualiza a lista de brasileiros")

    p_rank = sub.add_parser(
        "rankings",
        help="Exibe os Top brasileiros em 1v1, 2v2 e Team Games (3v3+4v4) pela média simples",
    )
    p_rank.add_argument("--mode", choices=["1v1", "2v2", "Team Games"], help="Modo específico (opcional)")
    p_rank.add_argument("--top", type=int, default=20, help="Quantidade por modo (padrão: 20)")

    p_seltop = sub.add_parser(
        "select-top",
        help="Atualiza config.json com os Top N brasileiros de 1v1, 2v2 e Team Games (padrão: Top 20)",
    )
    p_seltop.add_argument("--top", type=int, default=20, help="Quantidade por modo (padrão: 20)")
    p_seltop.add_argument(
        "--reset",
        action="store_true",
        help="Substitui a lista atual apenas pelos Top N atuais (sem manter anteriores)",
    )

    p_list = sub.add_parser("list-br", help="Exibe a lista geral de jogadores brasileiros encontrados")
    p_list.add_argument("--mode", choices=["1v1", "2v2", "3v3", "4v4"], help="Filtra por leaderboard bruta")
    p_list.add_argument("--search", help="Busca por apelido ou Relic ID")
    p_list.add_argument("--limit", type=int, default=30, help="Quantidade máxima de linhas")

    p_sel = sub.add_parser("select", help="Escolhe jogadores (por Relic ID ou apelido) para gravar partidas")
    p_sel.add_argument("players", nargs="+", help="IDs da Relic ou apelidos exatos")

    p_unsel = sub.add_parser("unselect", help="Remove jogadores do monitoramento")
    p_unsel.add_argument("players", nargs="+", help="IDs da Relic ou apelidos")

    sub.add_parser("selected", help="Lista apenas os jogadores brasileiros escolhidos no momento")

    p_hist = sub.add_parser("history", help="Lista no terminal as partidas já gravadas no SQLite")
    p_hist.add_argument("--limit", type=int, default=20)

    p_wh = sub.add_parser("set-webhook", help="Configura a URL do Webhook do Discord em config.json")
    p_wh.add_argument("url", nargs="?", help="URL do Webhook do Discord (se omitida, pergunta no terminal)")
    p_wh.add_argument("--name", help="Nome exibido no canal do Discord (padrão: CoH3 Brasil Monitor)")
    p_wh.add_argument("--test", action="store_true", help="Já publica a Lista Resumo inicial e 1 Card de teste")

    p_test = sub.add_parser("test-discord", help="Testa o envio da Lista Resumo + Card Webhook no Discord")
    p_test.add_argument("--dry-run", action="store_true", help="Exibe os JSONs de Embed sem enviar HTTP")

    args = parser.parse_args()
    dispatch = {
        "refresh-br": cmd_refresh_br,
        "rankings": cmd_rankings,
        "select-top": cmd_select_top,
        "list-br": cmd_list_br,
        "select": cmd_select,
        "unselect": cmd_unselect,
        "selected": cmd_selected,
        "history": cmd_history,
        "set-webhook": cmd_set_webhook,
        "test-discord": cmd_test_discord,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Monitor em tempo real das partidas e da entrada de novos brasileiros no Top 20 (1v1, 2v2 e Team Games)."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from database import MatchDatabase
from discord_notifier import DiscordWebhookClient
from relic_api import (
    RelicAPIClient,
    build_top_tracked_players,
    compute_merged_mode_rankings,
    export_merged_top_rankings,
    export_players_files,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("coh3_br.monitor")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"


SECRET_FILE_NAME = ".env.secret"
SAFE_WEBHOOK_PLACEHOLDER = "DEFINA_NOS_SECRETS_DO_GITHUB_DISCORD_WEBHOOK_URL"


def _read_local_secret_webhook(base_dir: Path) -> str:
    secret_path = base_dir / SECRET_FILE_NAME
    if not secret_path.exists():
        return ""
    for line in secret_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DISCORD_WEBHOOK_URL="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def load_config(config_path: Path) -> dict[str, Any]:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    env_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    local_secret = _read_local_secret_webhook(config_path.parent)
    if env_webhook:
        cfg["discord_webhook_url"] = env_webhook
    elif local_secret:
        cfg["discord_webhook_url"] = local_secret
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db:
        cfg["sqlite_db_path"] = env_db
    return cfg


def save_config_file(config_path: Path, cfg_to_save: dict[str, Any]) -> None:
    """Salva config.json garantindo que NENHUMA URL real de Webhook seja gravada em texto plano no Git."""
    sanitized_cfg = dict(cfg_to_save)
    raw_wh = str(sanitized_cfg.get("discord_webhook_url", ""))
    if "discord.com/api/" in raw_wh or "discordapp.com/api/" in raw_wh:
        sanitized_cfg["discord_webhook_url"] = SAFE_WEBHOOK_PLACEHOLDER

    serialized = json.dumps(sanitized_cfg, ensure_ascii=False, indent=2) + "\n"
    tmp_path = config_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(serialized, encoding="utf-8")
        tmp_path.replace(config_path)
    except OSError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        config_path.write_text(serialized, encoding="utf-8")


def maybe_refresh_top_rankings(
    config_path: Path,
    db: MatchDatabase,
    relic: RelicAPIClient,
    discord: DiscordWebhookClient,
    force: bool = False,
) -> bool:
    """
    Revarre periodicamente as leaderboards da Relic para detectar se algum brasileiro novo
    entrou entre os Top N colocados de '1v1', '2v2' ou 'Team Games' (3v3 + 4v4).
    Qualquer novo colocado passa automaticamente a ser seguido!
    """
    raw_disk_cfg = json.loads(config_path.read_text(encoding="utf-8"))
    if not raw_disk_cfg.get("auto_follow_top_br", True) and not force:
        return False

    refresh_mins = max(5, int(raw_disk_cfg.get("leaderboard_refresh_minutes", 30)))
    top_n = int(raw_disk_cfg.get("top_n_per_mode", 20))
    remove_dropped = bool(raw_disk_cfg.get("remove_if_drops_out_of_top", False))

    now = int(time.time())
    last_scan_str = db.get_state("last_leaderboard_scan_ts")
    last_scan_ts = int(last_scan_str) if last_scan_str and last_scan_str.isdigit() else 0

    if not force and last_scan_ts > 0 and (now - last_scan_ts) < (refresh_mins * 60):
        return False

    logger.info(
        "Atualizando leaderboards Steam na API da Relic para verificar novos brasileiros no Top %d (1v1, 2v2, Team Games)...",
        top_n,
    )
    players = relic.fetch_brazilian_players()
    base_dir = config_path.parent
    export_players_files(players, base_dir / "jogadores_br_steam.json", base_dir / "jogadores_br_steam.csv")

    rankings = compute_merged_mode_rankings(players)
    export_merged_top_rankings(
        rankings,
        top_n=top_n,
        json_path=base_dir / f"top{top_n}_br_por_modo.json",
        csv_path=base_dir / f"top{top_n}_br_por_modo.csv",
    )

    current_top_players = build_top_tracked_players(rankings, top_n=top_n)
    existing_list = raw_disk_cfg.get("tracked_players", [])
    existing_by_id: dict[int, dict[str, Any]] = {int(p["profile_id"]): p for p in existing_list}
    was_already_populated = len(existing_by_id) > 0

    newly_entered: list[dict[str, Any]] = []

    if remove_dropped:
        updated_by_id: dict[int, dict[str, Any]] = {}
        for tp in current_top_players:
            pid = tp["profile_id"]
            if pid not in existing_by_id:
                newly_entered.append(tp)
            updated_by_id[pid] = {
                "profile_id": pid,
                "alias": tp["alias"],
                "placements": tp["placements"],
            }
    else:
        # Modo cumulativo (padrão): mantém todos já seguidos e adiciona qualquer brasileiro novo que entrar no Top N
        updated_by_id = dict(existing_by_id)
        for tp in current_top_players:
            pid = tp["profile_id"]
            if pid not in updated_by_id:
                newly_entered.append(tp)
            updated_by_id[pid] = {
                "profile_id": pid,
                "alias": tp["alias"],
                "placements": tp["placements"],
            }

    db.set_state("last_leaderboard_scan_ts", str(now))

    if newly_entered or len(updated_by_id) != len(existing_by_id):
        raw_disk_cfg["tracked_players"] = list(updated_by_id.values())
        save_config_file(config_path, raw_disk_cfg)

    for np in newly_entered:
        logger.info(
            "[NOVO NO TOP %d BR] %s (#%d) entrou em %s e passou a ser seguido!",
            top_n,
            np["alias"],
            np["profile_id"],
            ", ".join(np["placements"]),
        )

    if newly_entered and was_already_populated and discord.is_configured:
        try:
            discord.send_new_top_entrant_card(newly_entered, top_n=top_n)
        except Exception as exc:
            logger.error("Erro ao notificar novo integrante Top %d no Discord: %s", top_n, exc)

    return len(newly_entered) > 0


def run_cycle(config_path: Path, relic: RelicAPIClient, force_rank_scan: bool = False) -> tuple[int, int]:
    """
    Executa um ciclo de varredura:
    - Revarre periodicamente as leaderboards para auto-seguir novos brasileiros no Top 20
    - Recarrega config.json (hot-reload)
    - Consulta histórico recente de cada jogador brasileiro seguido
    - Grava novas partidas no SQLite
    - Envia Card Webhook individual + atualiza a Lista Resumo Fixada no Discord
    """
    cfg = load_config(config_path)
    db_path = Path(cfg.get("sqlite_db_path", "./coh3_br_matches.db"))
    if not db_path.is_absolute():
        db_path = (config_path.parent / db_path).resolve()

    db = MatchDatabase(db_path)
    discord = DiscordWebhookClient(
        webhook_url=str(cfg.get("discord_webhook_url", "")),
        bot_username=str(cfg.get("bot_username", "CoH3 Brasil Monitor")),
    )

    # Verifica se está na hora de revarrer as leaderboards para descobrir novos brasileiros no Top 20
    try:
        added_from_top = maybe_refresh_top_rankings(config_path, db, relic, discord, force=force_rank_scan)
        if added_from_top:
            cfg = load_config(config_path)
    except Exception as exc:
        logger.error("Falha ao revarrer leaderboards Top BR (seguindo com lista atual): %s", exc)

    db.sync_tracked_players(cfg.get("tracked_players", []))
    active_players = db.get_active_players()

    only_automatch = bool(cfg.get("only_automatch", False))
    seed_limit = int(cfg.get("initial_seed_per_player", 3))
    summary_size = int(cfg.get("summary_list_size", 15))

    if not active_players:
        logger.warning("Nenhum jogador brasileiro selecionado em %s.", config_path.name)
        return 0, 0

    newly_finished: list[dict[str, Any]] = []
    seeded_count = 0
    players_changed = False

    for player in active_players:
        pid = int(player["profile_id"])
        alias = str(player["alias"])
        is_baseline_done = bool(player["baseline_synced"])

        try:
            recent_matches = relic.fetch_player_recent_matches(
                profile_id=pid,
                fallback_alias=alias,
                only_automatch=only_automatch,
            )
        except Exception as exc:
            logger.error("Erro ao buscar partidas de %s (#%d): %s", alias, pid, exc)
            continue

        resolved_alias = recent_matches[0]["tracked_alias"] if recent_matches else alias

        if not is_baseline_done:
            for m in reversed(recent_matches[:seed_limit]):
                if db.insert_match(m):
                    seeded_count += 1
            for m in recent_matches[seed_limit:]:
                db.insert_match(m)
            db.mark_baseline_synced(pid, resolved_alias)
            players_changed = True
            logger.info(
                "Jogador %s (#%d) sincronizado inicialmente (%d partidas recentes catalogadas).",
                resolved_alias,
                pid,
                min(len(recent_matches), 10),
            )
        else:
            player_new = [m for m in recent_matches if not db.match_exists(m["match_id"], pid)]
            player_new.sort(key=lambda x: x["completion_time"])
            for m in player_new:
                if db.insert_match(m):
                    newly_finished.append(m)
                    res_str = "VITÓRIA" if m["win"] else "DERROTA"
                    logger.info(
                        "[NOVA PARTIDA] %s (%s) -> %s em %s (%s) [#%d]",
                        m["tracked_alias"],
                        m["tracked_faction_short"],
                        res_str,
                        m["map_clean"],
                        m["mode"],
                        m["match_id"],
                    )
            if resolved_alias != alias:
                db.mark_baseline_synced(pid, resolved_alias)

    newly_finished.sort(key=lambda x: x["completion_time"])

    if discord.is_configured:
        for m in newly_finished:
            try:
                msg_id = discord.send_match_card(m)
                if msg_id:
                    db.update_match_discord_id(m["match_id"], m["tracked_profile_id"], msg_id)
                time.sleep(0.5)
            except Exception as exc:
                logger.error("Falha ao enviar Card da partida #%d ao Discord: %s", m["match_id"], exc)

        summary_msg_id = db.get_state("summary_message_id")
        if newly_finished or players_changed or not summary_msg_id:
            try:
                latest_catalog = db.get_recent_recorded_matches(limit=summary_size, only_active_players=True)
                updated_players = db.get_active_players()
                new_summary_id = discord.upsert_summary_message(
                    matches=latest_catalog,
                    tracked_players=updated_players,
                    existing_message_id=summary_msg_id,
                )
                if new_summary_id and new_summary_id != summary_msg_id:
                    db.set_state("summary_message_id", new_summary_id)
                    logger.info(
                        "Mensagem de Lista Resumo criada no Discord (ID %s). Fixe-a no canal privado!",
                        new_summary_id,
                    )
                else:
                    logger.info("Lista Resumo no Discord atualizada com sucesso.")
            except Exception as exc:
                logger.error("Falha ao atualizar Lista Resumo no Discord: %s", exc)
    else:
        if newly_finished or players_changed:
            logger.info(
                "Partidas salvas em %s (configure 'discord_webhook_url' em config.json para publicar no Discord).",
                db_path.name,
            )

    return len(newly_finished), seeded_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor em tempo real CoH3 Brasil -> SQLite + Discord Privado")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Caminho para config.json")
    parser.add_argument("--once", action="store_true", help="Executa apenas 1 ciclo de checagem e encerra")
    parser.add_argument(
        "--force-rank-scan",
        action="store_true",
        help="Força revarredura imediata das leaderboards Top BR neste ciclo",
    )
    args = parser.parse_args()

    if not args.config.exists():
        logger.error("Arquivo de configuração não encontrado: %s", args.config)
        return 1

    stop_requested = False

    def _handle_sig(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        logger.info("Sinal %d recebido; encerrando monitor com segurança...", signum)
        stop_requested = True

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    relic = RelicAPIClient()
    logger.info("Iniciando CoH3 Brasil Monitor usando %s...", args.config)

    first_iter = True
    while not stop_requested:
        start_t = time.monotonic()
        try:
            new_cnt, seed_cnt = run_cycle(
                args.config,
                relic,
                force_rank_scan=(args.force_rank_scan and first_iter),
            )
            first_iter = False
            logger.info("Ciclo concluído: %d nova(s), %d inicial(is).", new_cnt, seed_cnt)
        except Exception as exc:
            logger.exception("Erro inesperado no ciclo de monitoramento: %s", exc)

        if args.once or stop_requested:
            break

        try:
            poll_sec = max(20, int(load_config(args.config).get("poll_interval_seconds", 60)))
        except Exception:
            poll_sec = 60

        elapsed = time.monotonic() - start_t
        sleep_for = max(1.0, poll_sec - elapsed)
        end_sleep = time.monotonic() + sleep_for
        while time.monotonic() < end_sleep and not stop_requested:
            time.sleep(0.5)

    return 0


if __name__ == "__main__":
    sys.exit(main())

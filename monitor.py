#!/usr/bin/env python3
"""Monitor automático CoH3 Brasil v5 — Ranking (Top 20 + 31 com setas ▲/▼) e Partidas dos 31 (SteamID)."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from database import MatchDatabase
from discord_notifier import DiscordWebhookClient, group_matches_by_id
from relic_api import (
    CORE_BR_ROSTER,
    RelicAPIClient,
    build_roster_lookup_maps,
    build_top_tracked_players,
    compute_merged_mode_rankings,
    export_merged_top_rankings,
    export_players_files,
    fetch_custom_players_stats,
    format_bound_display_alias,
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
CURRENT_SUMMARY_LAYOUT_VERSION = "v5_ptbr_roster31_arrows"


def _read_local_secret_webhook(base_dir: Path) -> str:
    secret_path = base_dir / SECRET_FILE_NAME
    if not secret_path.exists():
        return ""
    for line in secret_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DISCORD_WEBHOOK_URL="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def ensure_core_roster_in_config(cfg: dict[str, Any]) -> bool:
    """
    Garante que os 31 jogadores brasileiros fixos estejam sempre atrelados pelo código Steam (steam_id)
    e nick original em custom_players, ativando por padrão o monitoramento exclusivo de partidas dos 31 (Opção 2).
    """
    changed = False
    if "monitor_only_custom_matches" not in cfg:
        cfg["monitor_only_custom_matches"] = True
        changed = True

    if int(cfg.get("leaderboard_refresh_minutes", 30)) >= 30:
        cfg["leaderboard_refresh_minutes"] = 20
        changed = True

    existing_custom: list[dict[str, Any]] = list(cfg.get("custom_players", []))
    by_sid: dict[str, dict[str, Any]] = {}
    by_pid: dict[int, dict[str, Any]] = {}
    ordered_list: list[dict[str, Any]] = []

    for item in existing_custom:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("steam_id") or "").replace("/steam/", "").strip()
        pid = int(item.get("profile_id", 0) or 0)
        entry = dict(item)
        if sid:
            by_sid[sid] = entry
        if pid > 0:
            by_pid[pid] = entry
        ordered_list.append(entry)

    for core in CORE_BR_ROSTER:
        c_sid = str(core["steam_id"])
        c_pid = int(core["profile_id"])
        c_orig = str(core["original_alias"])

        target = by_sid.get(c_sid) or by_pid.get(c_pid)
        if target is None:
            new_entry = {
                "profile_id": c_pid,
                "steam_id": c_sid,
                "original_alias": c_orig,
                "alias": c_orig,
                "is_core_roster": True,
            }
            ordered_list.append(new_entry)
            by_sid[c_sid] = new_entry
            by_pid[c_pid] = new_entry
            changed = True
        else:
            if target.get("steam_id") != c_sid:
                target["steam_id"] = c_sid
                changed = True
            if not target.get("original_alias"):
                target["original_alias"] = c_orig
                changed = True
            if not target.get("alias"):
                target["alias"] = c_orig
                changed = True
            if not int(target.get("profile_id", 0) or 0):
                target["profile_id"] = c_pid
                changed = True
            if not target.get("is_core_roster"):
                target["is_core_roster"] = True
                changed = True

    if changed:
        cfg["custom_players"] = ordered_list
    return changed


def load_config(config_path: Path) -> dict[str, Any]:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    ensure_core_roster_in_config(cfg)
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
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db and sanitized_cfg.get("sqlite_db_path") == env_db:
        sanitized_cfg["sqlite_db_path"] = "./coh3_br_matches.db"

    serialized = json.dumps(sanitized_cfg, ensure_ascii=False, indent=2) + "\n"
    tmp_path = config_path.with_suffix(".json.tmp")
    try:
        tmp_path.write_text(serialized, encoding="utf-8")
        tmp_path.replace(config_path)
    except OSError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        config_path.write_text(serialized, encoding="utf-8")


def merge_catalog_with_custom_players(
    base_players: list[dict[str, Any]],
    custom_players: list[dict[str, Any]],
    relic: RelicAPIClient,
) -> list[dict[str, Any]]:
    """
    Consulta getPersonalStat por conta Steam (/steam/<steam_id>) para os 31 jogadores + convidados extras
    (incluindo brasileiros registrados com outro país como 'us', ex: Lem22), atualizando profile_id e
    preservando o nick original caso o jogador tenha trocado de apelido na Steam.
    """
    by_pid: dict[int, dict[str, Any]] = {int(p["profile_id"]): dict(p) for p in base_players}
    effective_custom = custom_players if custom_players else list(CORE_BR_ROSTER)

    fetched_custom = fetch_custom_players_stats(relic, effective_custom)
    fetched_by_sid: dict[str, dict[str, Any]] = {}
    fetched_by_pid: dict[int, dict[str, Any]] = {}

    for cp_stat in fetched_custom:
        pid = int(cp_stat["profile_id"])
        sid = str(cp_stat.get("steam_id") or "")
        if sid:
            fetched_by_sid[sid] = cp_stat
        fetched_by_pid[pid] = cp_stat

        if pid in by_pid:
            existing = by_pid[pid]
            existing["alias"] = cp_stat["alias"]
            existing["current_alias"] = cp_stat.get("current_alias", cp_stat["alias"])
            existing["original_alias"] = cp_stat.get("original_alias", cp_stat["alias"])
            if sid:
                existing["steam_id"] = sid
            existing["is_custom"] = True
            existing["is_br_roster"] = True
            existing.setdefault("inactive_modes", {}).update(cp_stat.get("inactive_modes", {}))
            existing.setdefault("modes", {}).update(cp_stat.get("modes", {}))
            if cp_stat.get("max_elo", 0) > existing.get("max_elo", 0):
                existing["max_elo"] = cp_stat["max_elo"]
                existing["best_mode"] = cp_stat.get("best_mode", "")
            if cp_stat.get("last_match_date", 0) > existing.get("last_match_date", 0):
                existing["last_match_date"] = cp_stat["last_match_date"]
        else:
            by_pid[pid] = cp_stat

    # Sincroniza profile_id e alias formatado de volta na lista custom_players caso resolvido via SteamID64
    for cp in custom_players:
        sid = str(cp.get("steam_id") or "").replace("/steam/", "").strip()
        pid = int(cp.get("profile_id", 0) or 0)
        resolved = fetched_by_sid.get(sid) or fetched_by_pid.get(pid)
        if resolved:
            cp["profile_id"] = int(resolved["profile_id"])
            if resolved.get("steam_id"):
                cp["steam_id"] = str(resolved["steam_id"])
            orig = str(cp.get("original_alias") or resolved.get("original_alias") or resolved["alias"])
            cp["original_alias"] = orig
            cp["alias"] = format_bound_display_alias(str(resolved.get("current_alias") or resolved["alias"]), orig)

    return list(by_pid.values())


def _player_identity_key(entry: dict[str, Any]) -> str:
    sid = str(entry.get("steam_id") or "").replace("/steam/", "").strip()
    if sid:
        return f"steam:{sid}"
    return f"pid:{int(entry.get('profile_id', 0))}"


def detect_and_apply_ranking_movements(
    db: MatchDatabase,
    full_rankings: dict[str, list[dict[str, Any]]],
    top_n: int = 20,
    custom_players: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    """
    Compara a posição atual de cada jogador do grupo (Top 20 + 31 monitorados) com o último snapshot salvo.
    - Retorna (movements_by_mode, has_new_movements) para disparo do Card de Movimentação no Discord.
    - Aplica rank_delta (+N para subida ▲ verde, -N para queda ▼ vermelha) nas linhas do Ranking.
    """
    custom_ids = {int(cp["profile_id"]) for cp in (custom_players or []) if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp.get("steam_id") or "") for cp in (custom_players or []) if cp.get("steam_id")}

    prev_snap_raw = db.get_state("ranking_snapshot_v5")
    last_deltas_raw = db.get_state("ranking_last_deltas_v5")

    prev_snap: dict[str, dict[str, int]] = {}
    had_previous_snapshot = False
    if prev_snap_raw:
        try:
            parsed = json.loads(prev_snap_raw)
            if isinstance(parsed, dict) and parsed:
                prev_snap = parsed
                had_previous_snapshot = True
        except Exception:
            prev_snap = {}

    last_deltas: dict[str, dict[str, dict[str, int]]] = {}
    if last_deltas_raw:
        try:
            parsed_d = json.loads(last_deltas_raw)
            if isinstance(parsed_d, dict):
                last_deltas = parsed_d
        except Exception:
            last_deltas = {}

    new_snap: dict[str, dict[str, int]] = {}
    movements_by_mode: dict[str, list[dict[str, Any]]] = {}
    has_new_movements = False

    for mode, entries in full_rankings.items():
        mode_prev = prev_snap.get(mode, {})
        mode_curr_snap: dict[str, int] = {}
        mode_moves: list[dict[str, Any]] = []
        mode_new_deltas: dict[str, dict[str, int]] = {}

        for idx, e in enumerate(entries):
            key = _player_identity_key(e)
            curr_rank = int(e["br_rank"])
            mode_curr_snap[key] = curr_rank

            sid = str(e.get("steam_id") or "")
            in_tracked_table = (
                idx < top_n
                or int(e["profile_id"]) in custom_ids
                or (bool(sid) and sid in custom_sids)
                or bool(e.get("is_custom"))
            )
            if not in_tracked_table:
                continue

            if had_previous_snapshot and key in mode_prev:
                prev_rank = int(mode_prev[key])
                delta = prev_rank - curr_rank
                if delta != 0:
                    e["rank_delta"] = delta
                    e["prev_rank"] = prev_rank
                    mode_new_deltas[key] = {"rank_delta": delta, "prev_rank": prev_rank}
                    mode_moves.append(dict(e))
            elif (
                had_previous_snapshot
                and key not in mode_prev
                and not bool(e.get("inactive_fallback"))
                and idx < top_n
            ):
                e["is_new_entry"] = True
                e["rank_delta"] = 0
                mode_moves.append(dict(e))

        if mode_moves:
            has_new_movements = True
            mode_moves.sort(key=lambda x: (-abs(int(x.get("rank_delta", 0))), int(x.get("br_rank", 999))))
            movements_by_mode[mode] = mode_moves
            last_deltas[mode] = mode_new_deltas
        else:
            # Mantém as últimas setas registradas naquele modo na tabela fixa até a próxima oscilação
            saved_mode_deltas = last_deltas.get(mode, {})
            for e in entries:
                key = _player_identity_key(e)
                if key in saved_mode_deltas:
                    e["rank_delta"] = int(saved_mode_deltas[key].get("rank_delta", 0))
                    e["prev_rank"] = saved_mode_deltas[key].get("prev_rank")

        new_snap[mode] = mode_curr_snap

    db.set_state("ranking_snapshot_v5", json.dumps(new_snap, separators=(",", ":")))
    db.set_state("ranking_last_deltas_v5", json.dumps(last_deltas, separators=(",", ":")))
    return movements_by_mode, has_new_movements


def load_cached_rankings(base_dir: Path, top_n: int = 20) -> dict[str, list[dict[str, Any]]] | None:
    rank_file = base_dir / f"top{top_n}_br_por_modo.json"
    if not rank_file.exists():
        return None
    try:
        doc = json.loads(rank_file.read_text(encoding="utf-8"))
        return doc.get("rankings_by_mode")
    except Exception:
        return None


def _compute_rankings_digest(rankings_by_mode: dict[str, list[dict[str, Any]]] | None) -> str:
    """Gera hash determinístico dos dados visíveis do Ranking (ELO, vitórias, sequência, posição e nicks)."""
    if not rankings_by_mode:
        return ""
    rows_sig: list[tuple[Any, ...]] = []
    for mode in ("1v1", "2v2", "Team Games"):
        for e in rankings_by_mode.get(mode, []):
            rows_sig.append(
                (
                    mode,
                    int(e.get("profile_id", 0)),
                    int(e.get("br_rank", 0)),
                    round(float(e.get("avg_elo", 0.0)), 1),
                    int(e.get("wins", 0)),
                    int(e.get("losses", 0)),
                    int(e.get("streak", 0)),
                    int(e.get("last_match_date", 0)),
                    str(e.get("alias", "")),
                    int(e.get("rank_delta", 0) or 0),
                )
            )
    payload = json.dumps(rows_sig, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def maybe_refresh_top_rankings(
    config_path: Path,
    db: MatchDatabase,
    relic: RelicAPIClient,
    discord: DiscordWebhookClient,
    force: bool = False,
    is_oneshot: bool = False,
) -> bool:
    """
    Revarre as leaderboards da Relic para atualizar o Ranking (Top 20 + 31 jogadores),
    detecta quem subiu (▲ verde) ou desceu (▼ vermelho), notifica movimentações no Discord e mantém
    tracked_players focado exclusivamente nos 31 monitorados (Opção 2).
    """
    raw_disk_cfg = json.loads(config_path.read_text(encoding="utf-8"))
    cfg_upgraded = ensure_core_roster_in_config(raw_disk_cfg)

    if not raw_disk_cfg.get("auto_follow_top_br", True) and not force and not cfg_upgraded:
        return False

    refresh_mins = max(5, int(raw_disk_cfg.get("leaderboard_refresh_minutes", 20)))
    top_n = int(raw_disk_cfg.get("top_n_per_mode", 20))
    only_custom = bool(raw_disk_cfg.get("monitor_only_custom_matches", True))
    remove_dropped = bool(raw_disk_cfg.get("remove_if_drops_out_of_top", False))
    custom_players: list[dict[str, Any]] = raw_disk_cfg.get("custom_players", [])

    now = int(time.time())
    last_scan_str = db.get_state("last_leaderboard_scan_ts")
    last_scan_ts = int(last_scan_str) if last_scan_str and last_scan_str.isdigit() else 0

    # Em execuções agendadas (--once no GitHub Actions), sempre varre o Ranking para não perder ciclos;
    # no modo contínuo local, respeita leaderboard_refresh_minutes.
    if not force and not is_oneshot and not cfg_upgraded and last_scan_ts > 0 and (now - last_scan_ts) < (refresh_mins * 60):
        return False

    logger.info(
        "Atualizando Ranking BR (Top %d + %d monitorados SteamID: 1v1, 2v2, Jogos em Equipe)...",
        top_n,
        len(custom_players),
    )
    players = relic.fetch_brazilian_players()
    base_dir = config_path.parent
    export_players_files(players, base_dir / "jogadores_br_steam.json", base_dir / "jogadores_br_steam.csv")

    merged_players = merge_catalog_with_custom_players(players, custom_players, relic)
    custom_ids = {int(cp["profile_id"]) for cp in custom_players if int(cp.get("profile_id", 0)) > 0}
    custom_sids = {str(cp["steam_id"]) for cp in custom_players if cp.get("steam_id")}

    had_prev_snap = bool(db.get_state("ranking_snapshot_v5"))
    rankings = compute_merged_mode_rankings(
        merged_players,
        custom_ids=custom_ids,
        custom_steam_ids=custom_sids,
    )
    movements_by_mode, has_new_movements = detect_and_apply_ranking_movements(
        db=db,
        full_rankings=rankings,
        top_n=top_n,
        custom_players=custom_players,
    )

    export_merged_top_rankings(
        rankings,
        top_n=top_n,
        json_path=base_dir / f"top{top_n}_br_por_modo.json",
        csv_path=base_dir / f"top{top_n}_br_por_modo.csv",
        custom_players=custom_players,
    )

    exported_rankings = load_cached_rankings(base_dir, top_n=top_n)
    new_digest = _compute_rankings_digest(exported_rankings)
    prev_digest = db.get_state("ranking_digest_v5") or ""
    table_stats_changed = bool(new_digest and new_digest != prev_digest)
    if new_digest:
        db.set_state("ranking_digest_v5", new_digest)

    current_tracked = build_top_tracked_players(
        rankings,
        top_n=top_n,
        custom_players=custom_players,
        only_custom=only_custom,
    )
    existing_list = raw_disk_cfg.get("tracked_players", [])
    existing_by_id: dict[int, dict[str, Any]] = {int(p["profile_id"]): p for p in existing_list if "profile_id" in p}
    was_already_populated = len(existing_by_id) > 0

    newly_entered: list[dict[str, Any]] = []

    if only_custom or remove_dropped:
        updated_by_id: dict[int, dict[str, Any]] = {}
        for tp in current_tracked:
            pid = int(tp["profile_id"])
            if not only_custom and pid not in existing_by_id and not tp.get("is_custom"):
                newly_entered.append(tp)
            updated_by_id[pid] = {
                "profile_id": pid,
                "alias": tp["alias"],
                "original_alias": str(tp.get("original_alias") or tp["alias"]),
                "steam_id": str(tp.get("steam_id") or existing_by_id.get(pid, {}).get("steam_id") or ""),
                "placements": tp["placements"],
                "is_custom": bool(tp.get("is_custom")),
            }
    else:
        updated_by_id = dict(existing_by_id)
        for tp in current_tracked:
            pid = int(tp["profile_id"])
            if pid not in updated_by_id and not tp.get("is_custom"):
                newly_entered.append(tp)
            updated_by_id[pid] = {
                "profile_id": pid,
                "alias": tp["alias"],
                "original_alias": str(tp.get("original_alias") or tp["alias"]),
                "steam_id": str(tp.get("steam_id") or updated_by_id.get(pid, {}).get("steam_id") or ""),
                "placements": tp["placements"],
                "is_custom": bool(tp.get("is_custom")) or (pid in custom_ids),
            }

    db.set_state("last_leaderboard_scan_ts", str(now))
    if has_new_movements or table_stats_changed or not had_prev_snap or force or cfg_upgraded:
        db.set_state("rankings_updated_flag", "1")

    raw_disk_cfg["custom_players"] = custom_players
    raw_disk_cfg["tracked_players"] = list(updated_by_id.values())
    save_config_file(config_path, raw_disk_cfg)

    if has_new_movements:
        for mode_k, mv_list in movements_by_mode.items():
            for mv in mv_list:
                if mv.get("is_new_entry"):
                    arrow = "NOVO"
                else:
                    d = int(mv.get("rank_delta", 0))
                    arrow = f"▲ +{d}" if d > 0 else f"▼ {d}"
                logger.info(
                    "[MOVIMENTAÇÃO RANKING %s] %s: #%s -> #%d (%s)",
                    mode_k,
                    mv["alias"],
                    mv.get("prev_rank", "—"),
                    mv["br_rank"],
                    arrow,
                )
        if discord.is_configured:
            try:
                discord.send_ranking_movement_card(movements_by_mode)
            except Exception as exc:
                logger.error("Erro ao enviar Card de Movimentação do Ranking ao Discord: %s", exc)

    if not only_custom and newly_entered and was_already_populated and discord.is_configured:
        try:
            discord.send_new_top_entrant_card(newly_entered, top_n=top_n)
        except Exception as exc:
            logger.error("Erro ao notificar novo integrante Top %d no Discord: %s", top_n, exc)

    return has_new_movements or table_stats_changed or cfg_upgraded or (len(newly_entered) > 0)


def run_cycle(
    config_path: Path,
    relic: RelicAPIClient,
    force_rank_scan: bool = False,
    is_oneshot: bool = False,
) -> tuple[int, int]:
    """
    Executa um ciclo completo v5:
    1) Atualiza Ranking (Top 20 + 31 brasileiros) e publica movimentações com setas verdes ▲ / vermelhas ▼
    2) Monitora partidas finalizadas EXCLUSIVAMENTE dos 31 jogadores brasileiros listados (via conta Steam)
    3) Atualiza automaticamente o Painel Fixado em PT-BR no Discord
    """
    cfg = load_config(config_path)
    db_path = Path(cfg.get("sqlite_db_path", "./coh3_br_matches.db"))
    if not db_path.is_absolute():
        db_path = (config_path.parent / db_path).resolve()

    db = MatchDatabase(db_path)
    discord = DiscordWebhookClient(
        webhook_url=str(cfg.get("discord_webhook_url", "")),
        bot_username=str(cfg.get("bot_username", "CoH3 Brasil Monitor")),
        db=db,
        catalog_json_path=config_path.parent / "jogadores_br_steam.json",
    )

    layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION

    try:
        rank_changed = maybe_refresh_top_rankings(
            config_path,
            db,
            relic,
            discord,
            force=(force_rank_scan or layout_needs_upgrade),
            is_oneshot=is_oneshot,
        )
        if rank_changed or layout_needs_upgrade or force_rank_scan:
            cfg = load_config(config_path)
    except Exception as exc:
        logger.error("Falha ao revarrer leaderboards Top BR (seguindo com lista atual): %s", exc)

    custom_players = cfg.get("custom_players", [])
    roster_maps = build_roster_lookup_maps(custom_players)

    db.sync_tracked_players(cfg.get("tracked_players", []))
    active_players = db.get_active_players()

    only_automatch = bool(cfg.get("only_automatch", False))
    seed_limit = int(cfg.get("initial_seed_per_player", 3))
    summary_size = int(cfg.get("summary_list_size", 15))
    top_n = int(cfg.get("top_n_per_mode", 20))

    if not active_players:
        logger.warning("Nenhum jogador brasileiro selecionado em %s.", config_path.name)
        return 0, 0

    newly_finished: list[dict[str, Any]] = []
    seeded_count = 0
    players_changed = False

    def _fetch_one_player(pl: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]] | None, Exception | None]:
        p_id = int(pl["profile_id"])
        p_orig = str(pl.get("original_alias") or pl["alias"])
        try:
            res = relic.fetch_player_recent_matches(
                profile_id=p_id,
                fallback_alias=p_orig,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
            )
            return pl, res, None
        except Exception as err:
            return pl, None, err

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fetched_results = list(pool.map(_fetch_one_player, active_players))

    for player, recent_matches, fetch_err in fetched_results:
        pid = int(player["profile_id"])
        alias = str(player["alias"])
        is_baseline_done = bool(player["baseline_synced"])

        if fetch_err is not None or recent_matches is None:
            logger.error("Erro ao buscar partidas de %s (#%d): %s", alias, pid, fetch_err)
            continue

        resolved_alias = recent_matches[0]["tracked_alias"] if recent_matches else alias
        resolved_steam_id = (
            recent_matches[0].get("tracked_steam_id", "")
            if recent_matches
            else str(player.get("steam_id") or "")
        )

        if not is_baseline_done:
            for m in reversed(recent_matches[:seed_limit]):
                if db.insert_match(m):
                    seeded_count += 1
            for m in recent_matches[seed_limit:]:
                db.insert_match(m)
            db.mark_baseline_synced(pid, resolved_alias, steam_id=resolved_steam_id or None)
            players_changed = True
            logger.info(
                "Jogador %s (#%d | Steam %s) sincronizado inicialmente (%d partidas recentes catalogadas).",
                resolved_alias,
                pid,
                resolved_steam_id or "N/D",
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
            if resolved_alias != alias or (resolved_steam_id and not player.get("steam_id")):
                db.mark_baseline_synced(pid, resolved_alias, steam_id=resolved_steam_id or None)
                players_changed = True

    newly_finished.sort(key=lambda x: x["completion_time"])
    grouped_new_matches = group_matches_by_id(newly_finished)

    if discord.is_configured:
        for grp in grouped_new_matches:
            try:
                msg_id = discord.send_match_card(grp)
                if msg_id:
                    for rec in grp["records"]:
                        db.update_match_discord_id(rec["match_id"], rec["tracked_profile_id"], msg_id)
                time.sleep(0.5)
            except Exception as exc:
                logger.error("Falha ao enviar Card da partida #%d ao Discord: %s", grp["match_id"], exc)

        summary_msg_id = db.get_state("summary_message_id")
        layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION
        rankings_updated = db.get_state("rankings_updated_flag") == "1"

        if grouped_new_matches or players_changed or not summary_msg_id or layout_needs_upgrade or rankings_updated:
            try:
                latest_catalog = db.get_recent_recorded_matches(
                    limit=max(40, summary_size * 3),
                    only_active_players=True,
                )
                updated_players = db.get_active_players()
                cached_rankings = load_cached_rankings(config_path.parent, top_n=top_n)
                new_summary_id = discord.upsert_summary_message(
                    matches=latest_catalog,
                    tracked_players=updated_players,
                    existing_message_id=summary_msg_id,
                    rankings_by_mode=cached_rankings,
                    custom_players=custom_players,
                    top_n=top_n,
                )
                if new_summary_id:
                    if new_summary_id != summary_msg_id:
                        db.set_state("summary_message_id", new_summary_id)
                        logger.info("Mensagem Fixada criada no Discord (ID %s).", new_summary_id)
                    else:
                        logger.info("Painel Fixado (Ranking + Partidas dos 31) atualizado automaticamente no Discord.")
                    db.set_state("summary_layout_version", CURRENT_SUMMARY_LAYOUT_VERSION)
                    db.set_state("rankings_updated_flag", "0")
            except Exception as exc:
                logger.error("Falha ao atualizar Mensagem Fixada no Discord: %s", exc)
    else:
        if grouped_new_matches or players_changed:
            logger.info("Partidas salvas em %s.", db_path.name)

    return len(grouped_new_matches), seeded_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor CoH3 Brasil v5 -> SQLite + Discord Privado")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Caminho para config.json")
    parser.add_argument("--once", action="store_true", help="Executa apenas 1 ciclo de checagem e encerra")
    parser.add_argument(
        "--force-rank-scan",
        action="store_true",
        help="Força revarredura imediata do Ranking (Top 20 + 31) neste ciclo",
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
    logger.info("Iniciando CoH3 Brasil Monitor v5 usando %s...", args.config)

    first_iter = True
    while not stop_requested:
        start_t = time.monotonic()
        try:
            new_cnt, seed_cnt = run_cycle(
                args.config,
                relic,
                force_rank_scan=(args.force_rank_scan and first_iter),
                is_oneshot=bool(args.once),
            )
            first_iter = False
            logger.info("Ciclo concluído: %d partida(s) única(s) nova(s), %d inicial(is).", new_cnt, seed_cnt)
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
        slept = 0.0
        while slept < sleep_for and not stop_requested:
            step = min(1.0, sleep_for - slept)
            time.sleep(step)
            slept += step

    return 0


if __name__ == "__main__":
    sys.exit(main())

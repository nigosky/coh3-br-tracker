#!/usr/bin/env python3
"""Monitor automático CoH3 Brasil v7 — Ranking (Top 20 + 31 únicos ▲/▼), Partidas via SteamID e Segurança Endurecida."""

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
from security import (
    SAFE_WEBHOOK_PLACEHOLDER,
    atomic_write_text,
    configure_secure_logging,
    read_local_secret_webhook,
    redact_secrets,
    resolve_data_dir,
    resolve_safe_db_path,
)

configure_secure_logging(level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("coh3_br.monitor")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
CURRENT_SUMMARY_LAYOUT_VERSION = "v6_ptbr_arc_alekel_gabemerge"


def ensure_core_roster_in_config(cfg: dict[str, Any]) -> bool:
    """Garante que o elenco brasileiro fixo esteja sincronizado pelo SteamID64 em custom_players."""
    changed = False
    if "monitor_only_custom_matches" not in cfg:
        cfg["monitor_only_custom_matches"] = True
        changed = True

    if int(cfg.get("leaderboard_refresh_minutes", 30)) >= 20:
        cfg["leaderboard_refresh_minutes"] = 15
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
        c_known = list(core.get("known_aliases") or [])
        c_merged_pid = int(core.get("merged_into_profile_id", 0) or 0)
        c_merged_sid = str(core.get("merged_into_steam_id") or "")

        target = by_sid.get(c_sid) or by_pid.get(c_pid)
        if target is None:
            new_entry: dict[str, Any] = {
                "profile_id": c_pid,
                "steam_id": c_sid,
                "original_alias": c_orig,
                "alias": c_orig,
                "is_core_roster": True,
            }
            if c_known:
                new_entry["known_aliases"] = c_known
            if c_merged_pid:
                new_entry["merged_into_profile_id"] = c_merged_pid
            if c_merged_sid:
                new_entry["merged_into_steam_id"] = c_merged_sid
            ordered_list.append(new_entry)
            by_sid[c_sid] = new_entry
            by_pid[c_pid] = new_entry
            changed = True
        else:
            if target.get("steam_id") != c_sid:
                target["steam_id"] = c_sid
                changed = True
            if target.get("original_alias") != c_orig:
                target["original_alias"] = c_orig
                changed = True
            expected_alias = format_bound_display_alias(str(target.get("alias") or c_orig), c_orig, c_known)
            if target.get("alias") != expected_alias:
                target["alias"] = expected_alias
                changed = True
            if not int(target.get("profile_id", 0) or 0):
                target["profile_id"] = c_pid
                changed = True
            if c_known and target.get("known_aliases") != c_known:
                target["known_aliases"] = c_known
                changed = True
            if c_merged_pid and int(target.get("merged_into_profile_id", 0) or 0) != c_merged_pid:
                target["merged_into_profile_id"] = c_merged_pid
                changed = True
            if c_merged_sid and target.get("merged_into_steam_id") != c_merged_sid:
                target["merged_into_steam_id"] = c_merged_sid
                changed = True
            if not target.get("is_core_roster"):
                target["is_core_roster"] = True
                changed = True

    if changed:
        cfg["custom_players"] = ordered_list
    return changed


def load_config(config_path: Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Carrega config.json e injeta segredos exclusivamente em memória (env ou .env.secret)."""
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    ensure_core_roster_in_config(cfg)
    env_webhook = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    local_secret = read_local_secret_webhook(config_path.parent)
    if env_webhook:
        cfg["discord_webhook_url"] = env_webhook
    elif local_secret:
        cfg["discord_webhook_url"] = local_secret
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db:
        cfg["sqlite_db_path"] = env_db
    return cfg


def save_config_file(config_path: Path, cfg_to_save: dict[str, Any]) -> None:
    """Salva config.json garantindo que NUNCA nenhum valor real de Webhook seja gravado em disco."""
    sanitized_cfg = dict(cfg_to_save)
    sanitized_cfg["discord_webhook_url"] = SAFE_WEBHOOK_PLACEHOLDER

    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db and sanitized_cfg.get("sqlite_db_path") == env_db:
        try:
            disk_db = json.loads(config_path.read_text(encoding="utf-8")).get("sqlite_db_path", "./coh3_br_matches.db")
        except Exception:
            disk_db = "./coh3_br_matches.db"
        sanitized_cfg["sqlite_db_path"] = disk_db

    serialized = json.dumps(sanitized_cfg, ensure_ascii=False, indent=2) + "\n"
    atomic_write_text(config_path, serialized)


def _merge_player_stat_records(primary: dict[str, Any], secondary: dict[str, Any]) -> None:
    """Mescla estatísticas de conta secundária (ex.: gabe44arg) na conta principal (ex.: É o Gabe)."""
    p_modes = primary.setdefault("modes", {})
    p_inact = primary.setdefault("inactive_modes", {})
    s_modes = secondary.get("modes", {})
    s_inact = secondary.get("inactive_modes", {})

    all_keys = set(p_modes) | set(p_inact) | set(s_modes) | set(s_inact)
    for key in all_keys:
        pm, pi = p_modes.get(key), p_inact.get(key)
        sm, si = s_modes.get(key), s_inact.get(key)
        p_rec, s_rec = pm or pi, sm or si

        if p_rec and not s_rec:
            continue
        if s_rec and not p_rec:
            if sm:
                p_modes[key] = dict(sm)
            elif si:
                p_inact[key] = dict(si)
            continue

        assert p_rec is not None and s_rec is not None
        comb_wins = int(p_rec.get("wins", 0)) + int(s_rec.get("wins", 0))
        comb_losses = int(p_rec.get("losses", 0)) + int(s_rec.get("losses", 0))
        p_lmd, s_lmd = int(p_rec.get("lastmatchdate", 0)), int(s_rec.get("lastmatchdate", 0))
        latest_lmd = max(p_lmd, s_lmd)
        latest_streak = int((s_rec if s_lmd > p_lmd else p_rec).get("streak", 0))

        active_candidates = [r for r in (pm, sm) if r is not None]
        if active_candidates:
            merged_slot = dict(max(active_candidates, key=lambda r: int(r.get("elo", 0))))
            merged_slot.update(wins=comb_wins, losses=comb_losses, lastmatchdate=latest_lmd, streak=latest_streak)
            p_modes[key] = merged_slot
            p_inact.pop(key, None)
        else:
            merged_slot = dict(max((p_rec, s_rec), key=lambda r: int(r.get("elo", 0))))
            merged_slot.update(wins=comb_wins, losses=comb_losses, lastmatchdate=latest_lmd, streak=latest_streak)
            p_inact[key] = merged_slot

    primary["total_wins"] = int(primary.get("total_wins", 0)) + int(secondary.get("total_wins", 0))
    primary["total_losses"] = int(primary.get("total_losses", 0)) + int(secondary.get("total_losses", 0))
    if int(secondary.get("max_elo", 0)) > int(primary.get("max_elo", 0)):
        primary["max_elo"] = secondary["max_elo"]
        primary["best_mode"] = secondary.get("best_mode", primary.get("best_mode", ""))
    if int(secondary.get("last_match_date", 0)) > int(primary.get("last_match_date", 0)):
        primary["last_match_date"] = secondary["last_match_date"]


def merge_catalog_with_custom_players(
    base_players: list[dict[str, Any]],
    custom_players: list[dict[str, Any]],
    relic: RelicAPIClient,
) -> list[dict[str, Any]]:
    """Consulta getPersonalStat por SteamID64, aplica apelidos preferenciais e funde contas vinculadas."""
    by_pid: dict[int, dict[str, Any]] = {int(p["profile_id"]): dict(p) for p in base_players}
    effective_custom = custom_players if custom_players else list(CORE_BR_ROSTER)
    steam_map, pid_map = build_roster_lookup_maps(effective_custom)

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
            existing["merged_into_profile_id"] = int(cp_stat.get("merged_into_profile_id", 0) or 0)
            existing["merged_into_steam_id"] = str(cp_stat.get("merged_into_steam_id") or "")
            existing.setdefault("inactive_modes", {}).update(cp_stat.get("inactive_modes", {}))
            existing.setdefault("modes", {}).update(cp_stat.get("modes", {}))
            if cp_stat.get("max_elo", 0) > existing.get("max_elo", 0):
                existing["max_elo"] = cp_stat["max_elo"]
                existing["best_mode"] = cp_stat.get("best_mode", "")
            if cp_stat.get("last_match_date", 0) > existing.get("last_match_date", 0):
                existing["last_match_date"] = cp_stat["last_match_date"]
        else:
            by_pid[pid] = cp_stat

    merged_away_pids: list[int] = []
    for pid, p_obj in list(by_pid.items()):
        sid = str(p_obj.get("steam_id") or "")
        r_entry = steam_map.get(sid) or pid_map.get(pid) or {}
        target_pid = int(p_obj.get("merged_into_profile_id") or r_entry.get("merged_into_profile_id") or 0)
        if target_pid > 0 and target_pid != pid and target_pid in by_pid:
            _merge_player_stat_records(by_pid[target_pid], p_obj)
            merged_away_pids.append(pid)

    for sec_pid in merged_away_pids:
        by_pid.pop(sec_pid, None)

    for cp in custom_players:
        sid = str(cp.get("steam_id") or "").replace("/steam/", "").strip()
        pid = int(cp.get("profile_id", 0) or 0)
        resolved = fetched_by_sid.get(sid) or fetched_by_pid.get(pid)
        r_entry = steam_map.get(sid) or pid_map.get(pid) or {}
        if resolved:
            cp["profile_id"] = int(resolved["profile_id"])
            if resolved.get("steam_id"):
                cp["steam_id"] = str(resolved["steam_id"])
            orig = str(
                r_entry.get("original_alias")
                or cp.get("original_alias")
                or resolved.get("original_alias")
                or resolved["alias"]
            )
            cp["original_alias"] = orig
            cp["alias"] = format_bound_display_alias(
                str(resolved.get("current_alias") or resolved["alias"]),
                orig,
                r_entry.get("known_aliases") or cp.get("known_aliases"),
            )

    return list(by_pid.values())


def _player_identity_key(entry: dict[str, Any]) -> str:
    sid = str(entry.get("steam_id") or "").replace("/steam/", "").strip()
    return f"steam:{sid}" if sid else f"pid:{int(entry.get('profile_id', 0))}"


def detect_and_apply_ranking_movements(
    db: MatchDatabase,
    full_rankings: dict[str, list[dict[str, Any]]],
    top_n: int = 20,
    custom_players: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    """Compara a posição atual com o último snapshot salvo e aplica rank_delta (+N ▲ / -N ▼)."""
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
    for candidate_dir in (resolve_data_dir(base_dir), base_dir):
        rank_file = candidate_dir / f"top{top_n}_br_por_modo.json"
        if rank_file.is_file():
            try:
                doc = json.loads(rank_file.read_text(encoding="utf-8"))
                return doc.get("rankings_by_mode")
            except Exception:
                continue
    return None


def _compute_rankings_digest(rankings_by_mode: dict[str, list[dict[str, Any]]] | None) -> str:
    if not rankings_by_mode:
        return ""
    rows_sig = [
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
        for mode in ("1v1", "2v2", "Team Games")
        for e in rankings_by_mode.get(mode, [])
    ]
    payload = json.dumps(rows_sig, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def maybe_refresh_top_rankings(
    config_path: Path,
    cfg: dict[str, Any],
    db: MatchDatabase,
    relic: RelicAPIClient,
    discord: DiscordWebhookClient,
    force: bool = False,
    is_oneshot: bool = False,
) -> tuple[bool, dict[str, list[dict[str, Any]]] | None]:
    """Revarre leaderboards da Relic, detecta movimentações e retorna (alterou, rankings_em_memoria)."""
    cfg_upgraded = ensure_core_roster_in_config(cfg)

    if not cfg.get("auto_follow_top_br", True) and not force and not cfg_upgraded:
        return False, None

    refresh_mins = max(5, int(cfg.get("leaderboard_refresh_minutes", 15)))
    top_n = int(cfg.get("top_n_per_mode", 20))
    only_custom = bool(cfg.get("monitor_only_custom_matches", True))
    remove_dropped = bool(cfg.get("remove_if_drops_out_of_top", False))
    custom_players: list[dict[str, Any]] = cfg.get("custom_players", [])

    now = int(time.time())
    last_scan_str = db.get_state("last_leaderboard_scan_ts")
    last_scan_ts = int(last_scan_str) if last_scan_str and last_scan_str.isdigit() else 0

    if not force and not is_oneshot and not cfg_upgraded and last_scan_ts > 0 and (now - last_scan_ts) < (refresh_mins * 60):
        return False, None

    unique_cnt = sum(1 for cp in custom_players if not cp.get("merged_into_profile_id"))
    logger.info(
        "Atualizando Ranking BR (Top %d + %d monitorados únicos / %d contas Steam: 1v1, 2v2, Jogos em Equipe)...",
        top_n,
        unique_cnt,
        len(custom_players),
    )

    players = relic.fetch_brazilian_players()
    data_dir = resolve_data_dir(config_path.parent)
    export_players_files(players, data_dir / "jogadores_br_steam.json", data_dir / "jogadores_br_steam.csv")

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

    exported_rankings = export_merged_top_rankings(
        rankings,
        top_n=top_n,
        json_path=data_dir / f"top{top_n}_br_por_modo.json",
        csv_path=data_dir / f"top{top_n}_br_por_modo.csv",
        custom_players=custom_players,
    )

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
    existing_by_id: dict[int, dict[str, Any]] = {
        int(p["profile_id"]): p for p in cfg.get("tracked_players", []) if "profile_id" in p
    }
    was_already_populated = len(existing_by_id) > 0
    newly_entered: list[dict[str, Any]] = []

    updated_by_id: dict[int, dict[str, Any]] = {} if (only_custom or remove_dropped) else dict(existing_by_id)
    for tp in current_tracked:
        pid = int(tp["profile_id"])
        if not only_custom and pid not in existing_by_id and not tp.get("is_custom"):
            newly_entered.append(tp)
        rec_tp: dict[str, Any] = {
            "profile_id": pid,
            "alias": tp["alias"],
            "original_alias": str(tp.get("original_alias") or tp["alias"]),
            "steam_id": str(tp.get("steam_id") or existing_by_id.get(pid, {}).get("steam_id") or ""),
            "placements": tp["placements"],
            "is_custom": bool(tp.get("is_custom")) or (pid in custom_ids),
        }
        if tp.get("merged_into_profile_id"):
            rec_tp["merged_into_profile_id"] = int(tp["merged_into_profile_id"])
        updated_by_id[pid] = rec_tp

    db.set_state("last_leaderboard_scan_ts", str(now))
    db.prune_expired_avatars()
    if has_new_movements or table_stats_changed or not had_prev_snap or force or cfg_upgraded:
        db.set_state("rankings_updated_flag", "1")

    cfg["custom_players"] = custom_players
    cfg["tracked_players"] = list(updated_by_id.values())
    save_config_file(config_path, cfg)

    if has_new_movements:
        for mode_k, mv_list in movements_by_mode.items():
            for mv in mv_list:
                d = int(mv.get("rank_delta", 0))
                arrow = "NOVO" if mv.get("is_new_entry") else (f"▲ +{d}" if d > 0 else f"▼ {d}")
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
                logger.error("Erro ao enviar Card de Movimentação do Ranking ao Discord: %s", redact_secrets(exc))

    if not only_custom and newly_entered and was_already_populated and discord.is_configured:
        try:
            discord.send_new_top_entrant_card(newly_entered, top_n=top_n)
        except Exception as exc:
            logger.error("Erro ao notificar novo integrante Top %d no Discord: %s", top_n, redact_secrets(exc))

    changed = has_new_movements or table_stats_changed or cfg_upgraded or bool(newly_entered)
    return changed, exported_rankings


def run_cycle(
    config_path: Path,
    relic: RelicAPIClient,
    force_rank_scan: bool = False,
    is_oneshot: bool = False,
) -> tuple[int, int]:
    """Executa um ciclo completo de monitoramento de Ranking + Partidas."""
    cfg = load_config(config_path)
    db_path = resolve_safe_db_path(config_path.parent, cfg.get("sqlite_db_path"))
    data_dir = resolve_data_dir(config_path.parent)
    catalog_path = data_dir / "jogadores_br_steam.json"
    if not catalog_path.is_file():
        catalog_path = config_path.parent / "jogadores_br_steam.json"

    with MatchDatabase(db_path) as db:
        discord = DiscordWebhookClient(
            webhook_url=str(cfg.get("discord_webhook_url", "")),
            bot_username=str(cfg.get("bot_username", "CoH3 Brasil Monitor")),
            db=db,
            catalog_json_path=catalog_path,
        )

        layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION
        fresh_rankings: dict[str, list[dict[str, Any]]] | None = None

        try:
            _, fresh_rankings = maybe_refresh_top_rankings(
                config_path=config_path,
                cfg=cfg,
                db=db,
                relic=relic,
                discord=discord,
                force=(force_rank_scan or layout_needs_upgrade),
                is_oneshot=is_oneshot,
            )
        except Exception as exc:
            logger.error("Falha ao revarrer leaderboards Top BR (seguindo com lista atual): %s", redact_secrets(exc))

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
        now_ts = int(time.time())

        def _fetch_one_player(pl: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]] | None, Exception | None]:
            try:
                res = relic.fetch_player_recent_matches(
                    profile_id=int(pl["profile_id"]),
                    fallback_alias=str(pl.get("original_alias") or pl["alias"]),
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                )
                return pl, res, None
            except Exception as err:
                return pl, None, err

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(active_players))) as pool:
            fetched_results = list(pool.map(_fetch_one_player, active_players))

        for player, recent_matches, fetch_err in fetched_results:
            pid = int(player["profile_id"])
            alias = str(player["alias"])
            is_baseline_done = bool(player["baseline_synced"])

            if fetch_err is not None or recent_matches is None:
                logger.error("Erro ao buscar partidas de %s (#%d): %s", alias, pid, redact_secrets(fetch_err))
                continue

            resolved_alias = recent_matches[0]["tracked_alias"] if recent_matches else alias
            resolved_steam_id = (
                recent_matches[0].get("tracked_steam_id", "")
                if recent_matches
                else str(player.get("steam_id") or "")
            )

            if not is_baseline_done:
                for idx_m, m in enumerate(recent_matches):
                    is_very_recent = (now_ts - int(m.get("completion_time", 0))) <= 2700
                    if db.insert_match(m):
                        if is_very_recent:
                            newly_finished.append(m)
                        elif idx_m < seed_limit:
                            seeded_count += 1
                db.mark_baseline_synced(pid, resolved_alias, steam_id=resolved_steam_id or None)
                players_changed = True
                logger.info(
                    "Jogador %s (#%d | Steam %s) sincronizado inicialmente (%d partidas catalogadas).",
                    resolved_alias,
                    pid,
                    resolved_steam_id or "N/D",
                    min(len(recent_matches), 10),
                )
            else:
                if recent_matches:
                    existing_mids = db.get_player_match_ids(pid, [int(m["match_id"]) for m in recent_matches])
                    player_new = [m for m in recent_matches if int(m["match_id"]) not in existing_mids]
                    player_new.sort(key=lambda x: x["completion_time"])
                    for m in player_new:
                        if db.insert_match(m):
                            newly_finished.append(m)
                            logger.info(
                                "[NOVA PARTIDA] %s (%s) -> %s em %s (%s) [#%d]",
                                m["tracked_alias"],
                                m["tracked_faction_short"],
                                "VITÓRIA" if m["win"] else "DERROTA",
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
                        db.update_matches_discord_id_batch(grp["records"], msg_id)
                    time.sleep(0.4)
                except Exception as exc:
                    logger.error("Falha ao enviar Card da partida #%d ao Discord: %s", grp["match_id"], redact_secrets(exc))

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
                    rankings_for_panel = fresh_rankings or load_cached_rankings(config_path.parent, top_n=top_n)
                    new_summary_id = discord.upsert_summary_message(
                        matches=latest_catalog,
                        tracked_players=updated_players,
                        existing_message_id=summary_msg_id,
                        rankings_by_mode=rankings_for_panel,
                        custom_players=custom_players,
                        top_n=top_n,
                        recreate_message=layout_needs_upgrade,
                    )
                    if new_summary_id:
                        if new_summary_id != summary_msg_id:
                            db.set_state("summary_message_id", new_summary_id)
                            logger.info("Painel Resumo publicado no Discord (ID %s).", new_summary_id)
                        else:
                            logger.info("Painel Fixado (Ranking + Partidas) atualizado automaticamente no Discord.")
                        db.set_state("summary_layout_version", CURRENT_SUMMARY_LAYOUT_VERSION)
                        db.set_state("rankings_updated_flag", "0")
                except Exception as exc:
                    logger.error("Falha ao atualizar Mensagem Fixada no Discord: %s", redact_secrets(exc))
        elif grouped_new_matches or players_changed:
            logger.info("Partidas salvas em %s.", db_path.name)

    return len(grouped_new_matches), seeded_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor CoH3 Brasil v7 -> SQLite + Discord Privado")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Caminho para config.json")
    parser.add_argument("--once", action="store_true", help="Executa apenas 1 ciclo de checagem e encerra")
    parser.add_argument(
        "--force-rank-scan",
        action="store_true",
        help="Força revarredura imediata do Ranking (Top 20 + monitorados) neste ciclo",
    )
    args = parser.parse_args()

    if not args.config.is_file():
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
    logger.info("Iniciando CoH3 Brasil Monitor v7 usando %s...", args.config)

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
            logger.exception("Erro inesperado no ciclo de monitoramento: %s", redact_secrets(exc))
            if args.once:
                return 1

        if args.once or stop_requested:
            break

        try:
            poll_sec = max(20, int(load_config(args.config).get("poll_interval_seconds", 60)))
        except Exception:
            poll_sec = 60

        sleep_for = max(1.0, poll_sec - (time.monotonic() - start_t))
        slept = 0.0
        while slept < sleep_for and not stop_requested:
            step = min(1.0, sleep_for - slept)
            time.sleep(step)
            slept += step

    return 0


if __name__ == "__main__":
    sys.exit(main())

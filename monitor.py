#!/usr/bin/env python3
"""Monitor automático CoH3 Brasil v7.8 — Quádrupla Checagem (Relic Direta × coh3stats.com × Radar Veteranos × Discord), Resumo Semanal, Limpeza 72h e Segurança Endurecida."""

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from database import MatchDatabase, PENDING_DISCORD_MARKER, SEEDED_DISCORD_MARKER
from discord_notifier import DiscordWebhookClient, group_matches_by_id
from relic_api import (
    CORE_BR_ROSTER,
    Coh3StatsAPIClient,
    RelicAPIClient,
    VeteransRadarClient,
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
CURRENT_SUMMARY_CONTENT_VERSION = "v7_14_matches_only_panel"
CURRENT_MAP_NAMES_VERSION = "v1_coh3_patch_3_0_official_maps"
BRT_TZ = timezone(timedelta(hours=-3))
DEFAULT_DISCORD_CLEANUP_HOURS = 72


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


def load_config(config_path: Path = DEFAULT_CONFIG_PATH, ensure_roster: bool = True) -> dict[str, Any]:
    """Carrega config.json e injeta segredos exclusivamente em memória (env ou .env.secret)."""
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    if ensure_roster:
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


def _should_run_daily_ranking_scan(
    now_ts: int,
    last_scan_date_brt: str | None,
    last_scan_ts: int,
    cutoff_hour_brt: int = 0,
    cutoff_minute_brt: int = 1,
) -> tuple[bool, str]:
    """Determina se o ranking diário deve rodar hoje (apenas 1x ao dia, a partir das 00:01 BRT)."""
    now_brt = datetime.fromtimestamp(int(now_ts), tz=BRT_TZ)
    today_brt = now_brt.strftime("%Y-%m-%d")

    effective_last_date = (last_scan_date_brt or "").strip()
    if not effective_last_date and last_scan_ts > 0:
        effective_last_date = datetime.fromtimestamp(int(last_scan_ts), tz=BRT_TZ).strftime("%Y-%m-%d")

    past_cutoff = (now_brt.hour, now_brt.minute) >= (int(cutoff_hour_brt), int(cutoff_minute_brt))
    return (past_cutoff and effective_last_date != today_brt), today_brt


def _should_run_weekly_summary(
    now_ts: int,
    last_iso_week: str | None,
    cutoff_weekday: int = 0,
    cutoff_hour_brt: int = 0,
    cutoff_minute_brt: int = 5,
) -> tuple[bool, str]:
    """Determina se o Resumo Semanal deve ser postado (padrão: toda segunda-feira a partir de 00:05 BRT)."""
    now_brt = datetime.fromtimestamp(int(now_ts), tz=BRT_TZ)
    iso_year, iso_week, _ = now_brt.isocalendar()
    current_week_key = f"{iso_year}-W{iso_week:02d}"

    is_target_weekday = now_brt.weekday() == int(cutoff_weekday)
    past_cutoff = (now_brt.hour, now_brt.minute) >= (int(cutoff_hour_brt), int(cutoff_minute_brt))
    already_sent = (last_iso_week or "").strip() == current_week_key
    return (is_target_weekday and past_cutoff and not already_sent), current_week_key


def maybe_post_weekly_summary(
    db: MatchDatabase,
    discord: DiscordWebhookClient,
    custom_players: list[dict[str, Any]] | None = None,
    force: bool = False,
    now_ts: int | None = None,
) -> str | None:
    """Publica 1x por semana (segunda-feira >= 00:05 BRT ou forçado) o Card de Resumo Semanal dos Veteranos BR."""
    if not discord.is_configured:
        return None

    now = int(now_ts) if now_ts is not None else int(time.time())
    last_week = db.get_state("last_weekly_summary_iso_week")
    due, week_key = _should_run_weekly_summary(now_ts=now, last_iso_week=last_week)
    if not force and not due:
        return None

    merged_map = {
        int(cp["profile_id"]): int(cp["merged_into_profile_id"])
        for cp in (custom_players or CORE_BR_ROSTER)
        if int(cp.get("profile_id", 0) or 0) > 0 and int(cp.get("merged_into_profile_id", 0) or 0) > 0
    }
    stats = db.get_weekly_summary_stats(now_ts=now, window_days=7, merged_map=merged_map)
    if int(stats.get("unique_matches_count", 0)) <= 0:
        logger.info("[RESUMO SEMANAL] Nenhuma partida nos últimos 7 dias para gerar card (%s).", week_key)
        db.set_state("last_weekly_summary_iso_week", week_key)
        return None

    try:
        msg_id = discord.send_weekly_summary_card(stats)
        if msg_id:
            db.record_ephemeral_message(msg_id, kind="weekly_summary")
            db.set_state("last_weekly_summary_iso_week", week_key)
            logger.info(
                "[RESUMO SEMANAL] Card semanal (%s) publicado no Discord (ID %s | %d partidas únicas | %d duelos BR).",
                week_key,
                msg_id,
                stats["unique_matches_count"],
                stats["br_duels_count"],
            )
            return msg_id
    except Exception as exc:
        logger.error("Erro ao publicar Card de Resumo Semanal no Discord: %s", redact_secrets(exc))
    return None


def maybe_run_db_maintenance(
    db: MatchDatabase,
    force: bool = False,
    interval_days: int = 7,
    now_ts: int | None = None,
) -> dict[str, int] | None:
    """Executa compactação segura (>30 dias) + VACUUM no SQLite a cada `interval_days` dias."""
    now = int(now_ts) if now_ts is not None else int(time.time())
    last_raw = (db.get_state("last_db_maintenance_ts") or "").strip()
    last_ts = int(last_raw) if last_raw.isdigit() else 0
    min_interval_sec = max(1, int(interval_days)) * 86400

    if not force and last_ts > 0 and (now - last_ts) < min_interval_sec:
        return None

    try:
        res = db.run_periodic_maintenance(now_ts=now)
        db.set_state("last_db_maintenance_ts", str(now))
        logger.info(
            "[MANUTENÇÃO SQLITE] Compactadas %d linhas (>30d), %d efêmeros podados, %d avatares expirados | Tamanho: %.1f KB -> %.1f KB (-%.1f KB via VACUUM).",
            res["compacted_match_rows"],
            res["purged_ephemeral_rows"],
            res["purged_avatars"],
            res["bytes_before"] / 1024.0,
            res["bytes_after"] / 1024.0,
            res["bytes_saved"] / 1024.0,
        )
        return res
    except Exception as exc:
        logger.warning("Manutenção periódica do SQLite adiada: %s", redact_secrets(exc))
        return None


def prune_old_discord_messages(
    db: MatchDatabase,
    discord: DiscordWebhookClient,
    retention_hours: int = DEFAULT_DISCORD_CLEANUP_HOURS,
    max_per_cycle: int = 40,
) -> int:
    """Remove do canal de texto do Discord partidas/cards com mais de retention_hours (padrão 72h), preservando o Painel Fixado."""
    if retention_hours <= 0 or not discord.is_configured:
        return 0

    summary_msg_id = (db.get_state("summary_message_id") or "").strip()
    excluded = {summary_msg_id} if summary_msg_id else set()
    to_prune = db.get_prunable_discord_messages(
        max_age_sec=int(retention_hours) * 3600,
        exclude_message_ids=excluded,
        limit=max_per_cycle,
    )
    if not to_prune:
        return 0

    pruned_count = 0
    for msg_id, kind in to_prune:
        try:
            if discord.delete_message(msg_id, protected_message_id=summary_msg_id or None):
                db.mark_discord_message_pruned(msg_id)
                pruned_count += 1
            time.sleep(0.35)
        except Exception as exc:
            logger.warning(
                "Falha transitória ao limpar mensagem antiga (%s | %s) do Discord: %s",
                msg_id,
                kind,
                redact_secrets(exc),
            )

    if pruned_count:
        logger.info(
            "[LIMPEZA %dh] %d mensagem(ns) antiga(s) removida(s) do canal de texto do Discord (Painel Fixado preservado).",
            retention_hours,
            pruned_count,
        )
    return pruned_count


def reset_and_clean_discord_channel(
    db: MatchDatabase,
    discord: DiscordWebhookClient,
) -> int:
    """Apaga todas as mensagens conhecidas do bot no canal Discord e reinicia o painel do zero."""
    if not discord.is_configured:
        return 0

    targets = db.get_all_active_discord_message_ids(include_summary=True)
    deleted = 0
    for msg_id, kind in targets:
        try:
            if discord.delete_message(msg_id, protected_message_id=None):
                deleted += 1
            time.sleep(0.35)
        except Exception as exc:
            logger.warning(
                "Falha ao apagar mensagem (%s | %s) durante reset do canal Discord: %s",
                msg_id,
                kind,
                redact_secrets(exc),
            )

    db.reset_discord_channel_state()
    logger.info(
        "[RESET CANAL DISCORD] %d/%d mensagem(ns) removida(s) do canal; histórico preservado em SQLite e painel reiniciado do zero.",
        deleted,
        len(targets),
    )
    return deleted


def maybe_refresh_top_rankings(
    config_path: Path,
    cfg: dict[str, Any],
    db: MatchDatabase,
    relic: RelicAPIClient,
    discord: DiscordWebhookClient,
    force: bool = False,
    is_oneshot: bool = False,
) -> tuple[bool, dict[str, list[dict[str, Any]]] | None]:
    """Revarre leaderboards da Relic 1x/dia após 00:01 BRT (ou quando forçado) e retorna (alterou, rankings_em_memoria)."""
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
    ranking_mode = str(cfg.get("ranking_update_mode", "daily")).strip().lower()
    cutoff_h = max(0, min(23, int(cfg.get("ranking_daily_hour_brt", 0))))
    cutoff_m = max(0, min(59, int(cfg.get("ranking_daily_minute_brt", 1))))
    due_daily, today_brt = _should_run_daily_ranking_scan(
        now_ts=now,
        last_scan_date_brt=db.get_state("last_leaderboard_scan_date_brt"),
        last_scan_ts=last_scan_ts,
        cutoff_hour_brt=cutoff_h,
        cutoff_minute_brt=cutoff_m,
    )

    if not force and not cfg_upgraded:
        if ranking_mode == "daily":
            if not due_daily:
                return False, None
        else:
            effective_refresh_mins = max(refresh_mins, 30) if is_oneshot else refresh_mins
            if last_scan_ts > 0 and (now - last_scan_ts) < (effective_refresh_mins * 60):
                return False, None

    unique_cnt = sum(1 for cp in custom_players if not cp.get("merged_into_profile_id"))
    logger.info(
        "Atualizando Ranking BR diário (Top %d + %d monitorados únicos / %d contas Steam: 1v1, 2v2, Jogos em Equipe)...",
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

    post_ranking_movements = bool(cfg.get("post_ranking_movements", False))
    rankings = compute_merged_mode_rankings(
        merged_players,
        custom_ids=custom_ids,
        custom_steam_ids=custom_sids,
    )
    if post_ranking_movements:
        movements_by_mode, has_new_movements = detect_and_apply_ranking_movements(
            db=db,
            full_rankings=rankings,
            top_n=top_n,
            custom_players=custom_players,
        )
    else:
        movements_by_mode, has_new_movements = {}, False

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
    db.set_state("last_leaderboard_scan_date_brt", today_brt)
    db.prune_expired_avatars()
    if has_new_movements or table_stats_changed or not prev_digest or force or cfg_upgraded:
        db.set_state("rankings_updated_flag", "1")

    cfg["custom_players"] = custom_players
    cfg["tracked_players"] = list(updated_by_id.values())
    save_config_file(config_path, cfg)

    if post_ranking_movements and has_new_movements:
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
                mv_msg_id = discord.send_ranking_movement_card(movements_by_mode)
                if mv_msg_id:
                    db.record_ephemeral_message(mv_msg_id, kind="ranking_movement")
            except Exception as exc:
                logger.error("Erro ao enviar Card de Movimentação do Ranking ao Discord: %s", redact_secrets(exc))

    if not only_custom and newly_entered and was_already_populated and discord.is_configured:
        try:
            ent_msg_id = discord.send_new_top_entrant_card(newly_entered, top_n=top_n)
            if ent_msg_id:
                db.record_ephemeral_message(ent_msg_id, kind="new_top_entrant")
        except Exception as exc:
            logger.error("Erro ao notificar novo integrante Top %d no Discord: %s", top_n, redact_secrets(exc))

    changed = has_new_movements or table_stats_changed or cfg_upgraded or bool(newly_entered)
    return changed, exported_rankings


def _merge_match_records(primary: dict[str, Any], secondary: dict[str, Any]) -> dict[str, Any]:
    """Combina metadados mais completos (ELO, replay, SteamID, país) quando Relic Direta e coh3stats retornam a mesma partida."""
    merged = dict(primary)
    if merged.get("old_elo") is None and secondary.get("old_elo") is not None:
        merged["old_elo"] = secondary["old_elo"]
    if merged.get("new_elo") is None and secondary.get("new_elo") is not None:
        merged["new_elo"] = secondary["new_elo"]
    if not merged.get("tracked_steam_id") and secondary.get("tracked_steam_id"):
        merged["tracked_steam_id"] = secondary["tracked_steam_id"]
    if not merged.get("has_replay") and secondary.get("has_replay"):
        merged["has_replay"] = True
    if int(merged.get("duration_sec", 0) or 0) <= 0 and int(secondary.get("duration_sec", 0) or 0) > 0:
        merged["start_time"] = secondary["start_time"]
        merged["duration_sec"] = secondary["duration_sec"]

    for side in ("allies", "opponents"):
        prim_list = merged.get(side) or []
        sec_list = secondary.get(side) or []
        if not prim_list and sec_list:
            merged[side] = [dict(p) for p in sec_list]
            continue
        sec_by_pid = {
            int(p.get("profile_id", 0) or 0): p
            for p in sec_list
            if isinstance(p, dict) and int(p.get("profile_id", 0) or 0) > 0
        }
        enriched_side: list[dict[str, Any]] = []
        for p in prim_list:
            if not isinstance(p, dict):
                continue
            p_copy = dict(p)
            sp = sec_by_pid.get(int(p_copy.get("profile_id", 0) or 0))
            if sp:
                if not p_copy.get("steam_id") and sp.get("steam_id"):
                    p_copy["steam_id"] = sp["steam_id"]
                if (not p_copy.get("country") or p_copy.get("country") == "un") and sp.get("country") and sp.get("country") != "un":
                    p_copy["country"] = sp["country"]
                if p_copy.get("old_elo") is None and sp.get("old_elo") is not None:
                    p_copy["old_elo"] = sp["old_elo"]
                if p_copy.get("new_elo") is None and sp.get("new_elo") is not None:
                    p_copy["new_elo"] = sp["new_elo"]
                if p_copy.get("elo") is None and p_copy.get("new_elo") is not None:
                    p_copy["elo"] = p_copy["new_elo"]
                if p_copy.get("elo_delta") is None and p_copy.get("old_elo") is not None and p_copy.get("new_elo") is not None:
                    p_copy["elo_delta"] = int(p_copy["new_elo"]) - int(p_copy["old_elo"])
                cur_alias = str(p_copy.get("alias") or "")
                sec_alias = str(sp.get("alias") or "")
                if (cur_alias.startswith("Player ") or cur_alias.startswith("ID ")) and sec_alias and not (sec_alias.startswith("Player ") or sec_alias.startswith("ID ")):
                    p_copy["alias"] = sec_alias
            enriched_side.append(p_copy)
        merged[side] = enriched_side

    return merged


def _load_audited_open_data_days(db: MatchDatabase) -> set[int]:
    raw = (db.get_state("coh3stats_audited_days_json") or "").strip()
    if not raw:
        return set()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return {int(x) for x in parsed if isinstance(x, int) or (isinstance(x, str) and x.isdigit())}
    except Exception:
        pass
    return set()


def _save_audited_open_data_days(db: MatchDatabase, audited_days: set[int]) -> None:
    recent_days = sorted({int(d) for d in audited_days if int(d) > 0})[-14:]
    db.set_state("coh3stats_audited_days_json", json.dumps(recent_days, separators=(",", ":")))


def run_third_cross_check(
    db: MatchDatabase,
    relic: RelicAPIClient,
    coh3stats: Coh3StatsAPIClient | None,
    synced_players: list[dict[str, Any]],
    newly_finished: list[dict[str, Any]],
    only_automatch: bool,
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    recovery_min_completion_ts: int,
    live_marker: str | None,
    pending_max_age_sec: int = 21600,
    window_sec: int = 259200,
) -> dict[str, int]:
    """
    3ª Checagem Cruzada (API CoH3 Direta da Relic `getRecentMatchHistory` × Open Data oficial do site coh3stats.com).
    Cruza as duas fontes independentes contra o SQLite e recupera qualquer partida recente
    dentro da janela ativa que não foi postada no Discord — sem jamais duplicar cards já
    confirmados (Snowflake) nem reenviar partidas PRUNED ou SEEDED.
    """
    total_accounts = len(synced_players)
    stats: dict[str, int] = {
        "relic_direct_unique": 0,
        "relic_direct_ok_accounts": 0,
        "relic_direct_total_accounts": total_accounts,
        "relic_direct_failed_batches": 0,
        "coh3stats_unique": 0,
        "coh3stats_br_matches": 0,
        "coh3stats_total_scanned": 0,
        "coh3stats_days_audited": 0,
        "coh3stats_days_pending": 0,
        "cross_confirmed": 0,
        "recovered_unique": 0,
        "recovered_rows": 0,
        "recovered_from_both": 0,
        "recovered_from_relic_only": 0,
        "recovered_from_coh3stats_only": 0,
        "requeued_undelivered": 0,
        "synced_siblings": 0,
    }
    if not synced_players:
        return stats

    relic_by_pid: dict[int, list[dict[str, Any]]] = {}
    if callable(getattr(relic, "fetch_recent_matches_direct_batch", None)):
        try:
            relic_by_pid, failed_batches = relic.fetch_recent_matches_direct_batch(
                players=synced_players,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
                batch_size=1,
            )
            stats["relic_direct_failed_batches"] = failed_batches
            stats["relic_direct_ok_accounts"] = max(0, total_accounts - failed_batches)
        except Exception as exc:
            logger.warning(
                "[3ª CHECAGEM] Consulta direta à Relic API falhou (seguindo com coh3stats Open Data): %s",
                redact_secrets(exc),
            )

    coh3stats_by_pid: dict[int, list[dict[str, Any]]] = {}
    newly_audited_days: list[int] = []
    already_audited_days = _load_audited_open_data_days(db)
    if coh3stats is not None and callable(getattr(coh3stats, "fetch_open_data_days_matches", None)):
        now_utc = datetime.fromtimestamp(int(time.time()), tz=timezone.utc)
        today_utc_midnight = int(datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc).timestamp())
        retention_days = max(1, min(3, (max(24, int(window_sec // 3600)) + 23) // 24))
        candidate_days = [today_utc_midnight - (86400 * offset) for offset in range(1, retention_days + 1)]
        overlapping_days = [d for d in candidate_days if (d + 86400) > recovery_min_completion_ts]
        target_days = overlapping_days if overlapping_days else [today_utc_midnight - 86400]
        pending_days = [d for d in sorted(target_days) if d not in already_audited_days]
        stats["coh3stats_days_pending"] = len(pending_days)

        if pending_days:
            try:
                coh3stats_by_pid, ok_days, total_scanned, _fail_days = coh3stats.fetch_open_data_days_matches(
                    day_timestamps=pending_days,
                    players=synced_players,
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                    races=getattr(relic, "races", None) or None,
                    match_types=getattr(relic, "match_types", None) or None,
                )
                newly_audited_days = ok_days
                stats["coh3stats_days_audited"] = len(ok_days)
                stats["coh3stats_total_scanned"] = total_scanned
            except Exception as exc:
                logger.warning(
                    "[3ª CHECAGEM] Consulta ao Open Data oficial do coh3stats.com falhou (seguindo com Relic Direta): %s",
                    redact_secrets(exc),
                )

    relic_pairs: dict[tuple[int, int], dict[str, Any]] = {}
    for pid, rows in relic_by_pid.items():
        for m in rows:
            mid = int(m.get("match_id", 0) or 0)
            comp_ts = int(m.get("completion_time", 0) or 0)
            if mid > 0 and comp_ts >= recovery_min_completion_ts:
                relic_pairs[(mid, int(pid))] = m

    coh3stats_pairs: dict[tuple[int, int], dict[str, Any]] = {}
    coh3stats_all_br_mids: set[int] = set()
    for pid, rows in coh3stats_by_pid.items():
        for m in rows:
            mid = int(m.get("match_id", 0) or 0)
            if mid > 0:
                coh3stats_all_br_mids.add(mid)
            comp_ts = int(m.get("completion_time", 0) or 0)
            if mid > 0 and comp_ts >= recovery_min_completion_ts:
                coh3stats_pairs[(mid, int(pid))] = m

    relic_mids = {mid for mid, _ in relic_pairs}
    c3s_mids = {mid for mid, _ in coh3stats_pairs}
    stats["relic_direct_unique"] = len(relic_mids)
    stats["coh3stats_br_matches"] = len(coh3stats_all_br_mids)
    stats["coh3stats_unique"] = len(c3s_mids)
    stats["cross_confirmed"] = len(relic_mids & c3s_mids)

    combined_pairs: dict[tuple[int, int], tuple[dict[str, Any], str]] = {}
    for key in relic_pairs.keys() | coh3stats_pairs.keys():
        r_rec = relic_pairs.get(key)
        c_rec = coh3stats_pairs.get(key)
        if r_rec is not None and c_rec is not None:
            combined_pairs[key] = (_merge_match_records(r_rec, c_rec), "Relic+coh3stats")
        elif r_rec is not None:
            combined_pairs[key] = (r_rec, "Relic Direta")
        elif c_rec is not None:
            combined_pairs[key] = (c_rec, "coh3stats")

    if combined_pairs:
        all_candidate_mids = sorted({mid for mid, _ in combined_pairs})
        delivery_map = db.get_match_delivery_map(all_candidate_mids)
        now_ts = int(time.time())
        existing_new_keys = {(int(m["match_id"]), int(m["tracked_profile_id"])) for m in newly_finished}
        recovered_match_sources: dict[int, set[str]] = {}
        requeued_mids: set[int] = set()

        ordered_items = sorted(
            combined_pairs.items(),
            key=lambda kv: (int(kv[1][0].get("completion_time", 0)), kv[0][0], kv[0][1]),
        )

        for (mid, pid), (match_obj, source_tag) in ordered_items:
            info = delivery_map.get(mid)
            if info is not None:
                if info["handled_non_live"]:
                    continue

                existing_snowflake = info["snowflake"]
                if existing_snowflake:
                    if pid not in info["rows"]:
                        if db.insert_match(match_obj, discord_message_id=existing_snowflake):
                            stats["synced_siblings"] += 1
                    continue

                if pid in info["rows"]:
                    cur_msg_id, cur_rec_at = info["rows"][pid]
                    if cur_msg_id == PENDING_DISCORD_MARKER and (now_ts - cur_rec_at) < pending_max_age_sec:
                        continue
                    if (
                        live_marker == PENDING_DISCORD_MARKER
                        and mid not in requeued_mids
                        and db.requeue_undelivered_match(mid)
                    ):
                        requeued_mids.add(mid)
                        stats["requeued_undelivered"] += 1
                        stats["recovered_rows"] += 1
                        recovered_match_sources.setdefault(mid, set()).add(source_tag)
                        if (mid, pid) not in existing_new_keys:
                            newly_finished.append(match_obj)
                            existing_new_keys.add((mid, pid))
                        logger.info(
                            "[3ª CHECAGEM - REENFILEIRADA (%s)] %s (%s) -> %s em %s (%s) [#%d]",
                            source_tag,
                            match_obj["tracked_alias"],
                            match_obj["tracked_faction_short"],
                            "VITÓRIA" if match_obj["win"] else "DERROTA",
                            match_obj["map_clean"],
                            match_obj["mode"],
                            mid,
                        )
                    continue

                has_active_pending = any(
                    msg_id == PENDING_DISCORD_MARKER and (now_ts - rec_at) < pending_max_age_sec
                    for msg_id, rec_at in info["rows"].values()
                )
            else:
                has_active_pending = False

            if db.insert_match(match_obj, discord_message_id=live_marker):
                if (mid, pid) not in existing_new_keys:
                    newly_finished.append(match_obj)
                    existing_new_keys.add((mid, pid))
                if has_active_pending:
                    stats["synced_siblings"] += 1
                else:
                    stats["recovered_rows"] += 1
                    recovered_match_sources.setdefault(mid, set()).add(source_tag)
                    logger.info(
                        "[3ª CHECAGEM - RECUPERADA (%s)] %s (%s) -> %s em %s (%s) [#%d]",
                        source_tag,
                        match_obj["tracked_alias"],
                        match_obj["tracked_faction_short"],
                        "VITÓRIA" if match_obj["win"] else "DERROTA",
                        match_obj["map_clean"],
                        match_obj["mode"],
                        mid,
                    )

        stats["recovered_unique"] = len(recovered_match_sources)
        for sources in recovered_match_sources.values():
            if "Relic+coh3stats" in sources or ("Relic Direta" in sources and "coh3stats" in sources):
                stats["recovered_from_both"] += 1
            elif "coh3stats" in sources:
                stats["recovered_from_coh3stats_only"] += 1
            else:
                stats["recovered_from_relic_only"] += 1

    if newly_audited_days:
        _save_audited_open_data_days(db, already_audited_days | set(newly_audited_days))

    if stats["coh3stats_days_pending"] == 0:
        c3s_status = "em dia (cache diário OK)"
    else:
        c3s_status = (
            f"{stats['coh3stats_unique']} na janela "
            f"({stats['coh3stats_br_matches']} BR em {stats['coh3stats_total_scanned']} jogos; "
            f"{stats['coh3stats_days_audited']}/{stats['coh3stats_days_pending']} dia(s) OK)"
        )

    logger.info(
        "[3ª CHECAGEM CRUZADA] Relic Direta: %d partida(s) (%d/%d contas OK) | coh3stats Open Data: %s | Cruzadas: %d | Recuperadas p/ Discord: %d (Ambas: %d, Relic: %d, coh3stats: %d, Reenfileiradas: %d)",
        stats["relic_direct_unique"],
        stats["relic_direct_ok_accounts"],
        stats["relic_direct_total_accounts"],
        c3s_status,
        stats["cross_confirmed"],
        stats["recovered_unique"],
        stats["recovered_from_both"],
        stats["recovered_from_relic_only"],
        stats["recovered_from_coh3stats_only"],
        stats["requeued_undelivered"],
    )
    return stats


def _load_pid_set_state(db: MatchDatabase, key: str) -> set[int]:
    raw = (db.get_state(key) or "").strip()
    if not raw:
        return set()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return {
                int(x)
                for x in parsed
                if (isinstance(x, int) and not isinstance(x, bool) and x > 0)
                or (isinstance(x, str) and x.isdigit() and int(x) > 0)
            }
    except Exception:
        pass
    return set()


def _save_pid_set_state(db: MatchDatabase, key: str, pids: set[int]) -> None:
    clean = sorted({int(p) for p in pids if int(p) > 0})
    db.set_state(key, json.dumps(clean, separators=(",", ":")))


def run_fourth_radar_check(
    db: MatchDatabase,
    relic: RelicAPIClient,
    radar: VeteransRadarClient | None,
    synced_players: list[dict[str, Any]],
    newly_finished: list[dict[str, Any]],
    only_automatch: bool,
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    recovery_min_completion_ts: int,
    live_marker: str | None,
    pending_max_age_sec: int = 21600,
    radar_recent_window_sec: int = 5400,
    pass1_failed_pids: set[int] | None = None,
) -> dict[str, Any]:
    """
    4ª Checagem Cruzada (somente-leitura) com o Radar de Lobby dos Veteranos (`nigosky/coh3-br-lobby-radar`).
    Identifica Veteranos atualmente/recentemente no CoH3 (ou que acabaram de sair do Radar), cruza com o SQLite
    e com `getPersonalStat.lastmatchdate` da Relic, e executa rechecagem prioritária nos dois endpoints de histórico
    da Relic caso alguma partida recente não tenha sido capturada ou entregue ao Discord.
    """
    stats: dict[str, Any] = {
        "radar_ok": False,
        "radar_stale": False,
        "radar_age_min": -1,
        "flagged_count": 0,
        "exited_count": 0,
        "confirmed_count": 0,
        "rechecked_count": 0,
        "recovered_unique": 0,
        "requeued_undelivered": 0,
        "lagging_count": 0,
        "synced_siblings": 0,
    }
    if radar is None or not synced_players:
        return stats

    radar_res = radar.fetch_active_veteranos(max_age_sec=7200)
    if not radar_res.get("ok"):
        logger.warning(
            "[4ª CHECAGEM RADAR VETERANOS] Radar temporariamente indisponível (não-bloqueante): %s",
            radar_res.get("error") or "erro desconhecido",
        )
        return stats

    stats["radar_ok"] = True
    age_sec = int(radar_res.get("age_sec", -1))
    stats["radar_age_min"] = (age_sec // 60) if age_sec >= 0 else -1
    if radar_res.get("stale"):
        stats["radar_stale"] = True
        logger.info(
            "[4ª CHECAGEM RADAR VETERANOS] Estado do Radar expirado (sync há %d min); aguardando nova atualização.",
            stats["radar_age_min"],
        )
        return stats

    by_pid = {int(pl["profile_id"]): pl for pl in synced_players if int(pl.get("profile_id", 0) or 0) > 0}
    by_sid = {
        str(pl.get("steam_id") or "").strip(): pl
        for pl in synced_players
        if str(pl.get("steam_id") or "").strip()
    }

    curr_radar_pids: set[int] = set()
    for pid in radar_res.get("active_pids") or set():
        if int(pid) in by_pid:
            curr_radar_pids.add(int(pid))
    for sid in radar_res.get("active_steam_ids") or set():
        matched_pl = by_sid.get(str(sid).strip())
        if matched_pl is not None:
            curr_radar_pids.add(int(matched_pl["profile_id"]))

    prev_radar_pids = _load_pid_set_state(db, "last_radar_active_pids_json") & set(by_pid.keys())
    prev_lagging_pids = _load_pid_set_state(db, "radar_lagging_pids_json") & set(by_pid.keys())
    exited_radar_pids = prev_radar_pids - curr_radar_pids
    target_pids = curr_radar_pids | exited_radar_pids | prev_lagging_pids

    stats["flagged_count"] = len(curr_radar_pids)
    stats["exited_count"] = len(exited_radar_pids)

    if not target_pids:
        _save_pid_set_state(db, "last_radar_active_pids_json", curr_radar_pids)
        _save_pid_set_state(db, "radar_lagging_pids_json", set())
        age_lbl = f"sync há {stats['radar_age_min']} min" if stats["radar_age_min"] >= 0 else "sync OK"
        logger.info(
            "[4ª CHECAGEM RADAR VETERANOS] Radar OK (%s) | Nenhum Veterano em atividade CoH3 recente.",
            age_lbl,
        )
        return stats

    now_ts = int(time.time())
    radar_sync_ts = int(radar_res.get("last_sync_ts", 0) or 0)
    ref_ts = min(now_ts, radar_sync_ts) if radar_sync_ts > 0 else now_ts
    recent_cutoff_ts = ref_ts - max(1800, int(radar_recent_window_sec))
    failed_set = set(pass1_failed_pids or set())

    target_players = [by_pid[pid] for pid in sorted(target_pids)]
    stat_lmd_by_pid: dict[int, int] = {}
    if callable(getattr(relic, "fetch_players_latest_stat_timestamps", None)):
        try:
            stat_lmd_by_pid = relic.fetch_players_latest_stat_timestamps(target_players)
        except Exception as exc:
            logger.warning(
                "[4ª CHECAGEM RADAR VETERANOS] Falha ao consultar getPersonalStat: %s",
                redact_secrets(exc),
            )

    latest_info_by_pid: dict[int, dict[str, Any] | None] = {}
    recheck_players: list[dict[str, Any]] = []
    has_stat_ahead = False

    for pl in target_players:
        pid = int(pl["profile_id"])
        latest = db.get_player_latest_match_info(pid)
        latest_info_by_pid[pid] = latest
        db_ct = int(latest["completion_time"]) if latest else 0
        stat_lmd = int(stat_lmd_by_pid.get(pid, 0) or 0)

        stat_ahead = stat_lmd > (db_ct + 10)
        if stat_ahead:
            has_stat_ahead = True

        missing_recent = db_ct < recent_cutoff_ts
        latest_undelivered = False
        if latest and db_ct >= recent_cutoff_ts:
            msg_id = str(latest.get("discord_message_id") or "")
            rec_at = int(latest.get("recorded_at") or 0)
            is_delivered = bool(latest.get("is_delivered_snowflake"))
            is_active_pending = msg_id == PENDING_DISCORD_MARKER and (now_ts - rec_at) < pending_max_age_sec
            is_non_live = msg_id in (SEEDED_DISCORD_MARKER, "PRUNED")
            if not is_delivered and not is_active_pending and not is_non_live:
                latest_undelivered = True

        if stat_ahead or missing_recent or latest_undelivered or (pid in failed_set) or (pid in exited_radar_pids):
            recheck_players.append(pl)

    stats["rechecked_count"] = len(recheck_players)
    if recheck_players:
        if has_stat_ahead:
            time.sleep(1.5)

        candidate_pairs: dict[tuple[int, int], dict[str, Any]] = {}

        # Rechecagem prioritária #1: getRecentMatchHistoryByProfileId
        for pl in recheck_players:
            pid = int(pl["profile_id"])
            try:
                rows = relic.fetch_player_recent_matches(
                    profile_id=pid,
                    fallback_alias=str(pl.get("original_alias") or pl["alias"]),
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                )
                for m in rows:
                    mid = int(m.get("match_id", 0) or 0)
                    comp_ts = int(m.get("completion_time", 0) or 0)
                    if mid > 0 and comp_ts >= recovery_min_completion_ts:
                        candidate_pairs[(mid, pid)] = m
            except Exception as exc:
                logger.warning(
                    "[4ª CHECAGEM RADAR] Falha na rechecagem primária de %s (#%d): %s",
                    pl.get("alias", pid),
                    pid,
                    redact_secrets(exc),
                )

        # Rechecagem prioritária #2: getRecentMatchHistory (por SteamID64)
        if callable(getattr(relic, "fetch_recent_matches_direct_batch", None)):
            try:
                direct_map, _ = relic.fetch_recent_matches_direct_batch(
                    players=recheck_players,
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                    batch_size=1,
                    max_workers=min(4, len(recheck_players)),
                )
                for pid, rows in direct_map.items():
                    for m in rows:
                        mid = int(m.get("match_id", 0) or 0)
                        comp_ts = int(m.get("completion_time", 0) or 0)
                        if mid > 0 and comp_ts >= recovery_min_completion_ts:
                            key = (mid, int(pid))
                            if key in candidate_pairs:
                                candidate_pairs[key] = _merge_match_records(candidate_pairs[key], m)
                            else:
                                candidate_pairs[key] = m
            except Exception as exc:
                logger.warning(
                    "[4ª CHECAGEM RADAR] Falha na rechecagem direta Relic: %s",
                    redact_secrets(exc),
                )

        if candidate_pairs:
            all_mids = sorted({mid for mid, _ in candidate_pairs})
            delivery_map = db.get_match_delivery_map(all_mids)
            existing_new_keys = {(int(m["match_id"]), int(m["tracked_profile_id"])) for m in newly_finished}
            recovered_mids: set[int] = set()
            requeued_mids: set[int] = set()

            ordered = sorted(
                candidate_pairs.items(),
                key=lambda kv: (int(kv[1].get("completion_time", 0)), kv[0][0], kv[0][1]),
            )
            for (mid, pid), match_obj in ordered:
                info = delivery_map.get(mid)
                if info is not None:
                    if info["handled_non_live"]:
                        continue
                    existing_snowflake = info["snowflake"]
                    if existing_snowflake:
                        if pid not in info["rows"]:
                            if db.insert_match(match_obj, discord_message_id=existing_snowflake):
                                stats["synced_siblings"] += 1
                        continue
                    if pid in info["rows"]:
                        cur_msg_id, cur_rec_at = info["rows"][pid]
                        if cur_msg_id == PENDING_DISCORD_MARKER and (now_ts - cur_rec_at) < pending_max_age_sec:
                            continue
                        if (
                            live_marker == PENDING_DISCORD_MARKER
                            and mid not in requeued_mids
                            and db.requeue_undelivered_match(mid)
                        ):
                            requeued_mids.add(mid)
                            recovered_mids.add(mid)
                            stats["requeued_undelivered"] += 1
                            if (mid, pid) not in existing_new_keys:
                                newly_finished.append(match_obj)
                                existing_new_keys.add((mid, pid))
                            logger.info(
                                "[4ª CHECAGEM RADAR - REENFILEIRADA] %s (%s) -> %s em %s (%s) [#%d]",
                                match_obj["tracked_alias"],
                                match_obj["tracked_faction_short"],
                                "VITÓRIA" if match_obj["win"] else "DERROTA",
                                match_obj["map_clean"],
                                match_obj["mode"],
                                mid,
                            )
                        continue
                    has_active_pending = any(
                        msg_id == PENDING_DISCORD_MARKER and (now_ts - rec_at) < pending_max_age_sec
                        for msg_id, rec_at in info["rows"].values()
                    )
                else:
                    has_active_pending = False

                if db.insert_match(match_obj, discord_message_id=live_marker):
                    if (mid, pid) not in existing_new_keys:
                        newly_finished.append(match_obj)
                        existing_new_keys.add((mid, pid))
                    if has_active_pending:
                        stats["synced_siblings"] += 1
                    else:
                        recovered_mids.add(mid)
                        logger.info(
                            "[4ª CHECAGEM RADAR - RECUPERADA] %s (%s) -> %s em %s (%s) [#%d]",
                            match_obj["tracked_alias"],
                            match_obj["tracked_faction_short"],
                            "VITÓRIA" if match_obj["win"] else "DERROTA",
                            match_obj["map_clean"],
                            match_obj["mode"],
                            mid,
                        )

            stats["recovered_unique"] = len(recovered_mids)

    # Reavalia confirmação pós-checagem e identifica eventual atraso de indexação da Relic
    new_lagging_pids: set[int] = set()
    confirmed_count = 0
    for pid in sorted(target_pids):
        latest = db.get_player_latest_match_info(pid)
        db_ct = int(latest["completion_time"]) if latest else 0
        stat_lmd = int(stat_lmd_by_pid.get(pid, 0) or 0)
        if pid in curr_radar_pids and latest and db_ct >= recent_cutoff_ts:
            msg_id = str(latest.get("discord_message_id") or "")
            if bool(latest.get("is_delivered_snowflake")) or msg_id == PENDING_DISCORD_MARKER:
                confirmed_count += 1
        if stat_lmd > (db_ct + 10):
            new_lagging_pids.add(pid)
            lmd_brt = datetime.fromtimestamp(stat_lmd, tz=BRT_TZ).strftime("%d/%m %H:%M:%S BRT")
            logger.warning(
                "[4ª CHECAGEM RADAR] %s (#%d) possui lastmatchdate Relic mais recente (%s) ainda não indexado no histórico; rechecagem automática no próximo ciclo.",
                by_pid[pid].get("alias", pid),
                pid,
                lmd_brt,
            )

    stats["confirmed_count"] = confirmed_count
    stats["lagging_count"] = len(new_lagging_pids)
    _save_pid_set_state(db, "last_radar_active_pids_json", curr_radar_pids)
    _save_pid_set_state(db, "radar_lagging_pids_json", new_lagging_pids)

    flagged_aliases = ", ".join(str(by_pid[p].get("alias", p)) for p in sorted(curr_radar_pids)) or "nenhum"
    exited_part = f" | Saíram: {len(exited_radar_pids)}" if exited_radar_pids else ""
    age_lbl = f"sync há {stats['radar_age_min']} min" if stats["radar_age_min"] >= 0 else "sync OK"
    logger.info(
        "[4ª CHECAGEM RADAR VETERANOS] Radar OK (%s) | Sinalizados: %d (%s)%s | Confirmados no Tracker: %d/%d | Rechecados: %d | Recuperadas p/ Discord: +%d (Reenfileiradas: %d)",
        age_lbl,
        stats["flagged_count"],
        flagged_aliases,
        exited_part,
        stats["confirmed_count"],
        stats["flagged_count"],
        stats["rechecked_count"],
        stats["recovered_unique"],
        stats["requeued_undelivered"],
    )
    return stats


def run_cycle(
    config_path: Path,
    relic: RelicAPIClient,
    force_rank_scan: bool = False,
    is_oneshot: bool = False,
    verify_discord: bool = False,
    reset_discord_channel: bool = False,
    coh3stats: Coh3StatsAPIClient | None = None,
    enable_third_check: bool = True,
    radar: VeteransRadarClient | None = None,
    enable_fourth_check: bool = True,
    force_weekly_summary: bool = False,
) -> tuple[int, int]:
    """Executa um ciclo completo com quádrupla checagem (Relic + Relic Direta × coh3stats.com × Radar Veteranos × Discord), Resumo Semanal e compactação SQLite."""
    cfg = load_config(config_path, ensure_roster=False)
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

        if verify_discord:
            wh_info = discord.verify_webhook()
            logger.info(
                "[DUPLA CHECAGEM] Webhook Discord verificado e ativo: '%s' (canal #%s).",
                wh_info.get("name") or "Webhook",
                wh_info.get("channel_id") or "N/D",
            )

        if reset_discord_channel and discord.is_configured:
            reset_and_clean_discord_channel(db, discord)

        cfg_upgraded = ensure_core_roster_in_config(cfg)
        custom_players = list(cfg.get("custom_players") or [])
        tracked_existing = list(cfg.get("tracked_players") or [])
        existing_by_pid = {int(p["profile_id"]): p for p in tracked_existing if int(p.get("profile_id", 0)) > 0}
        synced_tracked: list[dict[str, Any]] = []
        seen_t_pids: set[int] = set()
        for cp in custom_players:
            pid = int(cp.get("profile_id", 0) or 0)
            if pid <= 0 or pid in seen_t_pids:
                continue
            seen_t_pids.add(pid)
            prev_tp = existing_by_pid.get(pid) or {}
            rec_tp: dict[str, Any] = {
                "profile_id": pid,
                "alias": str(cp.get("alias") or prev_tp.get("alias") or cp.get("original_alias") or f"Player {pid}"),
                "original_alias": str(cp.get("original_alias") or prev_tp.get("original_alias") or cp.get("alias") or f"Player {pid}"),
                "steam_id": str(cp.get("steam_id") or prev_tp.get("steam_id") or ""),
                "placements": list(prev_tp.get("placements") or ["⭐ Monitorado BR"]),
                "is_custom": True,
            }
            if cp.get("merged_into_profile_id"):
                rec_tp["merged_into_profile_id"] = int(cp["merged_into_profile_id"])
            synced_tracked.append(rec_tp)

        tracked_changed = cfg_upgraded or ({int(p["profile_id"]) for p in synced_tracked} != set(existing_by_pid.keys()))
        if tracked_changed:
            cfg["tracked_players"] = synced_tracked
            save_config_file(config_path, cfg)

        if db.get_state("map_names_version") != CURRENT_MAP_NAMES_VERSION:
            migrated_maps = db.refresh_recorded_map_names()
            db.set_state("map_names_version", CURRENT_MAP_NAMES_VERSION)
            if migrated_maps > 0:
                logger.info("Nomes oficiais de mapas atualizados no catálogo SQLite (%d registro(s)).", migrated_maps)

        layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION
        roster_maps = build_roster_lookup_maps(custom_players)

        db.sync_tracked_players(cfg.get("tracked_players", []))
        active_players = db.get_active_players()

        only_automatch = bool(cfg.get("only_automatch", False))
        seed_limit = int(cfg.get("initial_seed_per_player", 3))
        summary_size = int(cfg.get("summary_list_size", 15))
        top_n = int(cfg.get("top_n_per_mode", 20))
        cleanup_hours = max(0, int(cfg.get("discord_cleanup_hours", DEFAULT_DISCORD_CLEANUP_HOURS)))
        window_sec = cleanup_hours * 3600 if cleanup_hours > 0 else 86400
        pending_max_age_sec = max(21600, window_sec)

        if not active_players:
            logger.warning("Nenhum jogador brasileiro selecionado em %s.", config_path.name)
            return 0, 0

        pre_synced_pids = {int(pl["profile_id"]) for pl in active_players if bool(pl.get("baseline_synced"))}
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

        # Dupla checagem Relic API: retenta jogadores que sofreram falha transitória na 1ª passada
        failed_players = [pl for pl, res, err in fetched_results if err is not None or res is None]
        if failed_players:
            logger.warning(
                "[DUPLA CHECAGEM] %d jogador(es) falharam na 1ª consulta à Relic API; retentando em 2s...",
                len(failed_players),
            )
            time.sleep(2.0)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(failed_players))) as retry_pool:
                retried_map = {
                    int(pl["profile_id"]): (pl, res, err)
                    for pl, res, err in retry_pool.map(_fetch_one_player, failed_players)
                }
            fetched_results = [
                retried_map.get(int(pl["profile_id"]), (pl, res, err))
                for pl, res, err in fetched_results
            ]

        fetch_failures_final = 0
        pass1_failed_pids: set[int] = set()
        live_marker = PENDING_DISCORD_MARKER if discord.is_configured else None
        seed_marker = SEEDED_DISCORD_MARKER if discord.is_configured else None

        for player, recent_matches, fetch_err in fetched_results:
            pid = int(player["profile_id"])
            alias = str(player["alias"])
            is_baseline_done = bool(player["baseline_synced"])

            if fetch_err is not None or recent_matches is None:
                fetch_failures_final += 1
                pass1_failed_pids.add(pid)
                logger.error("Erro ao buscar partidas de %s (#%d) após dupla checagem: %s", alias, pid, redact_secrets(fetch_err))
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
                    marker = live_marker if is_very_recent else seed_marker
                    if db.insert_match(m, discord_message_id=marker):
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
                        if db.insert_match(m, discord_message_id=live_marker):
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

        # 3ª Checagem Cruzada: API Direta da Relic (getRecentMatchHistory) × Open Data oficial do coh3stats.com
        third_check_stats: dict[str, int] = {
            "recovered_unique": 0,
            "cross_confirmed": 0,
            "relic_direct_ok_accounts": 0,
            "relic_direct_total_accounts": 0,
            "coh3stats_days_audited": 0,
            "coh3stats_days_pending": 0,
        }
        display_since_raw = db.get_state("display_since_ts") or "0"
        display_since_ts = int(display_since_raw) if display_since_raw.isdigit() else 0
        recovery_min_completion_ts = max(now_ts - window_sec, display_since_ts)
        refreshed_active = db.get_active_players() if pre_synced_pids else []
        synced_for_audit = [pl for pl in refreshed_active if int(pl["profile_id"]) in pre_synced_pids]

        if enable_third_check and synced_for_audit:
            c3s_client = coh3stats if coh3stats is not None else Coh3StatsAPIClient()
            third_check_stats = run_third_cross_check(
                db=db,
                relic=relic,
                coh3stats=c3s_client,
                synced_players=synced_for_audit,
                newly_finished=newly_finished,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
                recovery_min_completion_ts=recovery_min_completion_ts,
                live_marker=live_marker,
                pending_max_age_sec=pending_max_age_sec,
                window_sec=window_sec,
            )

        # 4ª Checagem Cruzada (somente-leitura): Radar de Lobby dos Veteranos × Relic PersonalStat/Histórico
        fourth_check_stats: dict[str, Any] = {
            "radar_ok": False,
            "radar_stale": False,
            "flagged_count": 0,
            "confirmed_count": 0,
            "recovered_unique": 0,
        }
        if enable_fourth_check and synced_for_audit:
            radar_client = radar if radar is not None else VeteransRadarClient()
            fourth_check_stats = run_fourth_radar_check(
                db=db,
                relic=relic,
                radar=radar_client,
                synced_players=synced_for_audit,
                newly_finished=newly_finished,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
                recovery_min_completion_ts=recovery_min_completion_ts,
                live_marker=live_marker,
                pending_max_age_sec=pending_max_age_sec,
                pass1_failed_pids=pass1_failed_pids,
            )

        newly_finished.sort(key=lambda x: x["completion_time"])
        grouped_new_matches = group_matches_by_id(newly_finished)
        cards_confirmed = 0

        if discord.is_configured:
            # Recupera novas partidas + recuperadas na 3ª/4ª checagem + pendentes de falhas transitórias anteriores (sem duplicar)
            pending_records = db.get_pending_matches(max_age_sec=pending_max_age_sec, limit=100)
            grouped_to_send = group_matches_by_id(pending_records)
            new_match_ids = {int(g["match_id"]) for g in grouped_new_matches}
            retried_from_prev = sum(1 for g in grouped_to_send if int(g["match_id"]) not in new_match_ids)
            if retried_from_prev:
                logger.info(
                    "[DUPLA CHECAGEM] %d partida(s) pendente(s) de ciclo anterior recuperada(s) para reenvio.",
                    retried_from_prev,
                )

            retry_groups: list[dict[str, Any]] = []
            for grp in grouped_to_send:
                try:
                    msg_id = discord.send_match_card(grp)
                    if msg_id:
                        db.update_matches_discord_id_batch(grp["records"], msg_id)
                        cards_confirmed += 1
                    else:
                        retry_groups.append(grp)
                    time.sleep(0.4)
                except Exception as exc:
                    logger.warning(
                        "1ª tentativa falhou ao enviar Card da partida #%d ao Discord: %s",
                        grp["match_id"],
                        redact_secrets(exc),
                    )
                    retry_groups.append(grp)

            # 2ª passada de confirmação para cards que falharam na 1ª tentativa
            if retry_groups:
                logger.warning(
                    "[DUPLA CHECAGEM] Retentando %d Card(s) de partida no Discord após 3s...",
                    len(retry_groups),
                )
                time.sleep(3.0)
                for grp in retry_groups:
                    try:
                        msg_id = discord.send_match_card(grp)
                        if msg_id:
                            db.update_matches_discord_id_batch(grp["records"], msg_id)
                            cards_confirmed += 1
                            logger.info("[DUPLA CHECAGEM] Card #%d confirmado na 2ª tentativa (ID %s).", grp["match_id"], msg_id)
                        else:
                            logger.error("Card #%d sem Snowflake na 2ª tentativa; mantido como PENDING.", grp["match_id"])
                        time.sleep(0.5)
                    except Exception as exc:
                        logger.error(
                            "Falha na 2ª tentativa do Card #%d (mantido como PENDING para próximo ciclo): %s",
                            grp["match_id"],
                            redact_secrets(exc),
                        )

        if force_rank_scan:
            logger.info("Aviso: o Ranking Unificado BR foi migrado para o projeto dedicado nigosky/coh3-br-ranking.")

        if discord.is_configured:
            pruned_count = prune_old_discord_messages(db, discord, retention_hours=cleanup_hours)

            if cards_confirmed > 0 or newly_finished or players_changed or tracked_changed:
                db.set_state("summary_needs_refresh", "1")

            summary_msg_id = db.get_state("summary_message_id")
            layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION
            content_needs_refresh = db.get_state("summary_content_version") != CURRENT_SUMMARY_CONTENT_VERSION
            summary_needs_refresh = db.get_state("summary_needs_refresh") == "1"
            panel_status = "inalterado"

            if summary_needs_refresh or not summary_msg_id or layout_needs_upgrade or content_needs_refresh:
                display_since_raw = db.get_state("display_since_ts") or "0"
                display_since_ts = int(display_since_raw) if display_since_raw.isdigit() else 0
                latest_catalog = db.get_recent_recorded_matches(
                    limit=max(40, summary_size * 3),
                    only_active_players=True,
                    min_recorded_at=display_since_ts,
                )
                updated_players = db.get_active_players()
                panel_ok = False

                for attempt in (1, 2):
                    try:
                        new_summary_id = discord.upsert_summary_message(
                            matches=latest_catalog,
                            tracked_players=updated_players,
                            existing_message_id=summary_msg_id,
                            rankings_by_mode=None,
                            custom_players=custom_players,
                            top_n=top_n,
                            recreate_message=layout_needs_upgrade,
                        )
                        if new_summary_id:
                            if new_summary_id != summary_msg_id:
                                db.set_state("summary_message_id", new_summary_id)
                                logger.info("Painel Resumo publicado no Discord (ID %s).", new_summary_id)
                            else:
                                logger.info("Painel Fixado (Últimas Partidas) atualizado automaticamente no Discord.")
                            db.set_state("summary_layout_version", CURRENT_SUMMARY_LAYOUT_VERSION)
                            db.set_state("summary_content_version", CURRENT_SUMMARY_CONTENT_VERSION)
                            db.set_state("rankings_updated_flag", "0")
                            db.set_state("summary_needs_refresh", "0")
                            panel_ok = True
                            panel_status = f"atualizado (ID {new_summary_id})"
                            break
                        logger.warning("Tentativa %d/2 do Painel Fixado retornou sem Snowflake ID.", attempt)
                    except Exception as exc:
                        logger.warning(
                            "Tentativa %d/2 falhou ao atualizar Mensagem Fixada no Discord: %s",
                            attempt,
                            redact_secrets(exc),
                        )
                    if attempt == 1:
                        time.sleep(3.0)

                if not panel_ok:
                    panel_status = "pendente (retentará no próximo ciclo)"
                    logger.error("Falha ao atualizar Mensagem Fixada após dupla checagem; marcada para retentativa.")

            remaining_pending = db.count_pending_matches(max_age_sec=pending_max_age_sec)
            c3s_final_label = (
                "em dia"
                if third_check_stats.get("coh3stats_days_pending", 0) == 0
                else f"{third_check_stats.get('coh3stats_days_audited', 0)}/{third_check_stats.get('coh3stats_days_pending', 0)} dia(s) OK"
            )
            if not fourth_check_stats.get("radar_ok"):
                radar_final_label = "indisponível"
            elif fourth_check_stats.get("radar_stale"):
                radar_final_label = "expirado"
            else:
                radar_final_label = f"{fourth_check_stats.get('confirmed_count', 0)}/{fourth_check_stats.get('flagged_count', 0)} OK"

            logger.info(
                "[QUÁDRUPLA CHECAGEM FINAL] Jogadores OK: %d/%d | 3ª Checagem (Relic Direta %d/%d × coh3stats %s): +%d | 4ª Checagem Radar Veteranos (%s): +%d | Cards confirmados: %d | Pendentes: %d | Limpas (>%dh): %d | Painel Fixado: %s",
                len(active_players) - fetch_failures_final,
                len(active_players),
                third_check_stats.get("relic_direct_ok_accounts", 0),
                third_check_stats.get("relic_direct_total_accounts", 0),
                c3s_final_label,
                third_check_stats.get("recovered_unique", 0),
                radar_final_label,
                fourth_check_stats.get("recovered_unique", 0),
                cards_confirmed,
                remaining_pending,
                cleanup_hours,
                pruned_count,
                panel_status,
            )
            maybe_post_weekly_summary(
                db=db,
                discord=discord,
                custom_players=custom_players,
                force=force_weekly_summary,
                now_ts=now_ts,
            )
        elif grouped_new_matches or players_changed:
            logger.info("Partidas salvas em %s.", db_path.name)

        maybe_run_db_maintenance(db=db, now_ts=now_ts)

    return len(grouped_new_matches), seeded_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor CoH3 Brasil v7.8 -> SQLite + Quádrupla Checagem (Relic × coh3stats × Radar Veteranos) + Resumo Semanal + Discord Privado")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Caminho para config.json")
    parser.add_argument("--once", action="store_true", help="Executa apenas 1 ciclo de checagem e encerra")
    parser.add_argument(
        "--force-rank-scan",
        action="store_true",
        help="Força revarredura imediata do Ranking (Top 20 + monitorados) neste ciclo",
    )
    parser.add_argument(
        "--force-weekly-summary",
        action="store_true",
        help="Publica imediatamente o Card de Resumo Semanal dos Veteranos BR neste ciclo",
    )
    parser.add_argument(
        "--verify-discord",
        action="store_true",
        help="Valida ativamente o Webhook do Discord antes de iniciar o ciclo (dupla checagem de conectividade)",
    )
    parser.add_argument(
        "--reset-discord-channel",
        action="store_true",
        help="Remove todas as mensagens conhecidas do bot no canal Discord e reinicia o painel do zero",
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
    coh3stats = Coh3StatsAPIClient()
    radar = VeteransRadarClient()
    logger.info("Iniciando CoH3 Brasil Monitor v7.8 usando %s...", args.config)

    first_iter = True
    while not stop_requested:
        start_t = time.monotonic()
        try:
            new_cnt, seed_cnt = run_cycle(
                args.config,
                relic,
                force_rank_scan=(args.force_rank_scan and first_iter),
                is_oneshot=bool(args.once),
                verify_discord=(bool(args.verify_discord) and first_iter),
                reset_discord_channel=(bool(args.reset_discord_channel) and first_iter),
                coh3stats=coh3stats,
                radar=radar,
                force_weekly_summary=(bool(args.force_weekly_summary) and first_iter),
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

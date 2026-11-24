#!/usr/bin/env python3
"""Monitor automático CoH3 Brasil v7.9 — Quádrupla Checagem (Relic Direta × coh3stats.com × Radar Veteranos × Discord), Battlegroups (cohdb), Resumo Semanal e Segurança Endurecida."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from database import MatchDatabase, PENDING_DISCORD_MARKER, PRUNED_DISCORD_MARKER, SEEDED_DISCORD_MARKER
from discord_notifier import DiscordWebhookClient, group_matches_by_id
from relic_api import (
    AUTOMATCH_MODES,
    CORE_BR_ROSTER,
    MANUAL_OTHER_BR_DISPLAY,
    Coh3StatsAPIClient,
    CohDBClient,
    RelicAPIClient,
    VeteransRadarClient,
    build_roster_lookup_maps,
    enrich_match_with_roster,
    fetch_custom_players_stats,
    format_bound_display_alias,
    is_battlegroup_eligible_mode,
    refresh_core_br_roster,
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
from smurf_alert import (
    build_smurf_alert_context,
    enrich_group_with_smurf_alerts,
    save_smurf_probe_cache,
)

configure_secure_logging(level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("coh3_br.monitor")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
CURRENT_SUMMARY_LAYOUT_VERSION = "v6_ptbr_arc_alekel_gabemerge"
CURRENT_SUMMARY_CONTENT_VERSION = "v7_17_duration_label"
CURRENT_MAP_NAMES_VERSION = "v1_coh3_patch_3_0_official_maps"
BRT_TZ = timezone(timedelta(hours=-3))
DEFAULT_DISCORD_CLEANUP_HOURS = 72
DEFAULT_QUIET_AUDIT_HOURS = 3
DEFAULT_QUIET_AUDIT_COOLDOWN_HOURS = 3
QUIET_AUDIT_STAT_TOLERANCE_SEC = 60
BG_SUSPICIOUS_EMPTY_MIN_DURATION_SEC = 480  # >=8 min sem BG exige dupla confirmação antes de gravar '{}'
PRE_POST_BG_DOUBLE_CHECK_WAIT_SEC = 25.0  # Aguarda 25s para 2ª checagem obrigatória pré-envio no Discord
NEMESIS_OPEN_DATA_EARLIEST_DATE = "2023-06-30"  # 1º dia público disponível no arquivo Open Data do coh3stats.com


def ensure_core_roster_in_config(
    cfg: dict[str, Any],
    *,
    prune_removed_core: bool = True,
) -> bool:
    """Garante que o elenco brasileiro compartilhado esteja sincronizado (adições, flags e remoções) em custom_players."""
    changed = False
    if "monitor_only_custom_matches" not in cfg:
        cfg["monitor_only_custom_matches"] = True
        changed = True

    if int(cfg.get("leaderboard_refresh_minutes", 30)) >= 20:
        cfg["leaderboard_refresh_minutes"] = 15
        changed = True

    core_pids = {int(c["profile_id"]) for c in CORE_BR_ROSTER if int(c.get("profile_id", 0) or 0) > 0}
    core_sids = {str(c.get("steam_id") or "").strip() for c in CORE_BR_ROSTER if str(c.get("steam_id") or "").strip()}

    existing_custom: list[dict[str, Any]] = list(cfg.get("custom_players", []))
    by_sid: dict[str, dict[str, Any]] = {}
    by_pid: dict[int, dict[str, Any]] = {}
    ordered_list: list[dict[str, Any]] = []

    for item in existing_custom:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("steam_id") or "").replace("/steam/", "").strip()
        pid = int(item.get("profile_id", 0) or 0)
        if (
            prune_removed_core
            and bool(item.get("is_core_roster"))
            and pid not in core_pids
            and (not sid or sid not in core_sids)
        ):
            changed = True
            continue
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
        c_pin = bool(core.get("pin_alias"))
        c_show_smurf = bool(core.get("show_smurf_alias"))
        c_smurf_of = str(core.get("smurf_of") or "").strip()
        c_merged_pid = int(core.get("merged_into_profile_id", 0) or 0)
        c_merged_sid = str(core.get("merged_into_steam_id") or "")
        c_country = str(core.get("country") or "").strip().lower()

        target = by_pid.get(c_pid) or by_sid.get(c_sid)
        if target is None:
            new_entry: dict[str, Any] = {
                "profile_id": c_pid,
                "steam_id": c_sid,
                "original_alias": c_orig,
                "alias": c_orig,
                "is_core_roster": True,
            }
            if c_country and c_country != "br":
                new_entry["country"] = c_country
            if c_pin:
                new_entry["pin_alias"] = True
            if c_show_smurf:
                new_entry["show_smurf_alias"] = True
            if c_smurf_of:
                new_entry["smurf_of"] = c_smurf_of
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
            expected_alias = format_bound_display_alias(
                str(target.get("alias") or c_orig),
                c_orig,
                c_known,
                pin_alias=c_pin,
                show_smurf_alias=c_show_smurf,
                smurf_of=c_smurf_of,
            )
            if target.get("alias") != expected_alias:
                target["alias"] = expected_alias
                changed = True
            if not int(target.get("profile_id", 0) or 0):
                target["profile_id"] = c_pid
                changed = True
            if c_country and c_country != "br":
                if str(target.get("country") or "").strip().lower() != c_country:
                    target["country"] = c_country
                    changed = True
            elif "country" in target and str(target.get("country") or "").strip().lower() != "br":
                target.pop("country", None)
                changed = True
            if c_pin:
                if not target.get("pin_alias"):
                    target["pin_alias"] = True
                    changed = True
            elif "pin_alias" in target:
                target.pop("pin_alias", None)
                changed = True
            if c_show_smurf:
                if not target.get("show_smurf_alias"):
                    target["show_smurf_alias"] = True
                    changed = True
            elif "show_smurf_alias" in target:
                target.pop("show_smurf_alias", None)
                changed = True
            if c_smurf_of:
                if str(target.get("smurf_of") or "").strip() != c_smurf_of:
                    target["smurf_of"] = c_smurf_of
                    changed = True
            elif "smurf_of" in target:
                target.pop("smurf_of", None)
                changed = True
            if c_known:
                if target.get("known_aliases") != c_known:
                    target["known_aliases"] = c_known
                    changed = True
            elif "known_aliases" in target:
                target.pop("known_aliases", None)
                changed = True
            if c_merged_pid:
                if int(target.get("merged_into_profile_id", 0) or 0) != c_merged_pid:
                    target["merged_into_profile_id"] = c_merged_pid
                    changed = True
            elif "merged_into_profile_id" in target:
                target.pop("merged_into_profile_id", None)
                changed = True
            if c_merged_sid:
                if target.get("merged_into_steam_id") != c_merged_sid:
                    target["merged_into_steam_id"] = c_merged_sid
                    changed = True
            elif "merged_into_steam_id" in target:
                target.pop("merged_into_steam_id", None)
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
        r_entry = (pid_map.get(pid) if pid > 0 else None) or steam_map.get(sid) or {}
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
        r_entry = (pid_map.get(pid) if pid > 0 else None) or steam_map.get(sid) or {}
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
                pin_alias=bool(r_entry.get("pin_alias") or cp.get("pin_alias")),
                show_smurf_alias=bool(r_entry.get("show_smurf_alias") or cp.get("show_smurf_alias")),
                smurf_of=str(r_entry.get("smurf_of") or cp.get("smurf_of") or ""),
            )

    return list(by_pid.values())


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
    max_per_cycle: int = 80,
    now_ts: int | None = None,
) -> int:
    """Remove apenas do canal de texto do Discord partidas/cards com mais de retention_hours (padrão 72h), preservando o Painel Fixado e 100% do histórico em SQLite."""
    if retention_hours <= 0 or not discord.is_configured:
        return 0

    summary_msg_id = (db.get_state("summary_message_id") or "").strip()
    excluded = {summary_msg_id} if summary_msg_id else set()
    to_prune = db.get_prunable_discord_messages(
        max_age_sec=int(retention_hours) * 3600,
        exclude_message_ids=excluded,
        limit=max_per_cycle,
        now_ts=now_ts,
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
            "[LIMPEZA %dh] %d mensagem(ns) antiga(s) removida(s) apenas do canal Discord (Painel Fixado e histórico SQLite preservados).",
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


def _reconcile_recovered_matches(
    db: MatchDatabase,
    candidate_pairs: dict[tuple[int, int], tuple[dict[str, Any], str]],
    newly_finished: list[dict[str, Any]],
    live_marker: str | None,
    pending_max_age_sec: int,
    log_prefix: str,
) -> tuple[dict[int, set[str]], int, int, int]:
    """
    Reconcilia partidas recuperadas pela 3ª ou 4ª checagem contra o SQLite sem jamais duplicar
    entregas confirmadas (Snowflake), PRUNED ou SEEDED.
    Retorna `(recovered_match_sources, recovered_rows, requeued_undelivered, synced_siblings)`.
    """
    recovered_match_sources: dict[int, set[str]] = {}
    recovered_rows = 0
    requeued_undelivered = 0
    synced_siblings = 0
    if not candidate_pairs:
        return recovered_match_sources, recovered_rows, requeued_undelivered, synced_siblings

    all_candidate_mids = sorted({mid for mid, _ in candidate_pairs})
    delivery_map = db.get_match_delivery_map(all_candidate_mids)
    now_ts = int(time.time())
    existing_new_keys = {(int(m["match_id"]), int(m["tracked_profile_id"])) for m in newly_finished}
    requeued_mids: set[int] = set()

    ordered_items = sorted(
        candidate_pairs.items(),
        key=lambda kv: (int(kv[1][0].get("completion_time", 0)), kv[0][0], kv[0][1]),
    )

    for (mid, pid), (match_obj, source_tag) in ordered_items:
        src_suffix = f" ({source_tag})" if source_tag else ""
        info = delivery_map.get(mid)
        if info is not None:
            if info["handled_non_live"]:
                continue

            existing_snowflake = info["snowflake"]
            if existing_snowflake:
                if pid not in info["rows"]:
                    if db.insert_match(match_obj, discord_message_id=existing_snowflake):
                        synced_siblings += 1
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
                    requeued_undelivered += 1
                    recovered_rows += 1
                    recovered_match_sources.setdefault(mid, set()).add(source_tag)
                    if (mid, pid) not in existing_new_keys:
                        newly_finished.append(match_obj)
                        existing_new_keys.add((mid, pid))
                    logger.info(
                        "[%s - REENFILEIRADA%s] %s (%s) -> %s em %s (%s) [#%d]",
                        log_prefix,
                        src_suffix,
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
                synced_siblings += 1
            else:
                recovered_rows += 1
                recovered_match_sources.setdefault(mid, set()).add(source_tag)
                logger.info(
                    "[%s - RECUPERADA%s] %s (%s) -> %s em %s (%s) [#%d]",
                    log_prefix,
                    src_suffix,
                    match_obj["tracked_alias"],
                    match_obj["tracked_faction_short"],
                    "VITÓRIA" if match_obj["win"] else "DERROTA",
                    match_obj["map_clean"],
                    match_obj["mode"],
                    mid,
                )

    return recovered_match_sources, recovered_rows, requeued_undelivered, synced_siblings


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
        recovered_match_sources, rec_rows, req_cnt, sib_cnt = _reconcile_recovered_matches(
            db=db,
            candidate_pairs=combined_pairs,
            newly_finished=newly_finished,
            live_marker=live_marker,
            pending_max_age_sec=pending_max_age_sec,
            log_prefix="3ª CHECAGEM",
        )
        stats["recovered_rows"] += rec_rows
        stats["requeued_undelivered"] += req_cnt
        stats["synced_siblings"] += sib_cnt
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
            is_non_live = msg_id in (SEEDED_DISCORD_MARKER, PRUNED_DISCORD_MARKER)
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
            recovered_sources, _, req_cnt, sib_cnt = _reconcile_recovered_matches(
                db=db,
                candidate_pairs={k: (m_obj, "") for k, m_obj in candidate_pairs.items()},
                newly_finished=newly_finished,
                live_marker=live_marker,
                pending_max_age_sec=pending_max_age_sec,
                log_prefix="4ª CHECAGEM RADAR",
            )
            stats["requeued_undelivered"] += req_cnt
            stats["synced_siblings"] += sib_cnt
            stats["recovered_unique"] = len(recovered_sources)

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


def run_quiet_period_deep_audit(
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
    pass1_failed_pids: set[int] | None = None,
    expected_custom_count: int = 0,
    silence_threshold_sec: int = DEFAULT_QUIET_AUDIT_HOURS * 3600,
    cooldown_sec: int = DEFAULT_QUIET_AUDIT_COOLDOWN_HOURS * 3600,
    coh3stats_audited_this_cycle: bool = False,
    force: bool = False,
    now_ts: int | None = None,
) -> dict[str, Any]:
    """
    5ª Checagem Automática — Auditoria de Silêncio (Quiet-Period Deep Sweep):
    Dispara automaticamente sempre que passam `silence_threshold_sec` (padrão 3h) sem nenhuma partida nova
    no banco (respeitando cooldown de 3h), ou quando forçada manualmente:
      1. Cruza `getPersonalStat.lastmatchdate` em 100% do elenco (inclusive Steam privado que o Radar não vê)
         contra o maior `completion_time` salvo no SQLite por jogador.
      2. Reconsulta ambos os endpoints da Relic (`getRecentMatchHistoryByProfileId` + `getRecentMatchHistory`)
         para qualquer conta divergente ou com falha na Passada 1.
      3. Varre o próprio SQLite na janela ativa (72h) atrás de partidas sem entrega confirmada (NULL, vazias
         ou PENDING expiradas) e reenfileira automaticamente para envio ao Discord.
      4. Reaudita 1x/dia o arquivo `coh3stats.com` Open Data de ontem (UTC) caso tenha sido republicado
         depois da 1ª checagem.
      5. Valida paridade do elenco sem gerar spam no Discord quando realmente não houve partidas.
    """
    now = int(now_ts) if now_ts is not None else int(time.time())
    latest_match_ts = db.get_latest_recorded_match_ts(only_active_players=True)
    silence_sec = max(0, now - latest_match_ts) if latest_match_ts > 0 else 0
    last_audit_raw = (db.get_state("last_quiet_audit_ts") or "").strip()
    last_audit_ts = int(last_audit_raw) if last_audit_raw.isdigit() else 0

    stats: dict[str, Any] = {
        "ran": False,
        "silence_hours": round(silence_sec / 3600.0, 1),
        "checked_accounts": len(synced_players),
        "stat_ok_accounts": 0,
        "divergent_accounts": 0,
        "rechecked_accounts": 0,
        "sqlite_requeued": 0,
        "coh3stats_reaudited": False,
        "recovered_unique": 0,
        "recovered_rows": 0,
        "roster_parity_ok": True,
    }

    if not synced_players:
        return stats
    if not force:
        if newly_finished:
            return stats
        if latest_match_ts <= 0 or silence_sec < max(1800, int(silence_threshold_sec)):
            return stats
        if last_audit_ts > 0 and (now - last_audit_ts) < max(1800, int(cooldown_sec)):
            return stats

    stats["ran"] = True
    by_pid = {int(pl["profile_id"]): pl for pl in synced_players if int(pl.get("profile_id", 0) or 0) > 0}
    all_pids = sorted(by_pid.keys())
    failed_set = {int(p) for p in (pass1_failed_pids or set()) if int(p) in by_pid}

    if expected_custom_count > 0 and len(by_pid) < expected_custom_count:
        stats["roster_parity_ok"] = False
        logger.warning(
            "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Divergência de elenco detectada: %d ativa(s) vs %d configurada(s).",
            len(by_pid),
            expected_custom_count,
        )

    # 1. Varredura `getPersonalStat` em 100% do elenco (inclusive Steam privado)
    db_latest_by_pid = db.get_latest_match_ts_by_player(all_pids)
    stat_lmd_by_pid: dict[int, int] = {}
    if callable(getattr(relic, "fetch_players_latest_stat_timestamps", None)):
        try:
            stat_lmd_by_pid = relic.fetch_players_latest_stat_timestamps(synced_players)
        except Exception as exc:
            logger.warning(
                "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Falha ao consultar getPersonalStat completo: %s",
                redact_secrets(exc),
            )
    stats["stat_ok_accounts"] = len(stat_lmd_by_pid)

    recent_stat_window = max(int(window_sec), 72 * 3600)
    divergent_pids: set[int] = set()
    for pid in all_pids:
        stat_lmd = int(stat_lmd_by_pid.get(pid, 0) or 0)
        db_ct = int(db_latest_by_pid.get(pid, 0) or 0)
        if (
            stat_lmd > 0
            and (now - stat_lmd) <= recent_stat_window
            and stat_lmd > (db_ct + QUIET_AUDIT_STAT_TOLERANCE_SEC)
        ):
            divergent_pids.add(pid)

    stats["divergent_accounts"] = len(divergent_pids)
    recheck_pids = sorted(divergent_pids | failed_set)
    stats["rechecked_accounts"] = len(recheck_pids)

    candidate_pairs: dict[tuple[int, int], tuple[dict[str, Any], str]] = {}

    # 2. Rechecagem dupla (ambos endpoints Relic) para contas divergentes ou com falha na Passada 1
    if recheck_pids:
        if divergent_pids:
            time.sleep(1.5)
        recheck_players = [by_pid[pid] for pid in recheck_pids]
        pair_map: dict[tuple[int, int], dict[str, Any]] = {}

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
                        pair_map[(mid, pid)] = m
            except Exception as exc:
                logger.warning(
                    "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Falha na rechecagem ByProfileId de %s (#%d): %s",
                    pl.get("alias", pid),
                    pid,
                    redact_secrets(exc),
                )

        if callable(getattr(relic, "fetch_recent_matches_direct_batch", None)):
            try:
                direct_by_pid, _failed = relic.fetch_recent_matches_direct_batch(
                    players=recheck_players,
                    only_automatch=only_automatch,
                    roster_maps=roster_maps,
                    batch_size=1,
                )
                for pid, rows in direct_by_pid.items():
                    for m in rows:
                        mid = int(m.get("match_id", 0) or 0)
                        comp_ts = int(m.get("completion_time", 0) or 0)
                        if mid > 0 and comp_ts >= recovery_min_completion_ts:
                            key = (mid, int(pid))
                            if key in pair_map:
                                pair_map[key] = _merge_match_records(pair_map[key], m)
                            else:
                                pair_map[key] = m
            except Exception as exc:
                logger.warning(
                    "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Falha na rechecagem direta da Relic: %s",
                    redact_secrets(exc),
                )

        for key, m_obj in pair_map.items():
            candidate_pairs[key] = (m_obj, "Auditoria Silêncio/Relic")

    # 3. Reauditoria diária (1x/dia UTC após 04:00 UTC) do arquivo Open Data de ontem no coh3stats.com
    now_utc = datetime.fromtimestamp(now, tz=timezone.utc)
    yesterday_utc = int(datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc).timestamp()) - 86400
    last_reaudit_day = (db.get_state("quiet_audit_c3s_reaudited_day") or "").strip()
    should_reaudit_c3s = (
        coh3stats is not None
        and callable(getattr(coh3stats, "fetch_open_data_days_matches", None))
        and not coh3stats_audited_this_cycle
        and (yesterday_utc + 86400) > recovery_min_completion_ts
        and now_utc.hour >= 4
        and last_reaudit_day != str(yesterday_utc)
    )
    if should_reaudit_c3s:
        try:
            c3s_by_pid, ok_days, _scanned, _fail_days = coh3stats.fetch_open_data_days_matches(
                day_timestamps=[yesterday_utc],
                players=synced_players,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
                races=getattr(relic, "races", None) or None,
                match_types=getattr(relic, "match_types", None) or None,
            )
            if ok_days:
                stats["coh3stats_reaudited"] = True
                db.set_state("quiet_audit_c3s_reaudited_day", str(yesterday_utc))
                for pid, rows in c3s_by_pid.items():
                    for m in rows:
                        mid = int(m.get("match_id", 0) or 0)
                        comp_ts = int(m.get("completion_time", 0) or 0)
                        if mid > 0 and comp_ts >= recovery_min_completion_ts:
                            key = (mid, int(pid))
                            if key in candidate_pairs:
                                candidate_pairs[key] = (
                                    _merge_match_records(candidate_pairs[key][0], m),
                                    "Auditoria Silêncio/Relic+coh3stats",
                                )
                            else:
                                candidate_pairs[key] = (m, "Auditoria Silêncio/coh3stats")
        except Exception as exc:
            logger.warning(
                "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Reauditoria coh3stats Open Data adiada: %s",
                redact_secrets(exc),
            )

    recovered_mids: set[int] = set()
    if candidate_pairs:
        rec_sources, rec_rows, req_cnt, _sib_cnt = _reconcile_recovered_matches(
            db=db,
            candidate_pairs=candidate_pairs,
            newly_finished=newly_finished,
            live_marker=live_marker,
            pending_max_age_sec=pending_max_age_sec,
            log_prefix="5ª CHECAGEM SILÊNCIO",
        )
        stats["recovered_rows"] += rec_rows
        recovered_mids.update(int(mid) for mid in rec_sources.keys())
        stats["sqlite_requeued"] += req_cnt

    # 4. Varredura interna do SQLite: recupera qualquer partida <72h salva sem entrega confirmada no Discord
    if live_marker == PENDING_DISCORD_MARKER:
        undelivered_mids = db.get_undelivered_recent_match_ids(
            min_completion_time=recovery_min_completion_ts,
            pending_max_age_sec=pending_max_age_sec,
            limit=30,
            now_ts=now,
        )
        for umid in undelivered_mids:
            if umid in recovered_mids:
                continue
            if db.requeue_undelivered_match(umid):
                recovered_mids.add(umid)
                stats["sqlite_requeued"] += 1
                logger.info(
                    "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Partida #%d sem entrega confirmada no SQLite reenfileirada para o Discord.",
                    umid,
                )

    stats["recovered_unique"] = len(recovered_mids)

    db.set_state("last_quiet_audit_ts", str(now))

    div_names = ", ".join(str(by_pid[p].get("alias", p)) for p in sorted(divergent_pids)[:5]) or "nenhuma"
    c3s_tag = "reauditado OK" if stats["coh3stats_reaudited"] else "em dia"
    logger.info(
        "[5ª CHECAGEM — AUDITORIA DE SILÊNCIO] Silêncio há %.1fh | PersonalStat: %d/%d contas | Divergências: %d (%s) | Rechecadas: %d | coh3stats: %s | SQLite reenfileiradas: %d | Recuperadas p/ Discord: +%d",
        stats["silence_hours"],
        stats["stat_ok_accounts"],
        stats["checked_accounts"],
        stats["divergent_accounts"],
        div_names,
        stats["rechecked_accounts"],
        c3s_tag,
        stats["sqlite_requeued"],
        stats["recovered_unique"],
    )
    return stats


def enrich_group_with_battlegroups(
    db: MatchDatabase,
    cohdb: CohDBClient | None,
    grp: dict[str, Any],
    *,
    allow_commit_empty_long: bool = False,
) -> tuple[bool, bool]:
    """
    Consulta `cohdb.com` (somente-leitura) para obter os Battlegroups de uma partida Automatch ou Personalizada (Custom).
    Em partidas >=8 min que retornem 0 Battlegroups (`{}`), retém a gravação até dupla confirmação explícita
    (`allow_commit_empty_long=True`) para impedir falsos vazios permanentes.
    Retorna `(checked_on_cohdb, has_battlegroups)`.
    """
    if cohdb is None or cohdb.is_circuit_open:
        return False, False
    recs = grp.get("records") or [grp.get("primary") or grp]
    primary = recs[0]
    mode_str = str(primary.get("mode") or "")
    if not is_battlegroup_eligible_mode(mode_str):
        return False, False

    if any(bool(r.get("battlegroups_checked")) for r in recs):
        has_bg = any(bool(r.get("battlegroups")) for r in recs)
        return True, has_bg

    match_id = int(grp.get("match_id") or primary.get("match_id") or 0)
    if match_id <= 0:
        return False, False

    tracked_pids = [
        int(r.get("tracked_profile_id", 0) or 0)
        for r in recs
        if int(r.get("tracked_profile_id", 0) or 0) > 0
    ]
    tracked_set = set(tracked_pids)
    fallback_pids: list[int] = []
    opponent_aliases: list[str] = []
    for side_key in ("allies", "opponents"):
        for part in primary.get(side_key) or []:
            if not isinstance(part, dict):
                continue
            ppid = int(part.get("profile_id", 0) or 0)
            if ppid > 0 and ppid not in tracked_set and ppid not in fallback_pids:
                fallback_pids.append(ppid)
            if side_key == "opponents":
                raw_alias = str(part.get("current_alias") or part.get("alias") or "").strip()
                if raw_alias and raw_alias not in opponent_aliases:
                    opponent_aliases.append(raw_alias)
    map_clean = str(primary.get("map_clean") or "")
    duration_sec = max(0, int(primary.get("duration_sec", 0) or 0))
    try:
        try:
            bg_map = cohdb.fetch_match_battlegroups(
                match_id=match_id,
                tracked_profile_ids=tracked_pids,
                expected_map_clean=map_clean,
                fallback_profile_ids=fallback_pids,
                expected_duration_sec=duration_sec,
                expected_opponent_aliases=opponent_aliases,
            )
        except TypeError:
            bg_map = cohdb.fetch_match_battlegroups(
                match_id=match_id,
                tracked_profile_ids=tracked_pids,
                expected_map_clean=map_clean,
                fallback_profile_ids=fallback_pids,
            )
    except Exception as exc:
        logger.warning(
            "[COHDB BATTLEGROUPS] Falha ao consultar partida #%d: %s",
            match_id,
            redact_secrets(exc),
        )
        return False, False

    if bg_map is None:
        return False, False

    if not bg_map and duration_sec >= BG_SUSPICIOUS_EMPTY_MIN_DURATION_SEC and not allow_commit_empty_long:
        grp["_bg_empty_suspect"] = True
        logger.warning(
            "[COHDB BATTLEGROUPS] ALERTA: Partida #%d (%s | %s | %dm%02ds) retornou 0 Battlegroups na 1ª checagem; retendo gravação para dupla checagem obrigatória.",
            match_id,
            mode_str,
            map_clean or "Mapa N/D",
            duration_sec // 60,
            duration_sec % 60,
        )
        return False, False

    db.update_match_battlegroups(match_id, bg_map)
    grp.pop("_bg_empty_suspect", None)
    str_map = {str(k): v for k, v in bg_map.items()}
    for r in recs:
        r["battlegroups"] = str_map
        r["battlegroups_checked"] = True
    if isinstance(grp.get("primary"), dict):
        grp["primary"]["battlegroups"] = str_map
        grp["primary"]["battlegroups_checked"] = True
    if not str_map and duration_sec >= BG_SUSPICIOUS_EMPTY_MIN_DURATION_SEC:
        logger.info(
            "[COHDB BATTLEGROUPS] Dupla checagem confirmada: Partida #%d (%s | %s | %dm%02ds) indexada no cohdb.com sem nenhum Battlegroup selecionado pelos jogadores.",
            match_id,
            mode_str,
            map_clean or "Mapa N/D",
            duration_sec // 60,
            duration_sec % 60,
        )
    return True, bool(str_map)


def pre_post_double_check_battlegroups(
    db: MatchDatabase,
    cohdb: CohDBClient | None,
    grouped_to_send: list[dict[str, Any]],
    *,
    retry_wait_sec: float = PRE_POST_BG_DOUBLE_CHECK_WAIT_SEC,
) -> tuple[dict[int, tuple[bool, bool]], int, set[int]]:
    """
    Executa dupla checagem obrigatória de Battlegroups no `cohdb.com` ANTES de postar cards no Discord:
    - Passada 1: consulta todas as partidas elegíveis (Automatch e Custom) imediatamente.
    - Passada 2 (somente se alguma partida elegível ficou sem BG confirmado ou com 0 BGs suspeito >=8 min):
      aguarda `retry_wait_sec`, limpa o cache de jogadores/replays suspeitos e reconsulta antes do envio.
    Retorna `(status_by_match_id, enriched_with_bg_count, checked_match_ids)`.
    """
    status: dict[int, tuple[bool, bool]] = {}
    enriched_count = 0
    checked_mids: set[int] = set()
    if cohdb is None or cohdb.is_circuit_open or not grouped_to_send:
        return status, enriched_count, checked_mids

    need_second_check: list[dict[str, Any]] = []
    for grp in grouped_to_send:
        mid = int(grp["match_id"])
        prim = grp.get("primary") or (grp.get("records") or [{}])[0]
        mode_str = str(prim.get("mode") or "")
        checked_ok, has_bg = enrich_group_with_battlegroups(
            db,
            cohdb,
            grp,
            allow_commit_empty_long=False,
        )
        status[mid] = (checked_ok, has_bg)
        checked_mids.add(mid)
        if has_bg:
            enriched_count += 1
        elif (
            not checked_ok
            and is_battlegroup_eligible_mode(mode_str)
            and (bool(grp.get("_bg_empty_suspect")) or bool(prim.get("has_replay", True)))
        ):
            need_second_check.append(grp)

    if need_second_check and not cohdb.is_circuit_open:
        wait_s = max(0.0, float(retry_wait_sec))
        logger.info(
            "[COHDB BATTLEGROUPS] Dupla checagem pré-envio: %d partida(s) elegível(is) sem Battlegroup confirmado na 1ª passada; aguardando %.0fs para 2ª verificação antes de postar no Discord...",
            len(need_second_check),
            wait_s,
        )
        if wait_s > 0:
            time.sleep(wait_s)
        if hasattr(cohdb, "invalidate_player_cache"):
            cohdb.invalidate_player_cache()
        suspect_mids = [int(g["match_id"]) for g in need_second_check if bool(g.get("_bg_empty_suspect"))]
        if suspect_mids and hasattr(cohdb, "invalidate_match_cache"):
            cohdb.invalidate_match_cache(suspect_mids)

        for grp in need_second_check:
            if cohdb.is_circuit_open:
                break
            mid = int(grp["match_id"])
            was_suspect = bool(grp.get("_bg_empty_suspect"))
            checked_ok, has_bg = enrich_group_with_battlegroups(
                db,
                cohdb,
                grp,
                allow_commit_empty_long=was_suspect,
            )
            status[mid] = (checked_ok, has_bg)
            if has_bg:
                enriched_count += 1
                logger.info(
                    "[COHDB BATTLEGROUPS] Partida #%d enriquecida na 2ª checagem pré-envio (card será postado já com Battlegroups).",
                    mid,
                )
            elif not checked_ok:
                prim = grp.get("primary") or (grp.get("records") or [{}])[0]
                dur_sec = max(0, int(prim.get("duration_sec", 0) or 0))
                if dur_sec >= BG_SUSPICIOUS_EMPTY_MIN_DURATION_SEC:
                    logger.warning(
                        "[COHDB BATTLEGROUPS] AVISO: Partida #%d (%s | %s | %dm%02ds) segue sem indexação no cohdb.com após dupla checagem pré-envio; postando card e mantendo em fila de PATCH automático.",
                        mid,
                        str(prim.get("mode") or ""),
                        str(prim.get("map_clean") or "Mapa N/D"),
                        dur_sec // 60,
                        dur_sec % 60,
                    )

    return status, enriched_count, checked_mids


def _bg_retry_cooldown_seconds(match_age_sec: int, *, has_replay: bool = True) -> int:
    """Define intervalo de backoff entre rechecagens retroativas no cohdb.com conforme idade da partida (até 72h)."""
    age = max(0, int(match_age_sec))
    if age < 1800:
        return 0
    if not has_replay:
        return 7200
    if age < 43200:
        return 900
    if age < 172800:
        return 1800
    return 3600


def _load_bg_retry_state(db: MatchDatabase, now_ts: int, max_age_sec: int) -> dict[int, int]:
    """Carrega mapa `{match_id: last_probe_ts}` de retentativas cohdb pendentes em `bot_state`."""
    raw = str(db.get_state("bg_retry_state") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    cutoff = int(now_ts) - max(3600, int(max_age_sec))
    cleaned: dict[int, int] = {}
    for k, v in parsed.items():
        try:
            mid = int(k)
            ts = int(v)
        except (TypeError, ValueError):
            continue
        if mid > 0 and ts >= cutoff:
            cleaned[mid] = ts
    return cleaned


def _save_bg_retry_state(db: MatchDatabase, state: dict[int, int], now_ts: int, max_age_sec: int) -> None:
    """Persiste estado enxuto de backoff das rechecagens cohdb em `bot_state`."""
    cutoff = int(now_ts) - max(3600, int(max_age_sec))
    items = sorted(
        ((int(mid), int(ts)) for mid, ts in state.items() if int(mid) > 0 and int(ts) >= cutoff),
        key=lambda kv: kv[1],
        reverse=True,
    )[:200]
    payload = json.dumps({str(mid): ts for mid, ts in items}, separators=(",", ":"))
    db.set_state("bg_retry_state", payload)


def build_tracked_players_from_custom(
    custom_players: list[dict[str, Any]],
    existing_tracked: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Constrói a lista deduplicada `tracked_players` a partir de `custom_players` (compartilhado por monitor.py e manage.py)."""
    existing_by_pid = {
        int(p["profile_id"]): p
        for p in (existing_tracked or [])
        if isinstance(p, dict) and int(p.get("profile_id", 0) or 0) > 0
    }
    synced: list[dict[str, Any]] = []
    seen_pids: set[int] = set()
    for cp in custom_players or []:
        if not isinstance(cp, dict):
            continue
        pid = int(cp.get("profile_id", 0) or 0)
        if pid <= 0 or pid in seen_pids:
            continue
        seen_pids.add(pid)
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
        synced.append(rec_tp)
    return synced


def _patch_match_card_with_battlegroups(
    db: MatchDatabase,
    discord: DiscordWebhookClient,
    grp: dict[str, Any],
    msg_id: str,
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    *,
    log_suffix: str = "com Battlegroups",
) -> bool:
    """Atualiza silenciosamente um Card já postado no Discord com Battlegroups, Nemesis, Criptonita e Alertas Smurf preservados."""
    enrich_group_with_nemesis(db, grp, roster_maps=roster_maps)
    enrich_group_with_kryptonite(db, grp, roster_maps=roster_maps)
    if not grp.get("smurf_alerts"):
        recs = grp.get("records") or []
        prim = grp.get("primary") or (recs[0] if recs else {})
        hydrated = prim.get("smurf_alerts") if isinstance(prim, dict) else None
        if not hydrated:
            for r in recs:
                if isinstance(r, dict) and r.get("smurf_alerts"):
                    hydrated = r["smurf_alerts"]
                    break
        if isinstance(hydrated, list) and hydrated:
            grp["smurf_alerts"] = hydrated
    try:
        patched = discord.edit_match_card(msg_id, grp)
        if patched:
            logger.info(
                "[COHDB BATTLEGROUPS] Card #%d atualizado silenciosamente no Discord (ID %s) %s.",
                grp["match_id"],
                patched,
                log_suffix,
            )
        time.sleep(0.35)
        return bool(patched)
    except Exception as exc:
        logger.warning(
            "[COHDB BATTLEGROUPS] Falha ao atualizar Card #%d no Discord (%s): %s",
            grp["match_id"],
            log_suffix,
            redact_secrets(exc),
        )
        return False


def _build_roster_display_signature(
    custom_players: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Gera assinatura compacta `{profile_id: 'original_alias|smurf_of|country|is_vet'}` para detectar mudanças de roster/smurf."""
    sig: dict[str, str] = {}
    for is_vet, src in (
        (0, MANUAL_OTHER_BR_DISPLAY),
        (1, custom_players or []),
        (1, CORE_BR_ROSTER),
    ):
        for item in src:
            if not isinstance(item, dict):
                continue
            pid = int(item.get("profile_id", 0) or 0)
            if pid <= 0:
                continue
            orig = str(item.get("original_alias") or item.get("alias") or "").strip()
            smurf = str(item.get("smurf_of") or "").strip()
            ctry = str(item.get("country") or "br").strip().lower() or "br"
            sig[str(pid)] = f"{orig}|{smurf}|{ctry}|{is_vet}"
    return sig


def refresh_recent_cards_after_roster_changes(
    db: MatchDatabase,
    discord: DiscordWebhookClient,
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]],
    custom_players: list[dict[str, Any]] | None = None,
    *,
    max_age_sec: int = 259200,
    max_patches: int = 15,
) -> int:
    """
    Atualiza silenciosamente via PATCH os cards recentes (<=72h) já postados no Discord sempre que
    um Veterano ou Smurf é adicionado/renomeado no roster compartilhado (ou na 1ª execução após ativação,
    corrigindo cards pré-existentes com apelidos defasados como `Državljan H` -> `Državljan H (Smurf: arc)`).
    """
    if not discord.is_configured:
        return 0

    current_sig = _build_roster_display_signature(custom_players)
    if not current_sig:
        return 0

    prev_raw = (db.get_state("roster_card_display_sig_v1") or "").strip()
    prev_sig: dict[str, str] = {}
    is_first_baseline = True
    if prev_raw:
        try:
            parsed = json.loads(prev_raw)
            if isinstance(parsed, dict) and parsed:
                prev_sig = {str(k): str(v) for k, v in parsed.items()}
                is_first_baseline = False
        except Exception:
            prev_sig = {}

    changed_pids: set[int] = set()
    if not is_first_baseline:
        for k in set(current_sig.keys()) | set(prev_sig.keys()):
            if k.isdigit() and current_sig.get(k) != prev_sig.get(k):
                changed_pids.add(int(k))
        if not changed_pids:
            return 0

    recent_rows = db.get_recent_posted_matches(max_age_sec=max_age_sec, limit=60)
    if not recent_rows:
        db.set_state(
            "roster_card_display_sig_v1",
            json.dumps(current_sig, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        return 0

    _, pid_map = roster_maps
    patched_count = 0
    all_ok = True
    groups = group_matches_by_id(recent_rows)

    for m_grp in groups:
        if patched_count >= max(1, int(max_patches)):
            all_ok = False
            break
        recs = m_grp.get("records") or []
        if not recs:
            continue

        match_pids: set[int] = set()
        before_aliases: list[tuple[int, str, list[tuple[int, str]], list[tuple[int, str]]]] = []
        hydrated_bgs: dict[str, Any] = {}
        for rec in recs:
            tpid = int(rec.get("tracked_profile_id", 0) or 0)
            if tpid > 0:
                match_pids.add(tpid)
            al_snap = [(int(p.get("profile_id", 0) or 0), str(p.get("alias") or "")) for p in (rec.get("allies") or [])]
            op_snap = [(int(p.get("profile_id", 0) or 0), str(p.get("alias") or "")) for p in (rec.get("opponents") or [])]
            for ppid, _ in al_snap + op_snap:
                if ppid > 0:
                    match_pids.add(ppid)
            before_aliases.append((tpid, str(rec.get("tracked_alias") or ""), al_snap, op_snap))
            if isinstance(rec.get("battlegroups"), dict) and rec["battlegroups"] and not hydrated_bgs:
                hydrated_bgs = dict(rec["battlegroups"])

        if hydrated_bgs:
            for rec in recs:
                if not rec.get("battlegroups"):
                    rec["battlegroups"] = dict(hydrated_bgs)

        # Limpa eventual alerta de "smurf desconhecida" cujo perfil agora já foi promovido para Veteranos
        alerts_cleaned = False
        raw_alerts = m_grp.get("smurf_alerts") or (m_grp.get("primary") or {}).get("smurf_alerts") or []
        if isinstance(raw_alerts, list) and raw_alerts:
            kept_alerts = [
                a
                for a in raw_alerts
                if isinstance(a, dict)
                and not bool((pid_map.get(int(a.get("opponent_profile_id", 0) or 0)) or {}).get("is_veterano"))
            ]
            if len(kept_alerts) != len(raw_alerts):
                alerts_cleaned = True
                m_grp["smurf_alerts"] = kept_alerts
                for rec in recs:
                    rec["smurf_alerts"] = kept_alerts

        alias_changed = alerts_cleaned
        for idx, rec in enumerate(recs):
            enrich_match_with_roster(rec, roster_maps)
            prev_tpid, prev_talias, prev_al, prev_op = before_aliases[idx]
            _ = prev_tpid
            cur_al = [(int(p.get("profile_id", 0) or 0), str(p.get("alias") or "")) for p in (rec.get("allies") or [])]
            cur_op = [(int(p.get("profile_id", 0) or 0), str(p.get("alias") or "")) for p in (rec.get("opponents") or [])]
            if str(rec.get("tracked_alias") or "") != prev_talias or cur_al != prev_al or cur_op != prev_op:
                alias_changed = True

        needs_patch = alias_changed or (not is_first_baseline and bool(match_pids & changed_pids))
        if not needs_patch:
            continue

        existing_msg_id = next(
            (
                str(r.get("discord_message_id") or "").strip()
                for r in recs
                if str(r.get("discord_message_id") or "").strip().isdigit()
                and len(str(r.get("discord_message_id") or "").strip()) >= 15
            ),
            "",
        )
        if not existing_msg_id:
            continue

        if _patch_match_card_with_battlegroups(
            db,
            discord,
            m_grp,
            existing_msg_id,
            roster_maps,
            log_suffix="com atualização de roster/smurf",
        ):
            for rec in recs:
                db.update_match_participants_metadata(
                    int(rec["match_id"]),
                    int(rec["tracked_profile_id"]),
                    str(rec.get("tracked_alias") or ""),
                    list(rec.get("allies") or []),
                    list(rec.get("opponents") or []),
                )
            if alerts_cleaned:
                db.update_match_smurf_alerts(int(m_grp["match_id"]), list(m_grp.get("smurf_alerts") or []))
            patched_count += 1
        else:
            all_ok = False

    if all_ok:
        db.set_state(
            "roster_card_display_sig_v1",
            json.dumps(current_sig, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
    if patched_count > 0:
        logger.info(
            "[ROSTER PATCH] %d card(s) recente(s) atualizado(s) silenciosamente no Discord após mudança de roster/smurf.",
            patched_count,
        )
    return patched_count


def enrich_group_with_nemesis(
    db: MatchDatabase,
    grp: dict[str, Any],
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """
    Calcula em tempo real a condição de Nemesis em TODOS os modos Automatch (1v1, 2v2, 3v3, 4v4):
    trigger >= 2 confrontos Automatch no mesmo dia UTC contra o mesmo oponente Steam; após o trigger,
    contabiliza todas as partidas Automatch contra aquele oponente. Retorna lista ordenada de rivalidades ativas.
    """
    recs = grp.get("records") or [grp.get("primary") or grp]
    primary = recs[0]
    if str(primary.get("mode") or "").strip() not in AUTOMATCH_MODES:
        return []

    match_id = int(grp.get("match_id") or primary.get("match_id") or 0)
    comp_ts = int(primary.get("completion_time", 0) or 0)
    if match_id <= 0 or comp_ts <= 0:
        return []

    _, pid_map = roster_maps if roster_maps is not None else build_roster_lookup_maps()

    def _canonical_pid_group(tpid: int) -> tuple[int, list[int], str]:
        entry = pid_map.get(tpid) or {}
        canon = int(entry.get("merged_into_profile_id") or tpid)
        group = [tpid]
        if canon > 0 and canon not in group:
            group.append(canon)
        for r_pid, r_ent in pid_map.items():
            m_pid = int(r_ent.get("merged_into_profile_id") or r_pid)
            if m_pid == canon and r_pid not in group:
                group.append(r_pid)
        disp = str(entry.get("original_alias") or "").strip()
        return canon, group, disp

    best_by_opponent: dict[int, dict[str, Any]] = {}
    seen_pairs: set[tuple[int, int]] = set()

    for rec in recs:
        tpid = int(rec.get("tracked_profile_id", 0) or 0)
        if tpid <= 0:
            continue
        opponents = rec.get("opponents") or []
        if not isinstance(opponents, list) or not opponents:
            continue
        canon_pid, pid_group, roster_disp = _canonical_pid_group(tpid)
        tracked_disp = roster_disp or str(rec.get("tracked_alias") or f"Jogador {tpid}").strip()

        for opp in opponents:
            if not isinstance(opp, dict):
                continue
            opp_pid = int(opp.get("profile_id", 0) or 0)
            if opp_pid <= 0 or opp_pid in pid_group or (canon_pid, opp_pid) in seen_pairs:
                continue
            seen_pairs.add((canon_pid, opp_pid))

            nem = db.get_nemesis_status(
                tracked_profile_ids=pid_group,
                opponent_profile_id=opp_pid,
                up_to_completion_time=comp_ts,
                up_to_match_id=match_id,
                current_opponent_alias=str(opp.get("alias") or ""),
                current_opponent_steam_id=str(opp.get("steam_id") or ""),
            )
            if not nem:
                continue
            nem["tracked_alias"] = tracked_disp
            prev = best_by_opponent.get(opp_pid)
            if prev is None or (
                int(nem["total"]),
                1 if nem["is_new_trigger"] else 0,
                int(nem["same_day_games"]),
            ) > (
                int(prev["total"]),
                1 if prev["is_new_trigger"] else 0,
                int(prev["same_day_games"]),
            ):
                best_by_opponent[opp_pid] = nem

    if not best_by_opponent:
        return []

    nemesis_list = sorted(
        best_by_opponent.values(),
        key=lambda x: (-int(x["total"]), -(1 if x["is_new_trigger"] else 0), -int(x["same_day_games"])),
    )
    top_nem = nemesis_list[0]
    grp["nemesis"] = top_nem
    grp["nemesis_list"] = nemesis_list
    for r in recs:
        r["nemesis"] = top_nem
        r["nemesis_list"] = nemesis_list
    if isinstance(grp.get("primary"), dict):
        grp["primary"]["nemesis"] = top_nem
        grp["primary"]["nemesis_list"] = nemesis_list
    return nemesis_list


def enrich_group_with_kryptonite(
    db: MatchDatabase,
    grp: dict[str, Any],
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """
    Avalia em tempo real a condição de 'Criptonita' em partidas Automatch PvP (1v1, 2v2, 3v3, 4v4)
    para cada Veterano DERROTADO na partida, seguindo a cascata estrita de prioridade:
      1. Mapa específico;
      2. Battlegroup inimigo específico;
      3. Adversário específico (histórico desde 2023);
      4. Parceiro / aliado específico (último caso).
    """
    recs = grp.get("records") or [grp.get("primary") or grp]
    primary = recs[0]

    # Limpa eventuais valores anteriores (ex.: reavaliação após PATCH de Battlegroups do cohdb)
    grp.pop("kryptonite", None)
    grp.pop("kryptonite_list", None)
    for r in recs:
        if isinstance(r, dict):
            r.pop("kryptonite", None)
            r.pop("kryptonite_list", None)
    if isinstance(grp.get("primary"), dict):
        grp["primary"].pop("kryptonite", None)
        grp["primary"].pop("kryptonite_list", None)

    if str(primary.get("mode") or "").strip() not in AUTOMATCH_MODES:
        return []

    match_id = int(grp.get("match_id") or primary.get("match_id") or 0)
    comp_ts = int(primary.get("completion_time", 0) or 0)
    if match_id <= 0 or comp_ts <= 0:
        return []

    _, pid_map = roster_maps if roster_maps is not None else build_roster_lookup_maps()

    # Consolida o mapa de battlegroups de qualquer registro irmão do grupo
    bgs_map: dict[str, dict[str, Any]] = {}
    for src in (grp.get("primary"), *recs):
        if isinstance(src, dict) and isinstance(src.get("battlegroups"), dict):
            for k, v in src["battlegroups"].items():
                if isinstance(v, dict) and str(k) not in bgs_map:
                    bgs_map[str(k)] = v

    def _canonical_pid_group(tpid: int) -> tuple[int, list[int], str]:
        entry = pid_map.get(tpid) or {}
        canon = int(entry.get("merged_into_profile_id") or tpid)
        group = [tpid]
        if canon > 0 and canon not in group:
            group.append(canon)
        for r_pid, r_ent in pid_map.items():
            m_pid = int(r_ent.get("merged_into_profile_id") or r_pid)
            if m_pid == canon and r_pid not in group:
                group.append(r_pid)
        disp = str(entry.get("original_alias") or "").strip()
        return canon, group, disp

    def _resolve_participant_alias(part: dict[str, Any]) -> str:
        ppid = int(part.get("profile_id", 0) or 0)
        rent = pid_map.get(ppid) if ppid > 0 else None
        if isinstance(rent, dict) and str(rent.get("original_alias") or "").strip():
            return str(rent["original_alias"]).strip()
        return str(part.get("alias") or "").strip() or (f"ID #{ppid}" if ppid > 0 else "Jogador")

    by_veteran: dict[int, dict[str, Any]] = {}
    for rec in recs:
        if not isinstance(rec, dict) or bool(rec.get("win")):
            continue
        tpid = int(rec.get("tracked_profile_id", 0) or 0)
        if tpid <= 0:
            continue
        canon_pid, pid_group, roster_disp = _canonical_pid_group(tpid)
        if canon_pid in by_veteran:
            continue
        tracked_disp = roster_disp or str(rec.get("tracked_alias") or f"Jogador {tpid}").strip()

        raw_opps = rec.get("opponents") if isinstance(rec.get("opponents"), list) else []
        raw_allies = rec.get("allies") if isinstance(rec.get("allies"), list) else []

        enemy_bgs: list[tuple[str, str]] = []
        norm_opps: list[dict[str, Any]] = []
        for o in raw_opps:
            if not isinstance(o, dict):
                continue
            opid = int(o.get("profile_id", 0) or 0)
            norm_opps.append({"profile_id": opid, "alias": _resolve_participant_alias(o)})
            if opid > 0:
                bg_ent = bgs_map.get(str(opid))
                if isinstance(bg_ent, dict):
                    bk = str(bg_ent.get("key") or "").strip()
                    bn = str(bg_ent.get("name") or "").strip()
                    if bk or bn:
                        enemy_bgs.append((bk, bn or bk))

        norm_allies: list[dict[str, Any]] = []
        for a in raw_allies:
            if not isinstance(a, dict):
                continue
            apid = int(a.get("profile_id", 0) or 0)
            if apid > 0 and apid not in pid_group:
                norm_allies.append({"profile_id": apid, "alias": _resolve_participant_alias(a)})

        krypt = db.get_kryptonite_status(
            tracked_profile_ids=pid_group,
            up_to_completion_time=comp_ts,
            up_to_match_id=match_id,
            current_win=False,
            current_map_clean=str(rec.get("map_clean") or primary.get("map_clean") or ""),
            current_map_raw=str(rec.get("map_raw") or primary.get("map_raw") or ""),
            current_enemy_battlegroups=enemy_bgs,
            current_opponents=norm_opps,
            current_allies=norm_allies,
        )
        if not krypt:
            continue
        krypt["tracked_profile_id"] = tpid
        krypt["tracked_alias"] = tracked_disp
        by_veteran[canon_pid] = krypt

    if not by_veteran:
        return []

    kryptonite_list = sorted(
        by_veteran.values(),
        key=lambda x: (
            int(x.get("priority", 99)),
            -(int(x.get("losses", 0)) - int(x.get("wins", 0))),
            -int(x.get("losses", 0)),
            float(x.get("win_rate", 100.0)),
        ),
    )
    top_k = kryptonite_list[0]
    grp["kryptonite"] = top_k
    grp["kryptonite_list"] = kryptonite_list
    for r in recs:
        if isinstance(r, dict):
            r["kryptonite"] = top_k
            r["kryptonite_list"] = kryptonite_list
    if isinstance(grp.get("primary"), dict):
        grp["primary"]["kryptonite"] = top_k
        grp["primary"]["kryptonite_list"] = kryptonite_list
    return kryptonite_list


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
    enable_quiet_audit: bool = True,
    force_quiet_audit: bool = False,
    cohdb: CohDBClient | None = None,
    enable_battlegroups: bool = True,
    enable_smurf_alerts: bool = True,
    force_weekly_summary: bool = False,
    pre_post_bg_retry_wait_sec: float = PRE_POST_BG_DOUBLE_CHECK_WAIT_SEC,
    post_send_bg_retry_waits: tuple[float, ...] = (35.0, 40.0),
) -> tuple[int, int]:
    """Executa um ciclo completo com quíntupla checagem (Relic + Relic Direta × coh3stats.com × Radar Veteranos × Auditoria de Silêncio × Discord), Battlegroups (cohdb), Resumo Semanal e compactação SQLite."""
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

        refresh_core_br_roster()
        cfg_upgraded = ensure_core_roster_in_config(cfg)
        custom_players = list(cfg.get("custom_players") or [])
        tracked_existing = list(cfg.get("tracked_players") or [])
        existing_pids = {
            int(p["profile_id"])
            for p in tracked_existing
            if isinstance(p, dict) and int(p.get("profile_id", 0) or 0) > 0
        }
        synced_tracked = build_tracked_players_from_custom(custom_players, tracked_existing)

        tracked_changed = cfg_upgraded or ({int(p["profile_id"]) for p in synced_tracked} != existing_pids)
        if tracked_changed:
            cfg["tracked_players"] = synced_tracked
            save_config_file(config_path, cfg)

        if db.get_state("map_names_version") != CURRENT_MAP_NAMES_VERSION:
            migrated_maps = db.refresh_recorded_map_names()
            db.set_state("map_names_version", CURRENT_MAP_NAMES_VERSION)
            if migrated_maps > 0:
                logger.info("Nomes oficiais de mapas atualizados no catálogo SQLite (%d registro(s)).", migrated_maps)

        roster_maps = build_roster_lookup_maps(custom_players)
        _, roster_pid_map = roster_maps

        db.sync_tracked_players(cfg.get("tracked_players", []))
        active_players = db.get_active_players()

        only_automatch = bool(cfg.get("only_automatch", False))
        seed_limit = int(cfg.get("initial_seed_per_player", 3))
        summary_size = int(cfg.get("summary_list_size", 15))
        raw_cleanup_hours = cfg.get("discord_cleanup_hours", DEFAULT_DISCORD_CLEANUP_HOURS)
        cleanup_hours = max(0, int(DEFAULT_DISCORD_CLEANUP_HOURS if raw_cleanup_hours is None else raw_cleanup_hours))
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
            r_entry = roster_pid_map.get(pid) or {}
            own_roster_sid = str(r_entry.get("steam_id") or "").strip()
            existing_player_sid = str(player.get("steam_id") or "").strip()
            is_merged_avatar = bool(r_entry.get("merged_into_steam_id"))
            # Nunca sobrescrever o SteamID64 real da conta secundária/smurf com merged_into_steam_id (usado só no avatar)
            resolved_steam_id = (
                own_roster_sid
                or existing_player_sid
                or ("" if is_merged_avatar else str(recent_matches[0].get("tracked_steam_id") or "") if recent_matches else "")
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
                        m_ct = int(m.get("completion_time", 0) or 0)
                        is_expired_for_discord = bool(
                            cleanup_hours > 0 and m_ct > 0 and (now_ts - m_ct) > window_sec
                        )
                        target_marker = PRUNED_DISCORD_MARKER if is_expired_for_discord else live_marker
                        if db.insert_match(m, discord_message_id=target_marker):
                            if is_expired_for_discord:
                                logger.info(
                                    "[HISTÓRICO >%dh] %s (%s) -> %s em %s (%s) [#%d] registrada apenas no SQLite (fora da janela do Discord).",
                                    cleanup_hours,
                                    m["tracked_alias"],
                                    m["tracked_faction_short"],
                                    "VITÓRIA" if m["win"] else "DERROTA",
                                    m["map_clean"],
                                    m["mode"],
                                    m["match_id"],
                                )
                            else:
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
                if resolved_alias != alias or (resolved_steam_id and not existing_player_sid):
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

        # 5ª Checagem Automática — Auditoria de Silêncio (quando passam >=3h sem partidas)
        quiet_audit_stats: dict[str, Any] = {
            "ran": False,
            "silence_hours": 0.0,
            "divergent_accounts": 0,
            "recovered_unique": 0,
            "sqlite_requeued": 0,
        }
        if enable_quiet_audit and synced_for_audit:
            raw_qa_hours = cfg.get("quiet_audit_hours", DEFAULT_QUIET_AUDIT_HOURS)
            qa_hours = max(1, int(DEFAULT_QUIET_AUDIT_HOURS if raw_qa_hours is None else raw_qa_hours))
            raw_qa_cd = cfg.get("quiet_audit_cooldown_hours", DEFAULT_QUIET_AUDIT_COOLDOWN_HOURS)
            qa_cd_hours = max(1, int(DEFAULT_QUIET_AUDIT_COOLDOWN_HOURS if raw_qa_cd is None else raw_qa_cd))
            qa_c3s_client = coh3stats if coh3stats is not None else (Coh3StatsAPIClient() if enable_third_check else None)
            quiet_audit_stats = run_quiet_period_deep_audit(
                db=db,
                relic=relic,
                coh3stats=qa_c3s_client,
                synced_players=synced_for_audit,
                newly_finished=newly_finished,
                only_automatch=only_automatch,
                roster_maps=roster_maps,
                recovery_min_completion_ts=recovery_min_completion_ts,
                live_marker=live_marker,
                pending_max_age_sec=pending_max_age_sec,
                window_sec=window_sec,
                pass1_failed_pids=pass1_failed_pids,
                expected_custom_count=len(synced_tracked),
                silence_threshold_sec=qa_hours * 3600,
                cooldown_sec=qa_cd_hours * 3600,
                coh3stats_audited_this_cycle=bool(third_check_stats.get("coh3stats_days_audited", 0) > 0),
                force=force_quiet_audit,
                now_ts=now_ts,
            )

        newly_finished.sort(key=lambda x: x["completion_time"])
        grouped_new_matches = group_matches_by_id(newly_finished)
        cards_confirmed = 0
        bg_enriched_new = 0
        bg_patched_cards = 0
        smurf_alerts_triggered = 0
        cohdb_client = (cohdb if cohdb is not None else CohDBClient()) if enable_battlegroups else None
        smurf_alerts_active = bool(enable_smurf_alerts and cfg.get("enable_smurf_alerts", True))

        if discord.is_configured:
            # Recupera novas partidas + recuperadas na 3ª/4ª checagem + pendentes de falhas transitórias anteriores (sem duplicar)
            pending_records = db.get_pending_matches(max_age_sec=pending_max_age_sec, limit=100)
            all_pending_groups = group_matches_by_id(pending_records)
            grouped_to_send: list[dict[str, Any]] = []
            expired_pending_count = 0
            for grp in all_pending_groups:
                grp_ct = int(grp["primary"].get("completion_time", 0) or 0)
                if cleanup_hours > 0 and grp_ct > 0 and (now_ts - grp_ct) > window_sec:
                    db.update_matches_discord_id_batch(grp["records"], PRUNED_DISCORD_MARKER)
                    expired_pending_count += 1
                    continue
                grouped_to_send.append(grp)
            if expired_pending_count:
                logger.info(
                    "[LIMPEZA %dh] %d partida(s) pendente(s) com mais de %dh arquivada(s) apenas no SQLite (sem postar no Discord).",
                    cleanup_hours,
                    expired_pending_count,
                    cleanup_hours,
                )
            new_match_ids = {int(g["match_id"]) for g in grouped_new_matches}
            retried_from_prev = sum(1 for g in grouped_to_send if int(g["match_id"]) not in new_match_ids)
            if retried_from_prev:
                logger.info(
                    "[DUPLA CHECAGEM] %d partida(s) pendente(s) de ciclo anterior recuperada(s) para reenvio.",
                    retried_from_prev,
                )

            retry_groups: list[dict[str, Any]] = []
            posted_missing_bg: list[tuple[dict[str, Any], str]] = []
            bg_pre_status, bg_enriched_new, checked_in_this_cycle_mids = pre_post_double_check_battlegroups(
                db=db,
                cohdb=cohdb_client,
                grouped_to_send=grouped_to_send,
                retry_wait_sec=pre_post_bg_retry_wait_sec,
            )
            smurf_ctx = None
            if smurf_alerts_active and grouped_to_send:
                try:
                    smurf_ctx = build_smurf_alert_context(
                        db=db,
                        relic=relic,
                        custom_players=custom_players,
                        now_ts=now_ts,
                    )
                except Exception as exc:
                    logger.warning("[ALERTA SMURF] Contexto forense indisponível neste ciclo: %s", redact_secrets(exc))
                    smurf_ctx = None

            for grp in grouped_to_send:
                mid = int(grp["match_id"])
                checked_ok, _has_bg = bg_pre_status.get(mid, (False, False))
                nem_list = enrich_group_with_nemesis(db, grp, roster_maps=roster_maps)
                if nem_list:
                    top_nem = nem_list[0]
                    extra_nem = f" (+{len(nem_list) - 1} rival(is))" if len(nem_list) > 1 else ""
                    logger.info(
                        "[NEMESIS] %s vs %s -> %dV-%dD (%s)%s [#%d]",
                        top_nem.get("tracked_alias"),
                        top_nem.get("opponent_alias"),
                        int(top_nem.get("wins", 0)),
                        int(top_nem.get("losses", 0)),
                        "NOVO TRIGGER" if top_nem.get("is_new_trigger") else "ATIVO",
                        extra_nem,
                        grp["match_id"],
                    )
                if smurf_ctx is not None:
                    try:
                        smurf_list = enrich_group_with_smurf_alerts(db, relic, grp, ctx=smurf_ctx)
                        for s_al in smurf_list:
                            smurf_alerts_triggered += 1
                            target_lbl = (
                                f"smurf de {s_al.get('suspected_main_alias')}"
                                if s_al.get("suspected_main_alias")
                                else "smurf BR não identificado"
                            )
                            logger.warning(
                                "[ALERTA SMURF] Veterano %s enfrentou %s -> possível %s (%d%% • %s) | %s [#%d]",
                                s_al.get("tracked_alias"),
                                s_al.get("opponent_alias"),
                                target_lbl,
                                int(s_al.get("probability_pct", 0) or 0),
                                s_al.get("confidence_tier"),
                                ", ".join(s_al.get("top_reasons") or []),
                                grp["match_id"],
                            )
                    except Exception as exc:
                        logger.warning(
                            "[ALERTA SMURF] Falha ao avaliar oponentes da partida #%d: %s",
                            grp["match_id"],
                            redact_secrets(exc),
                        )
                is_bg_eligible = is_battlegroup_eligible_mode(str(grp["primary"].get("mode") or ""))
                try:
                    msg_id = discord.send_match_card(grp)
                    if msg_id:
                        db.update_matches_discord_id_batch(grp["records"], msg_id)
                        cards_confirmed += 1
                        if cohdb_client is not None and is_bg_eligible and not checked_ok:
                            posted_missing_bg.append((grp, msg_id))
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

            if smurf_ctx is not None:
                try:
                    save_smurf_probe_cache(db, smurf_ctx)
                except Exception as exc:
                    logger.debug("[ALERTA SMURF] Falha ao salvar cache de probes: %s", redact_secrets(exc))

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
                            is_bg_eligible = is_battlegroup_eligible_mode(str(grp["primary"].get("mode") or ""))
                            if (
                                cohdb_client is not None
                                and is_bg_eligible
                                and not bool(grp["primary"].get("battlegroups_checked"))
                            ):
                                posted_missing_bg.append((grp, msg_id))
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

            # Retentativa rápida pós-envio: cobre Automatch (até 2 rodadas) e Custom (1ª rodada rápida; 2ª+ via Scheduler e PATCH 72h)
            recently_retried_mids: set[int] = set()
            if cohdb_client is not None and posted_missing_bg and not cohdb_client.is_circuit_open:
                remaining_missing = list(posted_missing_bg)
                total_post_attempts = len(post_send_bg_retry_waits)
                for attempt_idx, wait_sec in enumerate(post_send_bg_retry_waits, start=1):
                    if attempt_idx >= 2:
                        remaining_missing = [
                            (p_grp, p_msg_id)
                            for p_grp, p_msg_id in remaining_missing
                            if str(p_grp["primary"].get("mode") or "") in AUTOMATCH_MODES
                            or bool(p_grp.get("_bg_empty_suspect"))
                        ]
                    if not remaining_missing or cohdb_client.is_circuit_open:
                        break
                    logger.info(
                        "[COHDB BATTLEGROUPS] Aguardando %.0fs (retentativa pós-envio %d/%d) para indexação do replay de %d partida(s) recém-postada(s)...",
                        float(wait_sec),
                        attempt_idx,
                        total_post_attempts,
                        len(remaining_missing),
                    )
                    if float(wait_sec) > 0:
                        time.sleep(float(wait_sec))
                    cohdb_client.invalidate_player_cache()
                    suspect_post_mids = [
                        int(p_grp["match_id"])
                        for p_grp, _ in remaining_missing
                        if bool(p_grp.get("_bg_empty_suspect"))
                    ]
                    if suspect_post_mids and hasattr(cohdb_client, "invalidate_match_cache"):
                        cohdb_client.invalidate_match_cache(suspect_post_mids)
                    still_missing: list[tuple[dict[str, Any], str]] = []
                    for p_grp, p_msg_id in remaining_missing:
                        if cohdb_client.is_circuit_open:
                            still_missing.append((p_grp, p_msg_id))
                            continue
                        recently_retried_mids.add(int(p_grp["match_id"]))
                        was_suspect = bool(p_grp.get("_bg_empty_suspect"))
                        checked_ok, has_bg = enrich_group_with_battlegroups(
                            db,
                            cohdb_client,
                            p_grp,
                            allow_commit_empty_long=was_suspect,
                        )
                        if checked_ok:
                            if has_bg and _patch_match_card_with_battlegroups(
                                db,
                                discord,
                                p_grp,
                                p_msg_id,
                                roster_maps,
                                log_suffix=f"na retentativa pós-envio {attempt_idx}/{total_post_attempts}",
                            ):
                                bg_patched_cards += 1
                        else:
                            still_missing.append((p_grp, p_msg_id))
                    remaining_missing = still_missing

            # Enriquecimento retroativo silencioso (PATCH): cobre Automatch e Personalizadas (Custom) até 72h com backoff inteligente
            retro_bg_max_age_sec = max(14400, int(cleanup_hours) * 3600) if cleanup_hours > 0 else 259200
            if cohdb_client is not None and not cohdb_client.is_circuit_open:
                bg_retry_state = _load_bg_retry_state(db, now_ts, retro_bg_max_age_sec)
                bg_retry_dirty = False
                skip_mids = recently_retried_mids | checked_in_this_cycle_mids
                missing_bg_rows = db.get_recent_matches_missing_battlegroups(
                    max_age_sec=retro_bg_max_age_sec,
                    limit=30,
                    exclude_match_ids=skip_mids,
                )
                retro_probed = 0
                for m_grp in group_matches_by_id(missing_bg_rows):
                    if cohdb_client.is_circuit_open or retro_probed >= 16:
                        break
                    mid = int(m_grp["match_id"])
                    if mid in skip_mids:
                        continue
                    m_prim = m_grp.get("primary") or (m_grp.get("records") or [{}])[0]
                    comp_ts = int(m_prim.get("completion_time", 0) or 0)
                    match_age = max(0, now_ts - comp_ts) if comp_ts > 0 else 0
                    cooldown_sec = _bg_retry_cooldown_seconds(
                        match_age,
                        has_replay=bool(m_prim.get("has_replay", True)),
                    )
                    last_probe_ts = int(bg_retry_state.get(mid, 0) or 0)
                    if cooldown_sec > 0 and last_probe_ts > 0 and (now_ts - last_probe_ts) < cooldown_sec:
                        continue

                    retro_probed += 1
                    checked_ok, has_bg = enrich_group_with_battlegroups(
                        db,
                        cohdb_client,
                        m_grp,
                        allow_commit_empty_long=False,
                    )
                    if not checked_ok and bool(m_grp.get("_bg_empty_suspect")) and not cohdb_client.is_circuit_open:
                        cohdb_client.invalidate_player_cache()
                        if hasattr(cohdb_client, "invalidate_match_cache"):
                            cohdb_client.invalidate_match_cache([mid])
                        time.sleep(2.0)
                        checked_ok, has_bg = enrich_group_with_battlegroups(
                            db,
                            cohdb_client,
                            m_grp,
                            allow_commit_empty_long=True,
                        )
                    if checked_ok:
                        if mid in bg_retry_state:
                            bg_retry_state.pop(mid, None)
                            bg_retry_dirty = True
                        if has_bg:
                            existing_msg_id = next(
                                (
                                    str(r.get("discord_message_id") or "").strip()
                                    for r in (m_grp.get("records") or [m_grp.get("primary") or {}])
                                    if str(r.get("discord_message_id") or "").strip().isdigit()
                                ),
                                "",
                            )
                            if existing_msg_id and _patch_match_card_with_battlegroups(
                                db,
                                discord,
                                m_grp,
                                existing_msg_id,
                                roster_maps,
                                log_suffix="com Battlegroups",
                            ):
                                bg_patched_cards += 1
                    else:
                        bg_retry_state[mid] = now_ts
                        bg_retry_dirty = True

                if bg_retry_dirty:
                    _save_bg_retry_state(db, bg_retry_state, now_ts, retro_bg_max_age_sec)

                if bg_enriched_new > 0 or bg_patched_cards > 0:
                    logger.info(
                        "[COHDB BATTLEGROUPS] Novos cards com BG: %d | Cards recentes atualizados (PATCH): %d",
                        bg_enriched_new,
                        bg_patched_cards,
                    )

        if force_rank_scan:
            logger.info("Aviso: o Ranking Unificado BR foi migrado para o projeto dedicado nigosky/coh3-br-ranking.")

        if discord.is_configured:
            pruned_count = prune_old_discord_messages(
                db,
                discord,
                retention_hours=cleanup_hours,
                now_ts=now_ts,
            )
            roster_patch_window_sec = max(14400, int(cleanup_hours) * 3600) if cleanup_hours > 0 else 259200
            roster_patched_cards = refresh_recent_cards_after_roster_changes(
                db=db,
                discord=discord,
                roster_maps=roster_maps,
                custom_players=custom_players,
                max_age_sec=roster_patch_window_sec,
                max_patches=15,
            )
            min_panel_ts = max(display_since_ts, now_ts - window_sec) if cleanup_hours > 0 else display_since_ts

            if (
                cards_confirmed > 0
                or bg_patched_cards > 0
                or roster_patched_cards > 0
                or newly_finished
                or players_changed
                or tracked_changed
            ):
                db.set_state("summary_needs_refresh", "1")
            elif pruned_count > 0 and cleanup_hours > 0:
                active_window_rows = db.get_recent_recorded_matches(
                    limit=20,
                    only_active_players=True,
                    min_recorded_at=display_since_ts,
                    min_completion_time=min_panel_ts,
                )
                if len(group_matches_by_id(active_window_rows)) < 5:
                    db.set_state("summary_needs_refresh", "1")

            summary_msg_id = db.get_state("summary_message_id")
            layout_needs_upgrade = db.get_state("summary_layout_version") != CURRENT_SUMMARY_LAYOUT_VERSION
            content_needs_refresh = db.get_state("summary_content_version") != CURRENT_SUMMARY_CONTENT_VERSION
            summary_needs_refresh = db.get_state("summary_needs_refresh") == "1"
            panel_status = "inalterado"

            if summary_needs_refresh or not summary_msg_id or layout_needs_upgrade or content_needs_refresh:
                latest_catalog = db.get_recent_recorded_matches(
                    limit=max(40, summary_size * 3),
                    only_active_players=True,
                    min_recorded_at=display_since_ts,
                    min_completion_time=min_panel_ts,
                )
                updated_players = db.get_active_players()
                panel_ok = False

                for attempt in (1, 2):
                    try:
                        new_summary_id = discord.upsert_summary_message(
                            matches=latest_catalog,
                            tracked_players=updated_players,
                            existing_message_id=summary_msg_id,
                            custom_players=custom_players,
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
            still_missing_bg_groups = (
                group_matches_by_id(
                    db.get_recent_matches_missing_battlegroups(max_age_sec=retro_bg_max_age_sec, limit=30)
                )
                if cohdb_client is not None
                else []
            )
            bg_awaiting_total = len(still_missing_bg_groups)
            bg_awaiting_automatch_long = [
                g
                for g in still_missing_bg_groups
                if str(g["primary"].get("mode") or "") in AUTOMATCH_MODES
                and int(g["primary"].get("duration_sec", 0) or 0) >= BG_SUSPICIOUS_EMPTY_MIN_DURATION_SEC
            ]
            if bg_awaiting_automatch_long:
                sample_mids = ", ".join(f"#{g['match_id']}" for g in bg_awaiting_automatch_long[:5])
                logger.warning(
                    "[COHDB BATTLEGROUPS] ATENÇÃO: %d partida(s) Automatch >=8min ainda aguardando indexação de Battlegroups (%s).",
                    len(bg_awaiting_automatch_long),
                    sample_mids,
                )
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

            quiet_final_label = (
                f"OK ({quiet_audit_stats.get('silence_hours', 0.0):.1f}h): +{quiet_audit_stats.get('recovered_unique', 0)}"
                if quiet_audit_stats.get("ran")
                else "inativa"
            )
            logger.info(
                "[QUÍNTUPLA CHECAGEM FINAL] Jogadores OK: %d/%d | 3ª Checagem (Relic Direta %d/%d × coh3stats %s): +%d | 4ª Checagem Radar Veteranos (%s): +%d | 5ª Checagem Silêncio (%s) | Battlegroups (cohdb): +%d novo(s)/%d patch (%d aguardando) | Alertas Smurf: %d | Cards confirmados: %d | Pendentes: %d | Limpas (>%dh): %d | Painel Fixado: %s",
                len(active_players) - fetch_failures_final,
                len(active_players),
                third_check_stats.get("relic_direct_ok_accounts", 0),
                third_check_stats.get("relic_direct_total_accounts", 0),
                c3s_final_label,
                third_check_stats.get("recovered_unique", 0),
                radar_final_label,
                fourth_check_stats.get("recovered_unique", 0),
                quiet_final_label,
                bg_enriched_new,
                bg_patched_cards,
                bg_awaiting_total,
                smurf_alerts_triggered,
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


def _parse_utc_date_to_midnight_ts(date_str: str) -> int:
    """Converte data `YYYY-MM-DD` em timestamp Unix da meia-noite UTC."""
    clean = str(date_str or "").strip()
    dt = datetime.strptime(clean, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def backfill_nemesis_history_from_open_data(
    db: MatchDatabase,
    tracked_players: list[dict[str, Any]],
    *,
    coh3stats: Coh3StatsAPIClient | None = None,
    start_date: str = NEMESIS_OPEN_DATA_EARLIEST_DATE,
    end_date: str | None = None,
    max_workers: int = 4,
    chunk_days: int = 30,
    roster_maps: tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]] | None = None,
    progress_callback: Any = None,
) -> dict[str, Any]:
    """
    Reconstroi o histórico completo de confrontos Automatch Steam na tabela `nemesis_matches`
    usando streaming de baixa memória (<4 MB/worker) sobre o arquivo oficial COH3 Stats Open Data
    (`https://storage.coh3stats.com/matches/matches-<day_ts>.json`, disponível a partir de 2023-06-30).
    Idempotente via `INSERT OR IGNORE`: preserva todos os registros antigos já existentes no SQLite.
    """
    earliest_ts = _parse_utc_date_to_midnight_ts(NEMESIS_OPEN_DATA_EARLIEST_DATE)
    req_start_ts = max(earliest_ts, _parse_utc_date_to_midnight_ts(start_date))
    now_utc = datetime.now(tz=timezone.utc)
    default_end_ts = int(datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc).timestamp()) - 86400
    req_end_ts = _parse_utc_date_to_midnight_ts(end_date) if end_date else default_end_ts

    effective_start_str = datetime.fromtimestamp(req_start_ts, tz=timezone.utc).strftime("%Y-%m-%d")
    effective_end_str = datetime.fromtimestamp(req_end_ts, tz=timezone.utc).strftime("%Y-%m-%d")

    if not tracked_players or req_start_ts > req_end_ts:
        return {
            "start_date": effective_start_str,
            "end_date": effective_end_str,
            "days_requested": 0,
            "days_ok": 0,
            "days_not_published": 0,
            "days_failed": 0,
            "matches_scanned": 0,
            "nemesis_rows_extracted": 0,
            "nemesis_rows_inserted": 0,
            "coverage_after": db.get_nemesis_coverage_summary(),
        }

    client = coh3stats if coh3stats is not None else Coh3StatsAPIClient(min_interval_sec=0.05)
    active_roster_maps = roster_maps or build_roster_lookup_maps()
    day_timestamps = list(range(req_start_ts, req_end_ts + 1, 86400))
    workers = max(1, min(int(max_workers), 6))
    step = max(1, min(int(chunk_days), 90))

    days_ok = 0
    days_not_published = 0
    days_failed = 0
    matches_scanned = 0
    rows_extracted = 0
    rows_inserted = 0

    def _fetch_one_day(day_ts: int) -> tuple[int, str, int, list[tuple[int, int, int, int, int, int, str, str, str]]]:
        try:
            by_pid, status, scanned = client.fetch_open_data_day_matches(
                day_utc_midnight_ts=day_ts,
                players=tracked_players,
                only_automatch=True,
                roster_maps=active_roster_maps,
                retries=2,
            )
        except Exception as exc:
            logger.warning(
                "[NEMESIS BACKFILL] Falha ao ler dia UTC %s: %s",
                datetime.fromtimestamp(day_ts, tz=timezone.utc).strftime("%Y-%m-%d"),
                redact_secrets(exc),
            )
            return day_ts, "failed", 0, [], []

        if status != "ok":
            return day_ts, status, int(scanned or 0), [], []

        day_rows: list[tuple[int, int, int, int, int, int, str, str, str]] = []
        day_krypt_rows: list[tuple[int, int, int, int, str, str, str]] = []
        for tpid, mlist in by_pid.items():
            for m in mlist:
                mode_str = str(m.get("mode") or "")
                ct_val = int(m.get("completion_time", 0) or 0)
                mid = int(m.get("match_id", 0) or 0)
                if ct_val <= 0 or mid <= 0 or mode_str not in AUTOMATCH_MODES:
                    continue
                opps = MatchDatabase._extract_automatch_steam_opponents(mode_str, int(tpid), m.get("opponents"))
                if not opps:
                    continue
                win_int = 1 if bool(m.get("win")) else 0
                uday = ct_val // 86400
                for opp_pid, opp_alias, opp_country in opps:
                    day_rows.append((int(tpid), opp_pid, mid, ct_val, uday, win_int, mode_str, opp_alias, opp_country))
                mclean = str(m.get("map_clean") or "").strip()
                raw_allies = m.get("allies") if isinstance(m.get("allies"), list) else []
                compact_allies = [
                    {"profile_id": int(a.get("profile_id", 0) or 0), "alias": str(a.get("alias") or "")[:64]}
                    for a in raw_allies
                    if isinstance(a, dict) and int(a.get("profile_id", 0) or 0) > 0 and int(a.get("profile_id", 0) or 0) != int(tpid)
                ]
                day_krypt_rows.append(
                    (
                        int(tpid),
                        mid,
                        ct_val,
                        win_int,
                        mode_str,
                        mclean,
                        json.dumps(compact_allies, ensure_ascii=False, separators=(",", ":")),
                    )
                )
        return day_ts, "ok", int(scanned or 0), day_rows, day_krypt_rows

    processed_days = 0
    krypt_rows_inserted = 0
    for idx in range(0, len(day_timestamps), step):
        chunk_ts = day_timestamps[idx : idx + step]
        chunk_rows: list[tuple[int, int, int, int, int, int, str, str, str]] = []
        chunk_krypt_rows: list[tuple[int, int, int, int, str, str, str]] = []
        if workers == 1:
            results = [_fetch_one_day(dts) for dts in chunk_ts]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(_fetch_one_day, chunk_ts))

        for _dts, status, scanned, day_rows, day_krypt_rows in results:
            processed_days += 1
            matches_scanned += scanned
            if status == "ok":
                days_ok += 1
                if day_rows:
                    chunk_rows.extend(day_rows)
                if day_krypt_rows:
                    chunk_krypt_rows.extend(day_krypt_rows)
            elif status == "not_published":
                days_not_published += 1
            else:
                days_failed += 1

        if chunk_rows:
            rows_extracted += len(chunk_rows)
            rows_inserted += db.insert_nemesis_matches_batch(chunk_rows)
        if chunk_krypt_rows:
            krypt_rows_inserted += db.insert_kryptonite_matches_batch(chunk_krypt_rows)

        if callable(progress_callback):
            progress_callback(processed_days, len(day_timestamps), rows_inserted, matches_scanned)

    db.set_state("nemesis_open_data_backfill_range", f"{effective_start_str}..{effective_end_str}")
    db.set_state("nemesis_open_data_backfill_ts", str(int(time.time())))

    return {
        "start_date": effective_start_str,
        "end_date": effective_end_str,
        "days_requested": len(day_timestamps),
        "days_ok": days_ok,
        "days_not_published": days_not_published,
        "days_failed": days_failed,
        "matches_scanned": matches_scanned,
        "nemesis_rows_extracted": rows_extracted,
        "nemesis_rows_inserted": rows_inserted,
        "kryptonite_rows_inserted": krypt_rows_inserted,
        "coverage_after": db.get_nemesis_coverage_summary(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor CoH3 Brasil v7.9 -> SQLite + Quíntupla Checagem (Relic × coh3stats × Radar Veteranos × Auditoria de Silêncio) + Battlegroups (cohdb) + Resumo Semanal + Discord Privado")
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
        "--force-quiet-audit",
        action="store_true",
        help="Força a 5ª checagem profunda (Auditoria de Silêncio em todo o elenco + SQLite + coh3stats) neste ciclo",
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
    cohdb = CohDBClient()
    logger.info("Iniciando CoH3 Brasil Monitor v7.9 usando %s...", args.config)

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
                cohdb=cohdb,
                force_weekly_summary=(bool(args.force_weekly_summary) and first_iter),
                force_quiet_audit=(bool(args.force_quiet_audit) and first_iter),
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

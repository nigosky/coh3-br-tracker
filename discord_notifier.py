"""Integração endurecida (hardened) via Webhook com o Discord Privado — TLS 1.2+, allowlist estrita e anti-spoofing."""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from card_renderer import (
    SteamAvatarProvider,
    render_matches_table_png,
    render_weekly_summary_card_png,
)
from relic_api import TRACKER_USER_AGENT, clean_map_name
from security import (
    ALLOWED_DISCORD_HOSTS,
    build_no_redirect_https_opener,
    read_bounded_http_body,
    redact_secrets,
    strip_unsafe_chars,
    validate_discord_webhook_url,
)

logger = logging.getLogger("coh3_br.discord")

COLOR_SUMMARY = 0x1D7DFA  # Azul Lista Horizontal de Partidas

BOT_AVATAR_URL = "https://coh3stats.com/logo/android-icon-192x192.png"

SNOWFLAKE_ID_RE = re.compile(r"^\d{15,25}$")
DISCORD_MD_ESCAPE_RE = re.compile(r"([\\*_~`|\[\]()<>@#])")
SAFE_ATTACHMENT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_DISCORD_RESPONSE_BYTES = 262_144  # 256 KB
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024  # 8 MB limite seguro por PNG

# Bloqueia qualquer menção (@everyone, @here, usuários ou cargos) no Discord
SAFE_ALLOWED_MENTIONS: dict[str, list[str]] = {"parse": []}

_SECURE_OPENER = build_no_redirect_https_opener()

__all__ = [
    "ALLOWED_DISCORD_HOSTS",
    "DiscordWebhookClient",
    "build_match_embed_payload",
    "build_safe_coh3stats_match_url",
    "build_summary_list_payload",
    "build_weekly_summary_payload",
    "format_duration",
    "format_elo_compact",
    "group_matches_by_id",
    "redact_secrets",
    "render_summary_attachments",
    "sanitize_discord_text",
    "validate_discord_webhook_url",
]


def sanitize_discord_text(raw: Any, max_len: int = 64) -> str:
    """Higieniza textos públicos da Steam/Relic contra menções, links falsos e spoofing Unicode BiDi."""
    cleaned = strip_unsafe_chars(raw)
    if not cleaned:
        return "Desconhecido"
    return DISCORD_MD_ESCAPE_RE.sub(r"\\\1", cleaned[:max_len])


def build_safe_coh3stats_match_url(profile_id: Any, match_id: Any) -> str:
    pid = int(profile_id)
    mid = int(match_id)
    if pid <= 0 or mid <= 0:
        raise ValueError("IDs de perfil/partida devem ser inteiros positivos.")
    return f"https://coh3stats.com/players/{pid}/matches/{mid}"


def format_duration(seconds: int) -> str:
    mins, secs = divmod(max(0, int(seconds)), 60)
    if mins >= 60:
        hrs, mins = divmod(mins, 60)
        return f"{hrs}h {mins:02d}m"
    return f"{mins}m {secs:02d}s"


def format_elo_compact(old_elo: int | None, new_elo: int | None) -> str:
    if not old_elo or not new_elo:
        return "S/R"
    old_i, new_i = int(old_elo), int(new_elo)
    diff = new_i - old_i
    return f"{old_i} ({f'+{diff}' if diff >= 0 else f'{diff}'})"


def _normalize_match_group(match_or_group: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(match_or_group, list):
        return {
            "match_id": int(match_or_group[0]["match_id"]),
            "primary": match_or_group[0],
            "records": match_or_group,
        }
    if "records" in match_or_group and "primary" in match_or_group:
        return match_or_group
    return {
        "match_id": int(match_or_group["match_id"]),
        "primary": match_or_group,
        "records": [match_or_group],
    }


def group_matches_by_id(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupa em O(N) registros que pertencem ao mesmo match_id preservando a ordem original."""
    grouped_map: dict[int, dict[str, Any]] = {}
    seen_pairs: set[tuple[int, int]] = set()
    ordered_ids: list[int] = []

    for m in matches:
        mid = int(m["match_id"])
        pid = int(m["tracked_profile_id"])
        if mid not in grouped_map:
            grouped_map[mid] = {"match_id": mid, "primary": m, "records": []}
            ordered_ids.append(mid)
        if (mid, pid) not in seen_pairs:
            seen_pairs.add((mid, pid))
            grouped_map[mid]["records"].append(m)

    return [grouped_map[mid] for mid in ordered_ids]


def _encode_multipart_formdata(
    payload: dict[str, Any],
    files: list[tuple[str, bytes, str]],
) -> tuple[bytes, str]:
    """Codifica payload_json + anexos PNG de forma segura em multipart/form-data (Discord API v10)."""
    boundary = f"----CoH3BRBoundary{secrets.token_hex(16)}"
    payload_copy = dict(payload)
    payload_copy["attachments"] = [
        {"id": idx, "filename": fname}
        for idx, (fname, _, _) in enumerate(files)
    ]

    chunks: list[bytes] = [
        f"--{boundary}\r\n".encode("ascii"),
        b'Content-Disposition: form-data; name="payload_json"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        json.dumps(payload_copy, ensure_ascii=False).encode("utf-8"),
        b"\r\n",
    ]

    for idx, (fname, file_bytes, mime_type) in enumerate(files):
        if not SAFE_ATTACHMENT_NAME_RE.fullmatch(fname):
            raise ValueError(f"Nome de anexo inválido bloqueado: {fname}")
        if not SAFE_ATTACHMENT_NAME_RE.fullmatch(mime_type.replace("/", "_")):
            raise ValueError("MIME type de anexo inválido bloqueado.")
        if len(file_bytes) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"Anexo {fname} excede o tamanho máximo seguro.")
        chunks.extend(
            (
                f"--{boundary}\r\n".encode("ascii"),
                f'Content-Disposition: form-data; name="files[{idx}]"; filename="{fname}"\r\n'.encode("ascii"),
                f"Content-Type: {mime_type}\r\n\r\n".encode("ascii"),
                file_bytes,
                b"\r\n",
            )
        )

    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _format_smurf_alerts_discord_content(smurf_alerts: list[dict[str, Any]]) -> str:
    """Formata linha de alerta sanitizada e legível em notificação push SOMENTE quando há alerta de smurf BR."""
    lines: list[str] = []
    seen_opps: set[int] = set()
    for alert in smurf_alerts or []:
        if not isinstance(alert, dict):
            continue
        prob = int(alert.get("probability_pct", 0) or 0)
        if prob < 75:
            continue
        opp_ctry = str(alert.get("opponent_country") or "").strip().lower()
        if opp_ctry and opp_ctry != "br":
            continue
        opp_pid = int(alert.get("opponent_profile_id", 0) or 0)
        if opp_pid > 0 and opp_pid in seen_opps:
            continue
        if opp_pid > 0:
            seen_opps.add(opp_pid)

        tracked = sanitize_discord_text(alert.get("tracked_alias") or "Veterano", max_len=36)
        opp = sanitize_discord_text(alert.get("opponent_alias") or (f"ID #{opp_pid}" if opp_pid > 0 else "Oponente"), max_len=36)
        tier = sanitize_discord_text(alert.get("confidence_tier") or "Alta", max_len=20)
        main_alias_raw = str(alert.get("suspected_main_alias") or "").strip()
        if main_alias_raw:
            main_txt = f"possível smurf de **{sanitize_discord_text(main_alias_raw, max_len=36)}**"
        else:
            main_txt = "possível **smurf BR não identificado**"

        raw_reasons = [
            sanitize_discord_text(r, max_len=32)
            for r in (alert.get("top_reasons") or [])
            if str(r or "").strip()
        ][:3]
        reasons_suffix = f" | {' • '.join(raw_reasons)}" if raw_reasons else ""
        lines.append(
            f"⚠️ **ALERTA SMURF:** Veterano **{tracked}** enfrentou **{opp}** — {main_txt} (**{prob}%** • {tier}){reasons_suffix}"
        )
        if len(lines) >= 2:
            break
    return "\n".join(lines)[:1800]


def build_match_embed_payload(
    match_or_group: dict[str, Any] | list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
    attachment_filename: str | None = None,
) -> dict[str, Any]:
    """Monta payload limpo sem cabeçalho redundante: exibe apenas o Card PNG (ou linha de ALERTA SMURF quando detectada)."""
    _ = attachment_filename
    grp_obj = _normalize_match_group(match_or_group)
    primary = grp_obj["primary"]

    # Validação defensiva dos IDs mesmo sem texto no cabeçalho
    build_safe_coh3stats_match_url(primary["tracked_profile_id"], primary["match_id"])

    raw_alerts = grp_obj.get("smurf_alerts") or primary.get("smurf_alerts") or []
    smurf_content = _format_smurf_alerts_discord_content(raw_alerts) if isinstance(raw_alerts, list) else ""

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "content": smurf_content,
        "embeds": [],
    }


def build_weekly_summary_payload(
    weekly_stats: dict[str, Any],
    bot_username: str = "CoH3 Brasil Monitor",
) -> dict[str, Any]:
    """Monta payload limpo sem texto redundante: o Card gráfico PNG carrega todos os destaques semanais."""
    _ = weekly_stats
    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "content": "",
        "embeds": [],
    }


def build_summary_list_payload(
    matches: list[dict[str, Any]],
    tracked_players: list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
    custom_players: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Monta o payload da Mensagem Fixada em PT-BR com Últimas Partidas dos jogadores monitorados."""
    grouped = group_matches_by_id(matches)[:5]
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    custom_list = custom_players or []
    unique_roster_count = sum(1 for cp in custom_list if not cp.get("merged_into_profile_id")) or len(tracked_players)

    quick_links: list[str] = []
    for row_idx, grp in enumerate(grouped, start=1):
        primary = grp["primary"]
        recs = grp["records"]
        safe_url = build_safe_coh3stats_match_url(primary["tracked_profile_id"], primary["match_id"])
        uniq_names = list(dict.fromkeys(sanitize_discord_text(r["tracked_alias"], 34) for r in recs))[:2]
        names = " + ".join(uniq_names)
        raw_map = str(primary.get("map_raw") or "").strip()
        disp_map = clean_map_name(raw_map) if raw_map else str(primary.get("map_clean") or "")
        safe_map = sanitize_discord_text(disp_map, 26)
        quick_links.append(f"`#{row_idx}` **{names}** ({safe_map}) ➔ [👁️ Detalhes / ⬇️ Replay ↗]({safe_url})")

    links_desc = (
        "\n".join(quick_links)
        if quick_links
        else f"_Aguardando novas partidas dos {unique_roster_count} jogadores monitorados._"
    )

    footer_txt = (
        f"Atualizado automaticamente via API Relic • Últimas {len(grouped)} partidas únicas • Ranking Unificado BR em canal dedicado"
    )
    embeds_list: list[dict[str, Any]] = [
        {
            "title": f"📌 ÚLTIMAS PARTIDAS DOS {unique_roster_count} MONITORADOS — COH3 BRASIL",
            "description": links_desc[:4000],
            "color": COLOR_SUMMARY,
            "image": {"url": "attachment://recent_matches.png"},
            "footer": {"text": footer_txt},
            "timestamp": now_iso,
        }
    ]

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "embeds": embeds_list,
    }


def render_summary_attachments(
    matches: list[dict[str, Any]],
    avatar_provider: SteamAvatarProvider,
) -> list[tuple[str, bytes, str]]:
    """Gera o PNG da Mensagem Fixada com as últimas partidas monitoradas."""
    grouped = group_matches_by_id(matches)[:5]
    return [
        ("recent_matches.png", render_matches_table_png(grouped, avatar_provider=avatar_provider, live_single=False), "image/png")
    ]


class DiscordWebhookClient:
    """Envia e edita mensagens e imagens PNG via Discord Webhook com TLS 1.2+, allowlist estrita e redaction."""

    def __init__(
        self,
        webhook_url: str,
        bot_username: str = "CoH3 Brasil Monitor",
        db: Any | None = None,
        catalog_json_path: Path | None = None,
    ) -> None:
        self._webhook_url = (webhook_url or "").strip().rstrip("/")
        self.bot_username = bot_username
        self.db = db
        self.catalog_json_path = catalog_json_path
        self._avatar_provider: SteamAvatarProvider | None = None

    def __repr__(self) -> str:
        return f"DiscordWebhookClient(configured={self.is_configured})"

    @property
    def is_configured(self) -> bool:
        return validate_discord_webhook_url(self._webhook_url)

    def get_avatar_provider(self) -> SteamAvatarProvider:
        if self._avatar_provider is None:
            self._avatar_provider = SteamAvatarProvider(
                db=self.db,
                catalog_json_path=self.catalog_json_path,
                allow_network=True,
            )
        return self._avatar_provider

    def _request(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
        files: list[tuple[str, bytes, str]] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        if not validate_discord_webhook_url(url, allow_message_subpath=True):
            raise ValueError("URL de destino bloqueada pela política estrita do DiscordWebhookClient.")

        method_upper = method.upper()
        headers = {"User-Agent": TRACKER_USER_AGENT, "Accept-Encoding": "gzip"}
        if method_upper in ("GET", "DELETE"):
            body = None
        elif files:
            body, content_type = _encode_multipart_formdata(payload or {}, files)
            headers["Content-Type"] = content_type
        else:
            body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"

        for attempt in range(3):
            req = urllib.request.Request(url, data=body, method=method_upper, headers=headers)
            try:
                with _SECURE_OPENER.open(req, timeout=25) as resp:
                    raw_bytes = read_bounded_http_body(resp, MAX_DISCORD_RESPONSE_BYTES)
                    raw = raw_bytes.decode("utf-8")
                    return resp.status, (json.loads(raw) if raw else None)
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    retry_after = 2.0
                    try:
                        err_json = json.loads(exc.read(4096).decode("utf-8"))
                        retry_after = min(max(float(err_json.get("retry_after", 2.0)), 0.5), 30.0)
                    except Exception:
                        pass
                    logger.warning("Rate limit no Discord Webhook; aguardando %.1fs...", retry_after)
                    time.sleep(retry_after + 0.2)
                    continue
                if exc.code in (500, 502, 503, 504) and attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                if exc.code == 404 and method_upper in ("PATCH", "DELETE"):
                    return 404, None
                err_body = redact_secrets(exc.read(1024).decode("utf-8", errors="replace"))
                raise RuntimeError(f"Erro HTTP {exc.code} no Discord Webhook: {err_body}") from None
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                reason = redact_secrets(getattr(exc, "reason", exc))
                raise RuntimeError(f"Falha de rede ao contatar Discord Webhook: {reason}") from None

        raise RuntimeError("Falha no envio ao Discord Webhook após múltiplas tentativas.")

    def _message_url(self, message_id: str) -> str:
        parsed = urllib.parse.urlparse(self._webhook_url)
        return urllib.parse.urlunparse(parsed._replace(path=f"{parsed.path.rstrip('/')}/messages/{message_id}"))

    def verify_webhook(self) -> dict[str, str]:
        """Valida silenciosamente (GET sem postar mensagem) que o Webhook está ativo e acessível no Discord."""
        if not self.is_configured:
            raise RuntimeError("Webhook do Discord ausente ou inválido na configuração.")
        status, data = self._request("GET", self._webhook_url)
        if status != 200 or not isinstance(data, dict) or not data.get("id"):
            raise RuntimeError(f"Verificação do Discord Webhook falhou (HTTP {status}).")
        return {
            "id": str(data.get("id", "")),
            "channel_id": str(data.get("channel_id", "")),
            "name": strip_unsafe_chars(data.get("name", ""))[:60],
        }

    def delete_message(self, message_id: str, protected_message_id: str | None = None) -> bool:
        """Apaga uma mensagem antiga do próprio Webhook no Discord, protegendo sempre o Painel Fixado."""
        if not self.is_configured:
            return False
        clean_id = (message_id or "").strip()
        if not clean_id or not SNOWFLAKE_ID_RE.fullmatch(clean_id):
            return False
        if protected_message_id and clean_id == protected_message_id.strip():
            logger.warning("Bloqueio de segurança: tentativa de remover o Painel Fixado (%s) ignorada.", clean_id)
            return False
        status, _ = self._request("DELETE", self._message_url(clean_id))
        return status in (200, 204, 404)

    @staticmethod
    def _append_wait_param(base_url: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        q = dict(urllib.parse.parse_qsl(parsed.query))
        q["wait"] = "true"
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))

    @staticmethod
    def _extract_snowflake(data: dict[str, Any] | None) -> str | None:
        msg_id = str(data["id"]) if data and "id" in data else None
        return msg_id if msg_id and SNOWFLAKE_ID_RE.fullmatch(msg_id) else None

    def send_match_card(self, match_or_group: dict[str, Any] | list[dict[str, Any]]) -> str | None:
        if not self.is_configured:
            return None
        grp = _normalize_match_group(match_or_group)
        fname = f"match_{int(grp['match_id'])}.png"
        png_bytes = render_matches_table_png([grp], avatar_provider=self.get_avatar_provider(), live_single=True)
        payload = build_match_embed_payload(grp, bot_username=self.bot_username, attachment_filename=fname)
        _, data = self._request("POST", self._append_wait_param(self._webhook_url), payload, files=[(fname, png_bytes, "image/png")])
        return self._extract_snowflake(data)

    def edit_match_card(
        self,
        message_id: str,
        match_or_group: dict[str, Any] | list[dict[str, Any]],
    ) -> str | None:
        """Atualiza silenciosamente (PATCH) o PNG de um Card de partida já postado no Discord (ex.: ao enriquecer Battlegroups)."""
        if not self.is_configured:
            return None
        clean_id = (message_id or "").strip()
        if not clean_id or not SNOWFLAKE_ID_RE.fullmatch(clean_id):
            return None
        grp = _normalize_match_group(match_or_group)
        fname = f"match_{int(grp['match_id'])}.png"
        png_bytes = render_matches_table_png([grp], avatar_provider=self.get_avatar_provider(), live_single=True)
        payload = build_match_embed_payload(grp, bot_username=self.bot_username, attachment_filename=fname)
        status, data = self._request("PATCH", self._message_url(clean_id), payload, files=[(fname, png_bytes, "image/png")])
        if status == 404:
            return None
        return self._extract_snowflake(data)

    def send_weekly_summary_card(self, weekly_stats: dict[str, Any]) -> str | None:
        if not self.is_configured or int((weekly_stats or {}).get("unique_matches_count", 0)) <= 0:
            return None
        fname = f"weekly_summary_{int(time.time())}.png"
        png_bytes = render_weekly_summary_card_png(weekly_stats, avatar_provider=self.get_avatar_provider())
        payload = build_weekly_summary_payload(weekly_stats, bot_username=self.bot_username)
        _, data = self._request("POST", self._append_wait_param(self._webhook_url), payload, files=[(fname, png_bytes, "image/png")])
        return self._extract_snowflake(data)

    def upsert_summary_message(
        self,
        matches: list[dict[str, Any]],
        tracked_players: list[dict[str, Any]],
        existing_message_id: str | None,
        custom_players: list[dict[str, Any]] | None = None,
        recreate_message: bool = False,
    ) -> str | None:
        if not self.is_configured:
            return None

        files = render_summary_attachments(
            matches=matches,
            avatar_provider=self.get_avatar_provider(),
        )
        payload = build_summary_list_payload(
            matches=matches,
            tracked_players=tracked_players,
            bot_username=self.bot_username,
            custom_players=custom_players,
        )

        clean_msg_id = (existing_message_id or "").strip()
        if clean_msg_id and SNOWFLAKE_ID_RE.fullmatch(clean_msg_id):
            msg_url = self._message_url(clean_msg_id)
            if recreate_message:
                try:
                    self._request("DELETE", msg_url)
                except Exception as exc:
                    logger.warning("Não foi possível remover painel anterior (%s): %s", clean_msg_id, redact_secrets(exc))
            else:
                status, data = self._request("PATCH", msg_url, payload, files=files)
                if status != 404:
                    patched_id = self._extract_snowflake(data)
                    if patched_id:
                        return patched_id
                logger.info("Mensagem resumo anterior (%s) não encontrada (404); criando nova.", clean_msg_id)

        _, data = self._request("POST", self._append_wait_param(self._webhook_url), payload, files=files)
        return self._extract_snowflake(data)

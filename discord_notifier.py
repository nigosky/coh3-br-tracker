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
    render_ranking_movement_card_png,
    render_ranking_table_png,
)
from security import (
    ALLOWED_DISCORD_HOSTS,
    build_no_redirect_https_opener,
    read_bounded_http_body,
    redact_secrets,
    strip_unsafe_chars,
    validate_discord_webhook_url,
)

logger = logging.getLogger("coh3_br.discord")

COLOR_WIN = 0x1D7DFA      # Azul Vitória
COLOR_LOSS = 0xE03131     # Vermelho Derrota
COLOR_DUEL = 0xEAB308     # Ouro Duelo Brasileiro
COLOR_RANKING = 0xEAB308  # Ouro Tabela de Ranking Tático
COLOR_SUMMARY = 0x1D7DFA  # Azul Lista Horizontal de Partidas

BOT_AVATAR_URL = "https://coh3stats.com/logo/android-icon-192x192.png"

MODE_COMPACT_LABELS: dict[str, str] = {
    "Team Games (3v3)": "3 vs 3",
    "Team Games (4v4)": "4 vs 4",
    "1v1": "1 vs 1",
    "2v2": "2 vs 2",
    "Custom": "Personalizada",
}

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
    "build_ranking_movement_payload",
    "build_safe_coh3stats_match_url",
    "build_summary_list_payload",
    "compact_mode",
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


def compact_mode(mode_raw: Any) -> str:
    s = strip_unsafe_chars(mode_raw)[:28]
    return MODE_COMPACT_LABELS.get(s, s or "Partida")


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


def build_match_embed_payload(
    match_or_group: dict[str, Any] | list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
    attachment_filename: str | None = None,
) -> dict[str, Any]:
    """Monta payload limpo sem cabeçalho redundante: exibe apenas o Card gráfico PNG da partida."""
    _ = attachment_filename
    grp_obj = _normalize_match_group(match_or_group)
    primary = grp_obj["primary"]

    # Validação defensiva dos IDs mesmo sem texto no cabeçalho
    build_safe_coh3stats_match_url(primary["tracked_profile_id"], primary["match_id"])

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "content": "",
        "embeds": [],
    }


def build_ranking_movement_payload(
    movements_by_mode: dict[str, list[dict[str, Any]]],
    bot_username: str = "CoH3 Brasil Monitor",
) -> dict[str, Any]:
    """Monta cabeçalho PT-BR para o Card de Movimentação no Ranking (setas verdes ▲ e vermelhas ▼)."""
    climbed = 0
    dropped = 0
    highlights: list[str] = []

    for mode_key, items in movements_by_mode.items():
        mode_lbl = "Equipe" if mode_key == "Team Games" else mode_key
        for mv in items:
            d = int(mv.get("rank_delta", 0))
            nm = sanitize_discord_text(mv.get("alias"), 22)
            cur = int(mv.get("br_rank", 0))
            if mv.get("is_new_entry"):
                climbed += 1
                if len(highlights) < 5:
                    highlights.append(f"🆕 **{nm}** (`#{cur}` {mode_lbl})")
            elif d > 0:
                climbed += 1
                if len(highlights) < 5:
                    highlights.append(f"🟢 ▲ **{nm}** (`#{cur}` {mode_lbl})")
            elif d < 0:
                dropped += 1
                if len(highlights) < 5:
                    highlights.append(f"🔴 ▼ **{nm}** (`#{cur}` {mode_lbl})")

    summary_line = "  •  ".join(highlights)
    content = (
        f"📊 **ATUALIZAÇÃO DE RANKING BRASILEIRO** — `🟢 {climbed} subiu`  |  `🔴 {dropped} desceu`\n"
        f"{summary_line}"
    ).strip()

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "content": content[:2000],
        "embeds": [],
    }


def build_summary_list_payload(
    matches: list[dict[str, Any]],
    tracked_players: list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
    rankings_by_mode: dict[str, list[dict[str, Any]]] | None = None,
    custom_players: list[dict[str, Any]] | None = None,
    has_ranking_images: bool = True,
    attachment_names: list[str] | None = None,
) -> dict[str, Any]:
    """Monta o payload da Mensagem Fixada em PT-BR com Tabelas de Ranking + Últimas Partidas."""
    grouped = group_matches_by_id(matches)[:5]
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    embeds_list: list[dict[str, Any]] = []
    att_set = set(attachment_names) if attachment_names is not None else None

    custom_list = custom_players or []
    ranked_pids = {
        int(e["profile_id"])
        for entries in (rankings_by_mode or {}).values()
        for e in entries
    }
    unique_roster_count = sum(1 for cp in custom_list if not cp.get("merged_into_profile_id")) or len(tracked_players)
    unranked_guests = [
        sanitize_discord_text(cp.get("alias"), 20)
        for cp in custom_list
        if int(cp.get("profile_id", 0)) not in ranked_pids and not cp.get("merged_into_profile_id")
    ]

    if rankings_by_mode and has_ranking_images:
        first_embed_added = False
        for m_key, m_title, fname1, fname2 in (
            ("1v1", "🏆 RANKING DIÁRIO BRASILEIRO — 1v1", "ranking_1v1.png", "ranking_1v1_p2.png"),
            ("2v2", "🏆 RANKING DIÁRIO BRASILEIRO — 2v2", "ranking_2v2.png", "ranking_2v2_p2.png"),
            ("Team Games", "🏆 RANKING DIÁRIO BRASILEIRO — JOGOS EM EQUIPE (3v3 + 4v4)", "ranking_team.png", "ranking_team_p2.png"),
        ):
            if not rankings_by_mode.get(m_key):
                continue
            if att_set is not None and fname1 not in att_set:
                continue
            r_embed: dict[str, Any] = {
                "title": m_title,
                "color": COLOR_RANKING,
                "image": {"url": f"attachment://{fname1}"},
            }
            if not first_embed_added:
                first_embed_added = True
                desc_note = (
                    f"🎯 **Ranking Diário Top 20 + {unique_roster_count} brasileiros fixos** "
                    f"• Atualizado 1x ao dia após **00:01 BRT**\n"
                    f"🎮 Partidas monitoradas exclusivamente dos **{unique_roster_count} jogadores da lista**"
                )
                if unranked_guests:
                    desc_note += "\n⭐ *Aguardando 1ª ranqueada:* " + ", ".join(f"**{g}**" for g in unranked_guests[:8])
                r_embed["description"] = desc_note
            embeds_list.append(r_embed)

            if att_set is not None and fname2 in att_set:
                embeds_list.append(
                    {
                        "title": f"{m_title} (Continuação • Monitorados)",
                        "color": COLOR_RANKING,
                        "image": {"url": f"attachment://{fname2}"},
                    }
                )

    quick_links: list[str] = []
    for row_idx, grp in enumerate(grouped, start=1):
        primary = grp["primary"]
        recs = grp["records"]
        safe_url = build_safe_coh3stats_match_url(primary["tracked_profile_id"], primary["match_id"])
        uniq_names = list(dict.fromkeys(sanitize_discord_text(r["tracked_alias"], 20) for r in recs))[:2]
        names = " + ".join(uniq_names)
        safe_map = sanitize_discord_text(primary.get("map_clean"), 22)
        quick_links.append(f"`#{row_idx}` **{names}** ({safe_map}) ➔ [👁️ Detalhes / ⬇️ Replay ↗]({safe_url})")

    links_desc = (
        "\n".join(quick_links)
        if quick_links
        else f"_Aguardando novas partidas dos {unique_roster_count} jogadores monitorados._"
    )

    embeds_list.append(
        {
            "title": f"📌 ÚLTIMAS PARTIDAS DOS {unique_roster_count} MONITORADOS — COH3 BRASIL",
            "description": links_desc[:4000],
            "color": COLOR_SUMMARY,
            "image": {"url": "attachment://recent_matches.png"},
            "footer": {
                "text": f"Atualizado automaticamente via API Relic • Últimas {len(grouped)} partidas únicas exibidas"
            },
            "timestamp": now_iso,
        }
    )

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "embeds": embeds_list[:10],
    }


def render_summary_attachments(
    matches: list[dict[str, Any]],
    rankings_by_mode: dict[str, list[dict[str, Any]]] | None,
    avatar_provider: SteamAvatarProvider,
    top_n: int = 20,
) -> list[tuple[str, bytes, str]]:
    """Gera os PNGs da Mensagem Fixada paginados para preservar largura total no Discord."""
    files: list[tuple[str, bytes, str]] = []

    if rankings_by_mode:
        for m_key, fname1, fname2 in (
            ("1v1", "ranking_1v1.png", "ranking_1v1_p2.png"),
            ("2v2", "ranking_2v2.png", "ranking_2v2_p2.png"),
            ("Team Games", "ranking_team.png", "ranking_team_p2.png"),
        ):
            entries = rankings_by_mode.get(m_key, [])
            if not entries:
                continue
            selected = [e for idx, e in enumerate(entries) if idx < top_n or bool(e.get("is_custom"))]
            if len(selected) <= 25:
                chunk_size = len(selected)
                page1, page2 = selected, []
            else:
                chunk_size = (len(selected) + 1) // 2
                page1, page2 = selected[:chunk_size], selected[chunk_size:]

            sub1 = (
                f"Parte 1/2 • {len(selected)} no Ranking"
                if page2
                else f"Top 20 + Monitorados ({len(selected)})"
            )
            files.append(
                (
                    fname1,
                    render_ranking_table_png(
                        entries=page1,
                        mode_title=m_key,
                        avatar_provider=avatar_provider,
                        max_rows=chunk_size,
                        subtitle_override=sub1,
                    ),
                    "image/png",
                )
            )
            if page2:
                files.append(
                    (
                        fname2,
                        render_ranking_table_png(
                            entries=page2,
                            mode_title=m_key,
                            avatar_provider=avatar_provider,
                            max_rows=len(page2),
                            subtitle_override=f"Parte 2/2 • Monitorados (+{len(page2)})",
                        ),
                        "image/png",
                    )
                )

    grouped = group_matches_by_id(matches)[:5]
    files.append(("recent_matches.png", render_matches_table_png(grouped, avatar_provider=avatar_provider, live_single=False), "image/png"))
    return files


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
        headers = {"User-Agent": "CoH3-BR-Discord-Tracker/7.3", "Accept-Encoding": "gzip"}
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
        parsed = urllib.parse.urlparse(self._webhook_url)
        msg_url = urllib.parse.urlunparse(parsed._replace(path=f"{parsed.path.rstrip('/')}/messages/{clean_id}"))
        status, _ = self._request("DELETE", msg_url)
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

    def send_ranking_movement_card(self, movements_by_mode: dict[str, list[dict[str, Any]]]) -> str | None:
        if not self.is_configured or not any(bool(v) for v in (movements_by_mode or {}).values()):
            return None
        fname = f"ranking_move_{int(time.time())}.png"
        png_bytes = render_ranking_movement_card_png(movements_by_mode, avatar_provider=self.get_avatar_provider())
        payload = build_ranking_movement_payload(movements_by_mode, bot_username=self.bot_username)
        _, data = self._request("POST", self._append_wait_param(self._webhook_url), payload, files=[(fname, png_bytes, "image/png")])
        return self._extract_snowflake(data)

    def upsert_summary_message(
        self,
        matches: list[dict[str, Any]],
        tracked_players: list[dict[str, Any]],
        existing_message_id: str | None,
        rankings_by_mode: dict[str, list[dict[str, Any]]] | None = None,
        custom_players: list[dict[str, Any]] | None = None,
        top_n: int = 20,
        recreate_message: bool = False,
    ) -> str | None:
        if not self.is_configured:
            return None

        files = render_summary_attachments(
            matches=matches,
            rankings_by_mode=rankings_by_mode,
            avatar_provider=self.get_avatar_provider(),
            top_n=top_n,
        )
        att_names = [f[0] for f in files]
        payload = build_summary_list_payload(
            matches=matches,
            tracked_players=tracked_players,
            bot_username=self.bot_username,
            rankings_by_mode=rankings_by_mode,
            custom_players=custom_players,
            has_ranking_images=any(nm.startswith("ranking_") for nm in att_names),
            attachment_names=att_names,
        )

        clean_msg_id = (existing_message_id or "").strip()
        if clean_msg_id and SNOWFLAKE_ID_RE.fullmatch(clean_msg_id):
            parsed = urllib.parse.urlparse(self._webhook_url)
            msg_url = urllib.parse.urlunparse(parsed._replace(path=f"{parsed.path.rstrip('/')}/messages/{clean_msg_id}"))
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

    def send_new_top_entrant_card(self, new_entrants: list[dict[str, Any]], top_n: int = 20) -> str | None:
        if not new_entrants or not self.is_configured:
            return None
        lines = []
        for p in new_entrants[:20]:
            pid = int(p["profile_id"])
            safe_alias = sanitize_discord_text(p.get("alias"), max_len=40)
            placements = ", ".join(sanitize_discord_text(pl, max_len=48) for pl in p.get("placements", [])[:4])
            lines.append(
                f"• :flag_br: **{safe_alias}** (`#{pid}`) — {placements} • [Perfil coh3stats ↗](https://coh3stats.com/players/{pid})"
            )
        embed = {
            "author": {"name": "COH3 BRASIL  •  RADAR TOP 20", "icon_url": BOT_AVATAR_URL},
            "title": f"🆕 Novo(s) Brasileiro(s) no Top {int(top_n)}!",
            "description": "\n".join(lines)[:4000],
            "color": COLOR_RANKING,
            "footer": {"text": "Monitoramento automático dos rankings 1v1, 2v2 e Jogos em Equipe (3v3 + 4v4)"},
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        payload = {
            "username": sanitize_discord_text(self.bot_username, max_len=80),
            "avatar_url": BOT_AVATAR_URL,
            "allowed_mentions": SAFE_ALLOWED_MENTIONS,
            "embeds": [embed],
        }
        _, data = self._request("POST", self._append_wait_param(self._webhook_url), payload)
        return self._extract_snowflake(data)

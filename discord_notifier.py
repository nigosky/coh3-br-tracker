"""Integração endurecida (hardened) via Webhook com o Discord Privado — Layout Gráfico v3 (coh3stats + Ranking Tático + Avatares Steam)."""

from __future__ import annotations

import json
import logging
import re
import secrets
import ssl
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
    render_ranking_table_png,
)

logger = logging.getLogger("coh3_br.discord")

COLOR_WIN = 0x1D7DFA      # Azul Vitória (padrão coh3stats image.png)
COLOR_LOSS = 0xE03131     # Vermelho Derrota (padrão coh3stats image.png)
COLOR_DUEL = 0xEAB308     # Ouro Duelo Brasileiro
COLOR_RANKING = 0xEAB308  # Ouro Tabela de Ranking Tático (image_2.png)
COLOR_SUMMARY = 0x1D7DFA  # Azul Lista Horizontal de Partidas

BOT_AVATAR_URL = "https://coh3stats.com/logo/android-icon-192x192.png"

MODE_COMPACT_LABELS: dict[str, str] = {
    "Team Games (3v3)": "3 vs 3",
    "Team Games (4v4)": "4 vs 4",
    "1v1": "1 vs 1",
    "2v2": "2 vs 2",
    "Custom": "Custom",
}

ALLOWED_DISCORD_HOSTS = frozenset(
    {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
)
WEBHOOK_PATH_RE = re.compile(r"^/api/(?:v\d+/)?webhooks/\d{15,25}/[A-Za-z0-9_-]{20,120}$")
SNOWFLAKE_ID_RE = re.compile(r"^\d{15,25}$")
DISCORD_MD_ESCAPE_RE = re.compile(r"([\\*_~`|\[\]()<>@])")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
WEBHOOK_REDACT_RE = re.compile(r"https?://[^\s/]+/api/(?:v\d+/)?webhooks/[^\s\"']+", re.IGNORECASE)
SAFE_ATTACHMENT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_DISCORD_RESPONSE_BYTES = 262_144  # 256 KB

# Bloqueia qualquer menção (@everyone, @here, usuários ou cargos) no Discord
SAFE_ALLOWED_MENTIONS: dict[str, list[str]] = {"parse": []}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Bloqueia redirecionamentos HTTP (proteção contra SSRF e vazamento de credenciais)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento bloqueado por política de segurança", headers, fp)


def _build_secure_opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirectHandler())


_SECURE_OPENER = _build_secure_opener()


def redact_secrets(text: str) -> str:
    """Remove qualquer URL de Webhook eventualmente presente em mensagens de erro."""
    return WEBHOOK_REDACT_RE.sub("[WEBHOOK_REDACTED]", text or "")


def sanitize_discord_text(raw: Any, max_len: int = 64) -> str:
    """Higieniza textos vindos de apelidos públicos da Steam/Relic para impedir menções ou links falsos."""
    cleaned = CONTROL_CHARS_RE.sub(" ", str(raw or "")).strip()
    if not cleaned:
        return "Desconhecido"
    cleaned = cleaned[:max_len]
    return DISCORD_MD_ESCAPE_RE.sub(r"\\\1", cleaned)


def build_safe_coh3stats_match_url(profile_id: Any, match_id: Any) -> str:
    pid = int(profile_id)
    mid = int(match_id)
    return f"https://coh3stats.com/players/{pid}/matches/{mid}"


def validate_discord_webhook_url(url: str) -> bool:
    """Valida estritamente protocolo HTTPS, domínio oficial do Discord e formato do caminho do Webhook."""
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return False
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https":
        return False
    if (parsed.hostname or "").lower() not in ALLOWED_DISCORD_HOSTS:
        return False
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        return False
    return bool(WEBHOOK_PATH_RE.fullmatch(parsed.path))


def compact_mode(mode_raw: Any) -> str:
    s = CONTROL_CHARS_RE.sub("", str(mode_raw or "")).strip()[:28]
    return MODE_COMPACT_LABELS.get(s, s or "Partida")


def format_duration(seconds: int) -> str:
    mins, secs = divmod(max(0, int(seconds)), 60)
    if mins >= 60:
        hrs, mins = divmod(mins, 60)
        return f"{hrs}h {mins:02d}m"
    return f"{mins}m {secs:02d}s"


def format_elo_compact(old_elo: int | None, new_elo: int | None) -> str:
    if not old_elo or not new_elo:
        return "N/A"
    old_i, new_i = int(old_elo), int(new_elo)
    diff = new_i - old_i
    sign = f"+{diff}" if diff >= 0 else f"{diff}"
    return f"{old_i} ({sign})"


def group_matches_by_id(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Agrupa registros que pertencem ao mesmo match_id (quando 2+ brasileiros seguidos
    jogam juntos em equipe ou se enfrentam num duelo BR), preservando a ordem original.
    """
    grouped_map: dict[int, dict[str, Any]] = {}
    ordered_ids: list[int] = []

    for m in matches:
        mid = int(m["match_id"])
        if mid not in grouped_map:
            grouped_map[mid] = {
                "match_id": mid,
                "primary": m,
                "records": [],
            }
            ordered_ids.append(mid)
        existing_pids = {int(r["tracked_profile_id"]) for r in grouped_map[mid]["records"]}
        if int(m["tracked_profile_id"]) not in existing_pids:
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

    chunks: list[bytes] = []
    # Parte 0: payload_json
    chunks.append(f"--{boundary}\r\n".encode("ascii"))
    chunks.append(b'Content-Disposition: form-data; name="payload_json"\r\n')
    chunks.append(b"Content-Type: application/json\r\n\r\n")
    chunks.append(json.dumps(payload_copy, ensure_ascii=False).encode("utf-8"))
    chunks.append(b"\r\n")

    # Partes 1..N: files[idx]
    for idx, (fname, file_bytes, mime_type) in enumerate(files):
        if not SAFE_ATTACHMENT_NAME_RE.fullmatch(fname):
            raise ValueError(f"Nome de anexo inválido bloqueado: {fname}")
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        chunks.append(
            f'Content-Disposition: form-data; name="files[{idx}]"; filename="{fname}"\r\n'.encode("ascii")
        )
        chunks.append(f"Content-Type: {mime_type}\r\n\r\n".encode("ascii"))
        chunks.append(file_bytes)
        chunks.append(b"\r\n")

    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def build_match_embed_payload(
    match_or_group: dict[str, Any] | list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
    attachment_filename: str | None = None,
) -> dict[str, Any]:
    """
    Monta uma mensagem de largura máxima (550px fora de Embed) com o Card Grande estilo coh3stats
    e cabeçalho clicável (Details / Replay com <url> sem gerar preview extra).
    """
    if isinstance(match_or_group, list):
        records = match_or_group
        grp_obj = {"match_id": int(records[0]["match_id"]), "primary": records[0], "records": records}
    elif "records" in match_or_group and "primary" in match_or_group:
        records = match_or_group["records"]
        grp_obj = match_or_group
    else:
        records = [match_or_group]
        grp_obj = {"match_id": int(match_or_group["match_id"]), "primary": match_or_group, "records": records}

    primary = grp_obj["primary"]
    match_id = int(primary["match_id"])
    primary_pid = int(primary["tracked_profile_id"])
    safe_url = build_safe_coh3stats_match_url(primary_pid, match_id)
    ts = int(primary["completion_time"])

    winners = [r for r in records if bool(r["win"])]
    losers = [r for r in records if not bool(r["win"])]
    safe_map = sanitize_discord_text(primary.get("map_clean"), max_len=40)
    mode_badge = compact_mode(primary.get("mode"))

    if winners and losers:
        w_names = " & ".join(sanitize_discord_text(r["tracked_alias"], 24) for r in winners[:3])
        l_names = " & ".join(sanitize_discord_text(r["tracked_alias"], 24) for r in losers[:3])
        headline = f"⚔️ **DUELO BR — {w_names} vs {l_names}** (`{mode_badge}` • **{safe_map}**)"
    else:
        win = bool(primary["win"])
        names = " & ".join(sanitize_discord_text(r["tracked_alias"], 24) for r in records[:4])
        res_lbl = "VICTORY" if win else "DEFEAT"
        badge = "🔵" if win else "🔴"
        headline = f"{badge} **{res_lbl} — {names}** (`{mode_badge}` • **{safe_map}**)"

    content = (
        f"{headline}\n"
        f"🕒 <t:{ts}:R>   •   "
        f"[👁️ **Details** (Ficha Completa) ↗](<{safe_url}>)   •   "
        f"[⬇️ **Replay** (Download) ↗](<{safe_url}>)"
    )

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
) -> dict[str, Any]:
    """
    Monta o payload da Mensagem Fixada com as Tabelas Gráficas de Ranking (1v1, 2v2, Team Games)
    no estilo tático dourado + Tabela Horizontal de Últimas Partidas estilo coh3stats + Links Details/Replay.
    """
    grouped = group_matches_by_id(matches)[:5]
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    embeds_list: list[dict[str, Any]] = []

    custom_list = custom_players or []
    ranked_pids = {
        int(e["profile_id"])
        for entries in (rankings_by_mode or {}).values()
        for e in entries
    }
    unranked_guests = [
        sanitize_discord_text(cp.get("alias"), 20)
        for cp in custom_list
        if int(cp.get("profile_id", 0)) not in ranked_pids
    ]

    if rankings_by_mode and has_ranking_images:
        mode_defs = [
            ("1v1", "🏆 RANKING BRASILEIRO — 1v1", "ranking_1v1.png"),
            ("2v2", "🏆 RANKING BRASILEIRO — 2v2", "ranking_2v2.png"),
            ("Team Games", "🏆 RANKING BRASILEIRO — TEAM GAMES (3v3 + 4v4)", "ranking_team.png"),
        ]
        for idx, (m_key, m_title, fname) in enumerate(mode_defs):
            if not rankings_by_mode.get(m_key):
                continue
            r_embed: dict[str, Any] = {
                "title": m_title,
                "color": COLOR_RANKING,
                "image": {"url": f"attachment://{fname}"},
            }
            if idx == 0:
                desc_note = f"🎯 **{len(tracked_players)} jogadores monitorados** (Top 20 por modo + convidados `★ EXTRA`)"
                if unranked_guests:
                    desc_note += "\n⭐ *Aguardando 1ª ranqueada:* " + ", ".join(f"**{g}**" for g in unranked_guests[:8])
                r_embed["description"] = desc_note
            embeds_list.append(r_embed)

    quick_links: list[str] = []
    for row_idx, grp in enumerate(grouped, start=1):
        primary = grp["primary"]
        recs = grp["records"]
        safe_url = build_safe_coh3stats_match_url(primary["tracked_profile_id"], primary["match_id"])
        names = " + ".join(sanitize_discord_text(r["tracked_alias"], 16) for r in recs[:2])
        safe_map = sanitize_discord_text(primary.get("map_clean"), 22)
        quick_links.append(f"`#{row_idx}` **{names}** ({safe_map}) ➔ [👁️ Details / ⬇️ Replay ↗]({safe_url})")

    links_desc = "\n".join(quick_links) if quick_links else "_Aguardando novas partidas dos jogadores seguidos._"

    matches_embed: dict[str, Any] = {
        "title": "📌 ÚLTIMAS PARTIDAS GRAVADAS — COH3 BRASIL",
        "description": links_desc[:4000],
        "color": COLOR_SUMMARY,
        "image": {"url": "attachment://recent_matches.png"},
        "footer": {
            "text": f"Atualizado automaticamente via API Relic • Últimas {len(grouped)} partidas únicas exibidas"
        },
        "timestamp": now_iso,
    }
    embeds_list.append(matches_embed)

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "avatar_url": BOT_AVATAR_URL,
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "embeds": embeds_list,
    }


def render_summary_attachments(
    matches: list[dict[str, Any]],
    rankings_by_mode: dict[str, list[dict[str, Any]]] | None,
    avatar_provider: SteamAvatarProvider,
    top_n: int = 20,
) -> list[tuple[str, bytes, str]]:
    """Gera os PNGs da Mensagem Fixada (3 tabelas de Ranking + 1 tabela horizontal de Partidas)."""
    files: list[tuple[str, bytes, str]] = []

    if rankings_by_mode:
        for m_key, fname in (
            ("1v1", "ranking_1v1.png"),
            ("2v2", "ranking_2v2.png"),
            ("Team Games", "ranking_team.png"),
        ):
            entries = rankings_by_mode.get(m_key, [])
            if not entries:
                continue
            selected = [
                e for idx, e in enumerate(entries) if idx < top_n or bool(e.get("is_custom"))
            ]
            png_bytes = render_ranking_table_png(
                entries=selected,
                mode_title=m_key,
                avatar_provider=avatar_provider,
                max_rows=max(top_n + 6, 25),
            )
            files.append((fname, png_bytes, "image/png"))

    grouped = group_matches_by_id(matches)[:5]
    matches_png = render_matches_table_png(grouped, avatar_provider=avatar_provider, live_single=False)
    files.append(("recent_matches.png", matches_png, "image/png"))
    return files


class DiscordWebhookClient:
    """Envia e edita mensagens e imagens PNG via Discord Webhook com TLS 1.2+, allowlist e redaction."""

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
        payload: dict[str, Any],
        files: list[tuple[str, bytes, str]] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ALLOWED_DISCORD_HOSTS:
            raise ValueError("URL de destino bloqueada pela política de segurança do DiscordWebhookClient.")

        if files:
            body, content_type = _encode_multipart_formdata(payload, files)
        else:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            content_type = "application/json"

        for _attempt in range(3):
            req = urllib.request.Request(
                url,
                data=body,
                method=method,
                headers={
                    "Content-Type": content_type,
                    "User-Agent": "CoH3-BR-Discord-Tracker/3.0",
                },
            )
            try:
                with _SECURE_OPENER.open(req, timeout=25) as resp:
                    raw_bytes = resp.read(MAX_DISCORD_RESPONSE_BYTES + 1)
                    if len(raw_bytes) > MAX_DISCORD_RESPONSE_BYTES:
                        raise RuntimeError("Resposta do Discord excedeu o limite máximo seguro de tamanho.")
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
                if exc.code == 404:
                    return 404, None
                err_body = redact_secrets(exc.read(1024).decode("utf-8", errors="replace"))
                raise RuntimeError(f"Erro HTTP {exc.code} no Discord Webhook: {err_body}") from None
            except urllib.error.URLError as exc:
                reason = redact_secrets(str(exc.reason))
                raise RuntimeError(f"Falha de rede ao contatar Discord Webhook: {reason}") from None
        raise RuntimeError("Falha no envio ao Discord Webhook após múltiplas tentativas de rate-limit.")

    def _append_wait_param(self, base_url: str) -> str:
        parsed = urllib.parse.urlparse(base_url)
        q = dict(urllib.parse.parse_qsl(parsed.query))
        q["wait"] = "true"
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))

    def send_match_card(self, match_or_group: dict[str, Any] | list[dict[str, Any]]) -> str | None:
        """Renderiza o Card Horizontal coh3stats com Avatares Steam BR e envia ao Discord."""
        if not self.is_configured:
            return None
        if isinstance(match_or_group, list):
            grp = {"match_id": int(match_or_group[0]["match_id"]), "primary": match_or_group[0], "records": match_or_group}
        elif "records" in match_or_group and "primary" in match_or_group:
            grp = match_or_group
        else:
            grp = {"match_id": int(match_or_group["match_id"]), "primary": match_or_group, "records": [match_or_group]}

        mid = int(grp["match_id"])
        fname = f"match_{mid}.png"
        png_bytes = render_matches_table_png([grp], avatar_provider=self.get_avatar_provider(), live_single=True)
        payload = build_match_embed_payload(grp, bot_username=self.bot_username, attachment_filename=fname)

        url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", url, payload, files=[(fname, png_bytes, "image/png")])
        msg_id = str(data["id"]) if data and "id" in data else None
        return msg_id if msg_id and SNOWFLAKE_ID_RE.fullmatch(msg_id) else None

    def upsert_summary_message(
        self,
        matches: list[dict[str, Any]],
        tracked_players: list[dict[str, Any]],
        existing_message_id: str | None,
        rankings_by_mode: dict[str, list[dict[str, Any]]] | None = None,
        custom_players: list[dict[str, Any]] | None = None,
        top_n: int = 20,
    ) -> str | None:
        """Atualiza (PATCH multipart) a Mensagem Fixada com os PNGs de Ranking + Partidas ou cria uma nova (POST)."""
        if not self.is_configured:
            return None

        files = render_summary_attachments(
            matches=matches,
            rankings_by_mode=rankings_by_mode,
            avatar_provider=self.get_avatar_provider(),
            top_n=top_n,
        )
        has_rank_imgs = any(f[0].startswith("ranking_") for f in files)
        payload = build_summary_list_payload(
            matches=matches,
            tracked_players=tracked_players,
            bot_username=self.bot_username,
            rankings_by_mode=rankings_by_mode,
            custom_players=custom_players,
            has_ranking_images=has_rank_imgs,
        )

        clean_msg_id = (existing_message_id or "").strip()
        if clean_msg_id and SNOWFLAKE_ID_RE.fullmatch(clean_msg_id):
            parsed = urllib.parse.urlparse(self._webhook_url)
            edit_path = parsed.path.rstrip("/") + f"/messages/{clean_msg_id}"
            edit_url = urllib.parse.urlunparse(parsed._replace(path=edit_path))
            status, data = self._request("PATCH", edit_url, payload, files=files)
            if status != 404 and data and "id" in data:
                ret_id = str(data["id"])
                return ret_id if SNOWFLAKE_ID_RE.fullmatch(ret_id) else None
            logger.info("Mensagem resumo anterior (%s) não encontrada (404); criando nova.", clean_msg_id)

        post_url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", post_url, payload, files=files)
        ret_id = str(data["id"]) if data and "id" in data else None
        return ret_id if ret_id and SNOWFLAKE_ID_RE.fullmatch(ret_id) else None

    def send_new_top_entrant_card(self, new_entrants: list[dict[str, Any]], top_n: int = 20) -> str | None:
        """Envia alerta no Discord quando novos brasileiros entram no Top N e passam a ser seguidos."""
        if not new_entrants or not self.is_configured:
            return None
        lines = []
        for p in new_entrants[:20]:
            pid = int(p["profile_id"])
            safe_alias = sanitize_discord_text(p.get("alias"), max_len=40)
            placements = ", ".join(
                sanitize_discord_text(pl, max_len=48) for pl in p.get("placements", [])[:4]
            )
            lines.append(
                f"• :flag_br: **{safe_alias}** (`#{pid}`) — {placements} • [Perfil coh3stats ↗](https://coh3stats.com/players/{pid})"
            )
        embed = {
            "author": {
                "name": "COH3 BRASIL  •  RADAR TOP 20",
                "icon_url": BOT_AVATAR_URL,
            },
            "title": f"🆕 Novo(s) Brasileiro(s) no Top {int(top_n)} — Seguindo Automaticamente!",
            "description": "\n".join(lines)[:4000],
            "color": COLOR_RANKING,
            "footer": {"text": "Monitoramento automático dos rankings 1v1, 2v2 e Team Games (3v3 + 4v4)"},
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        payload = {
            "username": sanitize_discord_text(self.bot_username, max_len=80),
            "avatar_url": BOT_AVATAR_URL,
            "allowed_mentions": SAFE_ALLOWED_MENTIONS,
            "embeds": [embed],
        }
        url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", url, payload)
        ret_id = str(data["id"]) if data and "id" in data else None
        return ret_id if ret_id and SNOWFLAKE_ID_RE.fullmatch(ret_id) else None

"""Integração endurecida (hardened) via Webhook com o Discord Privado."""

from __future__ import annotations

import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("coh3_br.discord")

COLOR_WIN = 0x2ECC71     # Verde Vitória
COLOR_LOSS = 0xE74C3C    # Vermelho Derrota
COLOR_SUMMARY = 0x3498DB # Azul Lista Resumo

ALLOWED_DISCORD_HOSTS = frozenset(
    {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
)
WEBHOOK_PATH_RE = re.compile(r"^/api/(?:v\d+/)?webhooks/\d{15,25}/[A-Za-z0-9_-]{20,120}$")
SNOWFLAKE_ID_RE = re.compile(r"^\d{15,25}$")
DISCORD_MD_ESCAPE_RE = re.compile(r"([\\*_~`|\[\]()<>@])")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
WEBHOOK_REDACT_RE = re.compile(r"https?://[^\s/]+/api/(?:v\d+/)?webhooks/[^\s\"']+", re.IGNORECASE)
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
    """
    Higieniza textos vindos de apelidos públicos da Steam/Relic para impedir:
    - Menções (@everyone / @here / <@id>)
    - Injeção de links falsos Markdown [texto](url)
    - Caracteres de controle ou quebras de linha
    """
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


def country_flag(code: str) -> str:
    """Converte código ISO-2 (ex: 'br', 'us') em emoji de bandeira do Discord."""
    c = (code or "").strip().lower()
    if len(c) == 2 and c.isascii() and c.isalpha() and c != "un":
        return f":flag_{c}:"
    return "🌐"


def format_duration(seconds: int) -> str:
    mins, secs = divmod(max(0, int(seconds)), 60)
    if mins >= 60:
        hrs, mins = divmod(mins, 60)
        return f"{hrs}h {mins:02d}m"
    return f"{mins}m {secs:02d}s"


def format_elo_change(old_elo: int | None, new_elo: int | None) -> str:
    if not old_elo or not new_elo:
        return "Sem rank"
    old_i, new_i = int(old_elo), int(new_elo)
    diff = new_i - old_i
    sign = f"+{diff}" if diff >= 0 else f"{diff}"
    return f"{old_i} → **{new_i}** (`{sign}`)"


def format_elo_compact(old_elo: int | None, new_elo: int | None) -> str:
    if not old_elo or not new_elo:
        return "—"
    old_i, new_i = int(old_elo), int(new_elo)
    diff = new_i - old_i
    sign = f"+{diff}" if diff >= 0 else f"{diff}"
    return f"{new_i} ({sign})"


def format_team_list(participants: list[dict[str, Any]]) -> str:
    if not participants:
        return "—"
    lines = []
    for p in participants[:8]:
        flag = country_flag(p.get("country", ""))
        safe_alias = sanitize_discord_text(p.get("alias", ""), max_len=40)
        safe_fac = sanitize_discord_text(p.get("faction_short", ""), max_len=12)
        elo_str = f" • `{int(p['elo'])}`" if p.get("elo") else ""
        lines.append(f"{flag} **{safe_alias}** ({safe_fac}{elo_str})")
    return "\n".join(lines)


def build_match_embed_payload(match: dict[str, Any], bot_username: str = "CoH3 Brasil Monitor") -> dict[str, Any]:
    """Monta o payload seguro de um Card Webhook individual para uma partida recém-terminada."""
    win = bool(match["win"])
    status_emoji = "🟢" if win else "🔴"
    status_label = "VITÓRIA" if win else "DERROTA"
    ts = int(match["completion_time"])
    iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    match_id = int(match["match_id"])
    profile_id = int(match["tracked_profile_id"])
    safe_url = build_safe_coh3stats_match_url(profile_id, match_id)

    safe_alias = sanitize_discord_text(match.get("tracked_alias"), max_len=48)
    safe_faction = sanitize_discord_text(match.get("tracked_faction"), max_len=24)
    safe_map = sanitize_discord_text(match.get("map_clean"), max_len=48)
    safe_mode = CONTROL_CHARS_RE.sub("", str(match.get("mode", "")))[:28]

    fields: list[dict[str, Any]] = [
        {"name": "Modo", "value": f"`{safe_mode}`", "inline": True},
        {"name": "Mapa", "value": safe_map, "inline": True},
        {"name": "Duração", "value": f"`{format_duration(match['duration_sec'])}`", "inline": True},
        {
            "name": "ELO Atualizado",
            "value": format_elo_change(match.get("old_elo"), match.get("new_elo")),
            "inline": True,
        },
        {"name": "Data / Hora", "value": f"<t:{ts}:f> (<t:{ts}:R>)", "inline": True},
        {
            "name": "Replay / Ficha",
            "value": f"[Abrir no coh3stats.com ↗]({safe_url})",
            "inline": True,
        },
    ]

    if match.get("allies"):
        fields.append(
            {
                "name": f"Aliados ({len(match['allies'])})",
                "value": format_team_list(match["allies"])[:1024],
                "inline": False,
            }
        )

    fields.append(
        {
            "name": f"Adversário(s) ({len(match.get('opponents', []))})",
            "value": format_team_list(match.get("opponents", []))[:1024],
            "inline": False,
        }
    )

    embed = {
        "title": f"{status_emoji} {status_label} — {safe_alias} ({safe_faction})"[:256],
        "url": safe_url,
        "color": COLOR_WIN if win else COLOR_LOSS,
        "fields": fields,
        "footer": {
            "text": f"Partida #{match_id} • Relic ID {profile_id}"
            + (" • Replay disponível" if match.get("has_replay") else "")
        },
        "timestamp": iso_ts,
    }

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "embeds": [embed],
    }


def build_summary_list_payload(
    matches: list[dict[str, Any]],
    tracked_players: list[dict[str, Any]],
    bot_username: str = "CoH3 Brasil Monitor",
) -> dict[str, Any]:
    """Monta o payload seguro da Mensagem Lista Resumo fixada no canal privado."""
    player_names = ", ".join(
        f"**{sanitize_discord_text(p.get('alias'), max_len=32)}**" for p in tracked_players[:15]
    )
    if len(tracked_players) > 15:
        player_names += f" e +{len(tracked_players) - 15}"

    lines: list[str] = []
    for m in matches[:15]:
        icon = "🟢 **VITÓRIA**" if m["win"] else "🔴 **DERROTA**"
        ts = int(m["completion_time"])
        opps = m.get("opponents", [])
        if not opps:
            opp_summary = "—"
        elif len(opps) == 1:
            opp_alias = sanitize_discord_text(opps[0].get("alias"), max_len=28)
            opp_fac = sanitize_discord_text(opps[0].get("faction_short"), max_len=10)
            opp_summary = f"{opp_alias} ({opp_fac})"
        else:
            opp_alias = sanitize_discord_text(opps[0].get("alias"), max_len=28)
            opp_summary = f"{opp_alias} +{len(opps) - 1}"

        safe_alias = sanitize_discord_text(m.get("tracked_alias"), max_len=32)
        safe_fac_short = sanitize_discord_text(m.get("tracked_faction_short"), max_len=10)
        safe_map = sanitize_discord_text(m.get("map_clean"), max_len=36)
        safe_mode = CONTROL_CHARS_RE.sub("", str(m.get("mode", "")))[:24]
        safe_url = build_safe_coh3stats_match_url(m["tracked_profile_id"], m["match_id"])
        elo_txt = format_elo_compact(m.get("old_elo"), m.get("new_elo"))

        line = (
            f"• <t:{ts}:d> <t:{ts}:t> | {icon} — **{safe_alias}** ({safe_fac_short}) "
            f"• `{safe_mode}` **{safe_map}** vs *{opp_summary}* • ELO `{elo_txt}` "
            f"• [Ficha/Replay]({safe_url})"
        )
        lines.append(line)

    description_header = (
        f"🎯 **Monitorados ({len(tracked_players)}):** {player_names or 'Nenhum selecionado'}\n"
        "*(Dica: fixe esta mensagem no canal — ela é atualizada automaticamente a cada nova partida!)*\n\n"
    )
    body = "\n".join(lines) if lines else "_Ainda não há partidas catalogadas para os jogadores selecionados._"

    full_desc = description_header + body
    if len(full_desc) > 4000:
        full_desc = full_desc[:3990] + "\n…"

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    embed = {
        "title": "📌 Lista de Partidas Gravadas — Jogadores Brasileiros (CoH3)",
        "description": full_desc,
        "color": COLOR_SUMMARY,
        "footer": {
            "text": f"Atualizado via API Relic • Últimas {min(len(matches), 15)} partidas exibidas"
        },
        "timestamp": now_iso,
    }

    return {
        "username": sanitize_discord_text(bot_username, max_len=80),
        "allowed_mentions": SAFE_ALLOWED_MENTIONS,
        "embeds": [embed],
    }


class DiscordWebhookClient:
    """Envia e edita mensagens via Discord Webhook com validação estrita de domínio, TLS 1.2+ e redaction."""

    def __init__(self, webhook_url: str, bot_username: str = "CoH3 Brasil Monitor") -> None:
        self._webhook_url = (webhook_url or "").strip().rstrip("/")
        self.bot_username = bot_username

    def __repr__(self) -> str:
        return f"DiscordWebhookClient(configured={self.is_configured})"

    @property
    def is_configured(self) -> bool:
        return validate_discord_webhook_url(self._webhook_url)

    def _request(self, method: str, url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in ALLOWED_DISCORD_HOSTS:
            raise ValueError("URL de destino bloqueada pela política de segurança do DiscordWebhookClient.")

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        for _attempt in range(3):
            req = urllib.request.Request(
                url,
                data=body,
                method=method,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "CoH3-BR-Discord-Tracker/1.0",
                },
            )
            try:
                with _SECURE_OPENER.open(req, timeout=15) as resp:
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

    def send_match_card(self, match: dict[str, Any]) -> str | None:
        """Envia um Card individual da partida e retorna o message_id criado no Discord."""
        if not self.is_configured:
            return None
        payload = build_match_embed_payload(match, bot_username=self.bot_username)
        url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", url, payload)
        msg_id = str(data["id"]) if data and "id" in data else None
        return msg_id if msg_id and SNOWFLAKE_ID_RE.fullmatch(msg_id) else None

    def upsert_summary_message(
        self,
        matches: list[dict[str, Any]],
        tracked_players: list[dict[str, Any]],
        existing_message_id: str | None,
    ) -> str | None:
        """Atualiza (PATCH) a Lista Resumo fixada ou cria uma nova (POST)."""
        if not self.is_configured:
            return None
        payload = build_summary_list_payload(matches, tracked_players, bot_username=self.bot_username)

        clean_msg_id = (existing_message_id or "").strip()
        if clean_msg_id and SNOWFLAKE_ID_RE.fullmatch(clean_msg_id):
            parsed = urllib.parse.urlparse(self._webhook_url)
            edit_path = parsed.path.rstrip("/") + f"/messages/{clean_msg_id}"
            edit_url = urllib.parse.urlunparse(parsed._replace(path=edit_path))
            status, data = self._request("PATCH", edit_url, payload)
            if status != 404 and data and "id" in data:
                ret_id = str(data["id"])
                return ret_id if SNOWFLAKE_ID_RE.fullmatch(ret_id) else None
            logger.info("Mensagem resumo anterior (%s) não encontrada (404); criando nova.", clean_msg_id)

        post_url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", post_url, payload)
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
            "title": f"🆕 Novo(s) Brasileiro(s) no Top {int(top_n)} — Seguindo Automaticamente!",
            "description": "\n".join(lines)[:4000],
            "color": 0xF1C40F,
            "footer": {"text": "Monitoramento automático dos rankings 1v1, 2v2 e Team Games (3v3 + 4v4)"},
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        payload = {
            "username": sanitize_discord_text(self.bot_username, max_len=80),
            "allowed_mentions": SAFE_ALLOWED_MENTIONS,
            "embeds": [embed],
        }
        url = self._append_wait_param(self._webhook_url)
        _, data = self._request("POST", url, payload)
        ret_id = str(data["id"]) if data and "id" in data else None
        return ret_id if ret_id and SNOWFLAKE_ID_RE.fullmatch(ret_id) else None

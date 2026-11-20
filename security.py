"""Primitivas centrais de segurança: TLS 1.2+, anti-SSRF, anti-bomb HTTP/Gzip, redaction de segredos e I/O atômico."""

from __future__ import annotations

import logging
import os
import re
import ssl
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import Any

SAFE_WEBHOOK_PLACEHOLDER = "DEFINA_NOS_SECRETS_DO_GITHUB_DISCORD_WEBHOOK_URL"
SECRET_FILE_NAME = ".env.secret"

ALLOWED_DISCORD_HOSTS: frozenset[str] = frozenset(
    {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
)

WEBHOOK_PATH_RE = re.compile(r"^/api/(?:v\d+/)?webhooks/\d{15,25}/[A-Za-z0-9_-]{20,120}$")
WEBHOOK_REQUEST_PATH_RE = re.compile(
    r"^/api/(?:v\d+/)?webhooks/\d{15,25}/[A-Za-z0-9_-]{20,120}(?:/messages/\d{15,25})?$"
)

WEBHOOK_REDACT_RE = re.compile(
    r"https?://[^\s/\"'<>]+/api/(?:v\d+/)?webhooks/[^\s\"'<>]+",
    re.IGNORECASE,
)
ENV_SECRET_REDACT_RE = re.compile(
    r"(DISCORD_(?:LOBBY_)?WEBHOOK_URL\s*=\s*)[^\s\"'<>]+",
    re.IGNORECASE,
)
TOKEN_ENV_REDACT_RE = re.compile(
    r"((?:TRACKER_DISPATCH_TOKEN|GITHUB_TOKEN|GH_TOKEN)\s*=\s*)[^\s\"'<>]+",
    re.IGNORECASE,
)
STEAM_API_KEY_QUERY_REDACT_RE = re.compile(
    r"([?&]key=)[^&\s\"'<>]+",
    re.IGNORECASE,
)
STEAM_API_KEY_ENV_REDACT_RE = re.compile(
    r"(STEAM_WEB_API_KEY\s*=\s*)[^\s\"'<>]+",
    re.IGNORECASE,
)
STEAM_API_KEY_HEADER_REDACT_RE = re.compile(
    r"(x-webapi-key\s*[:=]\s*)[^\s\"'<>]+",
    re.IGNORECASE,
)
GITHUB_TOKEN_REDACT_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
)
AUTH_HEADER_REDACT_RE = re.compile(
    r"(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)[^\s\"'<>]+",
    re.IGNORECASE,
)

# Remove caracteres de controle ASCII, zero-width e overrides bidirecionais Unicode (anti-spoofing visual RLO)
UNSAFE_TEXT_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]+")
URL_FORBIDDEN_CHARS_RE = re.compile(r"[\x00-\x20\x7f]")
URL_PATH_TRAVERSAL_RE = re.compile(r"(?:^|/)\.\.(?:/|$)|%2e%2e|%5c|\\", re.IGNORECASE)

CSV_DANGEROUS_INITIALS = ("=", "+", "-", "@", "|")
_EXC_FORMATTER = logging.Formatter()


def redact_secrets(text: Any) -> str:
    """Remove URLs/tokens de Webhook, chaves Steam Web API, tokens GitHub e cabeçalhos Authorization de logs/erros."""
    raw = str(text or "")
    if not raw:
        return ""
    scrubbed = WEBHOOK_REDACT_RE.sub("[WEBHOOK_REDACTED]", raw)
    scrubbed = ENV_SECRET_REDACT_RE.sub(r"\1[WEBHOOK_REDACTED]", scrubbed)
    scrubbed = TOKEN_ENV_REDACT_RE.sub(r"\1[TOKEN_REDACTED]", scrubbed)
    scrubbed = STEAM_API_KEY_QUERY_REDACT_RE.sub(r"\1[STEAM_KEY_REDACTED]", scrubbed)
    scrubbed = STEAM_API_KEY_ENV_REDACT_RE.sub(r"\1[STEAM_KEY_REDACTED]", scrubbed)
    scrubbed = STEAM_API_KEY_HEADER_REDACT_RE.sub(r"\1[STEAM_KEY_REDACTED]", scrubbed)
    scrubbed = GITHUB_TOKEN_REDACT_RE.sub("[GH_TOKEN_REDACTED]", scrubbed)
    return AUTH_HEADER_REDACT_RE.sub(r"\1[AUTH_REDACTED]", scrubbed)


class SecretRedactingFilter(logging.Filter):
    """Filtro global de logging que impede vazamento acidental de Webhooks/tokens/tracebacks em stdout ou Actions."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(v) if isinstance(v, (str, BaseException)) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(a) if isinstance(a, (str, BaseException)) else a
                    for a in record.args
                )
        if record.exc_info:
            record.exc_text = redact_secrets(_EXC_FORMATTER.formatException(record.exc_info))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redact_secrets(record.exc_text)
        return True


def configure_secure_logging(level: int = logging.INFO, datefmt: str = "%Y-%m-%d %H:%M:%S") -> None:
    """Configura o logger raiz e anexa o filtro anti-vazamento em todos os handlers."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt=datefmt,
        )
    redact_filter = SecretRedactingFilter()
    root.addFilter(redact_filter)
    for handler in root.handlers:
        handler.addFilter(redact_filter)


def strip_unsafe_chars(raw: Any) -> str:
    """Substitui caracteres de controle e caracteres Unicode invisíveis/BiDi por espaço simples."""
    return UNSAFE_TEXT_CHARS_RE.sub(" ", str(raw or "")).strip()


def sanitize_csv_cell(val: Any) -> Any:
    """Previne CSV Formula Injection (CWE-1236) mesmo com espaços/quebras de linha à esquerda."""
    if not isinstance(val, str):
        return val
    cleaned = UNSAFE_TEXT_CHARS_RE.sub(" ", val.replace("\x00", ""))
    probe = cleaned.lstrip(" ")
    if cleaned.startswith(("\t", "\r", "\n")) or probe.startswith(CSV_DANGEROUS_INITIALS):
        return f"'{cleaned}"
    return cleaned


def create_hardened_ssl_context() -> ssl.SSLContext:
    """Cria contexto TLS 1.2+ com verificação obrigatória de certificado e hostname."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


class HttpsOnlySchemeHandler(urllib.request.BaseHandler):
    """Bloqueia no nível do OpenerDirector qualquer esquema fora de HTTPS (defesa em profundidade anti-SSRF/LFI)."""

    handler_order = 100

    def default_open(self, req: Any) -> Any:
        scheme = str(getattr(req, "type", "") or "").lower()
        if scheme != "https":
            raise urllib.error.URLError(f"Esquema '{scheme or '<vazio>'}' bloqueado pela política HTTPS-only.")
        return None

    http_open = default_open
    ftp_open = default_open
    file_open = default_open
    data_open = default_open


class StrictNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Bloqueia qualquer redirecionamento HTTP 3xx (proteção estrita contra SSRF e vazamento de headers)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "Redirecionamento HTTP bloqueado por política de segurança",
            headers,
            fp,
        )


def build_no_redirect_https_opener() -> urllib.request.OpenerDirector:
    """Constrói OpenerDirector HTTPS-only seguro sem redirecionamentos, preservando suporte a proxy do ambiente."""
    return urllib.request.build_opener(
        HttpsOnlySchemeHandler(),
        urllib.request.HTTPSHandler(context=create_hardened_ssl_context()),
        StrictNoRedirectHandler(),
    )


def validate_https_endpoint(
    url: str,
    allowed_hosts: set[str] | frozenset[str],
    path_prefix: str = "/",
    path_regex: re.Pattern[str] | None = None,
    allow_query: bool = True,
) -> urllib.parse.ParseResult:
    """Valida esquema HTTPS, host em allowlist, porta 443, ausência de credenciais/fragmentos/traversal e caminho permitido."""
    clean = (url or "").strip()
    if not clean or URL_FORBIDDEN_CHARS_RE.search(clean):
        raise ValueError("URL inválida ou contendo caracteres de controle proibidos.")
    parsed = urllib.parse.urlparse(clean)
    if parsed.scheme != "https":
        raise ValueError("Apenas conexões HTTPS são permitidas.")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise ValueError(f"Host bloqueado pela allowlist de segurança: {host or '<vazio>'}")
    if parsed.username or parsed.password:
        raise ValueError("Credenciais embutidas na URL são bloqueadas por segurança.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Porta inválida na URL.") from exc
    if port not in (None, 443):
        raise ValueError(f"Porta não autorizada bloqueada: {port}")
    if parsed.params or parsed.fragment or "#" in clean:
        raise ValueError("Parâmetros de caminho ou fragmentos de URL são bloqueados por segurança.")
    path_val = parsed.path or ""
    if URL_PATH_TRAVERSAL_RE.search(path_val):
        raise ValueError("Tentativa de path traversal na URL bloqueada.")
    if path_prefix and not path_val.startswith(path_prefix):
        raise ValueError("Caminho da URL fora do escopo permitido.")
    if path_regex is not None and not path_regex.fullmatch(path_val):
        raise ValueError("Formato do caminho da URL rejeitado pela validação estrita.")
    if not allow_query and (parsed.query or "?" in clean):
        raise ValueError("Query string não permitida nesta URL.")
    return parsed


def validate_discord_webhook_url(url: str, allow_message_subpath: bool = False) -> bool:
    """Valida estritamente URLs de Webhook do Discord (HTTPS, host oficial, porta 443 e token válido)."""
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return False
    pattern = WEBHOOK_REQUEST_PATH_RE if allow_message_subpath else WEBHOOK_PATH_RE
    try:
        parsed = validate_https_endpoint(
            raw,
            ALLOWED_DISCORD_HOSTS,
            path_prefix="/api/",
            path_regex=pattern,
            allow_query=allow_message_subpath,
        )
        if parsed.query:
            q_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if not q_pairs or any(k != "wait" or v != "true" for k, v in q_pairs):
                return False
        return True
    except ValueError:
        return False


def read_bounded_http_body(resp: Any, max_bytes: int) -> bytes:
    """
    Lê resposta HTTP em blocos de 64 KB com limite rígido no fio e na descompressão Gzip em streaming,
    prevenindo ataques de exaustão de memória / Gzip Bomb (CWE-409) e payloads truncados.
    """
    limit = max(1, int(max_bytes))
    raw_chunks: list[bytes] = []
    wire_total = 0
    while True:
        chunk = resp.read(min(65_536, limit - wire_total + 1))
        if not chunk:
            break
        wire_total += len(chunk)
        if wire_total > limit:
            raise RuntimeError(f"Resposta HTTP excedeu o limite máximo seguro ({limit} bytes).")
        raw_chunks.append(chunk)
    raw = b"".join(raw_chunks)

    encoding = ""
    if hasattr(resp, "headers") and resp.headers is not None:
        encoding = str(resp.headers.get("Content-Encoding", "")).strip().lower()

    if encoding in ("gzip", "x-gzip") and raw:
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out_chunks: list[bytes] = []
        uz_total = 0
        for off in range(0, len(raw), 65_536):
            pending = raw[off : off + 65_536]
            while pending:
                remaining = limit - uz_total
                piece = decomp.decompress(pending, remaining + 1)
                uz_total += len(piece)
                if uz_total > limit or decomp.unconsumed_tail:
                    raise RuntimeError(f"Payload Gzip descomprimido excedeu o limite seguro ({limit} bytes).")
                if piece:
                    out_chunks.append(piece)
                pending = decomp.unconsumed_tail
        tail = decomp.flush(limit - uz_total + 1)
        uz_total += len(tail)
        if uz_total > limit:
            raise RuntimeError(f"Payload Gzip descomprimido excedeu o limite seguro ({limit} bytes).")
        if tail:
            out_chunks.append(tail)
        if not decomp.eof:
            raise RuntimeError("Payload Gzip truncado ou corrompido rejeitado.")
        return b"".join(out_chunks)

    return raw


def read_local_secret_webhook(base_dir: Path) -> str:
    """Lê DISCORD_WEBHOOK_URL de .env.secret local sem seguir symlinks (O_NOFOLLOW) e reforça chmod 0600."""
    secret_path = base_dir / SECRET_FILE_NAME
    if not secret_path.is_file() or secret_path.is_symlink():
        return ""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(secret_path, flags)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
            return ""
        if os.name == "posix" and (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "r", encoding="utf-8") as secret_fp:
            fd = -1
            for line in secret_fp.read().splitlines():
                stripped = line.strip()
                if stripped.startswith("DISCORD_WEBHOOK_URL="):
                    return stripped.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return ""
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    return ""


def write_local_secret_webhook(base_dir: Path, webhook_url: str) -> Path:
    """Grava DISCORD_WEBHOOK_URL em .env.secret com permissão restrita 0600 (somente dono) e O_NOFOLLOW."""
    secret_path = base_dir / SECRET_FILE_NAME
    if secret_path.is_symlink():
        raise RuntimeError(f"Recusando gravar segredo em symlink: {secret_path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(secret_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as secret_fp:
        secret_fp.write(f"DISCORD_WEBHOOK_URL={webhook_url.strip()}\n")
    if os.name == "posix":
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
    return secret_path


def resolve_safe_db_path(base_dir: Path, cfg_db_path: str | None) -> Path:
    """
    Resolve o caminho do banco SQLite bloqueando Path Traversal fora do diretório do projeto,
    exceto quando explicitamente definido pela variável de ambiente confiável SQLITE_DB_PATH (ex.: Docker).
    """
    env_db = os.environ.get("SQLITE_DB_PATH", "").strip()
    if env_db:
        return Path(env_db).resolve()

    base_resolved = base_dir.resolve()
    raw = str(cfg_db_path or "./coh3_br_matches.db").strip() or "./coh3_br_matches.db"
    candidate = Path(raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (base_resolved / candidate).resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"Caminho de banco SQLite fora do diretório seguro bloqueado: {raw}") from exc
    return resolved


def resolve_data_dir(base_dir: Path) -> Path:
    """Retorna diretório de exportação de dados (permite COH3_DATA_DIR em containers read-only)."""
    env_dir = os.environ.get("COH3_DATA_DIR", "").strip()
    if env_dir:
        p = Path(env_dir).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p
    return base_dir.resolve()


def atomic_write_text(target_path: Path, content: str) -> None:
    """Escreve arquivo de texto atomicamente via tempfile.mkstemp (O_CREAT|O_EXCL, anti-CWE-377), com fallback O_NOFOLLOW."""
    if target_path.is_symlink():
        raise RuntimeError(f"Escrita bloqueada em symlink não confiável: {target_path}")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode: int | None = None
    if target_path.exists():
        try:
            existing_mode = stat.S_IMODE(target_path.stat().st_mode) & 0o666
        except OSError:
            existing_mode = None

    tmp_name = ""
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target_path.name}.",
            suffix=".tmp",
            dir=str(target_path.parent),
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        if existing_mode is not None and os.name == "posix":
            try:
                os.chmod(tmp_name, existing_mode)
            except OSError:
                pass
        if target_path.is_symlink():
            raise RuntimeError(f"Escrita bloqueada em symlink não confiável: {target_path}")
        os.replace(tmp_name, target_path)
        tmp_name = ""
    except OSError:
        if target_path.is_symlink():
            raise RuntimeError(f"Escrita bloqueada em symlink não confiável: {target_path}") from None
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fallback_fd = os.open(target_path, flags, existing_mode if existing_mode is not None else 0o644)
        with os.fdopen(fallback_fd, "w", encoding="utf-8") as fallback_fp:
            fallback_fp.write(content)
    finally:
        if tmp_name and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass

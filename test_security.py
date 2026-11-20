"""Testes unitários das primitivas de segurança do CoH3 BR Tracker (HTTPS-only, redaction, anti-bomb e symlinks)."""

from __future__ import annotations

import gzip
import io
import logging
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path

from security import (
    ALLOWED_DISCORD_HOSTS,
    SecretRedactingFilter,
    atomic_write_text,
    build_no_redirect_https_opener,
    read_bounded_http_body,
    redact_secrets,
    strip_unsafe_chars,
    validate_discord_webhook_url,
    validate_https_endpoint,
)


class _FakeHttpResponse:
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None) -> None:
        self._buf = io.BytesIO(payload)
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)


class TestTrackerSecurity(unittest.TestCase):
    def test_opener_blocks_non_https_schemes(self) -> None:
        opener = build_no_redirect_https_opener()
        for bad_url in (
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
            "ftp://example.com/resource",
            "data:text/plain;base64,SGVsbG8=",
        ):
            with self.assertRaises(urllib.error.URLError, msg=f"Esquema deveria ser bloqueado: {bad_url}"):
                opener.open(bad_url, timeout=2)

    def test_read_bounded_http_body_blocks_gzip_bomb(self) -> None:
        bomb_gz = gzip.compress(b"\x00" * (2 * 1024 * 1024))
        self.assertLess(len(bomb_gz), 10_000)
        resp = _FakeHttpResponse(bomb_gz, {"Content-Encoding": "gzip"})
        with self.assertRaises(RuntimeError):
            read_bounded_http_body(resp, max_bytes=65_536)

        valid_payload = b'{"ok": true, "matches": 12}'
        valid_gz = gzip.compress(valid_payload)
        valid_resp = _FakeHttpResponse(valid_gz, {"Content-Encoding": "gzip"})
        self.assertEqual(read_bounded_http_body(valid_resp, max_bytes=4096), valid_payload)

        # Gzip truncado/corrompido deve ser rejeitado (decomp.eof == False)
        truncated_resp = _FakeHttpResponse(valid_gz[:-4], {"Content-Encoding": "gzip"})
        with self.assertRaises(RuntimeError):
            read_bounded_http_body(truncated_resp, max_bytes=4096)

    def test_validate_https_endpoint_blocks_ssrf_vectors(self) -> None:
        for bad in (
            "http://discord.com/api/v10/resource",
            "https://discord.com.evil.com/api/v10/resource",
            "https://user:pass@discord.com/api/v10/resource",
            "https://discord.com:8443/api/v10/resource",
            "https://discord.com/other/path",
            "https://discord.com/api/../admin",
            "https://discord.com/api/%2e%2e/admin",
            "https://discord.com/api/v10/resource#frag",
            "https://discord.com/api/v10/resource;param=1",
            "https://discord.com/api/v10/resource\r\nX-Injected: 1",
        ):
            with self.assertRaises(ValueError, msg=f"URL insegura não bloqueada: {bad!r}"):
                validate_https_endpoint(bad, ALLOWED_DISCORD_HOSTS, path_prefix="/api/")

        with self.assertRaises(ValueError):
            validate_https_endpoint(
                "https://discord.com/api/v10/resource?key=leak",
                ALLOWED_DISCORD_HOSTS,
                path_prefix="/api/",
                allow_query=False,
            )

        self.assertFalse(validate_discord_webhook_url("https://evil.example/api/webhooks/123456789012345678/tok"))
        sample_wh = "https://discord.com" + "/api/" + "webhooks/" + "123456789012345678/" + ("B" * 32)
        self.assertTrue(validate_discord_webhook_url(sample_wh))
        self.assertFalse(validate_discord_webhook_url(sample_wh + "?wait=true", allow_message_subpath=False))
        self.assertTrue(validate_discord_webhook_url(sample_wh + "?wait=true", allow_message_subpath=True))
        self.assertFalse(validate_discord_webhook_url(sample_wh + "?wait=true&extra=1", allow_message_subpath=True))

    def test_steam_xml_opener_blocks_non_https_schemes(self) -> None:
        import card_renderer

        for bad_url in ("file:///etc/passwd", "http://steamcommunity.com/profiles/76561197963172584/?xml=1"):
            with self.assertRaises(urllib.error.URLError):
                card_renderer._STEAM_XML_OPENER.open(bad_url, timeout=2)

    def test_redact_secrets_scrubs_webhooks_steam_keys_tokens_and_tracebacks(self) -> None:
        fake_host = "https://discord.com"
        fake_path = "/api/" + "webhooks/" + "999999999999999999/" + ("A" * 40)
        fake_steam_key = "ABCDEF1234567890" + "FEDCBA0987654321"
        fake_gh_tok = "ghp_" + ("X" * 36)
        fake_bearer = "tok_live_" + ("Z" * 24)
        fake_disp_tok = "disp_sec_" + ("Q" * 20)
        leaked = (
            f"Erro {fake_host}{fake_path} DISCORD_WEBHOOK_URL=secret123 "
            f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={fake_steam_key}&steamids=76561197963172584 "
            f"STEAM_WEB_API_KEY={fake_steam_key} x-webapi-key: {fake_steam_key} "
            f"TRACKER_DISPATCH_TOKEN={fake_disp_tok} "
            f"token={fake_gh_tok} Authorization: Bearer {fake_bearer}"
        )
        scrubbed = redact_secrets(leaked)
        self.assertNotIn("999999999999999999", scrubbed)
        self.assertNotIn("secret123", scrubbed)
        self.assertNotIn(fake_steam_key, scrubbed)
        self.assertNotIn(fake_disp_tok, scrubbed)
        self.assertNotIn(fake_gh_tok, scrubbed)
        self.assertNotIn(fake_bearer, scrubbed)
        self.assertIn("[WEBHOOK_REDACTED]", scrubbed)
        self.assertIn("[TOKEN_REDACTED]", scrubbed)
        self.assertIn("[STEAM_KEY_REDACTED]", scrubbed)
        self.assertIn("[GH_TOKEN_REDACTED]", scrubbed)
        self.assertIn("[AUTH_REDACTED]", scrubbed)

        # Verifica que logger.exception() também sanitiza o traceback formatado (exc_info -> exc_text)
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SecretRedactingFilter())
        test_logger = logging.getLogger("coh3_br.test_security_exc")
        test_logger.propagate = False
        test_logger.setLevel(logging.ERROR)
        test_logger.handlers = [handler]
        try:
            raise RuntimeError(
                f"Falha em https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={fake_steam_key}"
            )
        except RuntimeError:
            test_logger.exception("Excecao capturada")
        logged = stream.getvalue()
        self.assertNotIn(fake_steam_key, logged)
        self.assertIn("[STEAM_KEY_REDACTED]", logged)

        # Remove RLO (U+202E) e caracteres de controle
        self.assertEqual(strip_unsafe_chars("Jogador\u202e\x00\x07Test"), "Jogador Test")

    def test_atomic_write_text_blocks_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            real_file = Path(td) / "real.txt"
            real_file.write_text("original", encoding="utf-8")
            link_path = Path(td) / "link.txt"
            os.symlink(real_file, link_path)
            with self.assertRaises(RuntimeError):
                atomic_write_text(link_path, "overwritten")
            self.assertEqual(real_file.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()

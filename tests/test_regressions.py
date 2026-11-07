"""Regression tests for the non-destructive crawl, console escaping and evidence redaction."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import httpx
import pytest
from rich.console import Console

from webprobe import cli
from webprobe.checks.exposed_files import evidence_from
from webprobe.client import ClientConfig, HttpClient
from webprobe.console import render
from webprobe.crawler import Crawler
from webprobe.models import Finding, ScanResult, Severity

# --- crawler: destructive actions in the query string -------------------------

HOME = """<html><body>
<a href="/index.php?action=logout">Log out</a>
<a href="/item.php?id=3&op=delete">Delete item</a>
<a href="/account.php?logout=1">Sign off</a>
<a href="/item.php?id=4&op=view">View item</a>
<a href="/search.php?q=shoes">Search</a>
</body></html>"""


def _crawl(handler) -> tuple:
    hits: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        hits.append(request.url.raw_path.decode())  # path + query
        return handler(request)

    async def go():
        async with HttpClient("https://app.test/", ClientConfig(timeout=5), transport=httpx.MockTransport(record)) as client:
            return await Crawler(client).crawl("https://app.test/")

    return asyncio.run(go()), hits


def test_crawler_skips_destructive_query_actions():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html=HOME)
        return httpx.Response(200, html="<p>ok</p>")

    result, hits = _crawl(handler)
    assert "/index.php?action=logout" not in hits
    assert "/item.php?id=3&op=delete" not in hits
    assert "/account.php?logout=1" not in hits
    assert set(result.skipped_unsafe) == {
        "https://app.test/index.php?action=logout",
        "https://app.test/item.php?id=3&op=delete",
        "https://app.test/account.php?logout=1",
    }
    # Harmless parameterised links are still crawled.
    assert "/item.php?id=4&op=view" in hits
    assert "/search.php?q=shoes" in hits


# --- console: scan data must not be parsed as rich markup ---------------------


def _result(**kwargs) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(target="https://app.test/", started_at=now, finished_at=now, **kwargs)


def _render(result: ScanResult, verbose: bool = False) -> str:
    console = Console(record=True, width=250, color_system=None)
    render(result, console, verbose=verbose)
    return console.export_text()


@pytest.mark.parametrize("verbose", [False, True])
def test_console_prints_brackets_literally(verbose):
    finding = Finding("reflection", "Reflected input in parameter 'filter[status]'", Severity.MEDIUM,
                      "https://app.test/list?filter[status]=open", "desc")
    result = _result(findings=[finding], errors=["[tls] RuntimeError: handshake failed"])
    out = _render(result, verbose)
    assert "'filter[status]'" in out
    assert "?filter[status]=open" in out
    assert "warning: [tls] RuntimeError" in out


def test_console_survives_closing_tag_in_warning():
    out = _render(_result(errors=["unexpected [/y] in response"]))
    assert "unexpected [/y] in response" in out


class _FakeScanner:
    result: ScanResult

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def run(self) -> ScanResult:
        return self.result


def test_cli_writes_report_with_markup_like_warning(tmp_path, monkeypatch):
    _FakeScanner.result = _result(errors=["unexpected [/y] in response"])
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    report = tmp_path / "out[1].json"
    assert cli.main(["https://app.test/", "-q", "-o", str(report)]) == 0
    assert json.loads(report.read_text())["errors"] == ["unexpected [/y] in response"]


def test_cli_writes_reports_before_rendering(tmp_path, monkeypatch):
    def broken_render(*args, **kwargs):
        raise RuntimeError("terminal exploded")

    _FakeScanner.result = _result()
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    monkeypatch.setattr(cli, "render", broken_render)
    report = tmp_path / "report.md"
    with pytest.raises(RuntimeError):
        cli.main(["https://app.test/", "-q", "-o", str(report)])
    assert report.exists()


# --- exposed files: private keys and password hashes in evidence --------------

KEY_BODY = "\n".join(["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"] * 20)


@pytest.mark.parametrize("kind", ["OPENSSH ", "RSA ", "EC ", ""])
def test_evidence_hides_private_key_body(kind):
    body = f"-----BEGIN {kind}PRIVATE KEY-----\n{KEY_BODY}\n-----END {kind}PRIVATE KEY-----\n".encode()
    evidence = evidence_from(body)
    assert evidence.splitlines() == [
        f"-----BEGIN {kind}PRIVATE KEY-----",
        f"[{len(KEY_BODY)} bytes of key material redacted]",
        f"-----END {kind}PRIVATE KEY-----",
    ]


def test_evidence_hides_truncated_private_key():
    evidence = evidence_from(f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}".encode())
    assert "b3Bl" not in evidence
    assert evidence.startswith("-----BEGIN RSA PRIVATE KEY-----\n[")


def test_evidence_hides_private_key_inside_env_file():
    body = f'APP_NAME=shop\nJWT_KEY="-----BEGIN PRIVATE KEY-----\\n{KEY_BODY[:60]}\\n-----END PRIVATE KEY-----"\n'
    evidence = evidence_from(body.encode())
    assert "b3Bl" not in evidence
    assert "APP_NAME=shop" in evidence


def test_evidence_hides_htpasswd_hashes():
    body = (b"admin:$apr1$Qz8n2bVs$Kx3m9YjvF0bG4tq1nM5Hk/\n"
            b"deploy:$2y$10$abcdefghijklmnopqrstuuJ8XgB2l7wqSvaYk3mFQd9h0Gx1rXyZe\n"
            b"legacy:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n"
            b"old:rl0fgHrV9A6Ys\n")
    evidence = evidence_from(body)
    assert evidence.splitlines() == ["admin:$apr1$****", "deploy:$2y$****", "legacy:{SHA}****", "old:****"]


def test_evidence_hides_wp_config_defines():
    body = (b"<?php\n"
            b"define( 'DB_NAME', 'shop' );\n"
            b"define( 'DB_USER', 'shopuser' );\n"
            b"define( 'DB_PASSWORD', 'Sup3rS3cretPw!' );\n"
            b'define("AUTH_KEY", "x7:Qp]Zt4#mLw9!aB");\n'
            b"define('NONCE_SALT','k2&Vd8pQ@zR1');\n")
    evidence = evidence_from(body)
    assert "Sup3rS3cretPw" not in evidence and "S3cret" not in evidence
    assert "Qp]Zt4" not in evidence and "k2&Vd8" not in evidence
    assert "define( 'DB_PASSWORD', 'Sup****' );" in evidence
    assert "define( 'DB_USER', 'shopuser' );" in evidence  # not a secret, keep for context

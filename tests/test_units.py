"""Unit tests for parsing/analysis helpers and header logic (no network)."""

from __future__ import annotations

import httpx
import pytest

from conftest import run_scan
from webprobe.checks import select_checks
from webprobe.checks.content_discovery import parse_robots
from webprobe.checks.cookies import parse_set_cookie
from webprobe.checks.exposed_files import evidence_from
from webprobe.checks.headers import parse_csp
from webprobe.checks.reflection import analyse_reflection, is_exploitable
from webprobe.checks.sql_errors import detect_db_error
from webprobe.client import NotFoundProfile, Response


def _response(status=200, body="", headers=None, url="https://app.test/x") -> Response:
    return Response(url, status, httpx.Headers(headers or {}), body.encode())


def test_parse_set_cookie():
    cookie = parse_set_cookie("SID=abc=def; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert cookie.name == "SID" and cookie.value == "abc=def"
    assert cookie.has("secure") and cookie.has("httponly")
    assert cookie.attributes["samesite"] == "Lax"
    assert parse_set_cookie("garbage") is None


def test_parse_csp():
    csp = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
    assert csp["script-src"] == ["'self'", "'unsafe-inline'"]
    assert "frame-ancestors" in csp


@pytest.mark.parametrize(
    ("body", "exploitable"),
    [
        ("<p>S\"'<>`E</p>", True),                                # raw in HTML text
        ("<p>S&quot;&#x27;&lt;&gt;`E</p>", False),               # encoded
        ("<p>S\"'E</p>", False),                                  # quotes alone are harmless in text
        ('<input value="S"\'&lt;&gt;`E">', True),                 # quote breaks out of attribute
        ("<script>var q = 'S\\\"\\'<>`E';</script>", True),       # inside script block
    ],
)
def test_reflection_analysis(body, exploitable):
    results = analyse_reflection(body, "S", "E")
    assert results
    assert any(is_exploitable(ctx, chars) for ctx, chars in results) is exploitable


def test_detect_db_error():
    assert detect_db_error("ERROR: unterminated quoted string at or near \"'\"")[0] == "PostgreSQL"
    assert detect_db_error("ORA-01756: quoted string not properly terminated")[0] == "Oracle"
    assert detect_db_error("<h1>Welcome</h1>") is None


def test_parse_robots():
    text = "User-agent: *\nDisallow: /admin/\nDisallow: /*.pdf$\nAllow: /public\nDisallow:\n"
    assert parse_robots(text) == ["admin/", "public"]


def test_evidence_redacts_secrets():
    evidence = evidence_from(b"DB_PASSWORD=supersecret\nAPI_KEY: abcdef123\nDEBUG=true")
    assert "supersecret" not in evidence and "abcdef123" not in evidence
    assert "DEBUG=true" in evidence


def test_not_found_profile_soft_404():
    sample = _response(200, "<h1>Oops</h1><p>We couldn't find /webprobe-abc.</p>")
    profile = NotFoundProfile([("webprobe-abc", sample)])
    assert profile.matches(_response(200, "<h1>Oops</h1><p>We couldn't find /backup.</p>"), "backup")
    assert not profile.matches(_response(200, "<html><h1>Admin dashboard</h1><table>...</table></html>"), "admin")
    assert profile.matches(_response(404), "anything")


def test_not_found_profile_redirect_to_login():
    sample = _response(302, headers={"location": "/login?next=/webprobe-abc"})
    profile = NotFoundProfile([("webprobe-abc", sample)])
    assert profile.matches(_response(302, headers={"location": "/login?next=/backup"}), "backup")
    assert not profile.matches(_response(301, headers={"location": "/admin/"}), "admin")


def test_select_checks_rejects_unknown_ids():
    with pytest.raises(ValueError, match="nope"):
        select_checks(["headers", "nope"])
    assert [c.id for c in select_checks(exclude=["tls"])].count("tls") == 0


HARDENED = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
    "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax",
}


def _mock(headers):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers=headers, html="<html><body>hi</body></html>")
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def test_hardened_site_has_no_header_or_cookie_findings():
    result = run_scan("https://app.test/", transport=_mock(HARDENED), checks=["headers", "cookies"], crawl=False)
    assert result.findings == []
    assert result.errors == []


def test_weak_csp_and_short_hsts():
    headers = {**HARDENED,
               "Content-Security-Policy": "script-src 'self' 'unsafe-inline' https:; frame-ancestors 'self'",
               "Strict-Transport-Security": "max-age=600"}
    result = run_scan("https://app.test/", transport=_mock(headers), checks=["headers"], crawl=False)
    titles = {f.title for f in result.findings}
    assert titles == {
        "Content-Security-Policy allows inline scripts",
        "Content-Security-Policy allows scripts from any origin",
        "Strict-Transport-Security max-age is too short",
    }


def test_off_host_redirect_aborts_scan():
    from webprobe.engine import ScanError

    transport = httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://elsewhere.test/"}))
    with pytest.raises(ScanError, match="different host"):
        run_scan("https://app.test/", transport=transport, crawl=False)

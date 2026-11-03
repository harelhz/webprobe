"""End-to-end scans against the local ShopLab target."""

from __future__ import annotations

import json

from conftest import run_scan
from webprobe.models import Severity
from webprobe.reports import to_html, to_json, to_markdown


def _titles(result, check):
    return [f.title for f in result.findings if f.check == check]


def test_full_scan_finds_every_planted_issue(lab):
    result = run_scan(lab.url)
    assert result.errors == []

    assert "Content-Security-Policy header missing" in _titles(result, "headers")
    assert "Software version disclosed in Server header" in _titles(result, "headers")
    assert "Software version disclosed in X-Powered-By header" in _titles(result, "headers")
    assert any("sessionid" in t and "HttpOnly" in t for t in _titles(result, "cookies"))
    assert "Site served over plain HTTP" in _titles(result, "tls")

    exposed = {f.title: f for f in result.findings if f.check == "exposed-files"}
    assert set(exposed) == {"Git repository exposed", "Environment file exposed"}
    assert exposed["Environment file exposed"].severity is Severity.CRITICAL  # contains a password
    assert "lab-password-123" not in exposed["Environment file exposed"].evidence  # redacted

    discovery = _titles(result, "content-discovery")
    assert "robots.txt discloses paths" in discovery
    assert "Administrative interface reachable" in discovery
    listing = next(f for f in result.findings if f.title.startswith("Discovered"))
    assert "/internal-reports/" in listing.evidence  # found via robots.txt

    cors = [f for f in result.findings if f.check == "cors"]
    assert any(f.severity is Severity.HIGH and "arbitrary" in f.title for f in cors)

    methods = _titles(result, "http-methods")
    assert "HTTP TRACE method enabled" in methods
    assert "Potentially dangerous HTTP methods advertised" in methods

    xss = [f for f in result.findings if f.check == "reflected-input"]
    assert [f.title for f in xss] == ["Reflected input not encoded in 'q' (possible XSS)"]
    assert all("/safe-search" not in f.url for f in xss)  # the escaped control case stays clean

    sqli = [f for f in result.findings if f.check == "sql-errors"]
    assert len(sqli) == 1
    assert sqli[0].severity is Severity.HIGH  # confirmed by the balanced-quote test
    assert "'id'" in sqli[0].title and "MySQL" in sqli[0].title


def test_crawler_never_follows_logout(lab):
    run_scan(lab.url, checks=["headers"])
    assert "/logout" not in lab.hits
    assert "/product" in lab.hits


def test_soft_404_server_produces_no_false_positives(soft404_lab):
    result = run_scan(soft404_lab.url, checks=["content-discovery", "exposed-files"])
    discovered = next(f for f in result.findings if f.title.startswith("Discovered"))
    found_paths = {line.split()[1] for line in discovered.evidence.splitlines()}
    # Only paths that really exist; everything else answers 200 "Oops" and must be filtered.
    assert found_paths == {"/admin", "/internal-reports/"}
    assert {f.title for f in result.findings if f.check == "exposed-files"} == {
        "Git repository exposed", "Environment file exposed",
    }


def test_min_severity_filters_findings(lab):
    result = run_scan(lab.url, min_severity=Severity.HIGH)
    assert result.findings
    assert all(f.severity >= Severity.HIGH for f in result.findings)


def test_reports_render(lab):
    result = run_scan(lab.url, checks=["headers", "exposed-files"])
    data = json.loads(to_json(result))
    assert data["summary"]["critical"] == 1
    assert len(data["findings"]) == len(result.findings)
    assert "Environment file exposed" in to_html(result)
    assert "## Findings" in to_markdown(result)

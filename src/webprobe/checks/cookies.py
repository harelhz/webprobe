from __future__ import annotations

import re
from dataclasses import dataclass

from webprobe.checks.base import Check
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

SENSITIVE_NAME_RE = re.compile(r"sess|sid|token|auth|jwt|login|remember|connect\.|identity", re.I)
# CSRF tokens are commonly readable by JS on purpose (double-submit pattern).
CSRF_NAME_RE = re.compile(r"csrf|xsrf", re.I)


@dataclass(slots=True)
class SetCookie:
    name: str
    value: str
    attributes: dict[str, str]  # lower-cased keys; boolean flags map to ""

    def has(self, attribute: str) -> bool:
        return attribute in self.attributes


def parse_set_cookie(header: str) -> SetCookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, _, value = parts[0].partition("=")
    attributes = {}
    for part in parts[1:]:
        if part:
            key, _, val = part.partition("=")
            attributes[key.strip().lower()] = val.strip()
    return SetCookie(name.strip(), value.strip(), attributes)


class CookieFlagsCheck(Check):
    id = "cookies"
    name = "Cookie security attributes"
    description = "Secure / HttpOnly / SameSite flags on cookies set by the application."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for response in ctx.responses():
            https = response.url.startswith("https://")
            for header in response.headers.get_list("set-cookie"):
                cookie = parse_set_cookie(header)
                if cookie is None or cookie.name in seen:
                    continue
                seen.add(cookie.name)
                finding = self._assess(cookie, header, response.url, https)
                if finding:
                    findings.append(finding)
        return findings

    def _assess(self, cookie: SetCookie, raw: str, url: str, https: bool) -> Finding | None:
        sensitive = bool(SENSITIVE_NAME_RE.search(cookie.name)) and not CSRF_NAME_RE.search(cookie.name)
        problems: list[tuple[str, Severity, str]] = []

        if https and not cookie.has("secure"):
            problems.append(("Secure", Severity.MEDIUM if sensitive else Severity.LOW,
                             "the cookie can be sent over plain HTTP and sniffed"))
        if not cookie.has("httponly") and not CSRF_NAME_RE.search(cookie.name):
            problems.append(("HttpOnly", Severity.MEDIUM if sensitive else Severity.LOW,
                             "JavaScript (including injected XSS payloads) can read the cookie"))
        samesite = cookie.attributes.get("samesite", "").lower()
        if not samesite:
            problems.append(("SameSite", Severity.LOW if sensitive else Severity.INFO,
                             "cross-site requests rely on browser defaults for CSRF protection"))
        elif samesite == "none" and not cookie.has("secure"):
            problems.append(("SameSite=None requires Secure", Severity.LOW,
                             "browsers reject SameSite=None cookies without Secure"))

        if not problems:
            return None
        missing = ", ".join(p[0] for p in problems)
        kind = "Session-like cookie" if sensitive else "Cookie"
        return self.finding(
            f"{kind} '{cookie.name}' missing {missing}",
            max(p[1] for p in problems),
            url,
            "; ".join(f"Missing {flag}: {why}" for flag, _, why in problems) + ".",
            evidence=f"Set-Cookie: {_redact_value(raw)}",
            remediation="Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict) unless there is a specific reason not to.",
            references=["https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies"],
        )


def _redact_value(raw: str) -> str:
    name, sep, rest = raw.partition("=")
    value, semi, attrs = rest.partition(";")
    shown = value[:4] + "…" if len(value) > 6 else value
    return f"{name}{sep}{shown}{semi}{attrs}"

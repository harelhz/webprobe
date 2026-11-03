from __future__ import annotations

import re

from webprobe.checks.base import Check
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

HSTS_MIN_AGE = 15_552_000  # 180 days
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy into {directive: [sources]}. First occurrence wins."""
    directives: dict[str, list[str]] = {}
    for part in policy.replace(",", ";").split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


class SecurityHeadersCheck(Check):
    id = "headers"
    name = "Security headers"
    description = "Missing/weak browser security headers and version disclosure."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        response = ctx.homepage
        headers = response.headers
        url = response.url
        findings: list[Finding] = []

        csp_raw = headers.get("content-security-policy")
        csp = parse_csp(csp_raw) if csp_raw else {}
        if not csp_raw:
            findings.append(self.finding(
                "Content-Security-Policy header missing", Severity.MEDIUM, url,
                "Without a CSP the browser will execute any injected script, so a single XSS bug becomes fully exploitable.",
                remediation="Define a restrictive policy, e.g. \"default-src 'self'; object-src 'none'; base-uri 'self'\", and tighten from there.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
            ))
        else:
            findings += self._weak_csp(csp, csp_raw, url)

        xfo = headers.get("x-frame-options", "").strip().upper()
        if "frame-ancestors" not in csp and xfo not in ("DENY", "SAMEORIGIN"):
            findings.append(self.finding(
                "Clickjacking protection missing", Severity.MEDIUM, url,
                "The page can be framed by any site (no X-Frame-Options or CSP frame-ancestors), enabling clickjacking.",
                evidence=f"X-Frame-Options: {xfo or '(absent)'}",
                remediation="Send \"Content-Security-Policy: frame-ancestors 'self'\" (and X-Frame-Options: SAMEORIGIN for old browsers).",
                references=["https://owasp.org/www-community/attacks/Clickjacking"],
            ))

        if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
            findings.append(self.finding(
                "X-Content-Type-Options header missing", Severity.LOW, url,
                "Browsers may MIME-sniff responses, which can turn user uploads into executable content.",
                remediation="Send \"X-Content-Type-Options: nosniff\" on all responses.",
                references=[OWASP_HEADERS],
            ))

        if url.startswith("https://"):
            findings += self._hsts(headers.get("strict-transport-security"), url)

        if not headers.get("referrer-policy"):
            findings.append(self.finding(
                "Referrer-Policy header missing", Severity.INFO, url,
                "Modern browsers default to strict-origin-when-cross-origin, but an explicit policy avoids leaking full URLs (and any tokens in them) on older clients.",
                remediation="Send \"Referrer-Policy: strict-origin-when-cross-origin\" or stricter.",
            ))
        if not headers.get("permissions-policy"):
            findings.append(self.finding(
                "Permissions-Policy header missing", Severity.INFO, url,
                "No Permissions-Policy restricts powerful browser features (camera, geolocation, ...) for this origin and its frames.",
                remediation="Send a Permissions-Policy disabling features the app doesn't use, e.g. \"camera=(), microphone=(), geolocation=()\".",
            ))

        for name in DISCLOSURE_HEADERS:
            value = headers.get(name)
            if not value:
                continue
            if VERSION_RE.search(value):
                findings.append(self.finding(
                    f"Software version disclosed in {name} header", Severity.LOW, url,
                    "Exact version numbers let attackers look up known CVEs for this software without any probing.",
                    evidence=f"{name}: {value}",
                    remediation=f"Remove the {name} header or strip the version (e.g. ServerTokens Prod / server_tokens off).",
                ))
            elif name != "Server":
                findings.append(self.finding(
                    f"Technology disclosed in {name} header", Severity.INFO, url,
                    "The response advertises the framework/platform in use.",
                    evidence=f"{name}: {value}",
                    remediation=f"Remove the {name} header.",
                ))
        return findings

    def _weak_csp(self, csp: dict[str, list[str]], raw: str, url: str) -> list[Finding]:
        findings = []
        scripts = csp.get("script-src", csp.get("default-src"))
        if scripts is None:
            findings.append(self.finding(
                "Content-Security-Policy does not restrict scripts", Severity.LOW, url,
                "The policy has neither script-src nor default-src, so script loading is unrestricted.",
                evidence=raw, remediation="Add a default-src and/or script-src directive.",
            ))
            return findings
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts)
        if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
            findings.append(self.finding(
                "Content-Security-Policy allows inline scripts", Severity.LOW, url,
                "'unsafe-inline' lets injected <script> blocks and event handlers run, which defeats most of CSP's XSS protection.",
                evidence=raw, remediation="Replace 'unsafe-inline' with nonces or hashes.",
            ))
        if "'unsafe-eval'" in scripts:
            findings.append(self.finding(
                "Content-Security-Policy allows eval()", Severity.LOW, url,
                "'unsafe-eval' permits eval()/new Function(), widening DOM-XSS impact.",
                evidence=raw, remediation="Refactor code that needs eval and drop 'unsafe-eval'.",
            ))
        if any(s in ("*", "http:", "https:", "data:") for s in scripts):
            findings.append(self.finding(
                "Content-Security-Policy allows scripts from any origin", Severity.LOW, url,
                "A wildcard or scheme-only script source lets an attacker load script from a host they control.",
                evidence=raw, remediation="List specific trusted origins, or use 'strict-dynamic' with nonces.",
            ))
        return findings

    def _hsts(self, value: str | None, url: str) -> list[Finding]:
        if not value:
            return [self.finding(
                "Strict-Transport-Security header missing", Severity.MEDIUM, url,
                "Without HSTS, a network attacker can downgrade first visits to HTTP (SSL stripping).",
                remediation="Send \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".",
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            )]
        match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
        max_age = int(match.group(1)) if match else 0
        if max_age < HSTS_MIN_AGE:
            return [self.finding(
                "Strict-Transport-Security max-age is too short", Severity.LOW, url,
                f"HSTS max-age is {max_age}s; browsers forget the policy quickly, re-opening the downgrade window.",
                evidence=f"Strict-Transport-Security: {value}",
                remediation="Use a max-age of at least 15552000 (180 days); 31536000 is typical.",
            )]
        return []

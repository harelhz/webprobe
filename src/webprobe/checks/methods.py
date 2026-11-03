from __future__ import annotations

import secrets

from webprobe.checks.base import Check
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

RISKY_METHODS = frozenset({"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"})


class HTTPMethodsCheck(Check):
    id = "http-methods"
    name = "HTTP methods"
    description = "Advertised risky methods (OPTIONS) and TRACE echo. Never sends PUT/DELETE."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        url = ctx.target

        options = await ctx.client.fetch(url, method="OPTIONS", max_bytes=8_000)
        if options is not None:
            allow = options.headers.get("allow", "")
            advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = sorted(advertised & RISKY_METHODS)
            if risky:
                findings.append(self.finding(
                    "Potentially dangerous HTTP methods advertised", Severity.LOW, url,
                    f"The server advertises {', '.join(risky)}. Advertised isn't the same as allowed: "
                    "verify manually (on a throwaway path) whether e.g. PUT can create files.",
                    evidence=f"Allow: {allow}",
                    remediation="Disable methods the application doesn't need at the web server.",
                ))

        canary = secrets.token_hex(8)
        trace = await ctx.client.fetch(url, method="TRACE", headers={"X-Webprobe-Trace": canary}, max_bytes=16_000)
        if trace is not None and trace.status == 200 and canary in trace.text:
            findings.append(self.finding(
                "HTTP TRACE method enabled", Severity.LOW, url,
                "TRACE echoes the request back, including headers. Combined with other bugs it can expose "
                "HttpOnly cookies or auth headers (Cross-Site Tracing).",
                evidence=f"Request header X-Webprobe-Trace: {canary} was echoed in the response body",
                remediation="Disable TRACE (Apache: TraceEnable off).",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            ))
        return findings

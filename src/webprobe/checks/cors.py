from __future__ import annotations

import httpx

from webprobe.checks.base import Check
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

ATTACKER_DOMAIN = "webprobe-attacker.example"
MAX_URLS = 5
REFERENCES = ["https://portswigger.net/web-security/cors"]


class CORSCheck(Check):
    id = "cors"
    name = "CORS misconfiguration"
    description = "Origin reflection, null origin and weak origin-matching in Access-Control-Allow-Origin."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for url in self._urls(ctx):
            target = httpx.URL(url)
            probes = [
                ("arbitrary", f"https://{ATTACKER_DOMAIN}",
                 "The server reflects any Origin into Access-Control-Allow-Origin."),
                ("null", "null",
                 "The server trusts the 'null' origin, which any site can produce from a sandboxed iframe."),
                ("suffix", f"{target.scheme}://{target.host}.{ATTACKER_DOMAIN}",
                 "Origin validation only checks the prefix, so an attacker-registered subdomain like this one is trusted."),
                ("prefix", f"{target.scheme}://attacker{target.host}",
                 "Origin validation only checks the suffix, so an attacker-registered domain ending in the target's name is trusted."),
            ]
            for kind, origin, description in probes:
                response = await ctx.client.fetch(url, headers={"Origin": origin}, max_bytes=8_000)
                if response is None:
                    continue
                acao = response.headers.get("access-control-allow-origin", "")
                credentials = response.headers.get("access-control-allow-credentials", "").lower() == "true"
                if acao != origin:
                    continue
                severity = Severity.HIGH if credentials else Severity.LOW
                impact = (
                    " Because credentials are allowed, a malicious site can read authenticated responses (account data, CSRF tokens) as the victim."
                    if credentials else
                    " Credentials aren't allowed, so impact is limited to data readable without a session (e.g. intranet-only content)."
                )
                findings.append(self.finding(
                    f"CORS trusts {kind} origin" + (" with credentials" if credentials else ""),
                    severity, url, description + impact,
                    evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}\n"
                             f"Access-Control-Allow-Credentials: {str(credentials).lower()}",
                    remediation="Validate Origin against an exact allow-list of trusted origins; never reflect it or trust 'null'.",
                    references=REFERENCES,
                ))
                if kind == "arbitrary":
                    break  # full reflection subsumes the narrower bypasses
        return findings

    @staticmethod
    def _urls(ctx: ScanContext) -> list[str]:
        urls = [ctx.homepage.url]
        for url, response in ctx.crawl.pages.items():
            if len(urls) >= MAX_URLS:
                break
            if url not in urls and ("/api" in url or response.content_type == "application/json"):
                urls.append(url)
        return urls

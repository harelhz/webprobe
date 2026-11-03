from __future__ import annotations

import asyncio
import re
from importlib.resources import files
from pathlib import Path

from webprobe.checks.base import Check
from webprobe.client import Response
from webprobe.context import ScanContext
from webprobe.models import Finding, Severity

INTERESTING_STATUS = frozenset({200, 204, 301, 302, 307, 308, 401, 403, 405})
# If more than this share of paths "exist", the server is answering everything and results are noise.
WILDCARD_RATIO = 0.6

# Paths worth their own finding when reachable (HTTP 200). Matched against the path's first segments.
NOTABLE: dict[str, tuple[str, Severity, str]] = {
    "admin": ("Administrative interface reachable", Severity.LOW, "An admin area is reachable without network restriction; make sure it's protected by strong auth and ideally an allow-list."),
    "administrator": ("Administrative interface reachable", Severity.LOW, "An admin area is reachable without network restriction."),
    "wp-admin": ("WordPress admin reachable", Severity.LOW, "The WordPress admin login is publicly reachable; consider IP restrictions and 2FA."),
    "phpmyadmin": ("phpMyAdmin exposed", Severity.MEDIUM, "A database administration panel is publicly reachable."),
    "adminer.php": ("Adminer database tool exposed", Severity.MEDIUM, "A database administration tool is publicly reachable."),
    "manager/html": ("Tomcat manager exposed", Severity.MEDIUM, "The Tomcat manager allows WAR deployment (code execution) if credentials are weak."),
    "console": ("Debug/admin console reachable", Severity.MEDIUM, "A console endpoint is reachable; debug consoles (Werkzeug, H2, ...) can give code execution."),
    "h2-console": ("H2 database console exposed", Severity.MEDIUM, "The H2 web console is reachable and is a known remote-code-execution vector."),
    "debug": ("Debug endpoint reachable", Severity.MEDIUM, "A debug endpoint is reachable in what may be a production deployment."),
    "_profiler": ("Symfony profiler exposed", Severity.MEDIUM, "The Symfony profiler discloses requests, environment and credentials."),
    "elmah.axd": ("ELMAH error log exposed", Severity.MEDIUM, "ELMAH exposes full error logs including cookies and session data."),
    "trace.axd": ("ASP.NET trace exposed", Severity.MEDIUM, "trace.axd discloses request details of other users."),
    "jmx-console": ("JBoss JMX console exposed", Severity.MEDIUM, "The JMX console allows management actions, historically leading to RCE."),
    "web-console": ("JBoss web console exposed", Severity.MEDIUM, "A JBoss management console is reachable."),
    "graphql": ("GraphQL endpoint found", Severity.INFO, "Check whether introspection is enabled and whether queries are depth/cost limited."),
    "graphiql": ("GraphiQL IDE exposed", Severity.LOW, "An interactive GraphQL IDE is publicly reachable."),
    "swagger": ("API documentation exposed", Severity.LOW, "Public API docs map out every endpoint for an attacker; fine for public APIs, not for internal ones."),
    "swagger-ui": ("API documentation exposed", Severity.LOW, "Public API docs map out every endpoint for an attacker."),
    "swagger-ui.html": ("API documentation exposed", Severity.LOW, "Public API docs map out every endpoint for an attacker."),
    "swagger.json": ("API specification exposed", Severity.LOW, "The OpenAPI/Swagger spec lists every endpoint and parameter."),
    "openapi.json": ("API specification exposed", Severity.LOW, "The OpenAPI spec lists every endpoint and parameter."),
    "api-docs": ("API documentation exposed", Severity.LOW, "Public API docs map out every endpoint for an attacker."),
    "v2/api-docs": ("API specification exposed", Severity.LOW, "The Swagger spec lists every endpoint and parameter."),
    "v3/api-docs": ("API specification exposed", Severity.LOW, "The OpenAPI spec lists every endpoint and parameter."),
    "actuator": ("Spring Boot actuator exposed", Severity.LOW, "Actuator endpoints are reachable; review which ones are enabled (env, heapdump, mappings)."),
    "actuator/mappings": ("Spring Boot actuator mappings exposed", Severity.LOW, "All application routes are disclosed."),
    "xmlrpc.php": ("WordPress XML-RPC enabled", Severity.LOW, "XML-RPC enables credential brute-forcing via system.multicall and pingback abuse."),
}


def load_wordlist(path: Path | None) -> list[str]:
    text = path.read_text() if path else (files("webprobe") / "data" / "wordlist.txt").read_text()
    words = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line.lstrip("/"))
    return list(dict.fromkeys(words))


def parse_robots(text: str) -> list[str]:
    paths = []
    for line in text.splitlines():
        match = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
        if match:
            path = re.split(r"[*$]", match.group(1), maxsplit=1)[0].lstrip("/")
            if path:
                paths.append(path)
    return list(dict.fromkeys(paths))


class ContentDiscoveryCheck(Check):
    id = "content-discovery"
    name = "Content discovery"
    description = "Wordlist + robots.txt path enumeration with soft-404 filtering."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = load_wordlist(ctx.options.wordlist)

        robots = await ctx.client.fetch("robots.txt", max_bytes=64_000)
        if robots is not None and robots.status == 200 and "text/html" not in robots.content_type:
            robot_paths = parse_robots(robots.text)
            if robot_paths:
                findings.append(self.finding(
                    "robots.txt discloses paths", Severity.INFO, robots.url,
                    "robots.txt is not access control; entries often point at areas the owner considers sensitive.",
                    evidence="\n".join(f"/{p}" for p in robot_paths[:30]),
                ))
                candidates = list(dict.fromkeys(candidates + robot_paths))

        responses = await asyncio.gather(*(ctx.client.fetch(path, max_bytes=32_000) for path in candidates))
        hits: list[tuple[str, Response]] = []
        for path, response in zip(candidates, responses):
            if response is None or response.status not in INTERESTING_STATUS:
                continue
            if ctx.not_found.matches(response, path):
                continue
            hits.append((path, response))

        if candidates and len(hits) / len(candidates) > WILDCARD_RATIO:
            findings.append(self.finding(
                "Content discovery inconclusive", Severity.INFO, ctx.target,
                f"{len(hits)} of {len(candidates)} paths returned a non-404 answer that didn't match the not-found "
                "baseline, so the server likely answers every path. Results were discarded to avoid false positives.",
            ))
            return findings

        if hits:
            findings.append(self.finding(
                f"Discovered {len(hits)} paths", Severity.INFO, ctx.target,
                "Paths that exist on the server (status code, size, redirect target). Review each one manually.",
                evidence="\n".join(self._describe(path, r) for path, r in hits),
            ))
        for path, response in hits:
            notable = self._notable(path)
            if notable and response.status == 200:
                title, severity, description = notable
                findings.append(self.finding(title, severity, response.url, description, evidence=self._describe(path, response)))
        return findings

    @staticmethod
    def _describe(path: str, response: Response) -> str:
        size = f"{len(response.content)}{'+' if response.truncated else ''}B"
        line = f"{response.status}  /{path}  ({size})"
        return f"{line} -> {response.location}" if response.location else line

    @staticmethod
    def _notable(path: str) -> tuple[str, Severity, str] | None:
        clean = path.strip("/").lower()
        while clean:
            if clean in NOTABLE:
                return NOTABLE[clean]
            clean = clean.rpartition("/")[0]
        return None

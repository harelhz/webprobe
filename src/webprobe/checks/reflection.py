"""Reflected-input detection: a harmless marker, not an XSS payload.

We send ``<token>"'<>`<end-token>`` and look at what comes back between the
two tokens. If the special characters survive unencoded *in a context where
they matter*, the parameter is very likely injectable. Confirming actual script
execution is left to the tester.
"""

from __future__ import annotations

import asyncio
import re
import secrets

from webprobe.checks.base import Check
from webprobe.context import InjectionPoint, ScanContext
from webprobe.models import Finding, Severity

PROBE = "\"'<>`"


def reflection_context(body: str, position: int) -> str:
    """Rough HTML context of ``position``: 'script', 'attribute' or 'html'."""
    before = body[:position]
    lower = before.lower()
    if lower.rfind("<script") > lower.rfind("</script"):
        return "script"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


def analyse_reflection(body: str, start: str, end: str) -> list[tuple[str, set[str]]]:
    """Return (context, unencoded special chars) for every reflection of the probe."""
    results = []
    for match in re.finditer(re.escape(start) + r"(.{0,60}?)" + re.escape(end), body, re.S):
        survived = {c for c in PROBE if c in match.group(1)}
        results.append((reflection_context(body, match.start()), survived))
    return results


def is_exploitable(context: str, survived: set[str]) -> bool:
    if context == "html":
        return {"<", ">"} <= survived
    if context == "attribute":
        return bool(survived & {'"', "'", ">"})
    return bool(survived & {'"', "'", "`", "<"})  # script


class ReflectedInputCheck(Check):
    id = "reflected-input"
    name = "Reflected input (XSS indicator)"
    description = "Detects parameters reflected without HTML encoding, using a benign marker."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = ctx.injection_points()
        results = await asyncio.gather(*(self._probe(ctx, point) for point in points))
        return [f for f in results if f is not None]

    async def _probe(self, ctx: ScanContext, point: InjectionPoint) -> Finding | None:
        start, end = f"wp{secrets.token_hex(4)}", f"pw{secrets.token_hex(4)}"
        url = point.build(f"{start}{PROBE}{end}")
        response = await ctx.client.fetch(url)
        if response is None or not response.is_html:
            return None
        for context, survived in analyse_reflection(response.text, start, end):
            if is_exploitable(context, survived):
                chars = " ".join(sorted(survived))
                return self.finding(
                    f"Reflected input not encoded in '{point.name}' (possible XSS)", Severity.MEDIUM, point.url,
                    f"The value of parameter '{point.name}' is reflected into the page ({context} context) and the "
                    f"characters {chars} come back unencoded. That usually means script can be injected; confirm "
                    "manually with a context-appropriate payload.",
                    evidence=f"Request: {url}\nInjected: {start}{PROBE}{end}\nContext: {context}\nUnencoded: {chars}",
                    remediation="HTML-encode output for the context it lands in (use the template engine's auto-escaping) "
                                "and add a strict Content-Security-Policy as defence in depth.",
                    references=["https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                )
        return None

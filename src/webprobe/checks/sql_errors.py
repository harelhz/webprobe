"""Error-based SQL injection indicator.

Appends a single quote to each parameter and looks for database error messages
that weren't in the baseline response. If a balanced pair of quotes makes the
error go away again, that strongly suggests the input lands inside a SQL string.
No data is extracted.
"""

from __future__ import annotations

import asyncio
import re

from webprobe.checks.base import Check
from webprobe.context import InjectionPoint, ScanContext
from webprobe.models import Finding, Severity

DB_ERRORS: list[tuple[str, re.Pattern[str]]] = [
    ("MySQL/MariaDB", re.compile(
        r"SQL syntax.{0,80}(?:MySQL|MariaDB)|check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB)|"
        r"Warning.{0,40}\Wmysqli?_|MySqlException|com\.mysql\.jdbc", re.I | re.S)),
    ("PostgreSQL", re.compile(
        r"PostgreSQL.{0,40}ERROR|Warning.{0,40}\Wpg_|PG::SyntaxError|org\.postgresql\.util\.PSQLException|"
        r"Npgsql\.|unterminated quoted string at or near", re.I | re.S)),
    ("Microsoft SQL Server", re.compile(
        r"Unclosed quotation mark after the character string|System\.Data\.SqlClient\.SqlException|"
        r"Microsoft SQL Native Client error|ODBC SQL Server Driver|Incorrect syntax near", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}\b|quoted string not properly terminated|oracle\.jdbc", re.I)),
    ("SQLite", re.compile(
        r"SQLite3::SQLException|sqlite3\.OperationalError|SQLITE_ERROR|System\.Data\.SQLite|unrecognized token:", re.I)),
    ("Generic SQL", re.compile(r"SQLSTATE\[\w+\]|syntax error at or near|You have an error in your SQL syntax", re.I)),
]


def detect_db_error(text: str) -> tuple[str, str] | None:
    """Return (database, matched text) for the first DB error message found."""
    for database, pattern in DB_ERRORS:
        match = pattern.search(text)
        if match:
            return database, match.group(0)
    return None


class SQLErrorCheck(Check):
    id = "sql-errors"
    name = "SQL error disclosure (SQLi indicator)"
    description = "Single-quote probe per parameter; reports database errors that appear only with the probe."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        points = ctx.injection_points()
        results = await asyncio.gather(*(self._probe(ctx, point) for point in points))
        return [f for f in results if f is not None]

    async def _probe(self, ctx: ScanContext, point: InjectionPoint) -> Finding | None:
        baseline = await ctx.client.fetch(point.build(point.original))
        if baseline is None or detect_db_error(baseline.text):
            return None  # page already shows DB errors; can't attribute them to us

        for quote in ("'", '"'):
            probe_url = point.build(point.original + quote)
            probe = await ctx.client.fetch(probe_url)
            if probe is None:
                continue
            error = detect_db_error(probe.text)
            if error is None:
                continue
            balanced = await ctx.client.fetch(point.build(point.original + quote * 2))
            confirmed = balanced is not None and detect_db_error(balanced.text) is None
            database, snippet = error
            return self.finding(
                f"Possible SQL injection in '{point.name}' ({database} error)",
                Severity.HIGH if confirmed else Severity.MEDIUM,
                probe_url,
                f"Adding {quote} to parameter '{point.name}' triggers a {database} error message"
                + (", and doubling it makes the error disappear. The input is very likely concatenated into a SQL query."
                   if confirmed else ". This suggests the input reaches a SQL query unsanitised."),
                evidence=f"Probe: {point.name}={point.original + quote}\nHTTP {probe.status}\nError: {snippet[:200]}"
                         + (f"\nBalanced {quote * 2}: no error (HTTP {balanced.status})" if confirmed else ""),
                remediation="Use parameterised queries / prepared statements everywhere, and stop returning raw database errors to clients.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
            )
        return None

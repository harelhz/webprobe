"""Scan orchestration: resolve target -> baseline -> crawl -> run checks -> collate."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

import httpx

from webprobe.checks import Check, select_checks
from webprobe.client import ClientConfig, HttpClient, NotFoundProfile
from webprobe.context import ScanContext, ScanOptions
from webprobe.crawler import Crawler, CrawlResult
from webprobe.models import Finding, ScanResult

MAX_REDIRECTS = 5


class ScanError(Exception):
    """The scan couldn't start (unreachable target, off-host redirect, ...)."""


class Scanner:
    def __init__(
        self,
        target: str,
        config: ClientConfig | None = None,
        options: ScanOptions | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> None:
        self.target = target
        self.config = config or ClientConfig()
        self.options = options or ScanOptions()
        self.transport = transport
        self._progress = on_progress or (lambda message: None)
        self.checks: list[Check] = select_checks(self.options.checks, self.options.exclude)

    async def run(self) -> ScanResult:
        result = ScanResult(target=self.target, started_at=datetime.now(timezone.utc))
        async with HttpClient(self.target, self.config, transport=self.transport) as client:
            try:
                homepage = await self._resolve(client)
                result.target = str(client.base_url)

                self._progress("Fingerprinting not-found behaviour")
                not_found = await NotFoundProfile.build(client)

                crawl = CrawlResult()
                if self.options.crawl:
                    self._progress("Crawling")
                    crawler = Crawler(client, max_pages=self.options.max_pages, max_depth=self.options.max_depth)
                    crawl = await crawler.crawl(str(client.base_url))
                result.pages_crawled = len(crawl.pages)

                ctx = ScanContext(client, str(client.base_url), homepage, not_found, crawl, self.options)
                self._progress(f"Running {len(self.checks)} checks")
                outcomes = await asyncio.gather(*(self._run_check(check, ctx, result) for check in self.checks))
            finally:
                result.requests_sent = client.requests_sent

        result.checks_run = [check.id for check in self.checks]
        result.findings = self._collate(f for findings in outcomes for f in findings)
        if client.failures:
            result.errors.append(f"{client.failures} request(s) failed with network errors or timeouts")
        result.finished_at = datetime.now(timezone.utc)
        return result

    async def _resolve(self, client: HttpClient):
        """Follow redirects from the given URL, staying on the same host.

        http -> https upgrades and /path -> /path/ redirects re-base the scan;
        a redirect to a different host aborts, since that host may be out of scope.
        """
        self._progress(f"Connecting to {self.target}")
        url = self.target
        original_host = httpx.URL(url).host
        for _ in range(MAX_REDIRECTS + 1):
            try:
                response = await client.request("GET", url, enforce_scope=False)
            except httpx.HTTPError as exc:
                raise ScanError(f"could not reach {url}: {exc!r}") from exc
            if not response.is_redirect or not response.location:
                client.rebase(response.url)
                return response
            url = response.location
            if httpx.URL(url).host != original_host:
                raise ScanError(
                    f"{self.target} redirects to a different host ({url}). "
                    "Scan that URL directly if it's in scope."
                )
        raise ScanError(f"too many redirects starting from {self.target}")

    async def _run_check(self, check: Check, ctx: ScanContext, result: ScanResult) -> list[Finding]:
        try:
            findings = await check.run(ctx)
        except Exception as exc:  # one broken check shouldn't sink the scan
            result.errors.append(f"[{check.id}] {type(exc).__name__}: {exc}")
            return []
        self._progress(f"Finished {check.name}")
        return findings

    def _collate(self, findings) -> list[Finding]:
        unique: dict[tuple[str, str, str], Finding] = {}
        for finding in findings:
            if finding.severity >= self.options.min_severity:
                unique.setdefault(finding.key, finding)
        return sorted(unique.values(), key=lambda f: (-f.severity, f.check, f.title, f.url))

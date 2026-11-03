"""Shared state handed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import httpx

from webprobe.client import HttpClient, NotFoundProfile, Response
from webprobe.crawler import CrawlResult
from webprobe.models import Severity


@dataclass(slots=True)
class ScanOptions:
    checks: list[str] | None = None  # ids to run; None means all
    exclude: list[str] = field(default_factory=list)
    crawl: bool = True
    max_pages: int = 30
    max_depth: int = 2
    max_injection_points: int = 40
    wordlist: Path | None = None
    min_severity: Severity = Severity.INFO


@dataclass(slots=True)
class InjectionPoint:
    """A single query parameter we can put a probe value into."""

    url: str  # without query string
    params: tuple[tuple[str, str], ...]
    name: str
    source: str  # "link" or "form"

    @property
    def original(self) -> str:
        return dict(self.params).get(self.name, "")

    def build(self, value: str) -> str:
        params = [(k, value if k == self.name else v) for k, v in self.params]
        return str(httpx.URL(self.url, params=params))

    def __str__(self) -> str:
        return f"{self.url} [{self.name}]"


@dataclass(slots=True)
class ScanContext:
    client: HttpClient
    target: str
    homepage: Response
    not_found: NotFoundProfile
    crawl: CrawlResult
    options: ScanOptions

    def responses(self) -> list[Response]:
        """Homepage plus every crawled response, without duplicates."""
        seen = {self.homepage.url}
        out = [self.homepage]
        for response in self.crawl.pages.values():
            if response.url not in seen:
                seen.add(response.url)
                out.append(response)
        return out

    def injection_points(self) -> list[InjectionPoint]:
        points: list[InjectionPoint] = []
        seen: set[tuple[str, str]] = set()

        def add(url: httpx.URL, params: tuple[tuple[str, str], ...], source: str) -> None:
            base = str(url.copy_with(query=None, fragment=None))
            for name, _ in params:
                if (base, name) not in seen:
                    seen.add((base, name))
                    points.append(InjectionPoint(base, params, name, source))

        for page_url in self.crawl.pages:
            url = httpx.URL(page_url)
            if url.query:
                add(url, tuple(url.params.multi_items()), "link")
        for form in self.crawl.forms:
            if form.method == "GET" and form.fields:
                add(httpx.URL(form.action), tuple(form.fields.items()), "form")
        return points[: self.options.max_injection_points]

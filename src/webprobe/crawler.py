"""Small same-origin crawler that collects pages, links with parameters and forms."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

from webprobe.client import HttpClient, Response

SKIP_EXTENSIONS = frozenset(
    ".png .jpg .jpeg .gif .svg .ico .webp .css .js .map .woff .woff2 .ttf .eot "
    ".pdf .zip .gz .tar .rar .7z .mp3 .mp4 .webm .avi .mov .exe .dmg .iso".split()
)
# Links we never follow: they can end the session or change server state.
UNSAFE_LINK_RE = re.compile(r"log-?out|sign-?out|log_out|delete|remove|destroy|unsubscribe|reset", re.I)


@dataclass(slots=True)
class Form:
    page_url: str
    action: str
    method: str
    fields: dict[str, str]


@dataclass(slots=True)
class CrawlResult:
    pages: dict[str, Response] = field(default_factory=dict)
    forms: list[Form] = field(default_factory=list)
    skipped_unsafe: list[str] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(), "fields": {}}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select", "button") and self._form is not None and a.get("name"):
            if a.get("type", "").lower() != "file":
                self._form["fields"][a["name"]] = a.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


class Crawler:
    def __init__(self, client: HttpClient, *, max_pages: int = 30, max_depth: int = 2) -> None:
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth

    async def crawl(self, start: str) -> CrawlResult:
        result = CrawlResult()
        seen: set[tuple[str, frozenset[str]]] = set()
        frontier = [start]
        seen.add(self._signature(httpx.URL(start)))

        for depth in range(self.max_depth + 1):
            batch = frontier[: self.max_pages - len(result.pages)]
            if not batch:
                break
            responses = await asyncio.gather(*(self.client.fetch(url) for url in batch))
            next_frontier: list[str] = []
            for url, response in zip(batch, responses):
                if response is None:
                    continue
                result.pages[url] = response
                for link in self._extract(url, response, result):
                    candidate = self._accept(link, result)
                    if candidate is None:
                        continue
                    sig = self._signature(candidate)
                    if sig not in seen:
                        seen.add(sig)
                        next_frontier.append(str(candidate))
            if depth == self.max_depth:
                break
            frontier = next_frontier
        return result

    def _extract(self, page_url: str, response: Response, result: CrawlResult) -> list[str]:
        if response.is_redirect:
            return [response.location] if response.location else []
        if not response.is_html:
            return []
        parser = _PageParser()
        try:
            parser.feed(response.text)
        except Exception:  # malformed markup shouldn't kill the crawl
            pass
        base = httpx.URL(page_url)
        for raw in parser.forms:
            try:
                action = base.join(raw["action"]) if raw["action"] else base
            except httpx.InvalidURL:
                continue
            if self.client.in_scope(action):
                result.forms.append(Form(page_url, str(action), raw["method"], raw["fields"]))
        return [str(base.join(href)) for href in parser.links if self._joinable(base, href)]

    @staticmethod
    def _joinable(base: httpx.URL, href: str) -> bool:
        try:
            base.join(href)
        except httpx.InvalidURL:
            return False
        return True

    def _accept(self, link: str, result: CrawlResult) -> httpx.URL | None:
        url = httpx.URL(link).copy_with(fragment=None)
        if url.scheme not in ("http", "https") or not self.client.in_scope(url):
            return None
        path = url.path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return None
        if UNSAFE_LINK_RE.search(path):
            result.skipped_unsafe.append(str(url))
            return None
        return url

    @staticmethod
    def _signature(url: httpx.URL) -> tuple[str, frozenset[str]]:
        # /item?id=1 and /item?id=2 are the same "page" for our purposes; this
        # also stops calendars and pagination from eating the crawl budget.
        return (url.path, frozenset(k for k, _ in url.params.multi_items()))

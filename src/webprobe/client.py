"""HTTP layer: scope enforcement, concurrency/rate limiting, capped bodies, soft-404 detection."""

from __future__ import annotations

import asyncio
import difflib
import secrets
from dataclasses import dataclass, field

import httpx

from webprobe import __version__

DEFAULT_USER_AGENT = f"webprobe/{__version__} (authorized security testing)"
DEFAULT_MAX_BYTES = 512_000
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class OutOfScopeError(Exception):
    """Raised when a request would leave the origin being scanned."""


@dataclass(slots=True)
class ClientConfig:
    timeout: float = 10.0
    concurrency: int = 10
    rate_limit: float = 0.0  # max requests per second; 0 disables limiting
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    verify_tls: bool = False


@dataclass(slots=True)
class Response:
    """A fully-read (possibly truncated) HTTP response.

    We stream bodies and stop after ``max_bytes`` so that a stray multi-GB
    backup file can't exhaust memory, which is why this isn't an httpx.Response.
    """

    url: str
    status: int
    headers: httpx.Headers
    content: bytes
    truncated: bool = False
    encoding: str | None = None

    @property
    def text(self) -> str:
        return self.content.decode(self.encoding or "utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_STATUSES

    @property
    def location(self) -> str | None:
        """Absolute redirect target, if any."""
        loc = self.headers.get("location")
        return str(httpx.URL(self.url).join(loc)) if loc else None


def origin_of(url: httpx.URL) -> tuple[str, str, int]:
    port = url.port or (443 if url.scheme == "https" else 80)
    return (url.scheme, url.host, port)


class RateLimiter:
    """Spaces requests evenly so we never exceed ``rate`` requests per second."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def wait(self) -> None:
        if not self._interval:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            delay = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + self._interval
        if delay > 0:
            await asyncio.sleep(delay)


class HttpClient:
    """Async HTTP client that refuses to leave the target origin."""

    def __init__(
        self,
        base_url: str,
        config: ClientConfig | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config or ClientConfig()
        self.rebase(base_url)
        self._sem = asyncio.Semaphore(self.config.concurrency)
        self._limiter = RateLimiter(self.config.rate_limit)
        self._client = httpx.AsyncClient(
            headers={"User-Agent": self.config.user_agent, **self.config.headers},
            cookies=self.config.cookies,
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
            follow_redirects=False,
            # A custom transport (tests) takes precedence over a proxy.
            proxy=None if transport else self.config.proxy,
            transport=transport,
        )
        self.requests_sent = 0
        self.failures = 0

    def rebase(self, base_url: str) -> None:
        self.base_url = httpx.URL(base_url)
        self._origin = origin_of(self.base_url)
        # Directory of the target, so relative wordlist paths work for apps under a sub-path.
        path = self.base_url.path
        self.base_dir = self.base_url.copy_with(path=path[: path.rfind("/") + 1] or "/", query=None, fragment=None)

    def url(self, path_or_url: str) -> httpx.URL:
        return self.base_dir.join(path_or_url)

    def in_scope(self, url: str | httpx.URL) -> bool:
        return origin_of(httpx.URL(url)) == self._origin

    async def request(
        self,
        method: str,
        url: str | httpx.URL,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        enforce_scope: bool = True,
        **kwargs,
    ) -> Response:
        target = self.url(str(url))
        if enforce_scope and not self.in_scope(target):
            raise OutOfScopeError(str(target))
        async with self._sem:
            await self._limiter.wait()
            self.requests_sent += 1
            request = self._client.build_request(method, target, **kwargs)
            raw = await self._client.send(request, stream=True)
            body = bytearray()
            truncated = False
            try:
                async for chunk in raw.aiter_bytes():
                    body.extend(chunk)
                    if len(body) >= max_bytes:
                        truncated = True
                        break
            finally:
                await raw.aclose()
        return Response(
            url=str(raw.url),
            status=raw.status_code,
            headers=raw.headers,
            content=bytes(body[:max_bytes]),
            truncated=truncated,
            encoding=raw.charset_encoding,
        )

    async def fetch(self, url: str | httpx.URL, *, method: str = "GET", **kwargs) -> Response | None:
        """Like :meth:`request` but returns ``None`` on network errors instead of raising."""
        try:
            return await self.request(method, url, **kwargs)
        except httpx.HTTPError:
            self.failures += 1
            return None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> HttpClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


def _similar(a: str, b: str, threshold: float = 0.9) -> bool:
    a, b = a[:4000], b[:4000]
    if not a and not b:
        return True
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return (
        matcher.real_quick_ratio() >= threshold
        and matcher.quick_ratio() >= threshold
        and matcher.ratio() >= threshold
    )


class NotFoundProfile:
    """Fingerprint of how the server answers for paths that don't exist.

    Lots of apps return 200 or redirect to /login for unknown paths ("soft 404").
    Without this baseline every wordlist entry would look like a hit.
    """

    PLACEHOLDER = "\x00PATH\x00"

    def __init__(self, samples: list[tuple[str, Response]]) -> None:
        self.samples = samples

    @classmethod
    async def build(cls, client: HttpClient) -> NotFoundProfile:
        samples: list[tuple[str, Response]] = []
        for suffix in ("", ".php", "/"):
            token = f"webprobe-{secrets.token_hex(6)}"
            response = await client.fetch(f"{token}{suffix}")
            if response is not None:
                samples.append((token, response))
        return cls(samples)

    @property
    def is_soft(self) -> bool:
        """True if the server answers unknown paths with something other than 404."""
        return any(r.status != 404 for _, r in self.samples)

    def matches(self, response: Response, requested: str) -> bool:
        """Return True if ``response`` looks like the server's generic not-found answer."""
        if response.status == 404:
            return True
        needle = requested.strip("/").split("?")[0]
        for token, sample in self.samples:
            if response.status != sample.status:
                continue
            if response.is_redirect:
                if self._normalise(response.location or "", needle) == self._normalise(sample.location or "", token):
                    return True
                continue
            if _similar(self._normalise(response.text, needle), self._normalise(sample.text, token)):
                return True
        return False

    @classmethod
    def _normalise(cls, text: str, path: str) -> str:
        # Error pages often echo the requested path; take it out before comparing.
        return text.replace(path, cls.PLACEHOLDER) if path else text

"""ShopLab: a deliberately vulnerable web app to practise against (and to test webprobe).

It binds to 127.0.0.1 only. Never expose it to a network.

    python -m lab.vulnapp --port 8000
    python -m lab.vulnapp --port 8000 --soft-404   # unknown paths return 200

Planted issues: missing security headers, version disclosure, insecure session
cookie, exposed .git and .env, reflected XSS in /search, error-based SQLi in
/product, CORS origin reflection with credentials, TRACE enabled, an admin page
listed in robots.txt. /safe-search is the correctly-escaped control case.
"""

from __future__ import annotations

import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

HOME = """<!doctype html>
<html><head><title>ShopLab</title></head><body>
<h1>ShopLab</h1>
<nav>
  <a href="/search?q=shoes">Search</a>
  <a href="/safe-search?q=shoes">Safe search</a>
  <a href="/product?id=1">Product 1</a>
  <a href="/product?id=2">Product 2</a>
  <a href="/about">About</a>
  <a href="/logout">Log out</a>
</nav>
<form action="/search" method="get"><input name="q" value=""><input type="submit" value="Go"></form>
</body></html>"""

PRODUCTS = {"1": "Running shoes", "2": "Trail socks"}

STATIC = {
    "/about": ("text/html", "<html><body><h1>About ShopLab</h1><p>Since 2019.</p></body></html>"),
    "/admin": ("text/html", "<html><head><title>Admin login</title></head><body><form method='post'>"
                            "<input name='user'><input name='pass' type='password'></form></body></html>"),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /internal-reports/\n"),
    "/internal-reports/": ("text/html", "<html><body><h1>Q3 internal reports</h1></body></html>"),
    "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
    "/.env": ("text/plain", "APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD=lab-password-123\nSECRET_KEY=lab-not-a-real-secret\n"),
}


class ShopLabHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29 (Ubuntu)"  # planted: version disclosure
    sys_version = ""

    def log_message(self, format, *args) -> None:  # keep test output quiet
        pass

    def _send(self, status: int, body: str, content_type: str = "text/html", extra: dict | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.2.1")
        origin = self.headers.get("Origin")
        if origin:  # planted: CORS reflects any origin, with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = parse_qs(url.query, keep_blank_values=True)
        self.server.hits.append(url.path)

        if url.path == "/":
            # planted: session cookie without HttpOnly / SameSite
            self._send(200, HOME, extra={"Set-Cookie": "sessionid=9f8e7d6c5b4a; Path=/"})
        elif url.path == "/search":
            term = query.get("q", [""])[0]
            self._send(200, f"<html><body><p>Results for {term}</p></body></html>")  # planted: XSS
        elif url.path == "/safe-search":
            term = html.escape(query.get("q", [""])[0])
            self._send(200, f"<html><body><p>Results for {term}</p></body></html>")
        elif url.path == "/product":
            self._product(query.get("id", ["1"])[0])
        elif url.path in STATIC:
            content_type, body = STATIC[url.path]
            self._send(200, body, content_type)
        elif self.server.soft_404:
            self._send(200, f"<html><body><h1>Oops!</h1><p>We couldn't find {html.escape(url.path)}.</p></body></html>")
        else:
            self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    do_HEAD = do_GET

    def _product(self, product_id: str) -> None:
        # planted: emulates  SELECT * FROM products WHERE id = '<input>'
        if product_id.count("'") % 2:
            self._send(500, "<html><body><b>Fatal error</b>: You have an error in your SQL syntax; check the manual "
                            "that corresponds to your MySQL server version for the right syntax to use near "
                            f"''{html.escape(product_id)}'' at line 1</body></html>")
            return
        name = PRODUCTS.get(product_id.replace("'", ""), "Unknown product")
        self._send(200, f"<html><body><h1>{html.escape(name)}</h1></body></html>")

    def do_OPTIONS(self) -> None:
        self._send(200, "", extra={"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})

    def do_TRACE(self) -> None:  # planted: TRACE echoes the request
        echo = f"{self.requestline}\r\n{self.headers}"
        self._send(200, echo, "message/http")


class ShopLabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0, *, soft_404: bool = False) -> None:
        super().__init__(("127.0.0.1", port), ShopLabHandler)
        self.soft_404 = soft_404
        self.hits: list[str] = []

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/"


def main() -> None:
    parser = argparse.ArgumentParser(description="ShopLab - deliberately vulnerable practice target")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--soft-404", action="store_true", help="answer unknown paths with 200 instead of 404")
    args = parser.parse_args()
    server = ShopLabServer(args.port, soft_404=args.soft_404)
    print(f"ShopLab running at {server.url}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

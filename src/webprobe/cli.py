from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from webprobe import __version__
from webprobe.checks import ALL_CHECKS
from webprobe.client import DEFAULT_USER_AGENT, ClientConfig
from webprobe.console import render
from webprobe.context import ScanOptions
from webprobe.engine import Scanner, ScanError
from webprobe.models import Severity
from webprobe.reports import WRITERS, write_report

LEGAL_NOTICE = "Only scan systems you own or have written permission to test."


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _header(value: str) -> tuple[str, str]:
    name, sep, val = value.partition(":")
    if not sep or not name.strip():
        raise argparse.ArgumentTypeError(f"expected 'Name: value', got {value!r}")
    return name.strip(), val.strip()


def _cookies(value: str) -> dict[str, str]:
    jar = {}
    for part in value.split(";"):
        name, sep, val = part.partition("=")
        if sep and name.strip():
            jar[name.strip()] = val.strip()
    return jar


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webprobe",
        description="Non-destructive web application security scanner.",
        epilog=LEGAL_NOTICE,
    )
    p.add_argument("target", nargs="?", help="base URL to scan, e.g. https://staging.example.com/")
    p.add_argument("--version", action="version", version=f"webprobe {__version__}")
    p.add_argument("--list-checks", action="store_true", help="list available checks and exit")

    sel = p.add_argument_group("check selection")
    sel.add_argument("-c", "--checks", type=_csv, metavar="IDS", help="comma-separated check ids to run (default: all)")
    sel.add_argument("-x", "--exclude", type=_csv, default=[], metavar="IDS", help="comma-separated check ids to skip")

    crawl = p.add_argument_group("crawling and discovery")
    crawl.add_argument("--no-crawl", action="store_true", help="only test the target URL itself")
    crawl.add_argument("--max-pages", type=int, default=30, metavar="N", help="crawl budget (default: 30)")
    crawl.add_argument("--depth", type=int, default=2, metavar="N", help="max link depth (default: 2)")
    crawl.add_argument("-w", "--wordlist", type=Path, metavar="FILE", help="custom content-discovery wordlist")

    http = p.add_argument_group("HTTP")
    http.add_argument("-H", "--header", type=_header, action="append", default=[], metavar="'NAME: VALUE'",
                      help="extra request header (repeatable), e.g. an Authorization header")
    http.add_argument("--cookie", type=_cookies, default={}, metavar="'a=1; b=2'", help="cookies to send (authenticated scans)")
    http.add_argument("-A", "--user-agent", default=DEFAULT_USER_AGENT)
    http.add_argument("--proxy", metavar="URL", help="route traffic through a proxy, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    http.add_argument("--timeout", type=float, default=10.0, metavar="SEC")
    http.add_argument("--concurrency", type=int, default=10, metavar="N", help="parallel requests (default: 10)")
    http.add_argument("--rate-limit", type=float, default=0.0, metavar="RPS", help="max requests per second (default: unlimited)")
    http.add_argument("--verify-tls", action="store_true", help="fail on invalid certificates instead of scanning anyway")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", type=Path, action="append", default=[], metavar="FILE",
                     help=f"write a report; format from extension ({', '.join(WRITERS)}). Repeatable")
    out.add_argument("--min-severity", type=_severity, default=Severity.INFO, metavar="LEVEL",
                     help="hide findings below this severity (info, low, medium, high, critical)")
    out.add_argument("--fail-on", type=_severity, metavar="LEVEL",
                     help="exit with status 1 if any finding is at or above LEVEL (for CI)")
    out.add_argument("-v", "--verbose", action="store_true", help="print full details for every finding")
    out.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    return p


def list_checks(console: Console) -> None:
    table = Table("ID", "Name", "What it does", header_style="bold")
    for cls in ALL_CHECKS:
        table.add_row(cls.id, cls.name, cls.description)
    console.print(table)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()
    status_console = Console(stderr=True, quiet=args.quiet)

    if args.list_checks:
        list_checks(console)
        return 0
    if not args.target:
        parser.error("target is required")
    if not args.target.startswith(("http://", "https://")):
        parser.error("target must start with http:// or https://")
    for path in args.output:
        if path.suffix.lower() not in WRITERS:
            parser.error(f"unsupported report format for {path} (use {', '.join(WRITERS)})")

    config = ClientConfig(
        timeout=args.timeout,
        concurrency=max(1, args.concurrency),
        rate_limit=args.rate_limit,
        user_agent=args.user_agent,
        headers=dict(args.header),
        cookies=args.cookie,
        proxy=args.proxy,
        verify_tls=args.verify_tls,
    )
    options = ScanOptions(
        checks=args.checks,
        exclude=args.exclude,
        crawl=not args.no_crawl,
        max_pages=args.max_pages,
        max_depth=args.depth,
        wordlist=args.wordlist,
        min_severity=args.min_severity,
    )

    status_console.print(f"[dim]{LEGAL_NOTICE}[/]")
    try:
        with status_console.status("Starting") as status:
            scanner = Scanner(args.target, config, options, on_progress=lambda msg: status.update(msg))
            result = asyncio.run(scanner.run())
    except ValueError as exc:  # bad check ids etc.
        parser.error(str(exc))
    except ScanError as exc:
        status_console.print(f"[red]error:[/] {escape(str(exc))}")
        return 2
    except KeyboardInterrupt:
        status_console.print("[yellow]interrupted[/]")
        return 130

    # Reports first: a problem printing to the terminal must not cost the user the report files.
    for path in args.output:
        write_report(result, path)
    render(result, console, verbose=args.verbose)
    for path in args.output:
        status_console.print(f"[green]report written:[/] {escape(str(path))}")

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

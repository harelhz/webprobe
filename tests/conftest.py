from __future__ import annotations

import asyncio
import threading

import pytest

from lab.vulnapp import ShopLabServer
from webprobe.client import ClientConfig
from webprobe.context import ScanOptions
from webprobe.engine import Scanner
from webprobe.models import ScanResult


def _serve(soft_404: bool):
    server = ShopLabServer(0, soft_404=soft_404)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def lab():
    yield from _serve(soft_404=False)


@pytest.fixture
def soft404_lab():
    yield from _serve(soft_404=True)


def run_scan(target: str, transport=None, **options) -> ScanResult:
    scanner = Scanner(target, ClientConfig(timeout=5), ScanOptions(**options), transport=transport)
    return asyncio.run(scanner.run())

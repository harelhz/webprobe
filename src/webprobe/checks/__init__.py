"""Check registry. To add a check: subclass Check, give it a unique ``id``, list it here."""

from __future__ import annotations

from webprobe.checks.base import Check
from webprobe.checks.content_discovery import ContentDiscoveryCheck
from webprobe.checks.cookies import CookieFlagsCheck
from webprobe.checks.cors import CORSCheck
from webprobe.checks.exposed_files import ExposedFilesCheck
from webprobe.checks.headers import SecurityHeadersCheck
from webprobe.checks.methods import HTTPMethodsCheck
from webprobe.checks.reflection import ReflectedInputCheck
from webprobe.checks.sql_errors import SQLErrorCheck
from webprobe.checks.tls import TLSCheck

ALL_CHECKS: list[type[Check]] = [
    SecurityHeadersCheck,
    CookieFlagsCheck,
    TLSCheck,
    ExposedFilesCheck,
    ContentDiscoveryCheck,
    CORSCheck,
    HTTPMethodsCheck,
    ReflectedInputCheck,
    SQLErrorCheck,
]


def select_checks(include: list[str] | None = None, exclude: list[str] | None = None) -> list[Check]:
    known = {cls.id: cls for cls in ALL_CHECKS}
    unknown = [cid for cid in (include or []) + (exclude or []) if cid not in known]
    if unknown:
        raise ValueError(f"unknown check id(s): {', '.join(unknown)} (see --list-checks)")
    ids = include or list(known)
    return [known[cid]() for cid in ids if cid not in (exclude or [])]


__all__ = ["ALL_CHECKS", "Check", "select_checks"]

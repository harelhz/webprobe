"""Core data types shared by checks, the engine and the reporters."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from None


@dataclass(slots=True)
class Finding:
    check: str
    title: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity used to de-duplicate findings."""
        return (self.check, self.title, self.url)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data


@dataclass(slots=True)
class ScanResult:
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    requests_sent: int = 0

    @property
    def duration(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration, 2),
            "checks_run": self.checks_run,
            "pages_crawled": self.pages_crawled,
            "requests_sent": self.requests_sent,
            "summary": {s.name.lower(): n for s, n in self.counts().items()},
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

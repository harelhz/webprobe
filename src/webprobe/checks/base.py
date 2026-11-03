from __future__ import annotations

import abc
from typing import TYPE_CHECKING, ClassVar

from webprobe.models import Finding, Severity

if TYPE_CHECKING:
    from webprobe.context import ScanContext


class Check(abc.ABC):
    """Base class for all checks.

    A check receives the shared :class:`ScanContext` and returns findings.
    Checks must be non-destructive: no state-changing requests (PUT/DELETE,
    POST form submissions) and no exploitation beyond what's needed to
    demonstrate a weakness exists.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]: ...

    def finding(
        self,
        title: str,
        severity: Severity,
        url: str,
        description: str,
        *,
        evidence: str = "",
        remediation: str = "",
        references: list[str] | None = None,
    ) -> Finding:
        return Finding(
            check=self.id,
            title=title,
            severity=severity,
            url=url,
            description=description,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
        )

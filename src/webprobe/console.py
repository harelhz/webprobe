"""Terminal output using rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webprobe.models import ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def severity_text(severity: Severity) -> Text:
    return Text(f" {severity.label} ", style=SEVERITY_STYLE[severity])


def render(result: ScanResult, console: Console, *, verbose: bool = False) -> None:
    counts = result.counts()
    summary = Table.grid(padding=(0, 2))
    summary.add_row(*(severity_text(s) for s in reversed(Severity)))
    summary.add_row(*(Text(str(counts[s]), justify="center") for s in reversed(Severity)))
    console.print(Panel(
        summary,
        title=f"[bold]webprobe[/] - {result.target}",
        subtitle=f"{result.pages_crawled} pages, {result.requests_sent} requests, {result.duration:.1f}s",
        expand=False,
    ))

    if not result.findings:
        console.print("[green]No findings at or above the selected severity.[/]")
    else:
        table = Table(show_lines=False, header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Finding")
        table.add_column("URL", overflow="fold", style="dim")
        for finding in result.findings:
            table.add_row(severity_text(finding.severity), finding.title, finding.url)
        console.print(table)

    if verbose:
        for finding in result.findings:
            body = Text()
            body.append(finding.description + "\n")
            if finding.evidence:
                body.append("\nEvidence\n", style="bold")
                body.append(finding.evidence + "\n", style="green")
            if finding.remediation:
                body.append("\nFix\n", style="bold")
                body.append(finding.remediation + "\n")
            console.print(Panel(body, title=Text.assemble(severity_text(finding.severity), " ", finding.title),
                                subtitle=finding.url, title_align="left"))

    for error in result.errors:
        console.print(f"[yellow]warning:[/] {error}")

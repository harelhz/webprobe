"""File reports: JSON (machines), Markdown (write-ups), HTML (sharing)."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from webprobe import __version__
from webprobe.models import ScanResult, Severity


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# Web security scan: {result.target}",
        "",
        f"- **Date:** {result.started_at:%Y-%m-%d %H:%M} UTC",
        f"- **Tool:** webprobe {__version__}",
        f"- **Checks:** {', '.join(result.checks_run)}",
        f"- **Coverage:** {result.pages_crawled} pages crawled, {result.requests_sent} requests",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {s.label} | {counts[s]} |" for s in reversed(Severity)),
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("_No findings._")
    for i, finding in enumerate(result.findings, 1):
        lines += [
            f"### {i}. [{finding.severity.label}] {finding.title}",
            "",
            f"**URL:** `{finding.url}`  ",
            f"**Check:** `{finding.check}`",
            "",
            finding.description,
            "",
        ]
        if finding.evidence:
            lines += ["**Evidence**", "", "```", finding.evidence, "```", ""]
        if finding.remediation:
            lines += [f"**Remediation:** {finding.remediation}", ""]
        if finding.references:
            lines += ["**References:** " + ", ".join(f"<{r}>" for r in finding.references), ""]
    if result.errors:
        lines += ["## Scan warnings", "", *(f"- {e}" for e in result.errors), ""]
    return "\n".join(lines)


_CSS = """
:root{--bg:#f7f7f8;--card:#fff;--fg:#1b1d22;--muted:#636a77;--border:#e2e4e9;--code:#f0f1f4;
--critical:#b3123b;--high:#d9480f;--medium:#c78a00;--low:#1c7ed6;--info:#7a8290}
@media (prefers-color-scheme:dark){:root{--bg:#121317;--card:#1b1d23;--fg:#e7e9ee;--muted:#9aa1ad;
--border:#2c2f37;--code:#24272f;--critical:#ff5c7c;--high:#ff8a4c;--medium:#f5c242;--low:#5aa9ff;--info:#9aa1ad}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:1.5rem;margin:0 0 4px}.meta{color:var(--muted);font-size:.9rem;margin-bottom:24px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;cursor:pointer;
border-top:4px solid var(--c)}.tile b{display:block;font-size:1.6rem;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:.85rem}.tile.off{opacity:.35}
details{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:8px;
margin-bottom:8px}summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.badge{font-size:.72rem;font-weight:700;text-transform:uppercase;color:var(--c);letter-spacing:.04em;min-width:64px}
.url{color:var(--muted);font-size:.85rem;word-break:break-all;flex-basis:100%;padding-left:74px}
.body{padding:0 16px 14px 88px}.body h4{margin:12px 0 4px;font-size:.85rem;color:var(--muted)}
pre{background:var(--code);padding:10px;border-radius:6px;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;
word-break:break-all}a{color:var(--low)}
@media (max-width:600px){.url{padding-left:0}.body{padding:0 14px 14px}}
.critical{--c:var(--critical)}.high{--c:var(--high)}.medium{--c:var(--medium)}.low{--c:var(--low)}.info{--c:var(--info)}
"""

_JS = """
document.querySelectorAll('.tile').forEach(t=>t.addEventListener('click',()=>{
 t.classList.toggle('off');const s=t.dataset.sev,on=!t.classList.contains('off');
 document.querySelectorAll('details.'+s).forEach(d=>d.hidden=!on);}));
"""


def to_html(result: ScanResult) -> str:
    counts = result.counts()
    tiles = "".join(
        f'<div class="tile {s.name.lower()}" data-sev="{s.name.lower()}" title="Click to toggle">'
        f"<b>{counts[s]}</b><span>{s.label}</span></div>"
        for s in reversed(Severity)
    )
    items = []
    for f in result.findings:
        sev = f.severity.name.lower()
        parts = [f"<p>{escape(f.description)}</p>"]
        if f.evidence:
            parts.append(f"<h4>Evidence</h4><pre>{escape(f.evidence)}</pre>")
        if f.remediation:
            parts.append(f"<h4>Remediation</h4><p>{escape(f.remediation)}</p>")
        if f.references:
            links = " · ".join(f'<a href="{escape(r)}" rel="noreferrer">{escape(r)}</a>' for r in f.references)
            parts.append(f"<h4>References</h4><p>{links}</p>")
        items.append(
            f'<details class="{sev}"><summary><span class="badge">{f.severity.label}</span>'
            f"<strong>{escape(f.title)}</strong><span class=\"url\">{escape(f.url)}</span></summary>"
            f'<div class="body">{"".join(parts)}</div></details>'
        )
    errors = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>webprobe report - {escape(result.target)}</title><style>{_CSS}</style></head>
<body><main>
<h1>Web security scan</h1>
<div class="meta">{escape(result.target)} · {result.started_at:%Y-%m-%d %H:%M} UTC · {result.pages_crawled} pages ·
{result.requests_sent} requests · {result.duration:.1f}s · webprobe {__version__}</div>
<div class="tiles">{tiles}</div>
{"".join(items) or "<p>No findings.</p>"}
{f"<h3>Scan warnings</h3><ul>{errors}</ul>" if errors else ""}
</main><script>{_JS}</script></body></html>
"""


WRITERS = {".json": to_json, ".md": to_markdown, ".html": to_html, ".htm": to_html}


def write_report(result: ScanResult, path: Path) -> None:
    writer = WRITERS.get(path.suffix.lower())
    if writer is None:
        raise ValueError(f"unsupported report format {path.suffix!r} (use .json, .md or .html)")
    path.write_text(writer(result), encoding="utf-8")

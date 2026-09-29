"""Render reports as text, JSON or Markdown."""

from __future__ import annotations

import json
import textwrap

from . import __version__
from .model import DomainReport


def render(reports: list[DomainReport], fmt: str = "text") -> str:
    if fmt == "json":
        return render_json(reports)
    if fmt == "markdown":
        return render_markdown(reports)
    return render_text(reports)


def render_json(reports: list[DomainReport]) -> str:
    doc = {
        "tool": "email-dns-check",
        "version": __version__,
        "status": _overall(reports),
        "domains": [r.to_dict() for r in reports],
    }
    return json.dumps(doc, indent=2) + "\n"


def _overall(reports: list[DomainReport]) -> str:
    statuses = {r.status for r in reports}
    for s in ("fail", "warn"):
        if s in statuses:
            return s
    return "pass"


def render_text(reports: list[DomainReport]) -> str:
    out: list[str] = []
    for report in reports:
        out.append(f"{report.domain}: {report.status.upper()}")
        out.append("")
        for c in report.checks:
            out.append(f"  {c.name:<8} {c.status.upper():<4}  {c.summary}")
        for c in report.checks:
            out.append("")
            out.append(f"{c.name}: {c.status.upper()} - {c.summary}")
            for d in c.details:
                out.append(f"    {d}")
            for f in c.findings:
                out.append(f"  [{f.severity.upper()}] {f.title}")
                out.extend(textwrap.wrap(f.explanation, 96, initial_indent="         ",
                                         subsequent_indent="         ", break_on_hyphens=False))
                if f.record:
                    out.append(f"         Publish: {f.record}")
        out.append("")
    return "\n".join(out) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(reports: list[DomainReport]) -> str:
    out: list[str] = []
    for report in reports:
        out.append(f"# Email DNS check: {report.domain}")
        out.append("")
        out.append(f"Overall: **{report.status.upper()}**")
        out.append("")
        out.append("| Check | Status | Summary |")
        out.append("|---|---|---|")
        for c in report.checks:
            out.append(f"| {c.name} | {c.status.upper()} | {_cell(c.summary)} |")
        for c in report.checks:
            out.append("")
            out.append(f"## {c.name}: {c.status.upper()}")
            out.append("")
            block: list[str] = []
            for d in c.details + [""]:
                if d.startswith("  "):
                    block.append(d[2:])
                    continue
                if block:
                    out.append("```text")
                    out.extend(block)
                    out.append("```")
                    out.append("")
                    block = []
                if d.endswith(":"):
                    if out[-1] != "":
                        out.append("")
                    out.append(d[:1].upper() + d[1:])
                    out.append("")
                elif d:
                    out.append(f"- {d}")
            if c.findings:
                if out[-1] != "":
                    out.append("")
                for f in c.findings:
                    out.append(f"- **{f.severity.upper()}: {f.title}.** {f.explanation}")
                    if f.record:
                        out.append("")
                        out.append(f"  Publish: `{f.record}`")
                    out.append("")
                if out[-1] == "":
                    out.pop()
        out.append("")
    return "\n".join(out)

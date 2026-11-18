"""Render the governance report as Markdown (+ JSON sidecar)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .models import Report


def to_json(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataclasses.asdict(report), default=str, indent=2), encoding="utf-8")
    return path


def to_markdown(report: Report, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    s = report.summary
    lines = [
        "# Agentic Risk & Compliance Report",
        "",
        f"- **Generated:** {report.generated_at}",
        f"- **Environment:** {report.environment}",
        f"- **Model:** {report.model}",
        f"- **Guardrails:** {'ENABLED' if report.guardrails_enabled else 'DISABLED (baseline)'}",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Findings ingested | {s['total_findings']} |",
        f"| Reported | {s['reported']} |",
        f"| Suppressed | {s['suppressed']} |",
        f"| Escalated (high current risk) | {s['escalated']} |",
        f"| Awaiting human approval | {s['needs_human_approval']} |",
        f"| Injection attempts seen | {s['injection_events']} |",
        f"| **Injections acted on** | **{s['acted_on_injection']}** |",
        "",
        "## Prioritized findings",
        "",
        "| P | Finding | Inherent→Residual | Controls | Action | Human? |",
        "|---|---|---|---|---|---|",
    ]
    for d in report.decisions:
        ctrls = ", ".join(f"{c.control_id}" for c in d.controls) or "-"
        lines.append(
            f"| P{d.priority} | {d.finding_id} | "
            f"{d.risk.inherent:.0f}→{d.risk.residual:.1f} | {ctrls} | "
            f"{d.action.value} | {'yes' if d.requires_human_approval else 'no'} |"
        )
    lines += ["", "## Decision detail (audit view)", ""]
    for d in report.decisions:
        lines.append(f"### {d.finding_id}  ·  P{d.priority}  ·  confidence {d.confidence:.2f}")
        lines.append("")
        lines.append(f"- **Justification:** {d.justification}")
        lines.append(f"- **Controls:** " + "; ".join(
            f"{c.framework} {c.control_id} — {c.title} (eff {c.effectiveness:.0%})"
            for c in d.controls) + ".")
        lines.append(
            f"- **Risk:** inherent {d.risk.inherent:.0f} "
            f"(L{d.risk.likelihood}×I{d.risk.impact}), combined control effectiveness "
            f"{d.risk.combined_effectiveness:.0%}, residual {d.risk.residual:.1f}.")
        if d.guardrail_flags:
            lines.append(f"- **Guardrail flags:** {', '.join(d.guardrail_flags)}")
        lines.append(f"- **Evidence:** {', '.join(d.evidence)}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path

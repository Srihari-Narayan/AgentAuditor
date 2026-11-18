"""CLI entry point.

    python -m audit_agent.run --demo
    python -m audit_agent.run --findings data/findings/sample_findings.json
    python -m audit_agent.run --findings ... --no-guardrails   # vulnerable baseline
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent import AuditAnalyst
from .controls import ControlCatalog
from .guardrails import Guardrails
from .models import Finding
from .report import to_json, to_markdown

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT = _ROOT / "data" / "findings" / "sample_findings.json"


def load_findings(path: Path) -> list[Finding]:
    records = json.loads(path.read_text(encoding="utf-8"))
    return [Finding.from_dict(r) for r in records]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Auditable agentic risk & compliance analyst")
    ap.add_argument("--findings", type=Path, default=None)
    ap.add_argument("--demo", action="store_true", help="run the bundled sample")
    ap.add_argument("--no-guardrails", action="store_true",
                    help="disable the self-defense layer (vulnerable baseline)")
    ap.add_argument("--role", default="analyst", choices=["analyst", "operator"])
    ap.add_argument("--out", type=Path, default=_ROOT / "reports")
    args = ap.parse_args(argv)

    path = args.findings or (_DEFAULT if args.demo else None)
    if path is None:
        ap.error("provide --findings PATH or --demo")

    findings = load_findings(path)
    analyst = AuditAnalyst(
        guardrails=Guardrails(enabled=not args.no_guardrails),
        role=args.role,
        catalog=ControlCatalog(),
        audit_path=args.out / "audit_trail.jsonl",
    )
    report = analyst.run(findings)

    md = to_markdown(report, args.out / "report.md")
    js = to_json(report, args.out / "report.json")

    s = report.summary
    print(f"Guardrails: {'ENABLED' if report.guardrails_enabled else 'DISABLED'} | "
          f"model: {report.model}")
    print(f"Ingested {s['total_findings']} findings -> "
          f"{s['reported']} reported, {s['escalated']} escalated, "
          f"{s['needs_human_approval']} awaiting approval.")
    print(f"Injection attempts: {s['injection_events']} | acted on: {s['acted_on_injection']}")
    print(f"Report: {md}")
    print(f"JSON:   {js}")
    print(f"Audit:  {args.out / 'audit_trail.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

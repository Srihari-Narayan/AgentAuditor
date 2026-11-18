"""Audit trail.

The headline feature. Every decision the agent makes is written as a structured,
replayable record: which finding, which controls, the risk math, the confidence,
whether a human gate fired, any guardrail events, and the natural-language
justification. A reviewer can answer "why did the system say that?" for every
single line -- which is exactly what a compliance/SOC team needs and what most
agent demos cannot provide.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Decision


class AuditTrail:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[dict[str, Any]] = []

    def _event(self, kind: str, payload: dict[str, Any]) -> None:
        self._records.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **payload,
        })

    def log_guardrail(self, finding_id: str, flags: list[str], quarantined: str) -> None:
        self._event("guardrail", {
            "finding_id": finding_id,
            "flags": flags,
            "quarantined_sample": quarantined[:200],
        })

    def log_denied(self, tool: str, reason: str) -> None:
        self._event("tool_denied", {"tool": tool, "reason": reason})

    def log_decision(self, decision: Decision) -> None:
        self._event("decision", {
            "finding_id": decision.finding_id,
            "action": decision.action.value,
            "priority": decision.priority,
            "controls": [dataclasses.asdict(c) for c in decision.controls],
            "risk": decision.risk.as_dict(),
            "confidence": decision.confidence,
            "requires_human_approval": decision.requires_human_approval,
            "guardrail_flags": decision.guardrail_flags,
            "evidence": decision.evidence,
            "justification": decision.justification,
        })

    def flush(self) -> Path:
        """Write the trail as JSON Lines. Returns the path written."""
        with self.path.open("w", encoding="utf-8") as f:
            for rec in self._records:
                f.write(json.dumps(rec) + "\n")
        return self.path

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records)

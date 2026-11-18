"""Core data models for the audit agent.

These dataclasses are the shared vocabulary of the whole system. They are kept
deliberately small and serializable so that every decision the agent makes can
be written to an audit trail and replayed. Nothing here depends on an LLM: the
compliance logic is deterministic and inspectable, which is the point.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity, ordered. Drives the inherent-risk likelihood/impact."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class DecisionAction(str, Enum):
    """What the analyst decided to do with a finding."""

    REPORT = "report"                       # include in report at computed priority
    ESCALATE = "escalate"                    # flag for human review (high residual)
    REQUEST_REMEDIATION = "request_remediation"  # sensitive action -> HITL gate
    SUPPRESS = "suppress"                    # only ever via an auditable rule, never free text


@dataclass
class Finding:
    """A single security finding ingested from a scanner or SOC alert source.

    Free-text fields (``description``, ``raw``) are UNTRUSTED. They may contain
    attacker-controlled content (an S3 object name, a log line, a ticket body).
    The agent must treat them as data, never as instructions. See guardrails.py.
    """

    id: str
    source: str                 # e.g. "prowler", "securityhub", "soc"
    title: str
    severity: Severity
    category: str               # normalized category -> drives control mapping
    resource: str               # affected resource identifier
    description: str = ""        # UNTRUSTED free text
    raw: dict[str, Any] = field(default_factory=dict)  # UNTRUSTED original record

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Finding":
        return Finding(
            id=str(d["id"]),
            source=str(d.get("source", "unknown")),
            title=str(d.get("title", "")),
            severity=Severity(str(d.get("severity", "low")).lower()),
            category=str(d.get("category", "uncategorized")),
            resource=str(d.get("resource", "")),
            description=str(d.get("description", "")),
            raw=dict(d.get("raw", {})),
        )


@dataclass
class ControlRef:
    """A reference to a control in a framework (NIST 800-53, CIS)."""

    framework: str              # "NIST_800_53" | "CIS_AWS"
    control_id: str             # e.g. "AC-6", "2.1.1"
    title: str
    effectiveness: float        # 0..1 expected risk-reduction if implemented


@dataclass
class RiskScore:
    """Quantified risk for a finding: inherent -> mitigation -> residual."""

    likelihood: int             # 1..5
    impact: int                 # 1..5
    inherent: float             # likelihood * impact (1..25)
    combined_effectiveness: float  # 0..1 across applied controls
    residual: float             # inherent * (1 - combined_effectiveness)
    reduction: float            # inherent - residual

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Decision:
    """The analyst's decision about one finding, with everything needed to audit it."""

    finding_id: str
    action: DecisionAction
    priority: int                       # 1 (highest) .. N
    controls: list[ControlRef]
    risk: RiskScore
    justification: str                  # human-readable; may be LLM-authored narrative
    requires_human_approval: bool
    evidence: list[str] = field(default_factory=list)
    confidence: float = 1.0             # 0..1; low confidence forces escalation
    guardrail_flags: list[str] = field(default_factory=list)


@dataclass
class Report:
    """The governance artifact produced at the end of a run."""

    generated_at: str
    environment: str
    model: str
    guardrails_enabled: bool
    decisions: list[Decision]
    summary: dict[str, Any] = field(default_factory=dict)

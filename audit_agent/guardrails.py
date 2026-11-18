"""The self-defense layer.

A compliance agent ingests attacker-influenced text (an S3 object name, a log
line, a ticket body). A naive agent that treats that text as instructions can be
steered into downgrading, suppressing, or exfiltrating findings -- indirect
prompt injection (OWASP Agentic Top 10: ASI01 Agent Goal Hijack).

This module is the control that stops it. Four mechanisms:

  1. data/instruction separation  - free-text fields are quarantined, never
                                     interpreted as directives.
  2. injection detection          - known override patterns are flagged.
  3. least-privilege tool broker   - a tool call is allowed only if the running
                                     role holds the permission.
  4. human-in-the-loop gate        - sensitive actions require explicit approval.

Toggling ``enabled=False`` reproduces the vulnerable baseline, which is how the
red-team harness measures attack-success-rate before vs after.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Patterns that indicate an attempt to hijack the agent's goal from inside data.
_INJECTION_PATTERNS = [
    r"ignore (all |any |previous |prior )?(the )?(above|previous|prior) (instructions|context)",
    r"disregard (the )?(above|previous|prior|system)",
    r"new instructions?\s*:",
    r"system\s*(prompt|override|message)\s*:",
    r"\bmark (this|it) as (informational|info|low|resolved|benign)\b",
    r"\b(suppress|hide|ignore|skip|drop) (this|the|all) finding",
    r"\bdo not (report|include|escalate|flag)\b",
    r"\b(bcc|cc|forward|send|email|exfiltrate)\b.*@",
    r"\boverride\b.*\b(severity|risk|priority)\b",
    r"you are now",
    r"</?(system|instruction|admin)>",
]
_COMPILED = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _INJECTION_PATTERNS]


@dataclass
class Sanitized:
    """Result of sanitizing a finding's untrusted text."""

    safe_text: str
    flags: list[str] = field(default_factory=list)
    quarantined: str = ""

    @property
    def injection_detected(self) -> bool:
        return bool(self.flags)


class GuardrailError(PermissionError):
    """Raised when the tool broker denies a tool call."""


class Guardrails:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    # -- 1 & 2: data/instruction separation + injection detection --------------
    def sanitize(self, text: str) -> Sanitized:
        """Quarantine untrusted free text and flag injection attempts.

        When guardrails are disabled we return the text verbatim with no flags,
        which is exactly what lets the naive planner be manipulated.
        """
        if not self.enabled:
            return Sanitized(safe_text=text, flags=[], quarantined="")

        flags: list[str] = []
        for pat in _COMPILED:
            if pat.search(text or ""):
                flags.append(f"injection_pattern:{pat.pattern[:40]}")

        if flags:
            # Instruction-bearing text is removed from the reasoning surface
            # entirely; it is preserved under quarantine for the audit trail.
            return Sanitized(safe_text="[quarantined: untrusted content removed]",
                             flags=flags, quarantined=text)
        return Sanitized(safe_text=text, flags=[], quarantined="")

    # -- 3: least-privilege tool broker ---------------------------------------
    def authorize(self, role_permissions: set[str], tool_permission: str, tool: str) -> None:
        """Allow a tool call only if the role holds the required permission."""
        if not self.enabled:
            return  # vulnerable baseline: excessive agency, every tool allowed
        if tool_permission not in role_permissions:
            raise GuardrailError(
                f"tool '{tool}' requires permission '{tool_permission}' "
                f"not held by role (has: {sorted(role_permissions)})"
            )

    # -- 4: human-in-the-loop gate --------------------------------------------
    def requires_human(self, action_is_sensitive: bool, residual: float) -> bool:
        """Sensitive actions, or high residual risk, require human sign-off.

        With guardrails off, nothing is gated -- the agent can act autonomously
        on anything, including a remediation an attacker talked it into.
        """
        if not self.enabled:
            return False
        return action_is_sensitive or residual >= 16

"""The analyst agent: a thin, explicit tool-calling loop.

No heavy framework on purpose -- the control flow is legible so a reviewer can
see exactly where untrusted data enters, where guardrails act, and where human
approval is required. The loop per finding:

    sanitize(untrusted text) -> map controls -> score risk -> decide -> gate

Compliance ground truth (control mapping, risk math) is deterministic. The LLM
only writes the justification sentence. The guardrail layer is what separates a
safe decision from a hijacked one, which the red-team harness measures.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import risk as risk_mod
from .audit import AuditTrail
from .controls import ControlCatalog
from .guardrails import GuardrailError, Guardrails
from .llm import LLM, build_llm
from .models import (
    Decision,
    DecisionAction,
    Finding,
    Report,
    Severity,
)
from .tools import ROLE_PERMISSIONS, TOOLS, send_report

# Directives an attacker tries to smuggle through untrusted finding text. These
# are only ever parsed from RAW text in the vulnerable path; when guardrails are
# on, the text is quarantined first so none of this matches.
_DOWNGRADE = re.compile(r"mark (this|it) as (informational|info|low|resolved|benign)", re.I)
_SUPPRESS = re.compile(r"(suppress|hide|skip|drop) (this|the) finding|do not (report|include)", re.I)
_EXFIL = re.compile(r"(bcc|cc|forward|send|email)\b.*?([\w.+-]+@[\w-]+\.[\w.-]+)", re.I)


class AuditAnalyst:
    def __init__(
        self,
        guardrails: Guardrails | None = None,
        role: str = "analyst",
        llm: LLM | None = None,
        catalog: ControlCatalog | None = None,
        audit_path: Path | None = None,
    ) -> None:
        self.guardrails = guardrails or Guardrails(enabled=True)
        self.role = role
        self.permissions = ROLE_PERMISSIONS[role]
        self.llm = llm or build_llm()
        self.catalog = catalog or ControlCatalog()
        self.audit = AuditTrail(audit_path or Path("reports/audit_trail.jsonl"))

    # -- tool wrappers go through the broker ----------------------------------
    def _authorize(self, tool_name: str) -> None:
        spec = TOOLS[tool_name]
        try:
            self.guardrails.authorize(self.permissions, spec.permission, tool_name)
        except GuardrailError as e:
            self.audit.log_denied(tool_name, str(e))
            raise

    def _assess(self, finding: Finding) -> Decision:
        # 1. Untrusted text through the guardrail layer.
        san_desc = self.guardrails.sanitize(finding.description)
        flags = list(san_desc.flags)
        if san_desc.injection_detected:
            self.audit.log_guardrail(finding.id, san_desc.flags, san_desc.quarantined)

        # 2. The text the planner is allowed to reason over.
        planner_text = san_desc.safe_text

        # 3. Deterministic compliance ground truth (category-driven, text-immune).
        self._authorize("map_control")
        controls = self.catalog.map_finding(finding)

        # 4. Effective severity. In the DEFENDED path this is just the real
        #    severity. In the VULNERABLE path, an injected directive in the raw
        #    text can downgrade or suppress -- this is the attack succeeding.
        effective_sev = finding.severity
        action = DecisionAction.REPORT
        confidence = 1.0
        evidence = [f"source={finding.source}", f"category={finding.category}",
                    f"resource={finding.resource}"]

        if _DOWNGRADE.search(planner_text):
            effective_sev = Severity.INFO
            flags.append("ACTED_ON_INJECTION:downgrade")
            confidence = 0.2
        if _SUPPRESS.search(planner_text):
            action = DecisionAction.SUPPRESS
            flags.append("ACTED_ON_INJECTION:suppress")
            confidence = 0.1
        exfil = _EXFIL.search(planner_text)
        if exfil:
            # Naive agent is talked into a sensitive outbound action.
            flags.append(f"ACTED_ON_INJECTION:exfil->{exfil.group(2)}")
            action = DecisionAction.REQUEST_REMEDIATION

        # 5. Deterministic risk from effective severity. For an OPEN finding the
        #    controls are not yet implemented, so CURRENT exposure == inherent
        #    risk; residual is the projected risk *after* remediation. Priority
        #    and escalation rank on current exposure; residual quantifies the
        #    value of fixing it.
        self._authorize("score_risk")
        rscore = risk_mod.score(effective_sev, controls)
        priority = risk_mod.priority_rank(rscore.inherent)

        # 6. Escalate high current risk; low confidence also forces review.
        if action == DecisionAction.REPORT and rscore.inherent >= 16:
            action = DecisionAction.ESCALATE

        # 7. HITL gate for sensitive actions / high current exposure.
        sensitive = action == DecisionAction.REQUEST_REMEDIATION
        requires_human = self.guardrails.requires_human(sensitive, rscore.inherent)

        # 8. If an exfil action is requested, it must pass the sensitive-tool
        #    broker. Under least privilege the analyst role lacks report:send,
        #    so even a hijacked agent cannot send -- defense in depth.
        if sensitive:
            try:
                self._authorize("send_report")
                _ = send_report(exfil.group(2) if exfil else "", str(self.audit.path))
            except GuardrailError:
                flags.append("BLOCKED:send_denied_least_privilege")
                requires_human = True

        justification = self.llm.justify(
            title=finding.title, severity=effective_sev.value,
            controls=controls, risk=rscore,
        )

        return Decision(
            finding_id=finding.id,
            action=action,
            priority=priority,
            controls=controls,
            risk=rscore,
            justification=justification,
            requires_human_approval=requires_human,
            evidence=evidence,
            confidence=confidence,
            guardrail_flags=flags,
        )

    def run(self, findings: list[Finding], environment: str = "sandbox") -> Report:
        self._authorize("read_findings")
        decisions = [self._assess(f) for f in findings]
        # Keep every decision (including suppressed) available for red-team diffing.
        self.last_decisions: list[Decision] = decisions
        for d in decisions:
            self.audit.log_decision(d)

        reported = [d for d in decisions if d.action != DecisionAction.SUPPRESS]
        reported.sort(key=lambda d: (d.priority, -d.risk.residual))

        self._authorize("write_report")
        summary = {
            "total_findings": len(findings),
            "reported": len(reported),
            "suppressed": sum(1 for d in decisions if d.action == DecisionAction.SUPPRESS),
            "escalated": sum(1 for d in decisions if d.action == DecisionAction.ESCALATE),
            "needs_human_approval": sum(1 for d in decisions if d.requires_human_approval),
            "injection_events": sum(1 for d in decisions
                                    if any(f.startswith(("injection_pattern", "ACTED_ON_INJECTION"))
                                           for f in d.guardrail_flags)),
            "acted_on_injection": sum(1 for d in decisions
                                      if any(f.startswith("ACTED_ON_INJECTION")
                                             for f in d.guardrail_flags)),
            "control_coverage": self.catalog.coverage(),
        }
        self.audit.flush()
        return Report(
            generated_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat(),
            environment=environment,
            model=self.llm.name,
            guardrails_enabled=self.guardrails.enabled,
            decisions=reported,
            summary=summary,
        )

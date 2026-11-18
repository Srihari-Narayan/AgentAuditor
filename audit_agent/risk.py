"""Deterministic residual-risk scoring.

inherent = likelihood * impact                     (1..25)
combined_effectiveness = 1 - prod(1 - e_i)         (controls stack, with diminishing returns)
residual = inherent * (1 - combined_effectiveness)
reduction = inherent - residual

Every number here is reproducible from the inputs, which is what makes the
report auditable: a reviewer can recompute any score by hand.
"""

from __future__ import annotations

from .models import ControlRef, RiskScore, Severity

# Severity -> (likelihood, impact) on a 1..5 scale. Documented and fixed so the
# mapping is defensible in an audit rather than a black box.
_LIKELIHOOD = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_IMPACT = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

# Controls never credited with more than this combined effectiveness: residual
# risk never reaches zero, which reflects reality (defense in depth != immunity).
_MAX_EFFECTIVENESS = 0.9


def combined_effectiveness(controls: list[ControlRef]) -> float:
    remaining = 1.0
    for c in controls:
        remaining *= (1.0 - max(0.0, min(1.0, c.effectiveness)))
    eff = 1.0 - remaining
    return round(min(eff, _MAX_EFFECTIVENESS), 4)


def score(severity: Severity, controls: list[ControlRef]) -> RiskScore:
    likelihood = _LIKELIHOOD[severity]
    impact = _IMPACT[severity]
    inherent = float(likelihood * impact)
    eff = combined_effectiveness(controls)
    residual = round(inherent * (1.0 - eff), 1)
    reduction = round(inherent - residual, 1)
    return RiskScore(
        likelihood=likelihood,
        impact=impact,
        inherent=inherent,
        combined_effectiveness=eff,
        residual=residual,
        reduction=reduction,
    )


def priority_rank(current_risk: float) -> int:
    """Lower number = more urgent. Buckets current (inherent) risk into P1..P4.

    Open findings are prioritized on the exposure that exists *now*, before the
    mapped controls are implemented. Residual risk is reported separately to show
    how much remediation would buy.
    """
    if current_risk >= 16:
        return 1
    if current_risk >= 9:
        return 2
    if current_risk >= 4:
        return 3
    return 4

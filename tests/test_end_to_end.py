import json
from pathlib import Path

from audit_agent.agent import AuditAnalyst
from audit_agent.guardrails import Guardrails
from audit_agent.models import DecisionAction, Finding

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "findings" / "sample_findings.json"


def _load():
    return [Finding.from_dict(r) for r in json.loads(SAMPLE.read_text(encoding="utf-8"))]


def test_demo_runs_and_produces_decisions(tmp_path):
    analyst = AuditAnalyst(guardrails=Guardrails(True),
                           audit_path=tmp_path / "audit.jsonl")
    report = analyst.run(_load())
    assert report.summary["total_findings"] == 8
    assert report.decisions                       # non-empty
    # every reported decision carries controls, a risk score and a justification
    for d in report.decisions:
        assert d.controls
        assert d.risk.residual <= d.risk.inherent
        assert d.justification


def test_audit_trail_has_a_record_per_finding(tmp_path):
    analyst = AuditAnalyst(guardrails=Guardrails(True),
                           audit_path=tmp_path / "audit.jsonl")
    analyst.run(_load())
    kinds = [r["kind"] for r in analyst.audit.records]
    assert kinds.count("decision") == 8


def test_guardrails_on_quarantine_injection_but_do_not_act(tmp_path):
    # SOC-NOTE-008 carries an injection. With guardrails ON it must be flagged
    # but NOT acted on (not suppressed/downgraded).
    analyst = AuditAnalyst(guardrails=Guardrails(True),
                           audit_path=tmp_path / "audit.jsonl")
    report = analyst.run(_load())
    assert report.summary["injection_events"] >= 1
    assert report.summary["acted_on_injection"] == 0
    assert any(d.finding_id == "SOC-NOTE-008" for d in report.decisions)


def test_guardrails_off_is_vulnerable(tmp_path):
    # With guardrails OFF the same injection suppresses the finding.
    analyst = AuditAnalyst(guardrails=Guardrails(False),
                           audit_path=tmp_path / "audit.jsonl")
    analyst.run(_load())
    by_id = {d.finding_id: d for d in analyst.last_decisions}
    assert by_id["SOC-NOTE-008"].action == DecisionAction.SUPPRESS
    assert any(f.startswith("ACTED_ON_INJECTION") for f in by_id["SOC-NOTE-008"].guardrail_flags)

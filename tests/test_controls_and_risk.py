from audit_agent.controls import ControlCatalog
from audit_agent.models import Finding, Severity
from audit_agent import risk


def test_mapping_is_deterministic():
    cat = ControlCatalog()
    f = Finding(id="x", source="prowler", title="t", severity=Severity.HIGH,
                category="public_storage", resource="r")
    a = cat.map_finding(f)
    b = cat.map_finding(f)
    assert [c.control_id for c in a] == [c.control_id for c in b]
    assert {c.control_id for c in a} == {"AC-3", "SC-7", "2.1.5"}


def test_unknown_category_falls_back_to_default():
    cat = ControlCatalog()
    f = Finding(id="x", source="s", title="t", severity=Severity.LOW,
                category="never_seen", resource="r")
    refs = cat.map_finding(f)
    assert refs and refs[0].control_id == "SI-4"


def test_residual_is_recomputable_and_below_inherent():
    cat = ControlCatalog()
    f = Finding(id="x", source="s", title="t", severity=Severity.CRITICAL,
                category="unencrypted_data", resource="r")
    controls = cat.map_finding(f)
    s = risk.score(Severity.CRITICAL, controls)
    assert s.inherent == 25.0
    assert 0 < s.residual < s.inherent
    # residual never zero: defense in depth is not immunity
    assert s.combined_effectiveness <= 0.9


def test_priority_buckets_are_monotonic():
    assert risk.priority_rank(25) == 1
    assert risk.priority_rank(10) == 2
    assert risk.priority_rank(5) == 3
    assert risk.priority_rank(1) == 4

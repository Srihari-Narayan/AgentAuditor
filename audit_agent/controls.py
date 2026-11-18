"""Deterministic control mapping.

This is the compliance ground truth. A finding's *category* maps to a fixed set
of NIST 800-53 and CIS AWS controls via an auditable rule table loaded from
``data/controls/``. The LLM is NEVER allowed to decide which control applies --
that would make the mapping unreproducible and unauditable. The model's only job
(see llm.py) is to write the natural-language justification around these facts.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import ControlRef, Finding

_DATA = Path(__file__).resolve().parent.parent / "data" / "controls"


class ControlCatalog:
    """Loads control catalogs + the category->control mapping rules."""

    def __init__(self, data_dir: Path | None = None) -> None:
        d = data_dir or _DATA
        self._nist = json.loads((d / "nist_800_53.json").read_text(encoding="utf-8"))
        self._cis = json.loads((d / "cis_aws.json").read_text(encoding="utf-8"))
        self._rules = json.loads((d / "mapping_rules.json").read_text(encoding="utf-8"))

    def _ref(self, framework: str, control_id: str, effectiveness: float) -> ControlRef | None:
        catalog = self._nist if framework == "NIST_800_53" else self._cis
        title = catalog.get(control_id)
        if title is None:
            return None
        return ControlRef(
            framework=framework,
            control_id=control_id,
            title=title,
            effectiveness=float(effectiveness),
        )

    def map_finding(self, finding: Finding) -> list[ControlRef]:
        """Return the controls that apply to a finding, by its category.

        Deterministic: same finding category always yields the same controls.
        Unknown categories fall back to the ``default`` rule so nothing is
        silently dropped from compliance coverage.
        """
        rule = self._rules.get(finding.category) or self._rules["default"]
        refs: list[ControlRef] = []
        for item in rule["nist"]:
            ref = self._ref("NIST_800_53", item["id"], item["effectiveness"])
            if ref:
                refs.append(ref)
        for item in rule["cis"]:
            ref = self._ref("CIS_AWS", item["id"], item["effectiveness"])
            if ref:
                refs.append(ref)
        return refs

    def coverage(self) -> dict[str, int]:
        """How many controls exist in each framework (for the report summary)."""
        return {"NIST_800_53": len(self._nist), "CIS_AWS": len(self._cis)}

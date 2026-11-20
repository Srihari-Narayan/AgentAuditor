"""Tests for the optional web GUI.

The GUI is a presentation layer only. These tests exercise its pure functions
(no sockets): that it drives the SAME deterministic pipeline, that the
guardrails toggle still produces genuinely different behavior through it, that
untrusted finding text is HTML-escaped on output, and that bad input is rejected
cleanly.
"""

import json
from pathlib import Path

import pytest

from audit_agent import web

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "findings" / "sample_findings.json"
SAMPLE_JSON = SAMPLE.read_text(encoding="utf-8")


def test_run_report_matches_pipeline():
    report = web.run_report(SAMPLE_JSON, guardrails=True)
    assert report.summary["total_findings"] == 8
    assert report.decisions
    html = web.render_report_html(report)
    assert "Prioritized findings" in html
    assert "Summary" in html


def test_guardrails_toggle_differs_through_web():
    # The defense toggle must still change behavior via the GUI entry point.
    on = web.run_report(SAMPLE_JSON, guardrails=True)
    off = web.run_report(SAMPLE_JSON, guardrails=False)
    assert on.summary["acted_on_injection"] == 0
    assert off.summary["acted_on_injection"] >= 1


def test_untrusted_finding_text_is_escaped():
    # A finding whose fields carry HTML/script must never render as live markup.
    payload = json.dumps([{
        "id": "XSS-1",
        "source": "soc",
        "title": "<script>alert('xss')</script>",
        "severity": "high",
        "category": "network_exposure",
        "resource": "<img src=x onerror=alert(1)>",
        "description": "benign",
    }])
    report = web.run_report(payload, guardrails=True)
    html = web.render_report_html(report)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_invalid_json_raises_valueerror():
    with pytest.raises(ValueError):
        web.run_report("not json", guardrails=True)


def test_non_array_raises_valueerror():
    with pytest.raises(ValueError):
        web.run_report('{"id": "x"}', guardrails=True)


def test_form_prefill_is_escaped():
    # Prefilled content is also escaped so the textarea cannot break out.
    html = web.render_form("</textarea><script>bad()</script>")
    assert "<script>bad()</script>" not in html

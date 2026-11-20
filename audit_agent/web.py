"""Optional web GUI for AgentAuditor -- standard library only.

This is a thin PRESENTATION layer over the exact same deterministic pipeline the
CLI uses. It parses a findings JSON, runs :class:`AuditAnalyst`, and renders the
governance report as HTML. It adds no decision logic of its own: control mapping,
risk math, priorities and HITL gates all come from the deterministic core, just
as in ``python -m audit_agent.run``. The LLM still only writes the justification
sentence. Deleting this file changes nothing about any control, number, priority
or gate -- it is UI, nothing more.

Untrusted finding text is HTML-escaped on the way out, consistent with the
project's rule that finding text is data, never trusted markup.

Run it:

    python -m audit_agent.web                 # http://127.0.0.1:8000
    HOST=0.0.0.0 PORT=9000 python -m audit_agent.web

The CLI remains the primary interface; this GUI is entirely optional.
"""

from __future__ import annotations

import json
import os
import tempfile
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .agent import AuditAnalyst
from .controls import ControlCatalog
from .guardrails import Guardrails
from .models import Finding, Report

_ROOT = Path(__file__).resolve().parent.parent
_SAMPLE = _ROOT / "data" / "findings" / "sample_findings.json"
_MAX_BODY = 1_000_000  # 1 MB cap on request bodies


# --------------------------------------------------------------------------- #
# Core logic (pure, testable -- no sockets involved)
# --------------------------------------------------------------------------- #
def run_report(findings_json: str, guardrails: bool, role: str = "analyst") -> Report:
    """Parse a findings JSON string and run the deterministic pipeline.

    Raises ValueError on malformed input so callers can show a clean message.
    """
    try:
        records = json.loads(findings_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e
    if not isinstance(records, list):
        raise ValueError("Findings must be a JSON array of finding objects.")
    try:
        findings = [Finding.from_dict(r) for r in records]
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"Malformed finding: {e}") from e

    if role not in ("analyst", "operator"):
        role = "analyst"

    # Audit trail is written to a throwaway dir: the GUI does not clobber the
    # repo's reports/ directory, and nothing here is a trusted artifact.
    tmp = Path(tempfile.mkdtemp(prefix="agentauditor-web-"))
    analyst = AuditAnalyst(
        guardrails=Guardrails(enabled=guardrails),
        role=role,
        catalog=ControlCatalog(),
        audit_path=tmp / "audit_trail.jsonl",
    )
    return analyst.run(findings)


def _load_sample() -> str:
    try:
        return _SAMPLE.read_text(encoding="utf-8")
    except OSError:
        return "[]"


# --------------------------------------------------------------------------- #
# HTML rendering (all finding-derived text is escaped)
# --------------------------------------------------------------------------- #
_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0; background: #0f172a; color: #e2e8f0; line-height: 1.5; }
header { background: #1e293b; padding: 1.25rem 2rem; border-bottom: 1px solid #334155; }
header h1 { margin: 0; font-size: 1.25rem; }
header p { margin: .25rem 0 0; color: #94a3b8; font-size: .85rem; }
main { max-width: 1100px; margin: 0 auto; padding: 2rem; }
a { color: #7dd3fc; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 10px;
        padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; }
label { display: block; font-size: .8rem; color: #94a3b8; margin: .75rem 0 .25rem; }
textarea { width: 100%; min-height: 240px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
           font-size: .8rem; background: #0b1220; color: #e2e8f0; border: 1px solid #334155;
           border-radius: 8px; padding: .75rem; }
.row { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; margin-top: .75rem; }
select { background: #0b1220; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: .35rem .5rem; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 8px; padding: .6rem 1.25rem;
         font-size: .9rem; cursor: pointer; margin-top: 1rem; }
button:hover { background: #1d4ed8; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #334155; vertical-align: top; }
th { color: #94a3b8; font-weight: 600; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 600; }
.on  { background: #064e3b; color: #6ee7b7; }
.off { background: #7f1d1d; color: #fca5a5; }
.pill { font-family: ui-monospace, monospace; font-size: .75rem; color: #cbd5e1; }
.muted { color: #94a3b8; font-size: .8rem; }
.err { background: #7f1d1d; color: #fecaca; padding: .75rem 1rem; border-radius: 8px; }
.flag { color: #fca5a5; font-family: ui-monospace, monospace; font-size: .75rem; }
"""


def render_page(body: str, subtitle: str = "") -> str:
    sub = f"<p>{escape(subtitle)}</p>" if subtitle else ""
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>AgentAuditor</title>"
        f"<style>{_CSS}</style></head><body>"
        f"<header><h1>AgentAuditor &mdash; Risk &amp; Compliance Analyst</h1>{sub}</header>"
        f"<main>{body}</main></body></html>"
    )


def render_form(prefill: str, guardrails: bool = True, role: str = "analyst") -> str:
    checked = "checked" if guardrails else ""
    opt_analyst = "selected" if role == "analyst" else ""
    opt_operator = "selected" if role == "operator" else ""
    return render_page(
        "<form method='post' action='/run'>"
        "<div class='card'>"
        "<p class='muted'>Paste a findings JSON array (or use the bundled sample below), "
        "then run the deterministic analysis. Control mapping and risk are computed by "
        "rule, not by the model.</p>"
        "<label for='findings'>Findings JSON</label>"
        f"<textarea id='findings' name='findings' spellcheck='false'>{escape(prefill)}</textarea>"
        "<div class='row'>"
        f"<span><input type='checkbox' id='guardrails' name='guardrails' value='on' {checked}> "
        "<label style='display:inline' for='guardrails'>Guardrails enabled "
        "(uncheck for the vulnerable baseline)</label></span>"
        "<span><label style='display:inline' for='role'>Role</label> "
        f"<select id='role' name='role'>"
        f"<option value='analyst' {opt_analyst}>analyst</option>"
        f"<option value='operator' {opt_operator}>operator</option>"
        "</select></span>"
        "</div>"
        "<button type='submit'>Run analysis</button>"
        "</div></form>",
        subtitle="Auditable agentic SOC/compliance analyst with a prompt-injection self-defense layer.",
    )


def _summary_table(s: dict) -> str:
    rows = [
        ("Findings ingested", s.get("total_findings", 0)),
        ("Reported", s.get("reported", 0)),
        ("Suppressed", s.get("suppressed", 0)),
        ("Escalated (high current risk)", s.get("escalated", 0)),
        ("Awaiting human approval", s.get("needs_human_approval", 0)),
        ("Injection attempts seen", s.get("injection_events", 0)),
    ]
    body = "".join(f"<tr><td>{escape(k)}</td><td class='pill'>{escape(str(v))}</td></tr>" for k, v in rows)
    acted = s.get("acted_on_injection", 0)
    acted_cls = "off" if acted else "on"
    body += (
        f"<tr><td><strong>Injections acted on</strong></td>"
        f"<td><span class='badge {acted_cls}'>{escape(str(acted))}</span></td></tr>"
    )
    return f"<table>{body}</table>"


def render_report_html(report: Report) -> str:
    s = report.summary
    gcls = "on" if report.guardrails_enabled else "off"
    gtxt = "ENABLED" if report.guardrails_enabled else "DISABLED (baseline)"

    meta = (
        "<div class='card'>"
        f"<p class='muted'>Generated {escape(report.generated_at)} &middot; "
        f"environment {escape(report.environment)} &middot; model {escape(report.model)} &middot; "
        f"guardrails <span class='badge {gcls}'>{gtxt}</span></p>"
        f"<h2>Summary</h2>{_summary_table(s)}"
        "</div>"
    )

    # Prioritized findings table.
    prows = []
    for d in report.decisions:
        ctrls = ", ".join(escape(c.control_id) for c in d.controls) or "-"
        prows.append(
            f"<tr><td>P{d.priority}</td><td class='pill'>{escape(d.finding_id)}</td>"
            f"<td>{d.risk.inherent:.0f} &rarr; {d.risk.residual:.1f}</td>"
            f"<td>{ctrls}</td><td>{escape(d.action.value)}</td>"
            f"<td>{'yes' if d.requires_human_approval else 'no'}</td></tr>"
        )
    table = (
        "<div class='card'><h2>Prioritized findings</h2><table>"
        "<tr><th>P</th><th>Finding</th><th>Inherent &rarr; Residual</th>"
        "<th>Controls</th><th>Action</th><th>Human?</th></tr>"
        + ("".join(prows) or "<tr><td colspan='6' class='muted'>No findings reported.</td></tr>")
        + "</table></div>"
    )

    # Decision detail cards.
    details = []
    for d in report.decisions:
        ctrl_lines = "; ".join(
            f"{escape(c.framework)} {escape(c.control_id)} &mdash; {escape(c.title)} "
            f"(eff {c.effectiveness:.0%})"
            for c in d.controls
        ) or "-"
        flags = ""
        if d.guardrail_flags:
            flags = ("<p class='flag'>Guardrail flags: "
                     + ", ".join(escape(f) for f in d.guardrail_flags) + "</p>")
        details.append(
            "<div class='card'>"
            f"<h3>{escape(d.finding_id)} &middot; P{d.priority} &middot; confidence {d.confidence:.2f}</h3>"
            f"<p>{escape(d.justification)}</p>"
            f"<p class='muted'>Controls: {ctrl_lines}</p>"
            f"<p class='muted'>Risk: inherent {d.risk.inherent:.0f} "
            f"(L{d.risk.likelihood}&times;I{d.risk.impact}), combined effectiveness "
            f"{d.risk.combined_effectiveness:.0%}, residual {d.risk.residual:.1f}.</p>"
            f"{flags}"
            f"<p class='muted'>Evidence: {', '.join(escape(e) for e in d.evidence)}</p>"
            "</div>"
        )

    back = "<p><a href='/'>&larr; Run another</a></p>"
    detail_section = "<h2>Decision detail (audit view)</h2>" + "".join(details)
    return render_page(meta + table + detail_section + back)


def render_error(message: str, prefill: str) -> str:
    return render_page(
        f"<div class='card'><div class='err'>{escape(message)}</div>"
        "<p><a href='/'>&larr; Back to the form</a></p></div>"
        + render_form_fragment(prefill)
    )


def render_form_fragment(prefill: str) -> str:
    # Reuse the form so the user does not lose their input after an error.
    return (
        "<form method='post' action='/run'><div class='card'>"
        "<label for='findings'>Findings JSON</label>"
        f"<textarea id='findings' name='findings' spellcheck='false'>{escape(prefill)}</textarea>"
        "<button type='submit'>Run analysis</button></div></form>"
    )


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    server_version = "AgentAuditorGUI/1.0"

    def _send(self, html: str, status: int = 200) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path in ("/", "/index.html"):
            self._send(render_form(_load_sample()))
        elif self.path == "/healthz":
            self._send("ok")
        else:
            self._send(render_page("<div class='card'>Not found. "
                                   "<a href='/'>Go home</a>.</div>"), status=404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/run":
            self._send(render_page("<div class='card'>Not found.</div>"), status=404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > _MAX_BODY:
            self._send(render_error("Request too large.", ""), status=413)
            return
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw, keep_blank_values=True)
        findings_json = (form.get("findings") or [""])[0]
        guardrails = "guardrails" in form
        role = (form.get("role") or ["analyst"])[0]
        try:
            report = run_report(findings_json, guardrails=guardrails, role=role)
        except ValueError as e:
            self._send(render_error(str(e), findings_json), status=400)
            return
        self._send(render_report_html(report))

    def log_message(self, fmt: str, *args) -> None:  # quieter default logging
        return


def main() -> int:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    httpd = ThreadingHTTPServer((host, port), _Handler)
    print(f"AgentAuditor GUI on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

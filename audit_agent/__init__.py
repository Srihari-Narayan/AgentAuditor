"""Auditable agentic risk & compliance analyst.

A SOC/compliance agent that ingests cloud-posture + SOC findings, maps them to
NIST 800-53 and CIS controls, quantifies residual risk, and emits an auditable
governance report -- wrapped in a self-defense layer that resists indirect
prompt injection (OWASP Agentic Top 10). Compliance logic is deterministic; the
LLM only writes justifications; humans approve sensitive actions.
"""

__version__ = "0.1.0"

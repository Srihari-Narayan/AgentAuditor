# Architecture

## Modules

| Module | Responsibility | LLM? |
|---|---|---|
| `models.py` | serializable dataclasses shared across the system | no |
| `controls.py` | category → NIST/CIS control mapping (deterministic) | no |
| `risk.py` | inherent → residual risk scoring (deterministic) | no |
| `guardrails.py` | sanitize untrusted text, tool broker, HITL gate | no |
| `llm.py` | justification writer; mock or self-hosted endpoint | yes (narrative only) |
| `tools.py` | tool registry with permissions + sensitivity | no |
| `audit.py` | structured JSONL audit trail | no |
| `agent.py` | the thin tool-calling loop tying it together | orchestrates |
| `report.py` | render Markdown + JSON governance artifact | no |
| `run.py` | CLI | no |

## The loop (per finding)

1. **sanitize** — untrusted `description` through `Guardrails.sanitize`; injection
   patterns are flagged and the text quarantined (logged to the audit trail).
2. **map_control** — `ControlCatalog.map_finding` returns a fixed control set for
   the finding's category. Text-immune.
3. **score_risk** — `risk.score` computes inherent (current) and residual risk
   from severity + control effectiveness.
4. **decide** — priority from current risk; high current risk → escalate.
5. **gate** — sensitive actions / high exposure require human approval; sensitive
   tools additionally pass the least-privilege broker.

## Key invariant

The model sits *outside* the trust path for compliance facts. If you deleted
`llm.py` and replaced justifications with empty strings, every control mapping,
risk number, priority, and gate decision would be identical. That is what makes
the system auditable and robust to a compromised model.

## Data-residency note

With a self-hosted endpoint (`MODEL_BASE_URL`), finding text is only ever sent to
infrastructure you control. The default mock sends nothing anywhere.

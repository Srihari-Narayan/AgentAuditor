# CLAUDE.md — project guidance for Claude Code

This file tells Claude Code how to work in this repository (project name:
**AgentAuditor**). Read it before making changes.

## What this project is

**AgentAuditor** is an **auditable agentic SOC/compliance analyst** with a
**prompt-injection self-defense layer**. It ingests security findings (cloud-posture scans, SOC
alerts), maps each to **NIST 800-53** and **CIS AWS** controls, quantifies
**inherent → residual risk**, and emits an auditable governance report. A
red-team harness then attacks the agent with indirect prompt injection and
measures attack-success-rate (ASR) with the defenses off vs on.

It is a research / portfolio project. Synthetic data only; it takes no action on
real systems. See `DISCLAIMER.md`.

## The one invariant that must never break

**The LLM is not the source of truth.** Control mapping (`controls.py`) and risk
scoring (`risk.py`) are deterministic and recomputable by hand. The model
(`llm.py`) only writes the natural-language justification sentence. It must never
choose a control, compute a risk number, set a priority, or decide a gate.

Test of any change: *if you deleted `llm.py` and replaced every justification
with an empty string, all controls, risk numbers, priorities, and gate decisions
must stay identical.* If a change violates that, it is wrong for this project.

Reason: this is what makes the output auditable and robust to a hallucinating or
**compromised** model. It is the whole thesis. Do not undermine it for
convenience.

## Architecture (where things live)

```
audit_agent/
  models.py      dataclasses (Finding, Decision, RiskScore, Report). Serializable.
  controls.py    category -> NIST/CIS control mapping. DETERMINISTIC, text-immune.
  risk.py        inherent = L*I; residual = inherent*(1-eff). DETERMINISTIC.
  guardrails.py  sanitize untrusted text, least-privilege tool broker, HITL gate.
  llm.py         justification writer: offline MockLLM or self-hosted vLLM client.
  tools.py       tool registry: each tool has a permission + a `sensitive` flag.
  audit.py       structured JSONL audit trail (one record per decision/event).
  agent.py       the thin, explicit tool-calling loop tying it together.
  report.py      renders Markdown + JSON governance artifact.
  run.py         CLI entry point.
data/controls/   NIST + CIS catalogs and the category->control rule table.
data/findings/   synthetic sample findings (one carries an injection payload).
defense/redteam/ the injection red-team harness + injected fixtures.
docs/            architecture, threat-model, audit-trace spec.
tests/           pytest suite.
terraform/       OPTIONAL deliberately-insecure AWS sandbox (never applied in CI).
```

### The per-finding loop (agent.py)
`sanitize (guardrails) -> map_control (deterministic) -> score_risk
(deterministic) -> decide -> gate (HITL + least privilege)`

- `--no-guardrails` disables the defense layer to reproduce the vulnerable
  baseline. Several tests and the red-team harness depend on this toggle
  producing genuinely different behavior — do not make the two paths converge.
- Untrusted finding text (`description`, `title`, `raw`, resource names) is DATA,
  never instructions. It only enters reasoning after `Guardrails.sanitize`.

## Commands

```
make install        # pip install -e ".[dev]"
make test           # pytest (keep all tests green)
make demo           # run bundled sample, guardrails ON
make demo-baseline  # run bundled sample, guardrails OFF (vulnerable)
make redteam        # injection harness; prints ASR on vs off
make clean          # remove generated reports/

python -m audit_agent.run --demo
python -m audit_agent.run --findings <path.json> [--no-guardrails] [--role analyst|operator] [--out DIR]
python defense/redteam/run_redteam.py
```

Runtime is pure standard library and runs fully offline on a deterministic mock
model (no GPU, no network). A self-hosted model is optional via env vars:
`MODEL_BASE_URL`, `MODEL_NAME`, `MODEL_API_KEY` (see `.env.example`).

## Conventions

- Python >= 3.10, standard library only for runtime deps; `pytest` for dev.
- Keep modules small and single-purpose. Prefer explicit control flow over
  frameworks — the loop in `agent.py` is meant to be read top-to-bottom.
- Every new tool declares a `permission` and a `sensitive` flag in `tools.py` and
  goes through the broker; never bypass `_authorize`.
- Every new guardrail needs a test showing both OFF (vulnerable) and ON
  (defended) behavior, mirroring `tests/test_guardrails.py`.
- New findings/categories: add the category to `data/controls/mapping_rules.json`
  (never hardcode control IDs in Python). Unknown categories fall back to
  `default` — keep that fallback working so nothing drops out of coverage.

## Before you commit

1. `make test` — all green.
2. `make redteam` — defended ASR must stay **0** on the bundled suite; baseline
   ASR must stay **> 0** (the baseline must remain genuinely vulnerable).
3. Do not commit generated artifacts (`reports/*.md`, `*.json`, `*.jsonl`); they
   are gitignored.

## Security / scope guardrails (hard rules)

- Synthetic data only. Do not add real findings, real account IDs, real secrets,
  or anything from a third party's environment.
- The `terraform/` sandbox is intentionally insecure and must never be applied in
  CI or against a shared/production account. Keep it commented and documented.
- The red-team harness targets THIS project's own agent only. Do not add
  techniques that point at external systems.
- Do not overclaim robustness. The threat model honestly states what the
  injection detector does and does not catch; keep that honesty.

## Roadmap (safe directions to extend)

- A Prowler-output normalizer (Prowler JSON -> `Finding` schema).
- Multi-cloud posture (Azure Defender for Cloud) mapped to the same controls.
- RAG over the full NIST catalog for control selection *with citations* — still
  deterministic selection; RAG provides evidence, not the final mapping.
- A second reviewer agent that continuously red-teams this agent's decisions.
- A Sentinel/Elastic workbook over the JSONL audit trail.

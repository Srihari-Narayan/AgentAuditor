# AgentAuditor: Auditable Agentic Risk & Compliance Analyst

An agentic SOC/compliance analyst that ingests cloud-posture and SOC findings,
maps each to **NIST 800-53** and **CIS AWS** controls, quantifies **residual
risk**, and emits an **auditable** governance report, wrapped in a
**self-defense layer** that resists indirect prompt injection (OWASP Agentic
Top 10: *ASI01 Agent Goal Hijack*, *ASI02 Tool Misuse*).

It is built around one opinion: **in a compliance setting the LLM must not be
the source of truth.** Control mapping and risk math are deterministic and
recomputable by hand; the model only writes the human-readable justification;
humans approve sensitive actions. That is what makes every line of the output
answer the question a compliance team actually asks: *"why did the system say
that?"*

> ⚠️ Research / portfolio project. See [DISCLAIMER.md](DISCLAIMER.md). Everything
> runs against synthetic findings in a sandbox; it takes no action on real
> systems.

---

## Why this design

Three properties are the whole point, and each maps to a real governance need:

| Property | How | Why a reviewer cares |
|---|---|---|
| **Auditable** | every decision is a structured, replayable record (control, evidence, risk math, confidence, guardrail events, justification) | compliance lives on "show me why" |
| **Deterministic ground truth** | control mapping (`controls.py`) and residual-risk scoring (`risk.py`) are rule-based and reproducible; the LLM never picks a control or a number | a hallucinating or *compromised* model cannot corrupt the compliance result |
| **Self-defending** | a guardrail layer quarantines untrusted text, enforces least-privilege tools, and gates sensitive actions behind a human | the agent itself is an attack surface; most demos ignore this |

## Architecture

```
 findings (Prowler / Security Hub / SOC)         data/findings/*.json
        │
        ▼
 ┌──────────────────────────────────────────────────────────────┐
 │  AuditAnalyst  (audit_agent/agent.py) - thin tool-calling loop │
 │                                                                │
 │   sanitize ──▶ map_control ──▶ score_risk ──▶ decide ──▶ gate   │
 │   (guardrails) (deterministic) (deterministic)       (HITL)     │
 │        │            │              │            │               │
 │        ▼            ▼              ▼            ▼               │
 │   quarantine   NIST/CIS       inherent→     least-privilege     │
 │   injection    control refs   residual      broker + human      │
 └──────────────────────────────────────────────────────────────┘
        │                    │
        ▼                    ▼
 governance report     audit trail (JSONL)
 reports/report.md     reports/audit_trail.jsonl
```

The LLM (`audit_agent/llm.py`) runs against a **self-hosted, OpenAI-compatible
endpoint** (vLLM serving Qwen/Llama) so no finding data leaves your trust
boundary, a deliberate data-residency property. With no endpoint configured it
falls back to a deterministic offline mock, so the whole project runs in CI with
zero GPU and zero network.

## Quickstart

```bash
# runs against the bundled sample, guardrails on, offline mock model
make demo

# vulnerable baseline (guardrails off) for comparison
make demo-baseline

# the indirect-prompt-injection red-team: attack-success-rate on vs off
make redteam

# tests
make test
```

Or directly:

```bash
python -m audit_agent.run --demo
python -m audit_agent.run --findings data/findings/sample_findings.json --no-guardrails
```

### Using a real self-hosted model

```bash
export MODEL_BASE_URL=http://localhost:8000/v1   # your vLLM endpoint
export MODEL_NAME=Qwen2.5-7B-Instruct
python -m audit_agent.run --demo
```

## Run with Docker

The whole thing runs in a container with zero local setup (offline mock model,
guardrails on). Reports are written back to `./reports` on the host via a mounted
volume:

```bash
docker compose up analyst
```

Or build and run the image directly:

```bash
docker build -t agentauditor .
docker run --rm -v "$PWD/reports:/app/reports" agentauditor
```

Run a custom findings file, the vulnerable baseline, or the red-team harness
instead of the default demo:

```bash
docker compose run --rm analyst \
  python -m audit_agent.run --findings data/findings/sample_findings.json --no-guardrails

docker compose run --rm analyst python defense/redteam/run_redteam.py
```

## What the demo shows

Ingesting 8 sample findings (one of which hides a prompt-injection payload in an
analyst note) with guardrails **on**:

```
Ingested 8 findings -> 8 reported, 6 escalated, 6 awaiting approval.
Injection attempts: 1 | acted on: 0
```

The injected note is detected, quarantined, and reported, **but not acted on**.
Every decision lands in `reports/report.md` with its control mapping, inherent→
residual risk, and justification, and in `reports/audit_trail.jsonl` as a
replayable record.

## The self-defense result (headline)

`make redteam` establishes ground truth, then injects an override payload into
every finding's untrusted text and measures how often the agent is hijacked,
with the defense layer off vs on:

```
Injected findings: 8
ASR  guardrails OFF : 100%  (8 compromised)
ASR  guardrails ON  :   0%  (0 compromised)
Reduction           : 100% absolute
```

*Method, honestly stated:* an attack "succeeds" when the decision deviates from
ground truth (severity downgraded, finding suppressed, or a sensitive outbound
action requested). Detection is pattern- plus structure-based; see
[docs/threat-model.md](docs/threat-model.md) for what it does and does not
catch. The number is a demonstration of the control working on a defined suite,
not a claim of universal robustness.

## Repo layout

```
audit_agent/        the agent: models, deterministic controls+risk, guardrails,
                    llm client, thin loop, audit trail, report renderer
data/controls/      NIST 800-53 + CIS AWS catalogs and the category→control rules
data/findings/      synthetic sample findings (one carries an injection)
defense/redteam/    the injection red-team harness + injected fixtures
terraform/          OPTIONAL scaffolding for a deliberately-misconfigured AWS
                    sandbox + Prowler wiring (run only in a throwaway account)
docs/               architecture, threat model, audit-trace spec
tests/              pytest: mapping, risk, guardrails, end-to-end, red-team
```

## Cloud / real-data path (optional)

The project runs fully offline, but it is designed to consume **real** scanner
output. [terraform/](terraform/) stands up a deliberately-misconfigured sandbox
account and points [Prowler](https://github.com/prowler-cloud/prowler) at it;
its JSON becomes the agent's input. Structured audit logs are shaped to ship
into a SIEM (e.g. Microsoft Sentinel) for the defender's view. Run the sandbox
**only in a throwaway account you own**, never against production.

## Roadmap

- Multi-cloud posture (Azure Defender for Cloud) mapped to the same controls.
- RAG over the full NIST 800-53 catalog for control selection with citations.
- A second reviewer agent that red-teams this agent's decisions continuously.
- Sentinel workbook for the audit trail.

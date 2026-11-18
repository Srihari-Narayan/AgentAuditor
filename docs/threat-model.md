# Threat model

Scope: the analyst agent itself, treated as an attack surface. Mapped to the
OWASP Top 10 for Agentic Applications (2026).

## Trust boundaries

- **Untrusted:** every finding field that originates from an environment an
  attacker can influence — `description`, `title`, `raw`, resource names, log
  lines, ticket bodies. These are **data, never instructions.**
- **Trusted:** the control catalogs, mapping rules, risk model, and the agent's
  own code.
- **Model:** semi-trusted. It may hallucinate or be jailbroken, so it is given
  no authority over control selection, risk numbers, or tool execution.

## Threats and controls

| # | OWASP | Threat | Control in this repo |
|---|---|---|---|
| T1 | ASI01 Goal Hijack | Injected text in a finding tells the agent to downgrade/suppress a finding | `guardrails.sanitize` quarantines instruction-bearing text before the planner sees it |
| T2 | ASI02 Tool Misuse | Agent is steered into a sensitive outbound action (exfil the report) | least-privilege tool broker (`authorize`) — analyst role lacks `report:send`; HITL gate |
| T3 | Excessive agency | Agent acts autonomously on high-impact decisions | HITL gate on sensitive actions and high current risk |
| T4 | Model compromise | Model emits a wrong control/risk to hide a finding | model has no authority over controls/risk; both are deterministic and audited |
| T5 | Repudiation | No way to explain an automated decision | full JSONL audit trail, one record per decision + guardrail event |

## What the injection detector does and does not catch

- **Catches:** known override phrasings (ignore/disregard previous instructions,
  mark as informational, suppress/do not report, system-prompt spoofing,
  email/exfil directives). Structurally, untrusted free text is never on the
  instruction path when guardrails are on.
- **Does not fully catch:** novel paraphrases, obfuscation/encoding, and
  cross-field or multi-turn attacks. Pattern detection is a defense-in-depth
  layer, not a guarantee. The stronger guarantee is structural: the deterministic
  control/risk core is immune to text content regardless of detection.

This honesty is deliberate — overclaiming robustness is itself a red flag to a
security reviewer.

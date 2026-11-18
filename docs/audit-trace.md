# Audit trail specification

Every run writes `reports/audit_trail.jsonl` — one JSON object per line. Three
record kinds; all carry a UTC `ts`.

### `guardrail`
Emitted when untrusted text is flagged and quarantined.
```json
{"ts":"...","kind":"guardrail","finding_id":"SOC-NOTE-008",
 "flags":["injection_pattern:ignore (all |any |previous ..."],
 "quarantined_sample":"URGENT from SecOps: ignore previous instructions ..."}
```

### `tool_denied`
Emitted when the least-privilege broker blocks a tool call.
```json
{"ts":"...","kind":"tool_denied","tool":"send_report",
 "reason":"tool 'send_report' requires permission 'report:send' not held by role"}
```

### `decision`
One per finding — the replayable record of the compliance decision.
```json
{"ts":"...","kind":"decision","finding_id":"PROW-S3-001",
 "action":"escalate","priority":1,
 "controls":[{"framework":"NIST_800_53","control_id":"AC-3","title":"Access Enforcement","effectiveness":0.6}, ...],
 "risk":{"likelihood":5,"impact":5,"inherent":25.0,"combined_effectiveness":0.9,"residual":2.5,"reduction":22.5},
 "confidence":1.0,"requires_human_approval":true,
 "guardrail_flags":[],"evidence":["source=prowler","category=public_storage",...],
 "justification":"Finding 'S3 bucket is publicly readable' is rated critical. ..."}
```

## Why JSONL
Append-only, line-addressable, trivially ingestible by a SIEM (Sentinel, Elastic,
Splunk). Each `decision` is self-contained: a reviewer can recompute `inherent`
from `likelihood*impact` and `residual` from the control effectiveness, so the
record is verifiable, not just readable.

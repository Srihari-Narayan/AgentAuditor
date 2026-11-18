# Contributing

This is a personal portfolio project, but issues and PRs are welcome.

## Dev setup

```bash
pip install -e ".[dev]"
make test
```

## Conventions

- Keep the **compliance core deterministic.** The LLM must never choose a
  control or compute a risk number — if a change puts model output on that path,
  it will be rejected.
- Every new tool declares a permission and a `sensitive` flag in `tools.py`.
- New guardrails need a test that shows the vulnerable (off) and defended (on)
  behavior, like `tests/test_guardrails.py`.
- Run `make redteam` before a PR that touches `agent.py` or `guardrails.py`; the
  defended ASR must stay at 0 on the bundled suite.

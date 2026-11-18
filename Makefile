.PHONY: demo demo-baseline redteam test lint clean install

install:
	pip install -e ".[dev]"

demo:
	python -m audit_agent.run --demo

demo-baseline:
	python -m audit_agent.run --demo --no-guardrails

redteam:
	python defense/redteam/run_redteam.py

test:
	python -m pytest -q

lint:
	python -m pyflakes audit_agent defense tests || true

clean:
	rm -rf reports/*.md reports/*.json reports/*.jsonl __pycache__ \
		audit_agent/__pycache__ tests/__pycache__ .pytest_cache

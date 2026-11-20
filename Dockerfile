FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY audit_agent ./audit_agent
COPY data ./data
COPY defense ./defense
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]"

# Default: run the demo (offline mock model, guardrails on).
CMD ["python", "-m", "audit_agent.run", "--demo"]

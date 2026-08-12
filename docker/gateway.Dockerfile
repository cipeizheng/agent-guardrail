# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.11.20 AS uv

FROM python:3.12-slim-bookworm AS builder
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
COPY . .
RUN uv sync --frozen --extra gateway --no-dev --no-editable

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Agent Guardrail Gateway" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin guardrail \
    && mkdir -p /var/lib/agent-guardrail/audit \
    && chown -R guardrail:guardrail /var/lib/agent-guardrail
WORKDIR /app
COPY --from=builder --chown=guardrail:guardrail /app/.venv /app/.venv
COPY --from=builder /app/LICENSE /licenses/LICENSE
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGENT_GUARDRAIL_HOST=0.0.0.0 \
    AGENT_GUARDRAIL_PORT=8080
USER guardrail
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2).read()"]
ENTRYPOINT ["python", "-m", "agent_guardrail.gateway"]

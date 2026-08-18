# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.11.20 AS uv

FROM python:3.12-slim-bookworm AS builder
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
COPY . .
RUN uv sync --frozen --extra core-server --extra detectors --no-dev --no-editable \
    && uv venv /opt/semgrep \
    && uv pip install --python /opt/semgrep/bin/python semgrep==1.170.0
ENV AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/opt/agent-guardrail/detectors
RUN .venv/bin/agent-guardrail-prefetch-detectors

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Agent Guardrail Core" \
      org.opencontainers.image.licenses="MIT"
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin guardrail
WORKDIR /app
COPY --from=builder --chown=guardrail:guardrail /app/.venv /app/.venv
COPY --from=builder --chown=guardrail:guardrail /opt/semgrep /opt/semgrep
COPY --from=builder --chown=guardrail:guardrail \
    /opt/agent-guardrail/detectors /opt/agent-guardrail/detectors
COPY --from=builder /app/LICENSE /licenses/LICENSE
ENV PATH="/app/.venv/bin:/opt/semgrep/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    AGENT_GUARDRAIL_CORE_HOST=0.0.0.0 \
    AGENT_GUARDRAIL_CORE_PORT=8090 \
    AGENT_GUARDRAIL_CORE_DETECTOR_PROFILE=full_deberta \
    AGENT_GUARDRAIL_CORE_PROMPT_MODEL_DEVICE=cpu \
    AGENT_GUARDRAIL_CORE_DETECTOR_ASSETS_DIR=/opt/agent-guardrail/detectors
USER guardrail
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health/ready', timeout=2).read()"]
ENTRYPOINT ["python", "-m", "agent_guardrail.core_service"]

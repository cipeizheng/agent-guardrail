# syntax=docker/dockerfile:1.7
# The Detector stack baked into the image is chosen at build time:
#   full_deberta (default) -- production: Presidio/spaCy, Semgrep, YARA, and the
#                             pinned DeBERTa prompt model. Large; the builder
#                             prefetches and verifies ~750 MB of model assets.
#   local                 -- lightweight: base detectors only (no torch,
#                             presidio/spaCy, Semgrep, YARA, no model prefix).
#                             Fast build; validates the compose architecture,
#                             NOT the detector runtime.
ARG DETECTOR_PROFILE=full_deberta

FROM ghcr.io/astral-sh/uv:0.11.20 AS uv

FROM python:3.12-slim-bookworm AS builder
COPY --from=uv /uv /uvx /bin/
ARG DETECTOR_PROFILE=full_deberta
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    if [ "$DETECTOR_PROFILE" = "local" ]; then \
      uv sync --frozen --extra core-server --no-dev --no-editable; \
    else \
      uv sync --frozen --extra core-server --extra detectors --no-dev --no-editable \
      && uv venv /opt/semgrep \
      && uv pip install --python /opt/semgrep/bin/python semgrep==1.170.0; \
    fi
RUN mkdir -p /opt/semgrep /opt/agent-guardrail/detectors
ENV AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR=/opt/agent-guardrail/detectors
RUN if [ "$DETECTOR_PROFILE" != "local" ]; then \
      .venv/bin/agent-guardrail-prefetch-detectors; \
    fi

FROM python:3.12-slim-bookworm AS runtime
LABEL org.opencontainers.image.title="Agent Guardrail Core" \
      org.opencontainers.image.licenses="MIT"
ARG DETECTOR_PROFILE=full_deberta
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin guardrail
WORKDIR /app
COPY --from=builder --chown=guardrail:guardrail /app/.venv /app/.venv
COPY --from=builder --chown=guardrail:guardrail /opt/semgrep /opt/semgrep
COPY --from=builder --chown=guardrail:guardrail \
    /opt/agent-guardrail/detectors /opt/agent-guardrail/detectors
COPY --from=builder /app/LICENSE /licenses/LICENSE
# The compose deployment runs this image read-only (root mount), so every
# tool cache must land on the writable tmpfs (/tmp): semgrep --version creates
# $HOME/.semgrep, and torch/Transformers use $HOME/.cache. HOME=/tmp + XDG_*
# keep semgrep and model backends working without relaxing read_only.
ENV PATH="/app/.venv/bin:/opt/semgrep/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    XDG_DATA_HOME=/tmp/.data \
    XDG_STATE_HOME=/tmp/.state \
    AGENT_GUARDRAIL_CORE_HOST=0.0.0.0 \
    AGENT_GUARDRAIL_CORE_PORT=8090 \
    AGENT_GUARDRAIL_CORE_DETECTOR_PROFILE=${DETECTOR_PROFILE} \
    AGENT_GUARDRAIL_CORE_PROMPT_MODEL_DEVICE=cpu \
    AGENT_GUARDRAIL_CORE_DETECTOR_ASSETS_DIR=/opt/agent-guardrail/detectors
USER guardrail
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=3s --start-period=90s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health/ready', timeout=2).read()"]
ENTRYPOINT ["python", "-m", "agent_guardrail.core_service"]

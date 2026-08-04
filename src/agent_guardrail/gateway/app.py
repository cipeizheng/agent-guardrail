"""FastAPI composition root for the embedded-runtime OpenAI and MCP Gateways."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, cast
from uuid import uuid4

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import JsonValue, ValidationError
from starlette.requests import Request
from starlette.responses import Response

from agent_guardrail.adapters.openai import OpenAIAdapter, OpenAIAdapterError
from agent_guardrail.enforcement import (
    AuditSink,
    EnforcementSession,
    GuardrailUnavailable,
    JsonlAuditSink,
    NullAuditSink,
)
from agent_guardrail.gateway.auth import GatewayAuthenticationError, GatewayAuthenticator
from agent_guardrail.gateway.config import GatewaySettings
from agent_guardrail.gateway.http import RequestReadError, read_json_body
from agent_guardrail.gateway.mcp import MCPGateway
from agent_guardrail.gateway.mcp_upstream import MCPUpstream
from agent_guardrail.gateway.upstream import OpenAIUpstream, UpstreamError
from agent_guardrail.models import Decision, EventKind, GuardrailContext, Phase, Trace
from agent_guardrail.runtime import GuardrailRuntime


@dataclass(frozen=True, slots=True)
class GatewayServices:
    settings: GatewaySettings
    runtime: GuardrailRuntime
    adapter: OpenAIAdapter
    upstream: OpenAIUpstream | None
    mcp: MCPGateway
    audit: AuditSink
    authenticator: GatewayAuthenticator


def create_app(
    settings: GatewaySettings,
    *,
    runtime: GuardrailRuntime | None = None,
    upstream_http_client: httpx.AsyncClient | None = None,
    audit: AuditSink | None = None,
) -> FastAPI:
    """Create an app with explicit injectable process-scoped dependencies."""

    active_runtime = runtime or GuardrailRuntime.from_policy_file(settings.policy_file)
    active_audit = audit or (
        JsonlAuditSink(settings.audit_path) if settings.audit_path is not None else NullAuditSink()
    )
    owns_http_client = upstream_http_client is None
    http_client = upstream_http_client or httpx.AsyncClient(
        follow_redirects=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    authenticator = GatewayAuthenticator(settings)
    openai_upstream = (
        OpenAIUpstream(client=http_client, settings=settings)
        if settings.upstream_base_url is not None
        else None
    )
    mcp_upstream = (
        MCPUpstream(client=http_client, settings=settings)
        if settings.mcp_upstream_url is not None
        else None
    )
    mcp_gateway = MCPGateway(
        settings=settings,
        runtime=active_runtime,
        upstream=mcp_upstream,
        audit=active_audit,
        authenticator=authenticator,
    )
    services = GatewayServices(
        settings=settings,
        runtime=active_runtime,
        adapter=OpenAIAdapter(),
        upstream=openai_upstream,
        mcp=mcp_gateway,
        audit=active_audit,
        authenticator=authenticator,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.gateway = services
        try:
            await active_runtime.start()
            yield
        finally:
            if owns_http_client:
                await http_client.aclose()
            await active_runtime.close()

    app = FastAPI(title="Agent Guardrail Gateway", version="0.1.0", lifespan=lifespan)
    app.state.gateway = services

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        if services.runtime.ready:
            return JSONResponse({"status": "ready"})
        return _error_response(
            503,
            error_type="guardrail_unavailable",
            code="runtime_not_ready",
            message="Guardrail runtime is not ready.",
        )

    @app.get("/v1/policies/current")
    async def current_policy(request: Request) -> JSONResponse:
        authentication_error = _authenticate(services, request)
        if authentication_error is not None:
            return authentication_error
        info = services.runtime.policy_info
        return JSONResponse(
            {"version": info.version, "content_hash": info.content_hash},
        )

    @app.post("/v1/evaluate")
    async def evaluate(request: Request) -> JSONResponse:
        authentication_error = _authenticate(services, request)
        if authentication_error is not None:
            return authentication_error
        if not settings.evaluate_endpoint_enabled:
            return _error_response(
                404,
                error_type="not_found",
                code="evaluate_disabled",
                message="Direct evaluation is disabled.",
            )
        try:
            payload = await read_json_body(request, settings.max_request_bytes)
            context = GuardrailContext.model_validate(payload)
            decision = await services.runtime.evaluate(context)
        except RequestReadError as exc:
            return _error_response(
                exc.status_code,
                error_type="invalid_request_error",
                code=exc.code,
                message=str(exc),
            )
        except ValidationError:
            return _error_response(
                422,
                error_type="invalid_request_error",
                code="invalid_guardrail_context",
                message="The canonical guardrail context is malformed.",
            )
        except Exception:
            return _error_response(
                503,
                error_type="guardrail_unavailable",
                code="evaluation_failed",
                message="Guardrail evaluation is unavailable.",
            )
        return JSONResponse(decision.model_dump(mode="json"))

    @app.post("/v1/openai/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        client_authorization_or_error = _authenticate_with_value(services, request)
        if isinstance(client_authorization_or_error, JSONResponse):
            return client_authorization_or_error
        trace_id = f"trc_{uuid4().hex}"
        if services.upstream is None:
            return _error_response(
                503,
                error_type="upstream_error",
                code="openai_not_configured",
                message="The OpenAI-compatible upstream is not configured.",
                trace_id=trace_id,
            )
        try:
            raw_request = await read_json_body(request, settings.max_request_bytes)
            if isinstance(raw_request, dict) and raw_request.get("stream") is True:
                raise RequestReadError(
                    "streaming_not_supported",
                    "Streaming is not supported by this Gateway version.",
                )
            provider_request = services.adapter.parse_request(raw_request)
            canonical_request = services.adapter.request_to_canonical(provider_request)
        except RequestReadError as exc:
            return _error_response(
                exc.status_code,
                error_type="invalid_request_error",
                code=exc.code,
                message=str(exc),
                trace_id=trace_id,
            )
        except OpenAIAdapterError as exc:
            return _error_response(
                400,
                error_type="invalid_request_error",
                code=exc.code,
                message=str(exc),
                trace_id=trace_id,
            )

        session = EnforcementSession(
            evaluator=services.runtime,
            trace=Trace(id=trace_id, max_events=settings.max_trace_events),
            audit=services.audit,
        )
        try:
            pre_decision = await session.evaluate(
                kind=EventKind.MODEL_REQUEST,
                phase=Phase.PRE_LLM,
                payload=cast(
                    dict[str, JsonValue],
                    canonical_request.model_dump(mode="json"),
                ),
                metadata={"adapter": "openai_gateway"},
            )
        except GuardrailUnavailable:
            return _unavailable_response(trace_id, Phase.PRE_LLM)
        if pre_decision.blocked:
            return _blocked_response(pre_decision)

        try:
            raw_response = await services.upstream.complete(
                services.adapter.request_payload(provider_request),
                client_authorization=client_authorization_or_error,
            )
            provider_response = services.adapter.parse_response(raw_response)
            canonical_response = services.adapter.response_to_canonical(
                provider_response,
                request=provider_request,
            )
        except UpstreamError as exc:
            return _error_response(
                504 if exc.timed_out else 502,
                error_type="upstream_error",
                code=exc.code,
                message="The upstream model request failed.",
                trace_id=trace_id,
            )
        except OpenAIAdapterError as exc:
            return _error_response(
                502,
                error_type="upstream_error",
                code=exc.code,
                message=str(exc),
                trace_id=trace_id,
            )
        except Exception:
            return _error_response(
                502,
                error_type="upstream_error",
                code="upstream_unavailable",
                message="The upstream model request failed.",
                trace_id=trace_id,
            )

        try:
            post_decision = await session.evaluate(
                kind=EventKind.MODEL_RESPONSE,
                phase=Phase.POST_LLM,
                payload=cast(
                    dict[str, JsonValue],
                    canonical_response.model_dump(mode="json"),
                ),
                metadata={"adapter": "openai_gateway"},
            )
        except GuardrailUnavailable:
            return _unavailable_response(trace_id, Phase.POST_LLM)
        if post_decision.blocked:
            return _blocked_response(post_decision)

        return JSONResponse(
            services.adapter.response_payload(provider_response),
            headers={"x-guardrail-trace-id": trace_id},
        )

    @app.post("/v1/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        return await services.mcp.handle(request)

    return app


def _authenticate(services: GatewayServices, request: Request) -> JSONResponse | None:
    result = _authenticate_with_value(services, request)
    return result if isinstance(result, JSONResponse) else None


def _authenticate_with_value(
    services: GatewayServices,
    request: Request,
) -> str | None | JSONResponse:
    try:
        return services.authenticator.authenticate(request)
    except GatewayAuthenticationError:
        return _error_response(
            401,
            error_type="authentication_error",
            code="invalid_api_key",
            message="A valid Gateway API key is required.",
            headers={"www-authenticate": "Bearer"},
        )


def _blocked_response(decision: Decision) -> JSONResponse:
    violations = [
        {
            "rule_id": violation.rule_id,
            "code": violation.code,
            "message": violation.message,
        }
        for violation in decision.violations
    ]
    return _error_response(
        400,
        error_type="guardrail_violation",
        code="guardrail_blocked",
        message="Request blocked by guardrail policy.",
        trace_id=decision.trace_id,
        phase=decision.phase.value,
        violations=violations,
    )


def _unavailable_response(trace_id: str, phase: Phase) -> JSONResponse:
    return _error_response(
        503,
        error_type="guardrail_unavailable",
        code="evaluation_failed",
        message="Guardrail evaluation is unavailable.",
        trace_id=trace_id,
        phase=phase.value,
    )


def _error_response(
    status_code: int,
    *,
    error_type: str,
    code: str,
    message: str,
    trace_id: str | None = None,
    phase: str | None = None,
    violations: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"type": error_type, "code": code, "message": message}
    if trace_id is not None:
        error["trace_id"] = trace_id
    if phase is not None:
        error["phase"] = phase
    if violations is not None:
        error["violations"] = violations
    response_headers = dict(headers or {})
    if trace_id is not None:
        response_headers["x-guardrail-trace-id"] = trace_id
    return JSONResponse({"error": error}, status_code=status_code, headers=response_headers)

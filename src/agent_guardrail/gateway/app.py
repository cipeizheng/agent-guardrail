"""FastAPI composition root for embedded or remote-runtime protocol Gateways."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import Request
from starlette.responses import Response

from agent_guardrail.adapters.anthropic import AnthropicAdapter
from agent_guardrail.adapters.openai import OpenAIAdapter, OpenAIResponsesAdapter
from agent_guardrail.adapters.openai.responses_models import ResponsesRequest, ResponsesResponse
from agent_guardrail.adapters.protocols import (
    ModelProviderAdapter,
    ProviderAdapterError,
)
from agent_guardrail.adapters.streaming import (
    BoundedSSEParser,
    StreamProtocolError,
    StreamRelease,
)
from agent_guardrail.config import create_deployment_detector_registry
from agent_guardrail.enforcement import (
    AuditSink,
    EnforcementCheckpoint,
    EnforcementSession,
    GuardrailUnavailable,
    InputNormalizationError,
    InputNormalizer,
    JsonlAuditSink,
    NullAuditSink,
)
from agent_guardrail.gateway.auth import GatewayAuthenticationError, GatewayAuthenticator
from agent_guardrail.gateway.config import GatewaySettings
from agent_guardrail.gateway.http import RequestReadError, read_json_body
from agent_guardrail.gateway.mcp import MCPGateway
from agent_guardrail.gateway.mcp_upstream import MCPUpstream
from agent_guardrail.gateway.request_session import create_request_session
from agent_guardrail.gateway.responses_state import (
    ResponsesStateError,
    ResponsesStateStore,
)
from agent_guardrail.gateway.upstream import (
    AnthropicUpstream,
    ModelUpstream,
    UpstreamError,
    validate_upstream_path,
)
from agent_guardrail.models import Decision, SecurityDestination
from agent_guardrail.runtime import GuardrailRuntime, RuntimeNotReadyError
from agent_guardrail.runtime.remote import RemoteGuardrailRuntime

DecisionRuntime = GuardrailRuntime | RemoteGuardrailRuntime
_MAX_STREAM_EVENTS = 4_096
_MAX_SSE_EVENT_BYTES = 262_144
_CUSTOM_MODEL_ROUTE = re.compile(r"/v1/providers/[a-z0-9][a-z0-9_/-]{0,100}\Z")


@dataclass(frozen=True, slots=True)
class GatewayServices:
    settings: GatewaySettings
    runtime: DecisionRuntime
    chat_adapter: OpenAIAdapter
    responses_adapter: OpenAIResponsesAdapter
    responses_state_store: ResponsesStateStore | None
    anthropic_adapter: AnthropicAdapter
    normalizer: InputNormalizer
    upstream: ModelUpstream | None
    anthropic_upstream: AnthropicUpstream | None
    mcp: MCPGateway
    audit: AuditSink
    authenticator: GatewayAuthenticator


def create_app(
    settings: GatewaySettings,
    *,
    runtime: DecisionRuntime | None = None,
    upstream_http_client: httpx.AsyncClient | None = None,
    core_http_client: httpx.AsyncClient | None = None,
    audit: AuditSink | None = None,
    model_routes: Mapping[str, ModelProviderAdapter[Any, Any]] | None = None,
    responses_state_store: ResponsesStateStore | None = None,
) -> FastAPI:
    """Create an app with explicit injectable process-scoped dependencies."""

    active_runtime = runtime
    owns_core_http_client = False
    if active_runtime is None:
        if settings.decision_backend == "embedded":
            detector_registry = create_deployment_detector_registry(
                settings.detector_profile,
                prompt_model_device=settings.prompt_model_device,
                detector_assets_dir=settings.detector_assets_dir,
                pii=settings.detector_pii,
                semgrep=settings.detector_semgrep,
                yara=settings.detector_yara,
                prompt_model=settings.detector_prompt_model,
                prompt_model_threshold=settings.prompt_model_threshold,
            )
            if settings.policy_file is None:  # Settings validation makes this unreachable.
                raise ValueError("embedded Gateway requires a policy file")
            active_runtime = GuardrailRuntime.from_policy_file(
                settings.policy_file,
                detector_registry=detector_registry,
            )
        else:
            if settings.core_url is None or settings.core_api_key is None:
                raise ValueError("remote Gateway requires Core configuration")
            if core_http_client is None:
                core_http_client = httpx.AsyncClient(
                    follow_redirects=False,
                    limits=httpx.Limits(
                        max_connections=100,
                        max_keepalive_connections=20,
                    ),
                )
                owns_core_http_client = True
            active_runtime = RemoteGuardrailRuntime(
                base_url=settings.core_url,
                api_key=settings.core_api_key.get_secret_value(),
                timeout_seconds=settings.core_timeout_seconds,
                max_request_bytes=settings.core_max_request_bytes,
                max_response_bytes=settings.core_max_response_bytes,
                client=core_http_client,
            )
    active_audit = audit or (
        JsonlAuditSink(settings.audit_path) if settings.audit_path is not None else NullAuditSink()
    )
    owns_http_client = upstream_http_client is None
    http_client = upstream_http_client or httpx.AsyncClient(
        follow_redirects=False,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    authenticator = GatewayAuthenticator(settings)
    model_upstream = (
        ModelUpstream(client=http_client, settings=settings)
        if settings.upstream_base_url is not None
        else None
    )
    anthropic_upstream = (
        AnthropicUpstream(client=http_client, settings=settings)
        if settings.anthropic_upstream_base_url is not None
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
        chat_adapter=OpenAIAdapter(),
        responses_adapter=OpenAIResponsesAdapter(),
        responses_state_store=responses_state_store,
        anthropic_adapter=AnthropicAdapter(),
        normalizer=InputNormalizer(max_candidates=settings.max_trace_events),
        upstream=model_upstream,
        anthropic_upstream=anthropic_upstream,
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
            if owns_core_http_client and core_http_client is not None:
                await core_http_client.aclose()

    app = FastAPI(title="Agent Guardrail Gateway", version="0.1.0", lifespan=lifespan)
    app.state.gateway = services

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        if await services.runtime.check_ready():
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
        try:
            info = services.runtime.policy_info
        except RuntimeNotReadyError:
            return _error_response(
                503,
                error_type="guardrail_unavailable",
                code="runtime_not_ready",
                message="Guardrail runtime is not ready.",
            )
        return JSONResponse(
            {"version": info.version, "content_hash": info.content_hash},
        )

    @app.post("/v1/openai/chat/completions")
    async def chat_completions(request: Request) -> Response:
        return await _handle_model_request(request, services, services.chat_adapter)

    @app.post("/v1/openai/responses")
    async def responses(request: Request) -> Response:
        return await _handle_model_request(request, services, services.responses_adapter)

    @app.post("/v1/responses")
    async def responses_sdk_compatible(request: Request) -> Response:
        return await _handle_model_request(request, services, services.responses_adapter)

    @app.post("/v1/chat/completions")
    async def chat_completions_sdk_compatible(request: Request) -> Response:
        return await _handle_model_request(request, services, services.chat_adapter)

    @app.post("/v1/anthropic/messages")
    async def anthropic_messages(request: Request) -> Response:
        return await _handle_model_request(
            request,
            services,
            services.anthropic_adapter,
            anthropic_authentication=True,
        )

    @app.post("/v1/messages")
    async def anthropic_sdk_compatible(request: Request) -> Response:
        return await _handle_model_request(
            request,
            services,
            services.anthropic_adapter,
            anthropic_authentication=True,
        )

    for route_path, provider_adapter in (model_routes or {}).items():
        _validate_model_route(route_path, provider_adapter)
        app.add_api_route(
            route_path,
            _bind_model_route(services, provider_adapter),
            methods=["POST"],
        )

    @app.post("/v1/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        return await services.mcp.handle(request)

    return app


def _validate_model_route(
    route_path: str,
    adapter: ModelProviderAdapter[Any, Any],
) -> None:
    if (
        not isinstance(route_path, str)
        or not _CUSTOM_MODEL_ROUTE.fullmatch(route_path)
        or "//" in route_path
        or any(part in {".", ".."} for part in route_path.split("/"))
    ):
        raise ValueError("custom model route path is invalid")
    validate_upstream_path(adapter.upstream_path)


def _bind_model_route(
    services: GatewayServices,
    adapter: ModelProviderAdapter[Any, Any],
) -> Callable[[Request], Awaitable[Response]]:
    async def endpoint(request: Request) -> Response:
        return await _handle_model_request(request, services, adapter)

    return endpoint


async def _handle_model_request(
    request: Request,
    services: GatewayServices,
    adapter: Any,
    *,
    anthropic_authentication: bool = False,
) -> Response:
    client_authorization_or_error = _authenticate_with_value(
        services,
        request,
        anthropic=anthropic_authentication,
    )
    if isinstance(client_authorization_or_error, JSONResponse):
        return client_authorization_or_error
    session = create_request_session(
        analyzer=services.runtime,
        audit=services.audit,
        max_trace_events=services.settings.max_trace_events,
    )
    trace_id = session.trace.id
    active_upstream: ModelUpstream | None = (
        services.anthropic_upstream if anthropic_authentication else services.upstream
    )
    if active_upstream is None:
        return _error_response(
            503,
            error_type="upstream_error",
            code="model_provider_not_configured",
            message="The model provider upstream is not configured.",
            trace_id=trace_id,
        )
    try:
        raw_request = await read_json_body(
            request,
            services.settings.max_request_bytes,
        )
        provider_request = adapter.parse_request(raw_request)
        canonical_request_for_guardrail = provider_request
        responses_state_request: ResponsesRequest | None = None
        if isinstance(provider_request, ResponsesRequest):
            responses_state_request = provider_request
            if provider_request.previous_response_id is not None:
                if services.responses_state_store is None:
                    raise ProviderAdapterError(
                        "responses_state_unconfigured",
                        "Responses state support is not configured for previous_response_id.",
                    )
                try:
                    canonical_request_for_guardrail = (
                        await services.responses_state_store.resolve_request(provider_request)
                    )
                    responses_state_request = canonical_request_for_guardrail
                except ResponsesStateError as exc:
                    raise ProviderAdapterError(exc.code, str(exc)) from None
                except Exception:
                    raise ProviderAdapterError(
                        "responses_state_unavailable",
                        "Responses state could not be resolved.",
                    ) from None
        canonical_request = adapter.request_to_canonical(canonical_request_for_guardrail)
        normalized_request = services.normalizer.normalize_model_call(canonical_request)
        upstream_payload = adapter.request_payload(provider_request)
        if not isinstance(upstream_payload, dict):
            raise ProviderAdapterError(
                "invalid_request",
                "The provider adapter produced an invalid request payload.",
            )
        try:
            encoded_upstream_payload = json.dumps(
                upstream_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            raise ProviderAdapterError(
                "invalid_request",
                "The provider adapter produced an invalid request payload.",
            ) from None
        if len(encoded_upstream_payload) > services.settings.max_request_bytes:
            raise RequestReadError(
                "request_too_large",
                "The normalized provider request exceeds the configured limit.",
                status_code=413,
            )
        streaming = adapter.is_streaming(provider_request)
        stream_decoder = adapter.stream_decoder(provider_request) if streaming else None
    except RequestReadError as exc:
        return _error_response(
            exc.status_code,
            error_type="invalid_request_error",
            code=exc.code,
            message=str(exc),
            trace_id=trace_id,
        )
    except ProviderAdapterError as exc:
        state_unavailable = exc.code == "responses_state_unavailable"
        return _error_response(
            503 if state_unavailable else 400,
            error_type="guardrail_unavailable" if state_unavailable else "invalid_request_error",
            code=exc.code,
            message=str(exc),
            trace_id=trace_id,
            checkpoint=(
                EnforcementCheckpoint.BEFORE_MODEL_CALL.value
                if state_unavailable
                else None
            ),
        )
    except InputNormalizationError as exc:
        return _error_response(
            400,
            error_type="invalid_request_error",
            code=exc.code,
            message=str(exc),
            trace_id=trace_id,
            checkpoint=EnforcementCheckpoint.BEFORE_MODEL_CALL.value,
        )
    except Exception:
        return _error_response(
            400,
            error_type="invalid_request_error",
            code="provider_adapter_error",
            message="The model provider request could not be prepared.",
            trace_id=trace_id,
            checkpoint=EnforcementCheckpoint.BEFORE_MODEL_CALL.value,
        )

    try:
        pre_decision = await session.submit_candidates(
            normalized_request.candidates,
            primary_key=normalized_request.primary_key,
            security_context=session.security_context.with_enforcement_destination(
                SecurityDestination.LLM_PROVIDER
            ),
        )
    except GuardrailUnavailable:
        return _unavailable_response(
            trace_id,
            EnforcementCheckpoint.BEFORE_MODEL_CALL,
        )
    if pre_decision.blocked:
        return _blocked_response(
            pre_decision,
            EnforcementCheckpoint.BEFORE_MODEL_CALL,
        )

    if streaming:
        try:
            upstream_response = await active_upstream.open_stream(
                adapter.upstream_path,
                upstream_payload,
                client_authorization=client_authorization_or_error,
            )
        except UpstreamError as exc:
            return _error_response(
                504 if exc.timed_out else 502,
                error_type="upstream_error",
                code=exc.code,
                message="The upstream model request failed.",
                trace_id=trace_id,
            )
        if stream_decoder is None:  # Adapter contract makes this unreachable.
            await upstream_response.aclose()
            return _error_response(
                500,
                error_type="guardrail_unavailable",
                code="provider_adapter_error",
                message="The model provider stream could not be initialized.",
                trace_id=trace_id,
            )
        return StreamingResponse(
            _guarded_model_stream(
                upstream_response=upstream_response,
                decoder=stream_decoder,
                services=services,
                session=session,
                model_call_event_id=pre_decision.event_id,
                responses_state_store=services.responses_state_store,
                responses_state_request=responses_state_request,
            ),
            media_type="text/event-stream",
            headers={
                "cache-control": "no-cache",
                "x-accel-buffering": "no",
                "x-guardrail-trace-id": trace_id,
                "x-guardrail-streaming": "prefix-guarded-non-retractable",
            },
        )

    try:
        raw_response = await active_upstream.complete(
            adapter.upstream_path,
            upstream_payload,
            client_authorization=client_authorization_or_error,
        )
        provider_response = adapter.parse_response(raw_response)
        if (
            isinstance(provider_response, ResponsesResponse)
            and provider_response.previous_response_id is None
            and isinstance(provider_request, ResponsesRequest)
        ):
            provider_response = provider_response.model_copy(
                update={"previous_response_id": provider_request.previous_response_id}
            )
        canonical_response = adapter.response_to_canonical(
            provider_response,
            request=provider_request,
        )
        normalized_response = services.normalizer.normalize_model_output(
            canonical_response,
            model_call_event_id=pre_decision.event_id,
        )
    except UpstreamError as exc:
        return _error_response(
            504 if exc.timed_out else 502,
            error_type="upstream_error",
            code=exc.code,
            message="The upstream model request failed.",
            trace_id=trace_id,
        )
    except ProviderAdapterError as exc:
        return _error_response(
            502,
            error_type="upstream_error",
            code=exc.code,
            message=str(exc),
            trace_id=trace_id,
        )
    except InputNormalizationError as exc:
        return _error_response(
            502,
            error_type="upstream_error",
            code=exc.code,
            message=str(exc),
            trace_id=trace_id,
            checkpoint=EnforcementCheckpoint.BEFORE_MODEL_OUTPUT_RELEASE.value,
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
        post_decision = await session.submit_candidates(
            normalized_response.candidates,
            primary_key=normalized_response.primary_key,
            security_context=session.security_context.with_enforcement_destination(
                SecurityDestination.CLIENT
            ),
        )
    except GuardrailUnavailable:
        return _unavailable_response(
            trace_id,
            EnforcementCheckpoint.BEFORE_MODEL_OUTPUT_RELEASE,
        )
    if post_decision.blocked:
        return _blocked_response(
            post_decision,
            EnforcementCheckpoint.BEFORE_MODEL_OUTPUT_RELEASE,
        )

    if responses_state_request is not None and services.responses_state_store is not None:
        try:
            await _save_responses_state(
                store=services.responses_state_store,
                request=responses_state_request,
                response=provider_response,
            )
        except ResponsesStateError:
            return _error_response(
                503,
                error_type="guardrail_unavailable",
                code="responses_state_unavailable",
                message="Responses state could not be persisted.",
                trace_id=trace_id,
                checkpoint=EnforcementCheckpoint.BEFORE_MODEL_OUTPUT_RELEASE.value,
            )

    return JSONResponse(
        adapter.response_payload(provider_response),
        headers={"x-guardrail-trace-id": trace_id},
    )


async def _guarded_model_stream(
    *,
    upstream_response: httpx.Response,
    decoder: Any,
    services: GatewayServices,
    session: EnforcementSession,
    model_call_event_id: str,
    responses_state_store: ResponsesStateStore | None,
    responses_state_request: ResponsesRequest | None,
) -> AsyncIterator[bytes]:
    """Release only Adapter-recognized SSE whose cumulative output passed Policy."""

    parser = BoundedSSEParser(
        max_event_bytes=min(
            _MAX_SSE_EVENT_BYTES,
            services.settings.max_upstream_response_bytes,
        ),
        max_events=_MAX_STREAM_EVENTS,
    )
    held: list[bytes] = []
    total_bytes = 0
    try:
        async with asyncio.timeout(services.settings.upstream_timeout_seconds):
            async for chunk in upstream_response.aiter_bytes():
                total_bytes += len(chunk)
                if total_bytes > services.settings.max_upstream_response_bytes:
                    raise StreamProtocolError(
                        "upstream_stream_limit",
                        "The upstream model stream exceeds its configured limit.",
                    )
                for event in parser.feed(chunk):
                    update = decoder.consume(event)
                    if update.event is not None:
                        held.append(update.event.encode())
                    if update.release is StreamRelease.HOLD:
                        continue
                    if update.output is None:  # ProviderStreamUpdate enforces this.
                        raise RuntimeError("guarded stream update omitted canonical output")
                    normalized = services.normalizer.normalize_model_output(
                        update.output,
                        model_call_event_id=model_call_event_id,
                    )
                    security_context = session.security_context.with_enforcement_destination(
                        SecurityDestination.CLIENT
                    )
                    if update.release is StreamRelease.FINAL:
                        decision = await session.submit_candidates(
                            normalized.candidates,
                            primary_key=normalized.primary_key,
                            security_context=security_context,
                        )
                    else:
                        decision = await session.inspect_candidates(
                            normalized.candidates,
                            primary_key=normalized.primary_key,
                            security_context=security_context,
                        )
                    if decision.blocked:
                        yield decoder.error_event(
                            code="guardrail_blocked",
                            message="The model stream was blocked by guardrail policy.",
                        ).encode()
                        return
                    if update.release is StreamRelease.FINAL:
                        if (
                            responses_state_store is not None
                            and responses_state_request is not None
                        ):
                            terminal_response = getattr(decoder, "terminal_response", None)
                            if not isinstance(terminal_response, ResponsesResponse):
                                raise ResponsesStateError(
                                    "responses_state_unavailable",
                                    "The Responses stream had no validated terminal response.",
                                )
                            await _save_responses_state(
                                store=responses_state_store,
                                request=responses_state_request,
                                response=terminal_response,
                            )
                    yield b"".join(held)
                    held.clear()
            parser.finish()
            decoder.finish()
            if held:
                raise StreamProtocolError(
                    "upstream_incomplete_stream",
                    "The upstream model stream ended before buffered events were guarded.",
                )
    except GuardrailUnavailable:
        yield decoder.error_event(
            code="evaluation_failed",
            message="Guardrail evaluation is unavailable.",
        ).encode()
    except (ProviderAdapterError, StreamProtocolError, InputNormalizationError):
        yield decoder.error_event(
            code="stream_terminated",
            message="The model stream was terminated before further output could be released.",
        ).encode()
    except ResponsesStateError:
        yield decoder.error_event(
            code="responses_state_unavailable",
            message="Responses state could not be persisted.",
        ).encode()
    except (httpx.TimeoutException, httpx.HTTPError):
        yield decoder.error_event(
            code="upstream_stream_failed",
            message="The upstream model stream failed.",
        ).encode()
    except TimeoutError:
        yield decoder.error_event(
            code="upstream_stream_timeout",
            message="The upstream model stream exceeded its time limit.",
        ).encode()
    except Exception:
        yield decoder.error_event(
            code="stream_terminated",
            message="The model stream was terminated before further output could be released.",
        ).encode()
    finally:
        await upstream_response.aclose()


async def _save_responses_state(
    *,
    store: ResponsesStateStore,
    request: ResponsesRequest,
    response: ResponsesResponse,
) -> None:
    """Normalize state-owner write failures before any output is released."""

    try:
        await store.save_response(request=request, response=response)
    except ResponsesStateError:
        raise
    except Exception:
        raise ResponsesStateError(
            "responses_state_unavailable",
            "Responses state could not be persisted.",
        ) from None


def _authenticate(services: GatewayServices, request: Request) -> JSONResponse | None:
    result = _authenticate_with_value(services, request)
    return result if isinstance(result, JSONResponse) else None


def _authenticate_with_value(
    services: GatewayServices,
    request: Request,
    *,
    anthropic: bool = False,
) -> str | None | JSONResponse:
    try:
        if anthropic:
            services.authenticator.authenticate_anthropic(request)
            return None
        return services.authenticator.authenticate(request)
    except GatewayAuthenticationError:
        return _error_response(
            401,
            error_type="authentication_error",
            code="invalid_api_key",
            message="A valid Gateway API key is required.",
            headers={"www-authenticate": "Bearer"},
        )


def _blocked_response(
    decision: Decision,
    checkpoint: EnforcementCheckpoint,
) -> JSONResponse:
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
        checkpoint=checkpoint.value,
        violations=violations,
    )


def _unavailable_response(
    trace_id: str,
    checkpoint: EnforcementCheckpoint,
) -> JSONResponse:
    return _error_response(
        503,
        error_type="guardrail_unavailable",
        code="evaluation_failed",
        message="Guardrail evaluation is unavailable.",
        trace_id=trace_id,
        checkpoint=checkpoint.value,
    )


def _error_response(
    status_code: int,
    *,
    error_type: str,
    code: str,
    message: str,
    trace_id: str | None = None,
    checkpoint: str | None = None,
    violations: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"type": error_type, "code": code, "message": message}
    if trace_id is not None:
        error["trace_id"] = trace_id
    if checkpoint is not None:
        error["checkpoint"] = checkpoint
    if violations is not None:
        error["violations"] = violations
    response_headers = dict(headers or {})
    if trace_id is not None:
        response_headers["x-guardrail-trace-id"] = trace_id
    return JSONResponse({"error": error}, status_code=status_code, headers=response_headers)

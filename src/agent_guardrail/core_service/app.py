"""FastAPI composition root for the fixed-policy remote Core."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.requests import Request

from agent_guardrail.config import create_deployment_detector_registry
from agent_guardrail.core_service.config import CoreSettings
from agent_guardrail.core_service.http import CoreRequestReadError, read_core_json_body
from agent_guardrail.runtime import GuardrailRuntime, RuntimeNotReadyError
from agent_guardrail.runtime.remote_protocol import (
    RemoteAnalyzeRequest,
    RemoteAnalyzeResponse,
    RemotePolicyInfoResponse,
)


@dataclass(frozen=True, slots=True)
class CoreServices:
    settings: CoreSettings
    runtime: GuardrailRuntime


def create_core_app(
    settings: CoreSettings,
    *,
    runtime: GuardrailRuntime | None = None,
) -> FastAPI:
    """Create a Core app around one startup-fixed policy and detector registry."""

    active_runtime = runtime
    if active_runtime is None:
        detector_registry = create_deployment_detector_registry(
            settings.detector_profile,
            prompt_model_device=settings.prompt_model_device,
            detector_assets_dir=settings.detector_assets_dir,
        )
        active_runtime = GuardrailRuntime.from_policy_file(
            settings.policy_file,
            detector_registry=detector_registry,
        )
    services = CoreServices(settings=settings, runtime=active_runtime)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.core = services
        try:
            await active_runtime.start()
            yield
        finally:
            await active_runtime.close()

    app = FastAPI(title="Agent Guardrail Core", version="0.1.0", lifespan=lifespan)
    app.state.core = services

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def ready() -> JSONResponse:
        if await services.runtime.check_ready():
            return JSONResponse({"status": "ready"})
        return _error_response(
            503,
            error_type="core_unavailable",
            code="runtime_not_ready",
            message="Core runtime is not ready.",
        )

    @app.get("/v1/policies/current")
    async def current_policy(request: Request) -> JSONResponse:
        authentication_error = _authenticate(services, request)
        if authentication_error is not None:
            return authentication_error
        try:
            info = services.runtime.policy_info
        except RuntimeNotReadyError:
            return _runtime_unavailable_response()
        response = RemotePolicyInfoResponse(
            version=info.version,
            content_hash=info.content_hash,
        )
        return JSONResponse(response.model_dump(mode="json"))

    @app.post("/v1/analyze")
    async def analyze(request: Request) -> JSONResponse:
        authentication_error = _authenticate(services, request)
        if authentication_error is not None:
            return authentication_error
        try:
            payload = await read_core_json_body(request, settings.max_request_bytes)
            analysis_request = RemoteAnalyzeRequest.model_validate(payload)
            pending = analysis_request.pending
            pending_snapshot = pending.model_dump(mode="json")
            decision = await services.runtime.analyze_pending(pending)
            if pending.model_dump(mode="json") != pending_snapshot:
                raise RuntimeError("analyzer mutated the pending snapshot")
            response = RemoteAnalyzeResponse(decision=decision)
        except CoreRequestReadError as exc:
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
                code="invalid_pending_trace",
                message="The remote analysis request is malformed.",
            )
        except Exception:
            return _runtime_unavailable_response()
        return JSONResponse(response.model_dump(mode="json"))

    return app


def _authenticate(services: CoreServices, request: Request) -> JSONResponse | None:
    authorization = request.headers.get("authorization", "")
    scheme, separator, credential = authorization.partition(" ")
    expected = services.settings.api_key.get_secret_value()
    if (
        not separator
        or scheme.lower() != "bearer"
        or not credential
        or not hmac.compare_digest(credential, expected)
    ):
        return _error_response(
            401,
            error_type="authentication_error",
            code="invalid_api_key",
            message="A valid Core service API key is required.",
            headers={"www-authenticate": "Bearer"},
        )
    return None


def _runtime_unavailable_response() -> JSONResponse:
    return _error_response(
        503,
        error_type="core_unavailable",
        code="evaluation_failed",
        message="Core evaluation is unavailable.",
    )


def _error_response(
    status_code: int,
    *,
    error_type: str,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"type": error_type, "code": code, "message": message}
    return JSONResponse(
        {"error": error},
        status_code=status_code,
        headers=dict(headers or {}),
    )

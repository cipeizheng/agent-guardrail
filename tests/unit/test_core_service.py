from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from agent_guardrail.core_service import CoreSettings, create_core_app
from agent_guardrail.models import PendingTrace
from agent_guardrail.runtime import GuardrailRuntime
from agent_guardrail.runtime.remote_protocol import RemoteAnalyzeRequest
from tests.support import FAKE_SECRET, secret_policy_yaml, tool_context


def core_settings(tmp_path: Path, *, max_request_bytes: int = 8_388_608) -> CoreSettings:
    return CoreSettings(
        policy_file=tmp_path / "policy.yaml",
        api_key=SecretStr("core-test-key"),
        max_request_bytes=max_request_bytes,
    )


def test_core_settings_require_assets_for_full_profile(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="detector_assets_dir"):
        CoreSettings(
            policy_file=tmp_path / "policy.yaml",
            api_key=SecretStr("core-test-key"),
            detector_profile="full_local_v1",
        )


@pytest.mark.asyncio
async def test_core_analyze_authenticates_and_returns_closed_decision(tmp_path: Path) -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    app = create_core_app(core_settings(tmp_path), runtime=runtime)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://core.test",
        ) as client:
            unauthenticated = await client.post("/v1/analyze", json={})
            pending = PendingTrace.from_context(tool_context(body=FAKE_SECRET))
            response = await client.post(
                "/v1/analyze",
                headers={"authorization": "Bearer core-test-key"},
                json=RemoteAnalyzeRequest(pending=pending).model_dump(mode="json"),
            )

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["protocol_version"] == 1
    assert response.json()["decision"]["action"] == "block"
    assert FAKE_SECRET not in response.text


@pytest.mark.asyncio
async def test_core_rejects_oversized_body_before_analysis(tmp_path: Path) -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    app = create_core_app(core_settings(tmp_path, max_request_bytes=1_024), runtime=runtime)

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://core.test",
        ) as client:
            response = await client.post(
                "/v1/analyze",
                headers={
                    "authorization": "Bearer core-test-key",
                    "content-type": "application/json",
                },
                content=b'"' + (b"x" * 1_024) + b'"',
            )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"

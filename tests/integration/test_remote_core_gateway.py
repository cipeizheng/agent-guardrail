from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from agent_guardrail.core_service import CoreSettings, create_core_app
from agent_guardrail.gateway import GatewaySettings, create_app
from agent_guardrail.models import EventKind
from agent_guardrail.runtime import GuardrailRuntime
from tests.integration.test_gateway import chat_stream, streaming_message_analyzer
from tests.support import FAKE_SECRET, secret_policy_yaml


def _gateway_settings() -> GatewaySettings:
    return GatewaySettings(
        decision_backend="remote",
        core_url="http://core.test",
        core_api_key=SecretStr("core-test-key"),
        upstream_base_url="https://provider.example/v1",
        upstream_api_key=SecretStr("upstream-test-key"),
        upstream_allowed_hosts=("provider.example",),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )


def _request_payload() -> dict[str, object]:
    return {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Email the report"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "send_email",
                    "parameters": {"type": "object"},
                },
            }
        ],
    }


def _text_response() -> dict[str, object]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Safe response"},
                "finish_reason": "stop",
            }
        ],
    }


def _secret_tool_response() -> dict[str, object]:
    response = _text_response()
    response["choices"] = [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": json.dumps(
                                {"to": "outside@example.com", "body": FAKE_SECRET}
                            ),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
    return response


@pytest.mark.asyncio
async def test_two_service_topology_allows_safe_and_hides_blocked_output() -> None:
    core_runtime = GuardrailRuntime.from_policy_yaml(
        secret_policy_yaml(kind=EventKind.TOOL_CALL_PROPOSAL)
    )
    core_app = create_core_app(
        CoreSettings(
            policy_file=Path("unused.yaml"),
            api_key=SecretStr("core-test-key"),
        ),
        runtime=core_runtime,
    )
    provider_calls = 0

    def provider_handler(request: httpx.Request) -> httpx.Response:
        nonlocal provider_calls
        provider_calls += 1
        assert request.headers["authorization"] == "Bearer upstream-test-key"
        return httpx.Response(
            200,
            json=_text_response() if provider_calls == 1 else _secret_tool_response(),
        )

    core_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=core_app),
        base_url="http://core.test",
    )
    provider_client = httpx.AsyncClient(transport=httpx.MockTransport(provider_handler))

    async with core_app.router.lifespan_context(core_app):
        gateway_app = create_app(
            _gateway_settings(),
            core_http_client=core_client,
            upstream_http_client=provider_client,
        )
        async with gateway_app.router.lifespan_context(gateway_app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app),
                base_url="http://gateway.test",
            ) as gateway_client:
                headers = {"authorization": "Bearer gateway-test-key"}
                allowed = await gateway_client.post(
                    "/v1/openai/chat/completions",
                    headers=headers,
                    json=_request_payload(),
                )
                blocked = await gateway_client.post(
                    "/v1/openai/chat/completions",
                    headers=headers,
                    json=_request_payload(),
                )

    await core_client.aclose()
    await provider_client.aclose()
    assert allowed.status_code == 200
    assert blocked.status_code == 400
    assert blocked.json()["error"]["checkpoint"] == "before_model_output_release"
    assert FAKE_SECRET not in blocked.text
    assert provider_calls == 2


@pytest.mark.asyncio
async def test_remote_core_failure_before_decision_prevents_upstream_side_effect() -> None:
    provider_calls = 0

    def core_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/v1/policies/current":
            return httpx.Response(
                200,
                json={
                    "protocol_version": 4,
                    "version": 3,
                    "content_hash": "fixed-policy",
                },
            )
        return httpx.Response(503, json={"error": {"code": "evaluation_failed"}})

    def provider_handler(request: httpx.Request) -> httpx.Response:
        nonlocal provider_calls
        provider_calls += 1
        return httpx.Response(200, json=_text_response())

    core_client = httpx.AsyncClient(transport=httpx.MockTransport(core_handler))
    provider_client = httpx.AsyncClient(transport=httpx.MockTransport(provider_handler))
    gateway_app = create_app(
        _gateway_settings(),
        core_http_client=core_client,
        upstream_http_client=provider_client,
    )

    async with gateway_app.router.lifespan_context(gateway_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway_app),
            base_url="http://gateway.test",
        ) as gateway_client:
            response = await gateway_client.post(
                "/v1/openai/chat/completions",
                headers={"authorization": "Bearer gateway-test-key"},
                json=_request_payload(),
            )

    await core_client.aclose()
    await provider_client.aclose()
    assert response.status_code == 503
    assert response.json()["error"]["type"] == "guardrail_unavailable"
    assert provider_calls == 0


@pytest.mark.asyncio
async def test_remote_core_guards_streamed_prefixes_and_hides_blocked_delta() -> None:
    core_app = create_core_app(
        CoreSettings(
            policy_file=Path("unused.yaml"),
            api_key=SecretStr("core-test-key"),
        ),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
    )
    provider_calls = 0

    def provider_handler(request: httpx.Request) -> httpx.Response:
        nonlocal provider_calls
        provider_calls += 1
        return httpx.Response(
            200,
            content=(
                chat_stream("Safe response")
                if provider_calls == 1
                else chat_stream("Safe prefix. ", FAKE_SECRET)
            ),
            headers={"content-type": "text/event-stream"},
        )

    core_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=core_app),
        base_url="http://core.test",
    )
    provider_client = httpx.AsyncClient(transport=httpx.MockTransport(provider_handler))

    async with core_app.router.lifespan_context(core_app):
        gateway_app = create_app(
            _gateway_settings(),
            core_http_client=core_client,
            upstream_http_client=provider_client,
        )
        async with gateway_app.router.lifespan_context(gateway_app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=gateway_app),
                base_url="http://gateway.test",
            ) as gateway_client:
                payload = _request_payload()
                payload["stream"] = True
                headers = {"authorization": "Bearer gateway-test-key"}
                allowed = await gateway_client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                blocked = await gateway_client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )

    await core_client.aclose()
    await provider_client.aclose()
    assert allowed.status_code == 200
    assert "Safe response" in allowed.text
    assert blocked.status_code == 200
    assert "Safe prefix." in blocked.text
    assert FAKE_SECRET not in blocked.text
    assert "guardrail_blocked" in blocked.text
    assert provider_calls == 2

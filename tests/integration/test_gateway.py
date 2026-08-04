from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from agent_guardrail.core import (
    DetectorRegistry,
    EngineConfig,
    GuardrailEngine,
    PolicySet,
    RuleBinding,
)
from agent_guardrail.core.services import RuleServices
from agent_guardrail.enforcement import InMemoryAuditSink
from agent_guardrail.gateway import GatewaySettings, create_app
from agent_guardrail.models import Action, GuardrailContext, Phase, Violation
from agent_guardrail.runtime import GuardrailRuntime
from tests.support import FAKE_SECRET, tool_context

POLICY_FILE = Path(__file__).parents[2] / "examples/policies/secret-email.yaml"


def gateway_settings() -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        upstream_base_url="https://provider.example/v1",
        upstream_api_key=SecretStr("upstream-test-key"),
        upstream_allowed_hosts=("provider.example",),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )


def request_payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Email the report"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "send_email",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string"},
                            "body": {"type": "string"},
                        },
                        "required": ["to", "body"],
                        "additionalProperties": False,
                    },
                },
            }
        ],
        "stream": stream,
    }


def text_response(content: str = "Safe response") -> dict[str, object]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
    }


def tool_response(body: str) -> dict[str, object]:
    response = text_response()
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
                                {"to": "outside@example.com", "body": body}
                            ),
                        },
                    }
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
    return response


@asynccontextmanager
async def app_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    runtime: GuardrailRuntime | None = None,
    audit: InMemoryAuditSink | None = None,
    settings: GatewaySettings | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, list[httpx.Request]]]:
    requests: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(recording_handler))
    app = create_app(
        settings or gateway_settings(),
        runtime=runtime,
        upstream_http_client=upstream_client,
        audit=audit,
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://gateway.test",
        ) as client:
            yield client, requests
    await upstream_client.aclose()


def auth_headers() -> dict[str, str]:
    return {"authorization": "Bearer gateway-test-key"}


@pytest.mark.asyncio
async def test_allow_proxies_once_with_server_managed_auth() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer upstream-test-key"
        return httpx.Response(200, json=text_response())

    async with app_client(upstream) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Safe response"
    assert response.headers["x-guardrail-trace-id"].startswith("trc_")
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_post_llm_block_hides_response_and_records_sanitized_audit() -> None:
    audit = InMemoryAuditSink()

    async with app_client(
        lambda request: httpx.Response(200, json=tool_response(FAKE_SECRET)),
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["type"] == "guardrail_violation"
    assert response.json()["error"]["phase"] == "post_llm"
    assert FAKE_SECRET not in response.text
    assert len(requests) == 1
    assert len(audit.records) == 1
    assert FAKE_SECRET not in audit.records[0].model_dump_json()


class BlockPreLlmRule:
    id = "block-pre-llm"
    phases = frozenset({Phase.PRE_LLM})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        return [
            Violation(
                rule_id=self.id,
                code="blocked_for_test",
                phase=context.event.phase,
                message="Blocked before the provider call.",
            )
        ]


def pre_llm_blocking_runtime() -> GuardrailRuntime:
    rule = BlockPreLlmRule()
    engine = GuardrailEngine(
        policy=PolicySet(
            version=1,
            content_hash="pre-llm-test-policy",
            engine=EngineConfig(),
            rules=(RuleBinding(rule=rule, action=Action.BLOCK),),
        ),
        detectors=DetectorRegistry(),
    )
    return GuardrailRuntime(engine)


@pytest.mark.asyncio
async def test_pre_llm_block_makes_zero_upstream_requests() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        runtime=pre_llm_blocking_runtime(),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["phase"] == "pre_llm"
    assert requests == []


@pytest.mark.asyncio
async def test_streaming_is_explicitly_rejected_before_upstream() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "streaming_not_supported"
    assert requests == []


@pytest.mark.asyncio
async def test_invalid_upstream_tool_arguments_are_not_released() -> None:
    invalid = tool_response("safe")
    invalid["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = "not-json"  # type: ignore[index]

    async with app_client(
        lambda request: httpx.Response(200, json=invalid),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "invalid_tool_arguments_json"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_authentication_and_readiness_do_not_call_upstream() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
    ) as (client, requests):
        ready = await client.get("/health/ready")
        unauthorized = await client.post(
            "/v1/openai/chat/completions",
            headers={"authorization": "Bearer wrong-key"},
            json=request_payload(),
        )

    assert ready.status_code == 200
    assert unauthorized.status_code == 401
    assert "wrong-key" not in unauthorized.text
    assert requests == []


@pytest.mark.asyncio
async def test_direct_evaluate_is_explicit_and_has_no_upstream_side_effect() -> None:
    settings = gateway_settings().model_copy(update={"evaluate_endpoint_enabled": True})
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/evaluate",
            headers=auth_headers(),
            json=tool_context(body=FAKE_SECRET).model_dump(mode="json"),
        )

    assert response.status_code == 200
    assert response.json()["action"] == "block"
    assert response.json()["phase"] == "pre_tool"
    assert FAKE_SECRET not in response.text
    assert requests == []


@pytest.mark.asyncio
async def test_request_size_limit_runs_before_upstream() -> None:
    settings = gateway_settings().model_copy(update={"max_request_bytes": 1_024})
    oversized = request_payload()
    oversized["messages"] = [{"role": "user", "content": "x" * 2_000}]

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=oversized,
        )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "request_too_large"
    assert requests == []

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.enforcement import InMemoryAuditSink
from agent_guardrail.gateway import GatewaySettings, create_app
from agent_guardrail.models import (
    EventKind,
    EventOrigin,
    PendingTrace,
    Phase,
    SecurityDestination,
)
from agent_guardrail.runtime import GuardrailRuntime
from tests.support import (
    FAKE_CN_RESIDENT_ID,
    FAKE_PII,
    FAKE_SECRET,
    analyzer_from_yaml,
    empty_analyzer,
    pii_analyzer,
    tool_access_analyzer,
    tool_context,
)

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


def tool_response(body: str, *, content: str | None = None) -> dict[str, object]:
    response = text_response()
    response["choices"] = [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": json.dumps({"to": "outside@example.com", "body": body}),
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


@pytest.mark.asyncio
async def test_post_llm_message_and_tool_call_are_one_atomic_batch() -> None:
    audit = InMemoryAuditSink()

    async with app_client(
        lambda request: httpx.Response(
            200,
            json=tool_response(FAKE_SECRET, content="A safe-looking preface"),
        ),
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert len(requests) == 1
    assert len(audit.records) == 1
    decision = audit.records[0]
    assert len(decision.pending_event_ids) == 2
    assert len(decision.violations) == 1
    assert set(decision.violations[0].event_ids) < set(decision.pending_event_ids)
    assert FAKE_SECRET not in response.text
    assert "A safe-looking preface" not in response.text
    assert FAKE_SECRET not in decision.model_dump_json()


@pytest.mark.asyncio
async def test_tool_access_post_llm_block_hides_tool_call() -> None:
    runtime = GuardrailRuntime(tool_access_analyzer())
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("safe")),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["phase"] == "post_llm"
    assert response.json()["error"]["violations"][0]["code"] == "tool_access_denied"
    assert "tool_calls" not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("sensitive_value", [FAKE_PII, FAKE_CN_RESIDENT_ID])
async def test_pii_post_llm_block_hides_tool_call_and_records_safe_audit(
    sensitive_value: str,
) -> None:
    runtime = GuardrailRuntime(pii_analyzer())
    audit = InMemoryAuditSink()
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response(sensitive_value)),
        runtime=runtime,
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["phase"] == "post_llm"
    assert response.json()["error"]["violations"][0]["code"] == "pii_exfiltration"
    assert sensitive_value not in response.text
    assert sensitive_value not in audit.records[0].model_dump_json()
    assert len(requests) == 1


class RecordingAnalyzer(MatchPolicyAnalyzer):
    def __init__(self) -> None:
        super().__init__(empty_analyzer().policy)
        self.events: list[
            tuple[EventKind, Phase, EventOrigin, str, tuple[str, ...]]
        ] = []
        self.security_destinations: list[tuple[Phase, SecurityDestination]] = []

    async def analyze_pending(self, pending: PendingTrace):
        self.security_destinations.append(
            (pending.primary_event.phase, pending.security_context.destination)
        )
        self.events.extend(
            (
                event.kind,
                event.phase,
                event.origin,
                event.id,
                event.source_event_ids,
            )
            for event in pending.events
        )
        return await super().analyze_pending(pending)


def pre_llm_blocking_runtime() -> GuardrailRuntime:
    return GuardrailRuntime(
        analyzer_from_yaml(
            """\
version: 3
scopes: [pending]
rules:
  - id: block-pre-llm
    action: block
    events:
      message: {kind: message, domain: pending, phases: [pre_llm]}
    where: {present: [message, payload]}
    finding:
      code: blocked_for_test
      message: Blocked before the provider call.
      subjects: [message]
"""
        )
    )


@pytest.mark.asyncio
async def test_gateway_submits_independent_events_with_boundary_owned_origins() -> None:
    analyzer = RecordingAnalyzer()
    runtime = GuardrailRuntime(analyzer)

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert len(requests) == 1
    assert [(kind, phase, origin) for kind, phase, origin, _, _ in analyzer.events] == [
        (EventKind.MESSAGE, Phase.PRE_LLM, EventOrigin.CLIENT_ASSERTED),
        (EventKind.MESSAGE, Phase.POST_LLM, EventOrigin.OBSERVED),
    ]
    assert analyzer.security_destinations == [
        (Phase.PRE_LLM, SecurityDestination.LLM_PROVIDER),
        (Phase.POST_LLM, SecurityDestination.CLIENT),
    ]


@pytest.mark.asyncio
async def test_gateway_normalizes_valid_tool_history_as_one_related_batch() -> None:
    analyzer = RecordingAnalyzer()
    runtime = GuardrailRuntime(analyzer)
    payload = request_payload()
    payload["messages"] = [
        {"role": "user", "content": "Send the report"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-history-1",
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "arguments": json.dumps(
                            {"to": "inside@example.com", "body": "safe"}
                        ),
                    },
                }
            ],
        },
        {"role": "tool", "content": "sent", "tool_call_id": "call-history-1"},
    ]

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=payload,
        )

    assert response.status_code == 200
    assert len(requests) == 1
    assert [event[0] for event in analyzer.events] == [
        EventKind.MESSAGE,
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
        EventKind.MESSAGE,
    ]
    tool_call_event_id = analyzer.events[1][3]
    assert analyzer.events[2][4] == (tool_call_event_id,)


@pytest.mark.asyncio
async def test_orphan_tool_result_is_rejected_before_upstream() -> None:
    payload = request_payload()
    payload["messages"] = [
        {"role": "tool", "content": "untrusted result", "tool_call_id": "unknown"}
    ]

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=payload,
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "orphan_tool_result"
    assert response.json()["error"]["phase"] == "pre_llm"
    assert "untrusted result" not in response.text
    assert "unknown" not in response.text
    assert requests == []


@pytest.mark.asyncio
async def test_normalized_candidate_limit_is_rejected_before_upstream() -> None:
    settings = gateway_settings().model_copy(update={"max_trace_events": 2})
    payload = request_payload()
    payload["messages"] = [
        {"role": "user", "content": "one"},
        {"role": "user", "content": "two"},
    ]

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=payload,
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "candidate_limit_exceeded"
    assert requests == []


@pytest.mark.asyncio
async def test_response_candidate_limit_does_not_release_upstream_payload() -> None:
    settings = gateway_settings().model_copy(update={"max_trace_events": 3})
    oversized_response = tool_response("safe", content="private upstream text")
    tool_calls = oversized_response["choices"][0]["message"]["tool_calls"]  # type: ignore[index]
    tool_calls.append(  # type: ignore[union-attr]
        {
            "id": "call-2",
            "type": "function",
            "function": {
                "name": "send_email",
                "arguments": json.dumps(
                    {"to": "outside@example.com", "body": "also safe"}
                ),
            },
        }
    )

    async with app_client(
        lambda request: httpx.Response(200, json=oversized_response),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "candidate_limit_exceeded"
    assert response.json()["error"]["phase"] == "post_llm"
    assert "private upstream text" not in response.text
    assert "call-2" not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_combined_trace_capacity_does_not_release_upstream_payload() -> None:
    settings = gateway_settings().model_copy(update={"max_trace_events": 3})
    payload = request_payload()
    payload["messages"] = [
        {"role": "user", "content": "one"},
        {"role": "user", "content": "two"},
    ]

    async with app_client(
        lambda request: httpx.Response(
            200,
            json=tool_response("safe", content="private upstream text"),
        ),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=payload,
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "evaluation_failed"
    assert response.json()["error"]["phase"] == "post_llm"
    assert "private upstream text" not in response.text
    assert len(requests) == 1


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
async def test_request_snapshot_is_atomic_and_does_not_deduplicate_messages() -> None:
    audit = InMemoryAuditSink()
    payload = request_payload()
    payload["messages"] = [
        {"role": "user", "content": "same"},
        {"role": "user", "content": "same"},
    ]

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        runtime=pre_llm_blocking_runtime(),
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=payload,
        )

    assert response.status_code == 400
    assert requests == []
    assert len(audit.records) == 1
    assert len(audit.records[0].pending_event_ids) == 2
    assert len(audit.records[0].violations) == 2


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
async def test_direct_evaluate_cannot_spoof_the_trusted_security_channel() -> None:
    analyzer = analyzer_from_yaml(
        """\
version: 3
scopes: [pending]
parameters:
  security_authorization: {type: string, required: false, default: unknown}
rules:
  - id: trusted-authorization-only
    action: block
    events:
      call: {kind: tool_call, domain: pending, phases: [pre_tool]}
    where:
      compare:
        left: {parameter: security_authorization}
        operator: equals
        right: {literal: allowed}
    finding:
      code: spoofed_authorization
      message: A trusted authorization fact was present.
      subjects: [call]
"""
    )
    settings = gateway_settings().model_copy(update={"evaluate_endpoint_enabled": True})
    claimed_attributes = tool_context(body="safe").model_dump(mode="json")
    claimed_attributes["attributes"] = {"security_authorization": "allowed"}
    claimed_context = dict(claimed_attributes)
    claimed_context["security_context"] = {
        "authorization": "allowed",
        "authorities": {"authorization": "authorization_service"},
    }

    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
        runtime=GuardrailRuntime(analyzer),
    ) as (client, requests):
        attributes_response = await client.post(
            "/v1/evaluate",
            headers=auth_headers(),
            json=claimed_attributes,
        )
        context_response = await client.post(
            "/v1/evaluate",
            headers=auth_headers(),
            json=claimed_context,
        )

    assert attributes_response.status_code == 200
    assert attributes_response.json()["action"] == "allow"
    assert context_response.status_code == 422
    assert context_response.json()["error"]["code"] == "invalid_guardrail_context"
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

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from agent_guardrail.adapters.protocols import ProviderAdapterError
from agent_guardrail.adapters.streaming import (
    ProviderStreamUpdate,
    ServerSentEvent,
    StreamRelease,
)
from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.enforcement import InMemoryAuditSink
from agent_guardrail.gateway import TASK_SESSION_HEADER, GatewaySettings, create_app
from agent_guardrail.models import (
    ChatMessage,
    ChatRole,
    EventKind,
    EventOrigin,
    ModelRequest,
    ModelResponse,
    PendingTrace,
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


def anthropic_gateway_settings() -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        anthropic_upstream_base_url="https://api.anthropic.test",
        anthropic_upstream_api_key=SecretStr("anthropic-upstream-key"),
        anthropic_upstream_allowed_hosts=("api.anthropic.test",),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )


def anthropic_request_payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "claude-test",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "Email the report"}],
        "tools": [
            {
                "name": "send_email",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to", "body"],
                    "additionalProperties": False,
                },
            }
        ],
        "stream": stream,
    }


def anthropic_response(body: str = "safe") -> dict[str, object]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "send_email",
                "input": {"to": "outside@example.com", "body": body},
            }
        ],
        "model": "claude-test",
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def anthropic_text_stream(content: str) -> bytes:
    events = [
        (
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_stream",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": "claude-test",
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 4, "output_tokens": 1},
                },
            },
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": content},
            },
        ),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 5},
            },
        ),
        ("message_stop", {"type": "message_stop"}),
    ]
    return b"".join(
        f"event: {name}\n".encode()
        + b"data: "
        + json.dumps(payload, separators=(",", ":")).encode()
        + b"\n\n"
        for name, payload in events
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


def chat_stream(*contents: str, finish: bool = True) -> bytes:
    chunks: list[dict[str, object]] = [
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {"role": "assistant"}}],
        }
    ]
    chunks.extend(
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {"content": content}}],
        }
        for content in contents
    )
    if finish:
        chunks.append(
            {
                "id": "chatcmpl-stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "test-model",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
        )
    encoded = b"".join(
        b"data: " + json.dumps(chunk, separators=(",", ":")).encode() + b"\n\n" for chunk in chunks
    )
    return encoded + (b"data: [DONE]\n\n" if finish else b"")


def chat_tool_stream(body: str) -> bytes:
    arguments = json.dumps({"to": "outside@example.com", "body": body})
    chunks = [
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {"role": "assistant"}}],
        },
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-1",
                                "type": "function",
                                "function": {
                                    "name": "send_email",
                                    "arguments": arguments[: len(arguments) // 2],
                                },
                            }
                        ]
                    },
                }
            ],
        },
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"arguments": arguments[len(arguments) // 2 :]},
                            }
                        ]
                    },
                }
            ],
        },
        {
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
        },
    ]
    return (
        b"".join(
            b"data: " + json.dumps(chunk, separators=(",", ":")).encode() + b"\n\n"
            for chunk in chunks
        )
        + b"data: [DONE]\n\n"
    )


def response_api_payload(content: str = "Safe response") -> dict[str, object]:
    return {
        "id": "resp_1",
        "object": "response",
        "created_at": 1.0,
        "model": "test-model",
        "status": "completed",
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "output": [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": content, "annotations": []}],
            }
        ],
    }


def response_api_tool_payload(body: str) -> dict[str, object]:
    response = response_api_payload()
    response["output"] = [
        {
            "type": "function_call",
            "id": "fc_1",
            "call_id": "call-1",
            "name": "send_email",
            "arguments": json.dumps({"to": "outside@example.com", "body": body}),
            "status": "completed",
        }
    ]
    return response


def response_api_lifecycle_payload() -> dict[str, object]:
    response = response_api_payload()
    response["status"] = "in_progress"
    response["output"] = []
    return response


def responses_stream(content: str = "Safe response") -> bytes:
    events = [
        (
            "response.created",
            {
                "type": "response.created",
                "sequence_number": 0,
                "response": response_api_lifecycle_payload(),
            },
        ),
        (
            "response.output_text.delta",
            {
                "type": "response.output_text.delta",
                "sequence_number": 1,
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "delta": content,
                "logprobs": [],
            },
        ),
        (
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 2,
                "response": response_api_payload(content),
            },
        ),
    ]
    return b"".join(
        f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n".encode()
        for name, payload in events
    )


def responses_tool_stream(body: str) -> bytes:
    arguments = json.dumps({"to": "outside@example.com", "body": body})
    events = [
        (
            "response.created",
            {
                "type": "response.created",
                "sequence_number": 0,
                "response": response_api_lifecycle_payload(),
            },
        ),
        (
            "response.output_item.added",
            {
                "type": "response.output_item.added",
                "sequence_number": 1,
                "output_index": 0,
                "item": {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call-1",
                    "name": "send_email",
                    "arguments": "",
                    "status": "in_progress",
                },
            },
        ),
        (
            "response.function_call_arguments.delta",
            {
                "type": "response.function_call_arguments.delta",
                "sequence_number": 2,
                "item_id": "fc_1",
                "output_index": 0,
                "delta": arguments,
            },
        ),
        (
            "response.function_call_arguments.done",
            {
                "type": "response.function_call_arguments.done",
                "sequence_number": 3,
                "item_id": "fc_1",
                "output_index": 0,
                "arguments": arguments,
                "name": "send_email",
            },
        ),
        (
            "response.output_item.done",
            {
                "type": "response.output_item.done",
                "sequence_number": 4,
                "output_index": 0,
                "item": {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call-1",
                    "name": "send_email",
                    "arguments": arguments,
                    "status": "completed",
                },
            },
        ),
        (
            "response.completed",
            {
                "type": "response.completed",
                "sequence_number": 5,
                "response": response_api_tool_payload(body),
            },
        ),
    ]
    return b"".join(
        f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n".encode()
        for name, payload in events
    )


def responses_tool_request() -> dict[str, object]:
    return {
        "model": "test-model",
        "input": "Email it",
        "stream": True,
        "tools": [
            {
                "type": "function",
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
                "strict": True,
            }
        ],
    }


def streaming_message_analyzer() -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(
        """\
version: 3
engine: {on_analysis_error: block, on_detector_timeout: block}
scopes: [pending]
rules:
  - id: block-streamed-secret
    action: block
    events:
      output: {kind: message, domain: pending}
    where:
      detector:
        id: secret_scan
        capability: secrets
        inputs:
          - value: {field: [output, payload, content, text]}
            encoding: text
    finding:
      code: streamed_secret
      message: The streamed output contains secret material.
      subjects: [output]
      evidence: [{source: detector, id: secret_scan}]
"""
    )


class ToyProviderAdapter:
    """Deliberately non-OpenAI wire shape used to prove Adapter independence."""

    upstream_path = "generate"

    def parse_request(self, payload: object) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {"model", "prompt"}:
            raise ProviderAdapterError("invalid_request", "Toy request is invalid.")
        if not all(isinstance(payload[key], str) for key in payload):
            raise ProviderAdapterError("invalid_request", "Toy request is invalid.")
        return payload

    def request_to_canonical(self, request: dict[str, object]) -> ModelRequest:
        return ModelRequest(
            model=str(request["model"]),
            messages=(ChatMessage(role=ChatRole.USER, content=str(request["prompt"])),),
        )

    def request_payload(self, request: dict[str, object]) -> dict[str, object]:
        return dict(request)

    def is_streaming(self, request: dict[str, object]) -> bool:
        return False

    def parse_response(self, payload: object) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {"answer"}:
            raise ProviderAdapterError("invalid_upstream_response", "Toy response is invalid.")
        if not isinstance(payload["answer"], str):
            raise ProviderAdapterError("invalid_upstream_response", "Toy response is invalid.")
        return payload

    def response_to_canonical(
        self,
        response: dict[str, object],
        *,
        request: dict[str, object],
    ) -> ModelResponse:
        return ModelResponse(content=str(response["answer"]))

    def response_payload(self, response: dict[str, object]) -> dict[str, object]:
        return dict(response)

    def stream_decoder(self, request: dict[str, object]):
        raise ProviderAdapterError("invalid_request", "Toy streaming is unsupported.")


class ToyStreamingProviderAdapter(ToyProviderAdapter):
    upstream_path = "generate-stream"

    def parse_request(self, payload: object) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {"model", "prompt", "stream"}:
            raise ProviderAdapterError("invalid_request", "Toy stream request is invalid.")
        if not isinstance(payload["model"], str) or not isinstance(payload["prompt"], str):
            raise ProviderAdapterError("invalid_request", "Toy stream request is invalid.")
        if payload["stream"] is not True:
            raise ProviderAdapterError("invalid_request", "Toy stream request is invalid.")
        return payload

    def is_streaming(self, request: dict[str, object]) -> bool:
        return True

    def stream_decoder(self, request: dict[str, object]):
        return ToyStreamDecoder()


class ToyStreamDecoder:
    def __init__(self) -> None:
        self.content = ""
        self.terminal = False

    def consume(self, event: ServerSentEvent) -> ProviderStreamUpdate:
        payload = json.loads(event.data)
        if event.event == "token" and isinstance(payload, dict) and set(payload) == {"token"}:
            token = payload["token"]
            if not isinstance(token, str) or self.terminal:
                raise ProviderAdapterError("invalid_upstream_stream", "Toy stream is invalid.")
            self.content += token
            return ProviderStreamUpdate(
                release=StreamRelease.GUARD,
                output=ModelResponse(content=self.content),
                event=ServerSentEvent(
                    event="token",
                    data=json.dumps({"token": token}, separators=(",", ":")),
                ),
            )
        if event.event == "done" and payload == {"done": True, "answer": self.content}:
            self.terminal = True
            return ProviderStreamUpdate(
                release=StreamRelease.FINAL,
                output=ModelResponse(content=self.content),
                event=ServerSentEvent(
                    event="done",
                    data=json.dumps(payload, separators=(",", ":")),
                ),
            )
        raise ProviderAdapterError("invalid_upstream_stream", "Toy stream is invalid.")

    def finish(self) -> None:
        if not self.terminal:
            raise ProviderAdapterError("upstream_incomplete_stream", "Toy stream is incomplete.")

    def error_event(self, *, code: str, message: str) -> ServerSentEvent:
        return ServerSentEvent(
            event="error",
            data=json.dumps({"code": code, "message": message}, separators=(",", ":")),
        )


class _DelayedStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        await asyncio.sleep(0.02)
        yield chat_stream("raw-sensitive-late-output")


@asynccontextmanager
async def app_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    runtime: GuardrailRuntime | None = None,
    audit: InMemoryAuditSink | None = None,
    settings: GatewaySettings | None = None,
    model_routes: Mapping[str, Any] | None = None,
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
        model_routes=model_routes,
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
async def test_task_session_lifecycle_reuses_trace_and_rejects_deleted_token() -> None:
    settings = gateway_settings().model_copy(update={"task_sessions_required": True})
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
    ) as (client, requests):
        created = await client.post(
            "/v1/guardrail/task-sessions",
            headers=auth_headers(),
        )
        token = created.json()["session_token"]
        task_headers = {**auth_headers(), TASK_SESSION_HEADER: token}

        first = await client.post(
            "/v1/openai/chat/completions",
            headers=task_headers,
            json=request_payload(),
        )
        second = await client.post(
            "/v1/openai/chat/completions",
            headers=task_headers,
            json=request_payload(),
        )
        deleted = await client.delete(
            "/v1/guardrail/task-sessions",
            headers=task_headers,
        )
        rejected = await client.post(
            "/v1/openai/chat/completions",
            headers=task_headers,
            json=request_payload(),
        )

    assert created.status_code == 200
    assert created.headers["cache-control"] == "no-store"
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers["x-guardrail-trace-id"] == created.json()["trace_id"]
    assert second.headers["x-guardrail-trace-id"] == created.json()["trace_id"]
    assert deleted.status_code == 204
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "task_session_invalid"
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_required_task_session_fails_before_model_upstream() -> None:
    settings = gateway_settings().model_copy(update={"task_sessions_required": True})
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "task_session_required"
    assert requests == []


@pytest.mark.asyncio
async def test_standard_openai_route_aliases_use_their_provider_adapters() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json=text_response())
        assert request.url == "https://provider.example/v1/responses"
        return httpx.Response(200, json=response_api_payload())

    async with app_client(upstream) as (client, requests):
        chat = await client.post(
            "/v1/chat/completions",
            headers=auth_headers(),
            json=request_payload(),
        )
        responses = await client.post(
            "/v1/responses",
            headers=auth_headers(),
            json={"model": "test-model", "input": "Hello"},
        )

    assert chat.status_code == 200
    assert chat.json()["choices"][0]["message"]["content"] == "Safe response"
    assert responses.status_code == 200
    assert responses.json()["output"][0]["content"][0]["text"] == "Safe response"
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_anthropic_sdk_route_uses_dedicated_auth_and_canonical_pipeline() -> None:
    analyzer = RecordingAnalyzer()

    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.anthropic.test/v1/messages"
        assert request.headers["x-api-key"] == "anthropic-upstream-key"
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert json.loads(request.content)["model"] == "claude-test"
        return httpx.Response(200, json=anthropic_response())

    async with app_client(
        upstream,
        settings=anthropic_gateway_settings(),
        runtime=GuardrailRuntime(analyzer),
    ) as (client, requests):
        response = await client.post(
            "/v1/messages",
            headers={"x-api-key": "gateway-test-key"},
            json=anthropic_request_payload(),
        )

    assert response.status_code == 200
    assert response.json()["content"][0]["id"] == "toolu_1"
    assert len(requests) == 1
    assert [(kind, origin) for kind, origin, _, _ in analyzer.events] == [
        (EventKind.MESSAGE, EventOrigin.CLIENT_ASSERTED),
        (EventKind.MODEL_CALL, EventOrigin.OBSERVED),
        (EventKind.TOOL_CALL_PROPOSAL, EventOrigin.OBSERVED),
    ]


@pytest.mark.asyncio
async def test_anthropic_output_block_hides_tool_use_and_has_no_tool_side_effect() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=anthropic_response(FAKE_SECRET)),
        settings=anthropic_gateway_settings(),
    ) as (client, requests):
        response = await client.post(
            "/v1/anthropic/messages",
            headers=auth_headers(),
            json=anthropic_request_payload(),
        )

    assert response.status_code == 400
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
    assert FAKE_SECRET not in response.text
    assert "toolu_1" not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_anthropic_stream_releases_safe_prefix_and_hides_blocked_delta() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=anthropic_text_stream(FAKE_SECRET),
            headers={"content-type": "text/event-stream"},
        ),
        settings=anthropic_gateway_settings(),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
    ) as (client, requests):
        response = await client.post(
            "/v1/messages",
            headers={"x-api-key": "gateway-test-key"},
            json=anthropic_request_payload(stream=True),
        )

    assert response.status_code == 200
    assert FAKE_SECRET not in response.text
    assert "event: error" in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_anthropic_rejects_server_mcp_before_upstream() -> None:
    payload = anthropic_request_payload()
    payload["mcp_servers"] = [{"type": "url", "url": "https://mcp.example"}]
    async with app_client(
        lambda request: httpx.Response(200, json=anthropic_response()),
        settings=anthropic_gateway_settings(),
    ) as (client, requests):
        response = await client.post(
            "/v1/messages",
            headers={"x-api-key": "gateway-test-key"},
            json=payload,
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert requests == []


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
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
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
    runtime = GuardrailRuntime(tool_access_analyzer(kind=EventKind.TOOL_CALL_PROPOSAL))
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
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
    assert response.json()["error"]["violations"][0]["code"] == "tool_access_denied"
    assert "tool_calls" not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("sensitive_value", [FAKE_PII, FAKE_CN_RESIDENT_ID])
async def test_pii_post_llm_block_hides_tool_call_and_records_safe_audit(
    sensitive_value: str,
) -> None:
    runtime = GuardrailRuntime(pii_analyzer(kind=EventKind.TOOL_CALL_PROPOSAL))
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
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
    assert response.json()["error"]["violations"][0]["code"] == "pii_exfiltration"
    assert sensitive_value not in response.text
    assert sensitive_value not in audit.records[0].model_dump_json()
    assert len(requests) == 1


class RecordingAnalyzer(MatchPolicyAnalyzer):
    def __init__(self) -> None:
        super().__init__(empty_analyzer().policy)
        self.events: list[tuple[EventKind, EventOrigin, str, tuple[str, ...]]] = []
        self.security_destinations: list[SecurityDestination] = []

    async def analyze_pending(self, pending: PendingTrace):
        self.security_destinations.append(pending.security_context.destination)
        self.events.extend(
            (
                event.kind,
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
      message: {kind: message, domain: pending}
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
    assert [(kind, origin) for kind, origin, _, _ in analyzer.events] == [
        (EventKind.MESSAGE, EventOrigin.CLIENT_ASSERTED),
        (EventKind.MODEL_CALL, EventOrigin.OBSERVED),
        (EventKind.MESSAGE, EventOrigin.OBSERVED),
    ]
    assert analyzer.security_destinations == [
        SecurityDestination.LLM_PROVIDER,
        SecurityDestination.CLIENT,
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
                        "arguments": json.dumps({"to": "inside@example.com", "body": "safe"}),
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
        EventKind.TOOL_CALL_PROPOSAL,
        EventKind.TOOL_RESULT,
        EventKind.MODEL_CALL,
        EventKind.MESSAGE,
    ]
    tool_call_event_id = analyzer.events[1][2]
    assert analyzer.events[2][3] == (tool_call_event_id,)


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
    assert response.json()["error"]["checkpoint"] == "before_model_call"
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
async def test_response_trace_capacity_does_not_release_upstream_payload() -> None:
    settings = gateway_settings().model_copy(update={"max_trace_events": 3})
    oversized_response = tool_response("safe", content="private upstream text")
    tool_calls = oversized_response["choices"][0]["message"]["tool_calls"]  # type: ignore[index]
    tool_calls.append(  # type: ignore[union-attr]
        {
            "id": "call-2",
            "type": "function",
            "function": {
                "name": "send_email",
                "arguments": json.dumps({"to": "outside@example.com", "body": "also safe"}),
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

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "evaluation_failed"
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
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
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
    assert "private upstream text" not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_pre_llm_block_makes_zero_upstream_requests(streaming: bool) -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=text_response()),
        runtime=pre_llm_blocking_runtime(),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=streaming),
        )

    assert response.status_code == 400
    assert response.json()["error"]["checkpoint"] == "before_model_call"
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
    assert len(audit.records[0].pending_event_ids) == 3
    assert len(audit.records[0].violations) == 2


@pytest.mark.asyncio
async def test_streaming_releases_safe_prefixes_and_commits_final_output() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=chat_stream("Safe ", "response"),
            headers={"content-type": "text/event-stream"},
        ),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert response.headers["x-guardrail-streaming"] == ("prefix-guarded-non-retractable")
    assert "Safe " in response.text
    assert "response" in response.text
    assert "data: [DONE]" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_streaming_block_keeps_released_prefix_but_hides_current_window() -> None:
    audit = InMemoryAuditSink()
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=chat_stream("Safe prefix. ", FAKE_SECRET),
            headers={"content-type": "text/event-stream"},
        ),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert "Safe prefix." in response.text
    assert FAKE_SECRET not in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1
    assert len(audit.records) == 1
    assert FAKE_SECRET not in audit.records[0].model_dump_json()


@pytest.mark.asyncio
async def test_streaming_tool_arguments_are_held_until_validated_and_blocked() -> None:
    audit = InMemoryAuditSink()
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=chat_tool_stream(FAKE_SECRET),
            headers={"content-type": "text/event-stream"},
        ),
        audit=audit,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert FAKE_SECRET not in response.text
    assert "send_email" not in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1
    assert len(audit.records) == 1


@pytest.mark.asyncio
async def test_streaming_safe_tool_arguments_release_only_after_validation() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=chat_tool_stream("safe"),
            headers={"content-type": "text/event-stream"},
        )
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert "send_email" in response.text
    argument_fragments: list[str] = []
    for block in response.text.split("\n\n"):
        if not block.startswith("data: {"):
            continue
        chunk = json.loads(block.removeprefix("data: "))
        for call in chunk["choices"][0]["delta"].get("tool_calls", []):
            argument_fragments.append(call.get("function", {}).get("arguments", ""))
    assert json.loads("".join(argument_fragments))["to"] == "outside@example.com"
    assert "data: [DONE]" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_streaming_incomplete_terminal_releases_only_guarded_prefix() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=chat_stream("Safe prefix.", finish=False),
            headers={"content-type": "text/event-stream"},
        ),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert "Safe prefix." in response.text
    assert "stream_terminated" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_streaming_size_limit_hides_unreleased_upstream_data() -> None:
    settings = gateway_settings().model_copy(update={"max_upstream_response_bytes": 1_024})
    raw = (FAKE_SECRET * 100).encode()
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=raw,
            headers={"content-type": "text/event-stream"},
        ),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert FAKE_SECRET not in response.text
    assert "stream_terminated" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_streaming_total_timeout_hides_late_upstream_data() -> None:
    settings = gateway_settings().model_copy(update={"upstream_timeout_seconds": 0.001})
    async with app_client(
        lambda request: httpx.Response(
            200,
            stream=_DelayedStream(),
            headers={"content-type": "text/event-stream"},
        ),
        settings=settings,
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/chat/completions",
            headers=auth_headers(),
            json=request_payload(stream=True),
        )

    assert response.status_code == 200
    assert "raw-sensitive" not in response.text
    assert "upstream_stream_timeout" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_responses_non_streaming_block_hides_function_call() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=response_api_tool_payload(FAKE_SECRET))
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/responses",
            headers=auth_headers(),
            json={
                "model": "test-model",
                "input": "Email it",
                "tools": [
                    {
                        "type": "function",
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
                        "strict": True,
                    }
                ],
            },
        )

    assert response.status_code == 400
    assert response.json()["error"]["checkpoint"] == "before_model_output_release"
    assert FAKE_SECRET not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_responses_streaming_uses_named_sse_events() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=responses_stream(),
            headers={"content-type": "text/event-stream"},
        )
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/responses",
            headers=auth_headers(),
            json={"model": "test-model", "input": "Hello", "stream": True},
        )

    assert response.status_code == 200
    assert "event: response.output_text.delta" in response.text
    assert "event: response.completed" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_responses_streaming_block_hides_current_delta() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=responses_stream(FAKE_SECRET),
            headers={"content-type": "text/event-stream"},
        ),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/responses",
            headers=auth_headers(),
            json={"model": "test-model", "input": "Hello", "stream": True},
        )

    assert response.status_code == 200
    assert FAKE_SECRET not in response.text
    assert "event: error" in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_responses_streaming_releases_safe_complete_function_arguments() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=responses_tool_stream("safe"),
            headers={"content-type": "text/event-stream"},
        )
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/responses",
            headers=auth_headers(),
            json=responses_tool_request(),
        )

    assert response.status_code == 200
    assert "response.function_call_arguments.delta" in response.text
    assert "send_email" in response.text
    assert "outside@example.com" in response.text
    assert "event: response.completed" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_responses_streaming_blocks_complete_secret_function_arguments() -> None:
    async with app_client(
        lambda request: httpx.Response(
            200,
            content=responses_tool_stream(FAKE_SECRET),
            headers={"content-type": "text/event-stream"},
        )
    ) as (client, requests):
        response = await client.post(
            "/v1/openai/responses",
            headers=auth_headers(),
            json=responses_tool_request(),
        )

    assert response.status_code == 200
    assert FAKE_SECRET not in response.text
    assert "send_email" not in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_custom_non_openai_adapter_uses_fixed_provider_route() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/generate"
        assert json.loads(request.content) == {"model": "toy", "prompt": "Hello"}
        return httpx.Response(200, json={"answer": "Safe answer"})

    async with app_client(
        upstream,
        settings=gateway_settings(),
        model_routes={"/v1/providers/toy/generate": ToyProviderAdapter()},
    ) as (client, requests):
        response = await client.post(
            "/v1/providers/toy/generate",
            headers=auth_headers(),
            json={"model": "toy", "prompt": "Hello"},
        )

    assert response.status_code == 200
    assert response.json() == {"answer": "Safe answer"}
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_custom_non_openai_stream_uses_the_same_guarded_pipeline() -> None:
    wire = (
        b'event: token\ndata: {"token":"Safe "}\n\n'
        b'event: token\ndata: {"token":"answer"}\n\n'
        b'event: done\ndata: {"done":true,"answer":"Safe answer"}\n\n'
    )

    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/generate-stream"
        assert json.loads(request.content) == {
            "model": "toy",
            "prompt": "Hello",
            "stream": True,
        }
        return httpx.Response(200, content=wire, headers={"content-type": "text/event-stream"})

    async with app_client(
        upstream,
        settings=gateway_settings(),
        model_routes={"/v1/providers/toy/stream": ToyStreamingProviderAdapter()},
    ) as (client, requests):
        response = await client.post(
            "/v1/providers/toy/stream",
            headers=auth_headers(),
            json={"model": "toy", "prompt": "Hello", "stream": True},
        )

    assert response.status_code == 200
    assert "event: token" in response.text
    assert "Safe answer" in response.text
    assert "event: done" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_custom_non_openai_stream_hides_a_blocked_delta() -> None:
    wire = (
        b'event: token\ndata: {"token":"Safe prefix. "}\n\n'
        + b'event: token\ndata: {"token":'
        + json.dumps(FAKE_SECRET).encode()
        + b"}\n\n"
    )

    async with app_client(
        lambda request: httpx.Response(
            200,
            content=wire,
            headers={"content-type": "text/event-stream"},
        ),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
        model_routes={"/v1/providers/toy/stream": ToyStreamingProviderAdapter()},
    ) as (client, requests):
        response = await client.post(
            "/v1/providers/toy/stream",
            headers=auth_headers(),
            json={"model": "toy", "prompt": "Hello", "stream": True},
        )

    assert response.status_code == 200
    assert "Safe prefix." in response.text
    assert FAKE_SECRET not in response.text
    assert "guardrail_blocked" in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("route", "upstream_path"),
    [
        ("/v1/chat/completions", "generate"),
        ("/v1/providers/toy/generate", "../external"),
    ],
)
async def test_custom_adapter_cannot_override_routes_or_escape_fixed_upstream(
    route: str,
    upstream_path: str,
) -> None:
    adapter = ToyProviderAdapter()
    adapter.upstream_path = upstream_path
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"answer": "unexpected"})
        )
    )
    try:
        with pytest.raises(ValueError):
            create_app(
                gateway_settings(),
                upstream_http_client=upstream_client,
                model_routes={route: adapter},
            )
    finally:
        await upstream_client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "expanded_payload"])
async def test_custom_adapter_failure_is_redacted_before_upstream(failure: str) -> None:
    class BrokenToyProviderAdapter(ToyProviderAdapter):
        def parse_request(self, payload: object) -> dict[str, object]:
            if failure == "exception":
                raise RuntimeError("raw-sensitive-adapter-error")
            return super().parse_request(payload)

        def request_payload(self, request: dict[str, object]) -> dict[str, object]:
            if failure == "expanded_payload":
                return {"prompt": "x" * 2_000}
            return super().request_payload(request)

    settings = gateway_settings().model_copy(update={"max_request_bytes": 1_024})
    async with app_client(
        lambda request: httpx.Response(200, json={"answer": "unexpected"}),
        settings=settings,
        model_routes={
            "/v1/providers/toy/generate": BrokenToyProviderAdapter(),
        },
    ) as (client, requests):
        response = await client.post(
            "/v1/providers/toy/generate",
            headers=auth_headers(),
            json={"model": "toy", "prompt": "Hello"},
        )

    assert response.status_code in {400, 413}
    assert "raw-sensitive" not in response.text
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

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from agent_guardrail.adapters.anthropic import AnthropicAdapter, AnthropicAdapterError
from agent_guardrail.adapters.streaming import ServerSentEvent, StreamRelease
from agent_guardrail.models import ChatRole


def request_payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "claude-test",
        "max_tokens": 256,
        "system": "Keep data private.",
        "messages": [{"role": "user", "content": "Send the report"}],
        "tools": [
            {
                "name": "send_email",
                "description": "Send an email",
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


def response_payload(*, body: str = "safe") -> dict[str, object]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "I will send it."},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "send_email",
                "input": {"to": "outside@example.com", "body": body},
            },
        ],
        "model": "claude-test",
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 8},
    }


def event(name: str, payload: dict[str, object]) -> ServerSentEvent:
    return ServerSentEvent(event=name, data=json.dumps(payload, separators=(",", ":")))


def stream_decoder() -> Any:
    adapter = AnthropicAdapter()
    return adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))


def start(decoder: Any) -> Any:
    return decoder.consume(
        event(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": "claude-test",
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1},
                },
            },
        )
    )


def test_anthropic_maps_system_tool_history_and_tool_result() -> None:
    adapter = AnthropicAdapter()
    payload = request_payload()
    payload["messages"] = [
        {"role": "user", "content": "Send the report"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Checking."},
                {
                    "type": "tool_use",
                    "id": "toolu_0",
                    "name": "send_email",
                    "input": {"to": "outside@example.com", "body": "draft"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_0",
                    "content": [{"type": "text", "text": "sent"}],
                },
                {"type": "text", "text": "Summarize it."},
            ],
        },
    ]

    request = adapter.parse_request(payload)
    canonical = adapter.request_to_canonical(request)
    response = adapter.response_to_canonical(
        adapter.parse_response(response_payload()),
        request=request,
    )

    assert [message.role for message in canonical.messages] == [
        ChatRole.SYSTEM,
        ChatRole.USER,
        ChatRole.ASSISTANT,
        ChatRole.TOOL,
        ChatRole.USER,
    ]
    assert canonical.messages[2].tool_calls[0].call_id == "toolu_0"
    assert canonical.messages[3].tool_call_id == "toolu_0"
    assert response.content == "I will send it."
    assert response.tool_calls[0].call_id == "toolu_1"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda payload: payload.update({"mcp_servers": []}), "invalid_request"),
        (
            lambda payload: payload["tools"][0].update({"type": "web_search_20250305"}),
            "invalid_request",
        ),
        (
            lambda payload: payload.update(
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "after"},
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "toolu_0",
                                    "content": "result",
                                },
                            ],
                        }
                    ]
                }
            ),
            "invalid_request",
        ),
        (
            lambda payload: payload["tools"][0].update(
                {"input_schema": {"type": "not-a-schema-type"}}
            ),
            "invalid_tool_schema",
        ),
    ],
    ids=("server-mcp", "server-tool", "tool-result-order", "invalid-schema"),
)
def test_anthropic_rejects_unsupported_or_unsafe_requests(
    mutate: Callable[[dict[str, Any]], None],
    code: str,
) -> None:
    payload: dict[str, Any] = request_payload()
    mutate(payload)

    with pytest.raises(AnthropicAdapterError) as caught:
        AnthropicAdapter().parse_request(payload)

    assert caught.value.code == code


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda payload: payload["content"][1].update({"name": "undeclared"}),
            "undeclared_tool_call",
        ),
        (
            lambda payload: payload["content"][1].update({"input": {"body": "missing to"}}),
            "invalid_tool_arguments",
        ),
        (
            lambda payload: payload.update({"stop_reason": "max_tokens"}),
            "incomplete_upstream_response",
        ),
        (
            lambda payload: payload.update({"stop_reason": "end_turn"}),
            "invalid_upstream_response",
        ),
        (
            lambda payload: payload["content"].append(
                {"type": "server_tool_use", "id": "srv_1"}
            ),
            "invalid_upstream_response",
        ),
    ],
    ids=("undeclared", "schema", "truncated", "stop-mismatch", "server-content"),
)
def test_anthropic_rejects_unsafe_upstream_output(
    mutate: Callable[[dict[str, Any]], None],
    code: str,
) -> None:
    adapter = AnthropicAdapter()
    request = adapter.parse_request(request_payload())
    payload: dict[str, Any] = response_payload()
    mutate(payload)

    with pytest.raises(AnthropicAdapterError) as caught:
        response = adapter.parse_response(payload)
        adapter.response_to_canonical(response, request=request)

    assert caught.value.code == code


def test_anthropic_stream_guards_text_and_complete_tool_input() -> None:
    decoder = stream_decoder()
    assert start(decoder).release is StreamRelease.HOLD
    block = decoder.consume(
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
    )
    text = decoder.consume(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Safe"},
            },
        )
    )
    decoder.consume(
        event("content_block_stop", {"type": "content_block_stop", "index": 0})
    )
    decoder.consume(
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "send_email",
                    "input": {},
                },
            },
        )
    )
    arguments = '{"to":"outside@example.com","body":"safe"}'
    first = decoder.consume(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": arguments[:20]},
            },
        )
    )
    decoder.consume(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": arguments[20:]},
            },
        )
    )
    complete = decoder.consume(
        event("content_block_stop", {"type": "content_block_stop", "index": 1})
    )
    delta = decoder.consume(
        event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 12},
            },
        )
    )
    terminal = decoder.consume(event("message_stop", {"type": "message_stop"}))
    decoder.finish()

    assert block.release is StreamRelease.HOLD
    assert text.release is StreamRelease.GUARD
    assert text.output is not None and text.output.content == "Safe"
    assert first.release is StreamRelease.HOLD
    assert complete.release is StreamRelease.GUARD
    assert complete.output is not None
    assert complete.output.tool_calls[0].arguments["body"] == "safe"
    assert delta.release is StreamRelease.GUARD
    assert terminal.release is StreamRelease.FINAL
    error = decoder.error_event(code="guardrail_blocked", message="Blocked")
    assert error.event == "error"
    assert json.loads(error.data)["error"]["code"] == "guardrail_blocked"


@pytest.mark.parametrize(
    "exercise",
    [
        lambda decoder: decoder.consume(ServerSentEvent(data='{"type":"ping"}')),
        lambda decoder: decoder.consume(event("ping", {"type": "message_stop"})),
        lambda decoder: decoder.consume(event("ping", {"type": "ping"})),
        lambda decoder: (
            start(decoder),
            decoder.consume(event("unknown", {"type": "unknown"})),
        ),
        lambda decoder: (
            start(decoder),
            decoder.consume(
                event(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": 1,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
            ),
        ),
    ],
    ids=("unnamed", "name-type-mismatch", "ping-before-start", "unknown", "bad-index"),
)
def test_anthropic_stream_rejects_invalid_sequences(
    exercise: Callable[[Any], object],
) -> None:
    with pytest.raises(AnthropicAdapterError) as caught:
        exercise(stream_decoder())

    assert caught.value.code == "invalid_upstream_stream"


def test_anthropic_stream_rejects_truncated_tool_and_requires_terminal() -> None:
    invalid = stream_decoder()
    start(invalid)
    invalid.consume(
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "send_email",
                    "input": {},
                },
            },
        )
    )
    invalid.consume(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": "{"},
            },
        )
    )
    with pytest.raises(AnthropicAdapterError, match="JSON object"):
        invalid.consume(
            event("content_block_stop", {"type": "content_block_stop", "index": 0})
        )

    incomplete = stream_decoder()
    start(incomplete)
    with pytest.raises(AnthropicAdapterError, match="before message_stop"):
        incomplete.finish()

    adapter = AnthropicAdapter()
    request = adapter.parse_request(request_payload())
    with pytest.raises(AnthropicAdapterError, match="stream=true"):
        adapter.stream_decoder(request)

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from agent_guardrail.adapters.openai import OpenAIAdapter, OpenAIAdapterError
from agent_guardrail.adapters.streaming import ServerSentEvent, StreamRelease


def request_payload(*, stream: bool = True) -> dict[str, object]:
    return {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Send the report"}],
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


def chunk(
    delta: dict[str, object] | None = None,
    *,
    finish_reason: str | None = None,
    stream_id: str = "chatcmpl-stream",
    choices: list[dict[str, object]] | None = None,
    **extra: object,
) -> dict[str, object]:
    return {
        "id": stream_id,
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "test-model",
        "choices": choices
        if choices is not None
        else [{"index": 0, "delta": delta or {}, "finish_reason": finish_reason}],
        **extra,
    }


def consume(decoder: Any, payload: dict[str, object]) -> Any:
    return decoder.consume(ServerSentEvent(data=json.dumps(payload, separators=(",", ":"))))


def decoder() -> Any:
    adapter = OpenAIAdapter()
    return adapter.stream_decoder(adapter.parse_request(request_payload()))


def test_chat_stream_guards_text_refusal_and_emits_sdk_error_shape() -> None:
    text_decoder = decoder()
    role = consume(text_decoder, chunk({"role": "assistant"}))
    text = consume(text_decoder, chunk({"content": "Safe"}))
    finished = consume(text_decoder, chunk({}, finish_reason="stop"))
    terminal = text_decoder.consume(ServerSentEvent(data="[DONE]"))
    text_decoder.finish()

    refusal_decoder = decoder()
    refusal = consume(refusal_decoder, chunk({"refusal": "Cannot comply"}))
    error_event = refusal_decoder.error_event(code="guardrail_blocked", message="Blocked.")

    assert role.release is StreamRelease.HOLD
    assert text.release is StreamRelease.GUARD
    assert text.output is not None and text.output.content == "Safe"
    assert finished.release is StreamRelease.GUARD
    assert terminal.release is StreamRelease.FINAL
    assert terminal.event == ServerSentEvent(data="[DONE]")
    assert refusal.output is not None and refusal.output.content == "Cannot comply"
    assert json.loads(error_event.data)["error"]["code"] == "guardrail_blocked"


def test_chat_stream_holds_complete_tool_call_until_schema_validation() -> None:
    active = decoder()
    arguments = '{"to":"outside@example.com","body":"safe"}'
    first = consume(
        active,
        chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": arguments[:20],
                        },
                    }
                ]
            }
        ),
    )
    second = consume(
        active,
        chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "function": {"arguments": arguments[20:]},
                    }
                ]
            }
        ),
    )
    complete = consume(active, chunk({}, finish_reason="tool_calls"))
    terminal = active.consume(ServerSentEvent(data="[DONE]"))

    assert first.release is StreamRelease.HOLD
    assert second.release is StreamRelease.HOLD
    assert complete.release is StreamRelease.GUARD
    assert complete.output is not None
    assert complete.output.tool_calls[0].arguments["body"] == "safe"
    assert terminal.release is StreamRelease.FINAL


@pytest.mark.parametrize(
    "exercise",
    [
        lambda active: active.consume(ServerSentEvent(event="token", data="{}")),
        lambda active: active.consume(ServerSentEvent(data="not-json")),
        lambda active: (
            consume(active, chunk({"content": "safe"})),
            consume(active, chunk({"content": "changed"}, stream_id="changed")),
        ),
        lambda active: consume(active, chunk({"content": "safe"}, moderation={"x": 1})),
        lambda active: consume(
            active,
            chunk(
                {"content": "safe"},
                choices=[{"index": 0, "delta": {"content": "safe"}, "logprobs": {"x": 1}}],
            ),
        ),
        lambda active: consume(active, chunk({"content": "safe", "refusal": "no"})),
        lambda active: (
            consume(active, chunk({"refusal": "no"})),
            consume(active, chunk({"content": "later"})),
        ),
        lambda active: (
            consume(active, chunk({"content": "safe"})),
            active.consume(ServerSentEvent(data="[DONE]")),
            active.consume(ServerSentEvent(data="[DONE]")),
        ),
    ],
    ids=(
        "named-sse",
        "malformed-json",
        "identity-change",
        "moderation",
        "logprobs",
        "mixed-delta",
        "content-after-refusal",
        "after-terminal",
    ),
)
def test_chat_stream_rejects_invalid_text_protocol(
    exercise: Callable[[Any], object],
) -> None:
    with pytest.raises(OpenAIAdapterError) as caught:
        exercise(decoder())

    assert caught.value.code == "invalid_upstream_stream"


def tool_delta(
    *,
    index: int = 0,
    call_id: str | None = "call-1",
    name: str | None = "send_email",
    arguments: str | None = '{"to":"outside@example.com","body":"safe"}',
) -> dict[str, object]:
    function = {
        key: value
        for key, value in {"name": name, "arguments": arguments}.items()
        if value is not None
    }
    call = {
        key: value
        for key, value in {
            "index": index,
            "id": call_id,
            "type": "function" if call_id is not None else None,
            "function": function,
        }.items()
        if value is not None
    }
    return {"tool_calls": [call]}


@pytest.mark.parametrize(
    "exercise",
    [
        lambda active: (
            consume(active, chunk(tool_delta(index=1))),
            consume(active, chunk({}, finish_reason="tool_calls")),
        ),
        lambda active: (
            consume(active, chunk(tool_delta(call_id=None))),
            consume(active, chunk({}, finish_reason="tool_calls")),
        ),
        lambda active: (
            consume(active, chunk(tool_delta(name=None))),
            consume(active, chunk({}, finish_reason="tool_calls")),
        ),
        lambda active: (
            consume(active, chunk(tool_delta(arguments="[]"))),
            consume(active, chunk({}, finish_reason="tool_calls")),
        ),
        lambda active: (
            consume(active, chunk(tool_delta())),
            consume(active, chunk({}, finish_reason="stop")),
        ),
        lambda active: (
            consume(active, chunk(tool_delta(arguments=""))),
            consume(active, chunk(tool_delta(call_id="call-2", name=None, arguments=None))),
        ),
        lambda active: (
            consume(active, chunk(tool_delta(arguments=""))),
            consume(active, chunk(tool_delta(call_id=None, name="other", arguments=None))),
        ),
        lambda active: (
            consume(active, chunk(tool_delta())),
            consume(active, chunk({}, finish_reason="tool_calls")),
            consume(active, chunk(tool_delta(arguments="{}"))),
        ),
    ],
    ids=(
        "noncontiguous-index",
        "missing-id",
        "missing-name",
        "arguments-not-object",
        "wrong-finish-reason",
        "changed-id",
        "changed-name",
        "tool-after-completion",
    ),
)
def test_chat_stream_rejects_invalid_tool_state(
    exercise: Callable[[Any], object],
) -> None:
    with pytest.raises(OpenAIAdapterError):
        exercise(decoder())


def test_chat_stream_requires_output_and_terminal_event() -> None:
    empty = decoder()
    with pytest.raises(OpenAIAdapterError, match="no supported output"):
        empty.consume(ServerSentEvent(data="[DONE]"))

    incomplete = decoder()
    consume(incomplete, chunk({"content": "safe"}))
    with pytest.raises(OpenAIAdapterError, match=r"before \[DONE\]"):
        incomplete.finish()

    adapter = OpenAIAdapter()
    request = adapter.parse_request(request_payload(stream=False))
    with pytest.raises(OpenAIAdapterError, match="stream=true"):
        adapter.stream_decoder(request)

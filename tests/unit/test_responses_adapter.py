from __future__ import annotations

import json
from typing import Any

import pytest

from agent_guardrail.adapters.openai import (
    OpenAIResponsesAdapter,
    OpenAIResponsesAdapterError,
)
from agent_guardrail.adapters.streaming import ServerSentEvent, StreamRelease
from agent_guardrail.models import ChatRole


def request_payload(*, stream: bool = False) -> dict[str, object]:
    return {
        "model": "test-model",
        "input": "Send the report",
        "tools": [
            {
                "type": "function",
                "name": "send_email",
                "description": "Send an email",
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
        "stream": stream,
    }


def response_payload(*, body: str = "safe") -> dict[str, object]:
    return {
        "id": "resp_1",
        "object": "response",
        "created_at": 1.0,
        "model": "test-model",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "Ready", "annotations": []}],
            },
            {
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_1",
                "name": "send_email",
                "arguments": json.dumps({"to": "outside@example.com", "body": body}),
                "status": "completed",
            },
        ],
    }


def lifecycle_response_payload() -> dict[str, object]:
    payload = response_payload()
    payload["status"] = "in_progress"
    payload["output"] = []
    return payload


def stream_event(event_type: str, sequence_number: object, **fields: object) -> ServerSentEvent:
    return ServerSentEvent(
        event=event_type,
        data=json.dumps(
            {"type": event_type, "sequence_number": sequence_number, **fields},
            separators=(",", ":"),
        ),
    )


def message_response(
    content: dict[str, object],
    *,
    message_id: str = "msg_1",
) -> dict[str, object]:
    payload = response_payload()
    payload["output"] = [
        {
            "type": "message",
            "id": message_id,
            "role": "assistant",
            "status": "completed",
            "content": [content],
        }
    ]
    return payload


def test_responses_request_and_response_map_to_provider_neutral_models() -> None:
    adapter = OpenAIResponsesAdapter()
    request = adapter.parse_request(request_payload())
    response = adapter.parse_response(response_payload())

    canonical_request = adapter.request_to_canonical(request)
    canonical_response = adapter.response_to_canonical(response, request=request)

    assert canonical_request.messages[0].role is ChatRole.USER
    assert canonical_request.messages[0].content == "Send the report"
    assert canonical_request.tools[0].name == "send_email"
    assert canonical_response.content == "Ready"
    assert canonical_response.tool_calls[0].arguments["body"] == "safe"


def test_responses_instructions_and_developer_input_map_to_system_messages() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["instructions"] = "Follow policy"
    payload["input"] = [
        {"type": "message", "role": "developer", "content": "Use tools safely"},
        {"type": "message", "role": "user", "content": "Send it"},
    ]

    request = adapter.parse_request(payload)
    canonical = adapter.request_to_canonical(request)

    assert [message.role for message in canonical.messages] == [
        ChatRole.SYSTEM,
        ChatRole.SYSTEM,
        ChatRole.USER,
    ]
    assert adapter.request_payload(request)["instructions"] == "Follow policy"


def test_responses_accepts_text_content_parts_from_state_owner_replay() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["input"] = [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "remember this"}],
        },
        {
            "type": "message",
            "role": "assistant",
            "id": "msg_state_owner",
            "status": "completed",
            "content": [{"type": "output_text", "text": "remembered"}],
        },
        {
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "continue "},
                {"type": "input_text", "text": "the task"},
            ],
        },
    ]

    canonical = adapter.request_to_canonical(adapter.parse_request(payload))

    assert [message.content for message in canonical.messages] == [
        "remember this",
        "remembered",
        "continue the task",
    ]


def test_responses_rejects_non_text_content_parts_without_echoing_them() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["input"] = [
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "input_image", "image_url": "raw-sensitive"}],
        }
    ]

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        adapter.parse_request(payload)

    assert caught.value.code == "invalid_request"
    assert "raw-sensitive" not in str(caught.value)


def test_responses_rejects_invalid_tool_schema_without_echoing_it() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["tools"][0]["parameters"] = {"type": "raw-sensitive-invalid-type"}  # type: ignore[index]

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        adapter.parse_request(payload)

    assert caught.value.code == "invalid_tool_schema"
    assert "raw-sensitive" not in str(caught.value)


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ("not-json", "invalid_tool_arguments_json"),
        ("[]", "invalid_tool_arguments_json"),
        ('{"to":"outside@example.com"}', "invalid_tool_arguments"),
    ],
)
def test_responses_rejects_malformed_or_schema_invalid_arguments(
    arguments: str,
    code: str,
) -> None:
    adapter = OpenAIResponsesAdapter()
    payload = response_payload()
    payload["output"][1]["arguments"] = arguments  # type: ignore[index]
    request = adapter.parse_request(request_payload())
    response = adapter.parse_response(payload)

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        adapter.response_to_canonical(response, request=request)

    assert caught.value.code == code


@pytest.mark.parametrize("status", ["failed", "incomplete"])
def test_responses_rejects_non_completed_provider_response(status: str) -> None:
    adapter = OpenAIResponsesAdapter()
    payload = response_payload()
    payload["status"] = status

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        adapter.parse_response(payload)

    assert caught.value.code == "invalid_upstream_response"


def test_responses_rejects_empty_output_and_unsupported_text_metadata() -> None:
    adapter = OpenAIResponsesAdapter()
    request = adapter.parse_request(request_payload())
    empty = response_payload()
    empty["output"] = []
    annotated = message_response(
        {
            "type": "output_text",
            "text": "safe",
            "annotations": [{"type": "raw-sensitive-annotation"}],
        }
    )

    for payload in (empty, annotated):
        response = adapter.parse_response(payload)
        with pytest.raises(OpenAIResponsesAdapterError) as caught:
            adapter.response_to_canonical(response, request=request)
        assert caught.value.code == "invalid_upstream_response"
        assert "raw-sensitive" not in str(caught.value)


def test_responses_reencodes_only_canonicalized_response_fields() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = response_payload()
    payload["metadata"] = {"covert": "raw-sensitive-top-level"}
    function = payload["output"][1]  # type: ignore[index]
    function["caller"] = {"covert": "raw-sensitive-caller"}  # type: ignore[index]
    function["namespace"] = "raw-sensitive-namespace"  # type: ignore[index]
    response = adapter.parse_response(payload)

    canonical = adapter.response_to_canonical(
        response,
        request=adapter.parse_request(request_payload()),
    )
    reencoded = json.dumps(adapter.response_payload(response))

    assert canonical.tool_calls[0].name == "send_email"
    assert "raw-sensitive" not in reencoded
    assert "metadata" not in reencoded
    assert "caller" not in reencoded
    assert "namespace" not in reencoded


def test_responses_function_history_becomes_canonical_tool_turn() -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["input"] = [
        {"type": "message", "role": "user", "content": "Send it"},
        {
            "type": "function_call",
            "call_id": "call_1",
            "name": "send_email",
            "arguments": '{"to":"inside@example.com","body":"safe"}',
        },
        {
            "type": "function_call_output",
            "call_id": "call_1",
            "output": "sent",
        },
    ]

    canonical = adapter.request_to_canonical(adapter.parse_request(payload))

    assert [message.role for message in canonical.messages] == [
        ChatRole.USER,
        ChatRole.ASSISTANT,
        ChatRole.TOOL,
    ]
    assert canonical.messages[1].tool_calls[0].call_id == "call_1"
    assert canonical.messages[2].tool_call_id == "call_1"


@pytest.mark.parametrize(
    "history",
    [
        [{"type": "function_call_output", "call_id": "missing", "output": "sent"}],
        [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "send_email",
                "arguments": "{}",
            },
            {"type": "message", "role": "user", "content": "next"},
        ],
        [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "send_email",
                "arguments": "{}",
            },
            {
                "type": "function_call_output",
                "call_id": "call_1",
                "name": "other",
                "output": "sent",
            },
        ],
        [
            {
                "type": "function_call",
                "call_id": "call_1",
                "name": "send_email",
                "arguments": "{}",
            }
        ],
    ],
    ids=("orphan-output", "message-before-output", "changed-name", "unresolved-call"),
)
def test_responses_rejects_inconsistent_function_history(
    history: list[dict[str, object]],
) -> None:
    adapter = OpenAIResponsesAdapter()
    payload = request_payload()
    payload["input"] = history

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        adapter.request_to_canonical(adapter.parse_request(payload))

    assert caught.value.code == "invalid_request_history"


def test_responses_parses_state_reference_and_rejects_builtins_and_invalid_calls() -> None:
    adapter = OpenAIResponsesAdapter()

    hidden = adapter.parse_request(
        {"model": "test-model", "input": "hello", "previous_response_id": "r"}
    )
    with pytest.raises(OpenAIResponsesAdapterError) as builtin:
        adapter.parse_request(
            {
                "model": "test-model",
                "input": "search",
                "tools": [{"type": "web_search_preview"}],
            }
        )
    request = adapter.parse_request(request_payload())
    with pytest.raises(OpenAIResponsesAdapterError) as arguments:
        adapter.response_to_canonical(
            adapter.parse_response(response_payload(body="safe")),
            request=request.model_copy(
                update={"tools": ()},
            ),
        )

    assert hidden.previous_response_id == "r"
    assert builtin.value.code == "invalid_request"
    assert arguments.value.code == "undeclared_tool_call"


def test_responses_stream_guards_text_and_requires_completed_terminal() -> None:
    adapter = OpenAIResponsesAdapter()
    request = adapter.parse_request(request_payload(stream=True))
    decoder = adapter.stream_decoder(request)

    created = decoder.consume(
        ServerSentEvent(
            event="response.created",
            data=json.dumps(
                {
                    "type": "response.created",
                    "sequence_number": 0,
                    "response": lifecycle_response_payload(),
                }
            ),
        )
    )
    delta = decoder.consume(
        ServerSentEvent(
            event="response.output_text.delta",
            data=(
                '{"type":"response.output_text.delta","sequence_number":1,'
                '"item_id":"msg_1","output_index":0,"content_index":0,'
                '"delta":"Safe","logprobs":[]}'
            ),
        )
    )
    terminal_payload = {
        "type": "response.completed",
        "sequence_number": 2,
        "response": {
            "id": "resp_1",
            "object": "response",
            "created_at": 1.0,
            "model": "test-model",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "id": "msg_1",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": "Safe", "annotations": []}],
                }
            ],
        },
    }
    completed = decoder.consume(
        ServerSentEvent(
            event="response.completed",
            data=json.dumps(terminal_payload),
        )
    )
    decoder.finish()

    assert created.release is StreamRelease.HOLD
    assert delta.release is StreamRelease.GUARD
    assert delta.output is not None and delta.output.content == "Safe"
    assert completed.release is StreamRelease.FINAL


def test_responses_stream_rejects_event_type_mismatch_without_content_echo() -> None:
    adapter = OpenAIResponsesAdapter()
    decoder = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        decoder.consume(
            ServerSentEvent(
                event="response.output_text.delta",
                data='{"type":"response.failed","secret":"raw-sensitive"}',
            )
        )

    assert caught.value.code == "invalid_upstream_stream"
    assert "raw-sensitive" not in str(caught.value)


def test_responses_stream_error_is_an_sdk_compatible_next_event() -> None:
    adapter = OpenAIResponsesAdapter()
    decoder = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    decoder.consume(
        ServerSentEvent(
            event="response.created",
            data=json.dumps(
                {
                    "type": "response.created",
                    "sequence_number": 0,
                    "response": lifecycle_response_payload(),
                }
            ),
        )
    )

    event = decoder.error_event(code="guardrail_blocked", message="Stream blocked.")

    assert event.event == "error"
    assert json.loads(event.data) == {
        "type": "error",
        "code": "guardrail_blocked",
        "message": "Stream blocked.",
        "param": None,
        "sequence_number": 1,
    }


def test_responses_stream_never_flushes_pending_function_arguments_with_text() -> None:
    adapter = OpenAIResponsesAdapter()
    decoder = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))

    added = decoder.consume(
        ServerSentEvent(
            event="response.output_item.added",
            data=json.dumps(
                {
                    "type": "response.output_item.added",
                    "sequence_number": 0,
                    "output_index": 1,
                    "item": {
                        "type": "function_call",
                        "id": "fc_1",
                        "call_id": "call_1",
                        "name": "send_email",
                        "arguments": "",
                        "status": "in_progress",
                    },
                }
            ),
        )
    )
    arguments = decoder.consume(
        ServerSentEvent(
            event="response.function_call_arguments.delta",
            data=(
                '{"type":"response.function_call_arguments.delta",'
                '"sequence_number":1,"item_id":"fc_1","output_index":1,'
                '"delta":"raw-sensitive-arguments"}'
            ),
        )
    )
    text = decoder.consume(
        ServerSentEvent(
            event="response.output_text.delta",
            data=(
                '{"type":"response.output_text.delta","sequence_number":2,'
                '"item_id":"msg_1","output_index":0,"content_index":0,'
                '"delta":"Safe text","logprobs":[]}'
            ),
        )
    )

    assert added.release is StreamRelease.HOLD
    assert arguments.release is StreamRelease.HOLD
    assert text.release is StreamRelease.HOLD


def test_responses_stream_rejects_structural_event_with_premature_text() -> None:
    adapter = OpenAIResponsesAdapter()
    decoder = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    payload = {
        "type": "response.output_item.added",
        "sequence_number": 0,
        "output_index": 0,
        "item": {
            "type": "message",
            "id": "msg_1",
            "role": "assistant",
            "status": "in_progress",
            "content": [
                {
                    "type": "output_text",
                    "text": "raw-sensitive-structural-text",
                    "annotations": [],
                }
            ],
        },
    }

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        decoder.consume(
            ServerSentEvent(
                event="response.output_item.added",
                data=json.dumps(payload),
            )
        )

    assert caught.value.code == "invalid_upstream_stream"
    assert "raw-sensitive" not in str(caught.value)


def test_responses_stream_rejects_unmapped_delta_fields_without_echo() -> None:
    adapter = OpenAIResponsesAdapter()
    decoder = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    payload = {
        "type": "response.output_text.delta",
        "sequence_number": 0,
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": "safe",
        "logprobs": [],
        "covert": "raw-sensitive-extra-field",
    }

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        decoder.consume(
            ServerSentEvent(
                event="response.output_text.delta",
                data=json.dumps(payload),
            )
        )

    assert caught.value.code == "invalid_upstream_stream"
    assert "raw-sensitive" not in str(caught.value)


def test_responses_stream_validates_full_refusal_structure() -> None:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    added = active.consume(
        stream_event(
            "response.output_item.added",
            0,
            output_index=0,
            item={
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "in_progress",
                "content": [],
            },
        )
    )
    part_added = active.consume(
        stream_event(
            "response.content_part.added",
            1,
            item_id="msg_1",
            output_index=0,
            content_index=0,
            part={"type": "refusal", "refusal": ""},
        )
    )
    delta = active.consume(
        stream_event(
            "response.refusal.delta",
            2,
            item_id="msg_1",
            output_index=0,
            content_index=0,
            delta="Cannot comply",
        )
    )
    done = active.consume(
        stream_event(
            "response.refusal.done",
            3,
            item_id="msg_1",
            output_index=0,
            content_index=0,
            refusal="Cannot comply",
        )
    )
    part_done = active.consume(
        stream_event(
            "response.content_part.done",
            4,
            item_id="msg_1",
            output_index=0,
            content_index=0,
            part={"type": "refusal", "refusal": "Cannot comply"},
        )
    )
    item_done = active.consume(
        stream_event(
            "response.output_item.done",
            5,
            output_index=0,
            item={
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "refusal", "refusal": "Cannot comply"}],
            },
        )
    )
    completed = active.consume(
        stream_event(
            "response.completed",
            6,
            response=message_response({"type": "refusal", "refusal": "Cannot comply"}),
        )
    )
    active.finish()

    assert added.release is StreamRelease.HOLD
    assert part_added.release is StreamRelease.HOLD
    assert delta.release is StreamRelease.GUARD
    assert delta.output is not None and delta.output.content == "Cannot comply"
    assert done.release is StreamRelease.HOLD
    assert part_done.release is StreamRelease.HOLD
    assert item_done.release is StreamRelease.HOLD
    assert completed.release is StreamRelease.FINAL


@pytest.mark.parametrize("sequence", [True, -1, 1, "0", None])
def test_responses_stream_rejects_nonconsecutive_sequence(sequence: object) -> None:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))

    with pytest.raises(OpenAIResponsesAdapterError, match="invalid event sequence"):
        active.consume(
            stream_event(
                "response.output_text.delta",
                sequence,
                item_id="msg_1",
                output_index=0,
                content_index=0,
                delta="safe",
                logprobs=[],
            )
        )


@pytest.mark.parametrize(
    "event_type",
    ["error", "response.failed", "response.incomplete"],
)
def test_responses_stream_maps_provider_terminal_failures(event_type: str) -> None:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))

    with pytest.raises(OpenAIResponsesAdapterError) as caught:
        active.consume(stream_event(event_type, 0))

    assert caught.value.code == "upstream_stream_failed"


def _function_stream() -> tuple[Any, str]:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    arguments = '{"to":"outside@example.com","body":"safe"}'
    active.consume(
        stream_event(
            "response.output_item.added",
            0,
            output_index=0,
            item={
                "type": "function_call",
                "id": "fc_1",
                "call_id": "call_1",
                "name": "send_email",
                "arguments": "",
                "status": "in_progress",
            },
        )
    )
    active.consume(
        stream_event(
            "response.function_call_arguments.delta",
            1,
            item_id="fc_1",
            output_index=0,
            delta=arguments,
        )
    )
    return active, arguments


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"item_id": "changed", "output_index": 0}, "changed its output item"),
        ({"item_id": "fc_1", "output_index": 1}, "matching output item"),
        ({"item_id": "fc_1", "output_index": 0, "name": "other"}, "changed completed"),
        ({"item_id": "fc_1", "output_index": 0, "arguments": "{}"}, "changed completed"),
    ],
)
def test_responses_stream_rejects_function_done_mismatch(
    fields: dict[str, object],
    message: str,
) -> None:
    active, arguments = _function_stream()
    payload = {
        "item_id": "fc_1",
        "output_index": 0,
        "name": "send_email",
        "arguments": arguments,
        **fields,
    }

    with pytest.raises(OpenAIResponsesAdapterError, match=message):
        active.consume(stream_event("response.function_call_arguments.done", 2, **payload))


def test_responses_stream_rejects_function_delta_without_added_item() -> None:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))

    with pytest.raises(OpenAIResponsesAdapterError, match="matching output item"):
        active.consume(
            stream_event(
                "response.function_call_arguments.delta",
                0,
                item_id="fc_1",
                output_index=0,
                delta="raw-sensitive",
            )
        )


def test_responses_stream_rejects_incomplete_function_at_terminal() -> None:
    active, arguments = _function_stream()
    terminal = response_payload()
    terminal["output"] = [
        {
            "type": "function_call",
            "id": "fc_1",
            "call_id": "call_1",
            "name": "send_email",
            "arguments": arguments,
            "status": "completed",
        }
    ]

    with pytest.raises(OpenAIResponsesAdapterError, match="before its item was complete"):
        active.consume(stream_event("response.completed", 2, response=terminal))


@pytest.mark.parametrize(
    ("terminal_content", "message_id", "message"),
    [
        ("changed", "msg_1", "changed released text"),
        ("Safe", "changed", "changed its text item"),
    ],
)
def test_responses_stream_rejects_terminal_text_mismatch(
    terminal_content: str,
    message_id: str,
    message: str,
) -> None:
    adapter = OpenAIResponsesAdapter()
    active = adapter.stream_decoder(adapter.parse_request(request_payload(stream=True)))
    active.consume(
        stream_event(
            "response.output_text.delta",
            0,
            item_id="msg_1",
            output_index=0,
            content_index=0,
            delta="Safe",
            logprobs=[],
        )
    )

    with pytest.raises(OpenAIResponsesAdapterError, match=message):
        active.consume(
            stream_event(
                "response.completed",
                1,
                response=message_response(
                    {
                        "type": "output_text",
                        "text": terminal_content,
                        "annotations": [],
                    },
                    message_id=message_id,
                ),
            )
        )


def test_responses_stream_rejects_events_after_terminal_and_requires_terminal() -> None:
    adapter = OpenAIResponsesAdapter()
    request = adapter.parse_request(request_payload(stream=True))
    complete = adapter.stream_decoder(request)
    complete.consume(
        stream_event(
            "response.completed",
            0,
            response=message_response({"type": "output_text", "text": "safe", "annotations": []}),
        )
    )
    with pytest.raises(OpenAIResponsesAdapterError, match="after stream completion"):
        complete.consume(stream_event("response.completed", 1, response=response_payload()))

    incomplete = adapter.stream_decoder(request)
    with pytest.raises(OpenAIResponsesAdapterError, match="before response.completed"):
        incomplete.finish()

    non_streaming = adapter.parse_request(request_payload(stream=False))
    with pytest.raises(OpenAIResponsesAdapterError, match="stream=true"):
        adapter.stream_decoder(non_streaming)

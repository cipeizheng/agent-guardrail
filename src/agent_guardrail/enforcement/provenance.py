"""Conservative structural provenance inference for canonical inline events."""

from __future__ import annotations

import json

from pydantic import JsonValue

from agent_guardrail.models import (
    ChatRole,
    EventKind,
    ModelRequest,
    ModelResponse,
    Phase,
    ToolCall,
    ToolResult,
    Trace,
)


def infer_source_event_ids(
    *,
    trace: Trace,
    kind: EventKind,
    payload: dict[str, JsonValue],
) -> tuple[str, ...]:
    """Infer exact relations for the single-event Inline compatibility path."""

    if kind is EventKind.MODEL_REQUEST:
        request = ModelRequest.model_validate(payload)
        return _tool_result_sources(trace, request)
    if kind is EventKind.TOOL_CALL:
        call = ToolCall.model_validate(payload)
        return _proposed_tool_call_source(trace, call)
    return ()


def _tool_result_sources(trace: Trace, request: ModelRequest) -> tuple[str, ...]:
    tool_messages = tuple(
        message
        for message in request.messages
        if message.role is ChatRole.TOOL
        and message.tool_call_id is not None
        and message.content is not None
    )
    if not tool_messages:
        return ()

    result_events = trace.find(kind=EventKind.TOOL_RESULT)
    used_event_ids: set[str] = set()
    source_event_ids: list[str] = []
    for message in tool_messages:
        for event in reversed(result_events):
            if event.id in used_event_ids:
                continue
            result = ToolResult.model_validate(event.payload)
            if (
                result.call_id == message.tool_call_id
                and _output_text(result.output) == message.content
            ):
                used_event_ids.add(event.id)
                source_event_ids.append(event.id)
                break
    return tuple(source_event_ids)


def _proposed_tool_call_source(trace: Trace, call: ToolCall) -> tuple[str, ...]:
    for event in reversed(trace.find(kind=EventKind.TOOL_CALL, phase=Phase.POST_LLM)):
        if ToolCall.model_validate(event.payload) == call:
            return (event.id,)
    for event in reversed(trace.find(kind=EventKind.MODEL_RESPONSE)):
        response = ModelResponse.model_validate(event.payload)
        if call in response.tool_calls:
            return (event.id,)
    return ()


def _output_text(output: JsonValue) -> str:
    if isinstance(output, str):
        return output
    return json.dumps(output, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

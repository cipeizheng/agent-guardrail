from __future__ import annotations

import pytest

from agent_guardrail.enforcement import InputNormalizationError, InputNormalizer
from agent_guardrail.models import (
    CandidateEvent,
    ChatMessage,
    ChatRole,
    EventKind,
    EventOrigin,
    ModelRequest,
    ModelResponse,
    ToolCall,
)


def call(call_id: str, *, name: str = "lookup") -> ToolCall:
    return ToolCall(call_id=call_id, name=name, arguments={"query": "safe"})


def tool_message(call_id: str, content: str = "result") -> ChatMessage:
    return ChatMessage(
        role=ChatRole.TOOL,
        content=content,
        tool_call_id=call_id,
    )


def test_request_snapshot_expands_text_and_turn_local_tool_exchange() -> None:
    request = ModelRequest(
        messages=(
            ChatMessage(role=ChatRole.SYSTEM, content="system"),
            ChatMessage(role=ChatRole.USER, content="question"),
            ChatMessage(
                role=ChatRole.ASSISTANT,
                content="checking",
                tool_calls=(call("call-a", name="search"), call("call-b", name="lookup")),
            ),
            tool_message("call-b", "result-b"),
            tool_message("call-a", "result-a"),
            ChatMessage(role=ChatRole.USER, content="continue"),
        )
    )
    snapshot = request.model_dump(mode="json")

    batch = InputNormalizer().normalize_model_call(request)

    assert [candidate.kind for candidate in batch.candidates] == [
        EventKind.MESSAGE,
        EventKind.MESSAGE,
        EventKind.MESSAGE,
        EventKind.TOOL_CALL_PROPOSAL,
        EventKind.TOOL_CALL_PROPOSAL,
        EventKind.TOOL_RESULT,
        EventKind.TOOL_RESULT,
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
    ]
    assert all(
        candidate.origin is EventOrigin.CLIENT_ASSERTED for candidate in batch.candidates[:-1]
    )
    assert batch.candidates[-1].origin is EventOrigin.OBSERVED
    assert batch.primary_key == batch.candidates[-1].key

    first_result = batch.candidates[5]
    second_result = batch.candidates[6]
    assert first_result.payload == {
        "call_id": "call-b",
        "name": "lookup",
        "output": "result-b",
    }
    assert first_result.relations[0].source_candidate_key == batch.candidates[4].key
    assert second_result.payload["name"] == "search"
    assert second_result.relations[0].source_candidate_key == batch.candidates[3].key
    assert request.model_dump(mode="json") == snapshot


def test_request_snapshot_does_not_deduplicate_equal_messages() -> None:
    request = ModelRequest(
        messages=(
            ChatMessage(role=ChatRole.USER, content="same"),
            ChatMessage(role=ChatRole.USER, content="same"),
        )
    )

    batch = InputNormalizer().normalize_model_call(request)

    assert len(batch.candidates) == 3
    assert batch.candidates[0].key != batch.candidates[1].key
    assert batch.candidates[0].payload == batch.candidates[1].payload


def test_request_snapshot_allows_call_id_reuse_in_later_turn() -> None:
    request = ModelRequest(
        messages=(
            ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("reused"),)),
            tool_message("reused", "first"),
            ChatMessage(role=ChatRole.USER, content="next"),
            ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("reused"),)),
            tool_message("reused", "second"),
            ChatMessage(role=ChatRole.USER, content="done"),
        )
    )

    batch = InputNormalizer().normalize_model_call(request)
    tool_calls = tuple(
        candidate
        for candidate in batch.candidates
        if candidate.kind is EventKind.TOOL_CALL_PROPOSAL
    )
    tool_results = tuple(
        candidate for candidate in batch.candidates if candidate.kind is EventKind.TOOL_RESULT
    )

    assert len(tool_calls) == len(tool_results) == 2
    assert tool_calls[0].key != tool_calls[1].key
    assert tool_results[0].relations[0].source_candidate_key == tool_calls[0].key
    assert tool_results[1].relations[0].source_candidate_key == tool_calls[1].key


@pytest.mark.parametrize(
    ("messages", "error_code"),
    [
        ((tool_message("orphan"),), "orphan_tool_result"),
        (
            (
                ChatMessage(
                    role=ChatRole.ASSISTANT,
                    tool_calls=(call("duplicate"), call("duplicate")),
                ),
            ),
            "duplicate_tool_call_id",
        ),
        (
            (
                ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("call-1"),)),
                tool_message("call-1"),
                tool_message("call-1"),
            ),
            "duplicate_tool_result",
        ),
        (
            (ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("missing"),)),),
            "incomplete_tool_call_group",
        ),
        (
            (
                ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("missing"),)),
                ChatMessage(role=ChatRole.USER, content="interrupted"),
            ),
            "incomplete_tool_call_group",
        ),
        (
            (
                ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("old"),)),
                tool_message("old"),
                ChatMessage(role=ChatRole.USER, content="new turn"),
                tool_message("old"),
            ),
            "orphan_tool_result",
        ),
    ],
)
def test_request_snapshot_rejects_malformed_tool_turns(
    messages: tuple[ChatMessage, ...],
    error_code: str,
) -> None:
    request = ModelRequest(messages=messages)

    with pytest.raises(InputNormalizationError) as error:
        InputNormalizer().normalize_model_call(request)

    assert error.value.code == error_code


def test_normalization_error_does_not_include_provider_identifiers() -> None:
    sensitive_call_id = "provider-call-private-value"
    request = ModelRequest(
        messages=(
            ChatMessage(
                role=ChatRole.ASSISTANT,
                tool_calls=(call(sensitive_call_id), call(sensitive_call_id)),
            ),
        )
    )

    with pytest.raises(InputNormalizationError) as error:
        InputNormalizer().normalize_model_call(request)

    assert sensitive_call_id not in str(error.value)


def test_response_expands_observed_message_and_tool_calls() -> None:
    response = ModelResponse(
        content="answer",
        tool_calls=(call("call-a"), call("call-b")),
    )
    snapshot = response.model_dump(mode="json")

    batch = InputNormalizer().normalize_model_output(
        response,
        model_call_event_id="model-call",
    )

    assert [candidate.kind for candidate in batch.candidates] == [
        EventKind.MESSAGE,
        EventKind.TOOL_CALL_PROPOSAL,
        EventKind.TOOL_CALL_PROPOSAL,
    ]
    assert all(candidate.origin is EventOrigin.OBSERVED for candidate in batch.candidates)
    assert all(
        candidate.relations[0].source_event_id == "model-call"
        for candidate in batch.candidates
    )
    assert batch.candidates[0].payload == {
        "role": "assistant",
        "content": {"type": "text", "text": "answer"},
    }
    assert batch.primary_key == "response-tool-call-1"
    assert response.model_dump(mode="json") == snapshot


def test_tool_only_response_does_not_create_empty_message() -> None:
    response = ModelResponse(tool_calls=(call("call-a"),))

    batch = InputNormalizer().normalize_model_output(
        response,
        model_call_event_id="model-call",
    )

    assert len(batch.candidates) == 1
    assert batch.candidates[0].kind is EventKind.TOOL_CALL_PROPOSAL


def test_normalizer_revalidates_canonical_inputs() -> None:
    valid = ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content="hello"),))
    invalid = valid.model_copy(update={"messages": ()})

    with pytest.raises(InputNormalizationError) as error:
        InputNormalizer().normalize_model_call(invalid)

    assert error.value.code == "invalid_canonical_input"


def test_normalizer_enforces_candidate_and_relation_limits() -> None:
    request = ModelRequest(
        messages=(
            ChatMessage(role=ChatRole.USER, content="first"),
            ChatMessage(role=ChatRole.USER, content="second"),
        )
    )
    with pytest.raises(InputNormalizationError) as candidate_error:
        InputNormalizer(max_candidates=1).normalize_model_call(request)
    assert candidate_error.value.code == "candidate_limit_exceeded"

    tool_exchange = ModelRequest(
        messages=(
            ChatMessage(role=ChatRole.ASSISTANT, tool_calls=(call("call-1"),)),
            tool_message("call-1"),
        )
    )
    with pytest.raises(InputNormalizationError) as relation_error:
        InputNormalizer(max_relations_per_event=0).normalize_model_call(tool_exchange)
    assert relation_error.value.code == "relation_limit_exceeded"

    with pytest.raises(ValueError, match="max_candidates"):
        InputNormalizer(max_candidates=0)
    with pytest.raises(ValueError, match="max_relations_per_event"):
        InputNormalizer(max_relations_per_event=-1)


def test_normalized_batch_contains_only_candidate_events() -> None:
    request = ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content="hello"),))

    batch = InputNormalizer().normalize_model_call(request)

    assert all(isinstance(candidate, CandidateEvent) for candidate in batch.candidates)

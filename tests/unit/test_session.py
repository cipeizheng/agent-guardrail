from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import JsonValue

from agent_guardrail.enforcement import EnforcementSession, GuardrailUnavailable
from agent_guardrail.models import (
    MAX_PENDING_EVENTS,
    MAX_RELATIONS_PER_EVENT,
    Action,
    CandidateEvent,
    CandidateRelation,
    ChatMessage,
    ChatRole,
    Decision,
    Event,
    EventKind,
    EventOrigin,
    FlowAuthorization,
    FlowSecurityContext,
    Message,
    MessageRole,
    ModelRequest,
    ModelResponse,
    PendingTrace,
    Phase,
    SecurityDestination,
    SecurityFactAuthorities,
    SecurityFactAuthority,
    TextContent,
    ToolCall,
    ToolResult,
    Trace,
)
from tests.support import FAKE_SECRET, empty_analyzer, secret_analyzer


def request_payload(content: str = "hello") -> dict[str, JsonValue]:
    request = ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content=content),))
    return cast(dict[str, JsonValue], request.model_dump(mode="json"))


def tool_call_payload() -> dict[str, JsonValue]:
    call = ToolCall(call_id="call-1", name="read_file", arguments={"path": "report"})
    return cast(dict[str, JsonValue], call.model_dump(mode="json"))


def tool_result_payload() -> dict[str, JsonValue]:
    result = ToolResult(call_id="call-1", name="read_file", output="report")
    return cast(dict[str, JsonValue], result.model_dump(mode="json"))


def message_payload(
    *,
    role: MessageRole = MessageRole.USER,
    text: str = "hello",
) -> dict[str, JsonValue]:
    message = Message(role=role, content=TextContent(text=text))
    return cast(dict[str, JsonValue], message.model_dump(mode="json"))


class BrokenAnalyzer:
    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        del pending
        raise RuntimeError("raw provider data must not enter the wrapper error")


class WrongDecisionAnalyzer:
    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        return Decision(
            action=Action.ALLOW,
            trace_id=pending.trace.id,
            event_id="wrong-event",
            pending_event_ids=("wrong-event",),
            phase=pending.primary_event.phase,
            policy_version=1,
            policy_hash="wrong-policy",
        )


class MutatingAnalyzer:
    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        pending.events[0].metadata["changed"] = True
        return Decision(
            action=Action.ALLOW,
            trace_id=pending.trace.id,
            event_id=pending.primary_event_id,
            pending_event_ids=pending.event_ids,
            phase=pending.primary_event.phase,
            policy_version=1,
            policy_hash="mutating-policy",
        )


class CapturingAnalyzer:
    def __init__(self) -> None:
        self.pending: list[PendingTrace] = []

    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        self.pending.append(pending.model_copy(deep=True))
        return Decision(
            action=Action.ALLOW,
            trace_id=pending.trace.id,
            event_id=pending.primary_event_id,
            pending_event_ids=pending.event_ids,
            phase=pending.primary_event.phase,
            policy_version=3,
            policy_hash="security-context-test",
        )


@pytest.mark.asyncio
async def test_session_rejects_invalid_kind_phase_mapping() -> None:
    session = EnforcementSession(analyzer=empty_analyzer(), trace=Trace(id="trace-1"))

    with pytest.raises(ValueError, match="invalid enforcement boundary"):
        await session.evaluate(
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.PRE_LLM,
            payload=request_payload(),
        )


@pytest.mark.asyncio
async def test_session_snapshots_trusted_context_and_allows_per_flow_override() -> None:
    analyzer = CapturingAnalyzer()
    base_context = FlowSecurityContext(
        destination=SecurityDestination.LLM_PROVIDER,
        authorization=FlowAuthorization.ALLOWED,
        authorities=SecurityFactAuthorities(
            destination=SecurityFactAuthority.ENFORCEMENT,
            authorization=SecurityFactAuthority.AUTHORIZATION_SERVICE
        ),
    )
    session = EnforcementSession(
        analyzer=analyzer,
        trace=Trace(id="trace-1"),
        attributes={"security_authorization": "denied"},
        security_context=base_context,
    )

    await session.evaluate(
        kind=EventKind.MODEL_REQUEST,
        phase=Phase.PRE_LLM,
        payload=request_payload(),
        security_context=session.security_context.with_enforcement_destination(
            SecurityDestination.LLM_PROVIDER
        ),
    )

    captured = analyzer.pending[0]
    assert captured.security_context.authorization is FlowAuthorization.ALLOWED
    assert captured.security_context.destination is SecurityDestination.LLM_PROVIDER
    assert (
        captured.security_context.authorities.destination
        is SecurityFactAuthority.ENFORCEMENT
    )
    assert captured.attributes == {"security_authorization": "denied"}
    assert session.security_context.destination is SecurityDestination.LLM_PROVIDER


def test_session_rejects_untyped_security_context() -> None:
    with pytest.raises(TypeError, match="FlowSecurityContext"):
        EnforcementSession(
            analyzer=empty_analyzer(),
            trace=Trace(id="trace-1"),
            security_context=cast(FlowSecurityContext, {"authorization": "allowed"}),
        )


@pytest.mark.asyncio
async def test_session_commits_only_valid_trusted_source_event_ids() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    call_decision = await session.evaluate(
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=tool_call_payload(),
    )

    await session.evaluate(
        kind=EventKind.TOOL_RESULT,
        phase=Phase.POST_TOOL,
        payload=tool_result_payload(),
        source_event_ids=(call_decision.event_id,),
    )

    assert trace.events[-1].source_event_ids == (call_decision.event_id,)
    assert trace.sources_of(trace.events[-1]) == (trace.events[0],)


@pytest.mark.asyncio
async def test_session_does_not_infer_relation_from_call_id_alone() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    call_decision = await session.evaluate(
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=tool_call_payload(),
    )
    await session.evaluate(
        kind=EventKind.TOOL_RESULT,
        phase=Phase.POST_TOOL,
        payload=tool_result_payload(),
        source_event_ids=(call_decision.event_id,),
    )
    mismatched_request = ModelRequest(
        messages=(
            ChatMessage(
                role=ChatRole.TOOL,
                content="different content",
                tool_call_id="call-1",
            ),
        )
    )

    await session.evaluate(
        kind=EventKind.MODEL_REQUEST,
        phase=Phase.PRE_LLM,
        payload=cast(
            dict[str, JsonValue],
            mismatched_request.model_dump(mode="json"),
        ),
    )

    assert not trace.events[-1].source_event_ids


@pytest.mark.asyncio
async def test_session_does_not_infer_relation_from_tool_call_id_alone() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    request_decision = await session.evaluate(
        kind=EventKind.MODEL_REQUEST,
        phase=Phase.PRE_LLM,
        payload=request_payload(),
    )
    response = ModelResponse(
        tool_calls=(ToolCall(call_id="call-1", name="read_file", arguments={"path": "a"}),)
    )
    await session.evaluate(
        kind=EventKind.MODEL_RESPONSE,
        phase=Phase.POST_LLM,
        payload=cast(dict[str, JsonValue], response.model_dump(mode="json")),
        source_event_ids=(request_decision.event_id,),
    )
    different_call = ToolCall(
        call_id="call-1",
        name="read_file",
        arguments={"path": "b"},
    )

    await session.evaluate(
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=cast(dict[str, JsonValue], different_call.model_dump(mode="json")),
    )

    assert not trace.events[-1].source_event_ids


@pytest.mark.asyncio
async def test_session_rejects_caller_supplied_reserved_provenance_metadata() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)

    with pytest.raises(ValueError, match="reserved"):
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload(),
            metadata={"source_event_ids": ["untrusted"]},
        )

    assert not trace.events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source_event_ids",
    [("missing",), ("",), (1,), ("same", "same"), "event-1"],
)
async def test_session_rejects_invalid_declared_sources(
    source_event_ids: object,
) -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)

    with pytest.raises(ValueError, match="source_event"):
        await session.evaluate(
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=cast(
                dict[str, JsonValue],
                ModelResponse(content="safe").model_dump(mode="json"),
            ),
            source_event_ids=source_event_ids,  # type: ignore[arg-type]
        )

    assert not trace.events


@pytest.mark.asyncio
async def test_session_rejects_guardrail_decision_as_a_source() -> None:
    decision_event = Event(
        id="decision-1",
        trace_id="trace-1",
        sequence=0,
        kind=EventKind.GUARDRAIL_DECISION,
        phase=Phase.PRE_LLM,
        timestamp=datetime(2026, 8, 5, tzinfo=UTC),
        payload={"sanitized": True},
    )
    trace = Trace(id="trace-1", events=(decision_event,))
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)

    with pytest.raises(ValueError, match="decision events"):
        await session.evaluate(
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=cast(
                dict[str, JsonValue],
                ModelResponse(content="safe").model_dump(mode="json"),
            ),
            source_event_ids=(decision_event.id,),
        )

    assert trace.events == (decision_event,)


@pytest.mark.asyncio
async def test_evaluator_failure_is_safe_and_commits_no_raw_event() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=BrokenAnalyzer(), trace=trace)

    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload("sensitive input"),
        )

    assert unavailable.value.error_type == "RuntimeError"
    assert "sensitive input" not in str(unavailable.value)
    assert not trace.events


@pytest.mark.asyncio
async def test_session_rejects_mismatched_decision_identity() -> None:
    session = EnforcementSession(analyzer=WrongDecisionAnalyzer(), trace=Trace(id="trace-1"))

    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload(),
        )

    assert unavailable.value.error_type == "invalid_decision_identity"
    assert not session.trace.events


@pytest.mark.asyncio
async def test_session_rejects_analyzer_mutation_of_pending_snapshot() -> None:
    session = EnforcementSession(analyzer=MutatingAnalyzer(), trace=Trace(id="trace-1"))

    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload("sensitive input"),
        )

    assert unavailable.value.error_type == "invalid_pending_snapshot"
    assert "sensitive input" not in str(unavailable.value)
    assert not session.trace.events


@pytest.mark.asyncio
async def test_trace_capacity_fails_closed_without_overwriting_history() -> None:
    trace = Trace(id="trace-1", max_events=1)
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)

    await session.evaluate(
        kind=EventKind.MODEL_REQUEST,
        phase=Phase.PRE_LLM,
        payload=request_payload("first"),
    )
    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload("second"),
        )

    assert unavailable.value.error_type == "trace_capacity_exceeded"
    assert len(trace.events) == 1
    assert trace.events[0].sequence == 0


@pytest.mark.asyncio
async def test_concurrent_session_checks_keep_strict_event_order() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)

    await asyncio.gather(
        *(
            session.evaluate(
                kind=EventKind.MODEL_REQUEST,
                phase=Phase.PRE_LLM,
                payload=request_payload(f"request-{index}"),
            )
            for index in range(20)
        )
    )

    assert [event.sequence for event in trace.events] == list(range(20))


@pytest.mark.asyncio
async def test_candidate_batch_is_analyzed_and_committed_atomically() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    candidates = (
        CandidateEvent(
            key="first-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_TOOL,
            payload=tool_call_payload(),
            origin=EventOrigin.OBSERVED,
        ),
        CandidateEvent(
            key="second-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_TOOL,
            payload=cast(
                dict[str, JsonValue],
                ToolCall(
                    call_id="call-2",
                    name="summarize",
                    arguments={"text": "safe"},
                ).model_dump(mode="json"),
            ),
            origin=EventOrigin.DERIVED,
            relations=(CandidateRelation(source_candidate_key="first-call"),),
        ),
    )

    decision = await session.evaluate_candidates(candidates, primary_key="second-call")

    assert decision.pending_event_ids == tuple(event.id for event in trace.events)
    assert decision.event_id == trace.events[1].id
    assert [event.sequence for event in trace.events] == [0, 1]
    assert [event.origin for event in trace.events] == [
        EventOrigin.OBSERVED,
        EventOrigin.DERIVED,
    ]
    assert trace.sources_of(trace.events[1]) == (trace.events[0],)


@pytest.mark.asyncio
async def test_session_preserves_single_aggregate_response_compatibility() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    call = ToolCall(call_id="call-1", name="read_file", arguments={"path": "report"})
    response = ModelResponse(tool_calls=(call,))
    candidate = CandidateEvent(
        key="response",
        kind=EventKind.MODEL_RESPONSE,
        phase=Phase.POST_LLM,
        payload=cast(dict[str, JsonValue], response.model_dump(mode="json")),
        origin=EventOrigin.OBSERVED,
    )

    decision = await session.evaluate_candidates((candidate,))

    assert decision.pending_event_ids == (trace.events[0].id,)
    assert trace.events[0].kind is EventKind.MODEL_RESPONSE


@pytest.mark.asyncio
async def test_session_rejects_mixed_aggregate_and_independent_batch() -> None:
    trace = Trace(id="trace-1")
    allocated_ids: list[str] = []

    def id_factory() -> str:
        allocated_ids.append("allocated")
        return "unexpected-event-id"

    session = EnforcementSession(
        analyzer=BrokenAnalyzer(),
        trace=trace,
        id_factory=id_factory,
    )
    call = ToolCall(call_id="call-1", name="read_file", arguments={"path": "report"})
    response = ModelResponse(tool_calls=(call,))
    candidates = (
        CandidateEvent(
            key="response",
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=cast(dict[str, JsonValue], response.model_dump(mode="json")),
            origin=EventOrigin.OBSERVED,
        ),
        CandidateEvent(
            key="tool-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.POST_LLM,
            payload=cast(dict[str, JsonValue], call.model_dump(mode="json")),
            origin=EventOrigin.DERIVED,
            relations=(CandidateRelation(source_candidate_key="response"),),
        ),
    )

    with pytest.raises(ValueError, match="single-candidate compatibility"):
        await session.evaluate_candidates(candidates, primary_key="response")

    assert not trace.events
    assert not allocated_ids


@pytest.mark.asyncio
async def test_session_rejects_multiple_aggregate_model_events() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=BrokenAnalyzer(), trace=trace)
    response_payload = cast(
        dict[str, JsonValue],
        ModelResponse(content="safe").model_dump(mode="json"),
    )
    candidates = (
        CandidateEvent(
            key="first-response",
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=response_payload,
            origin=EventOrigin.OBSERVED,
        ),
        CandidateEvent(
            key="second-response",
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=response_payload,
            origin=EventOrigin.OBSERVED,
        ),
    )

    with pytest.raises(ValueError, match="single-candidate compatibility"):
        await session.evaluate_candidates(candidates)

    assert not trace.events


@pytest.mark.asyncio
async def test_session_commits_independent_pre_llm_event_batch() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    candidates = (
        CandidateEvent(
            key="user-message",
            kind=EventKind.MESSAGE,
            phase=Phase.PRE_LLM,
            payload=message_payload(),
        ),
        CandidateEvent(
            key="tool-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_LLM,
            payload=tool_call_payload(),
        ),
        CandidateEvent(
            key="tool-result",
            kind=EventKind.TOOL_RESULT,
            phase=Phase.PRE_LLM,
            payload=tool_result_payload(),
            relations=(CandidateRelation(source_candidate_key="tool-call"),),
        ),
    )

    decision = await session.evaluate_candidates(candidates)

    assert decision.pending_event_ids == tuple(event.id for event in trace.events)
    assert [event.kind for event in trace.events] == [
        EventKind.MESSAGE,
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
    ]
    assert all(event.origin is EventOrigin.CLIENT_ASSERTED for event in trace.events)
    assert trace.sources_of(trace.events[-1]) == (trace.events[1],)


@pytest.mark.asyncio
async def test_session_commits_independent_post_llm_event_batch() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    candidates = (
        CandidateEvent(
            key="assistant-message",
            kind=EventKind.MESSAGE,
            phase=Phase.POST_LLM,
            payload=message_payload(role=MessageRole.ASSISTANT),
            origin=EventOrigin.OBSERVED,
        ),
        CandidateEvent(
            key="tool-call",
            kind=EventKind.TOOL_CALL,
            phase=Phase.POST_LLM,
            payload=tool_call_payload(),
            origin=EventOrigin.OBSERVED,
        ),
    )

    await session.evaluate_candidates(candidates, primary_key="assistant-message")

    assert [event.kind for event in trace.events] == [EventKind.MESSAGE, EventKind.TOOL_CALL]
    assert all(event.origin is EventOrigin.OBSERVED for event in trace.events)


@pytest.mark.asyncio
async def test_session_rejects_independent_event_at_invalid_phase() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    candidate = CandidateEvent(
        key="message",
        kind=EventKind.MESSAGE,
        phase=Phase.PRE_TOOL,
        payload=message_payload(),
    )

    with pytest.raises(ValueError, match="invalid candidate enforcement phase"):
        await session.evaluate_candidates((candidate,))

    assert not trace.events


@pytest.mark.asyncio
async def test_session_rechecks_candidate_batch_and_relation_limits() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    oversized_batch = tuple(
        CandidateEvent(
            key=f"message-{index}",
            kind=EventKind.MESSAGE,
            phase=Phase.PRE_LLM,
            payload=message_payload(text=str(index)),
        )
        for index in range(MAX_PENDING_EVENTS + 1)
    )

    with pytest.raises(ValueError, match="candidate batch cannot exceed"):
        await session.evaluate_candidates(oversized_batch)

    valid = CandidateEvent(
        key="message",
        kind=EventKind.MESSAGE,
        phase=Phase.PRE_LLM,
        payload=message_payload(),
    )
    oversized_relations = valid.model_copy(
        update={
            "relations": tuple(
                CandidateRelation(source_candidate_key=f"source-{index}")
                for index in range(MAX_RELATIONS_PER_EVENT + 1)
            )
        }
    )
    with pytest.raises(ValueError, match="candidate relations cannot exceed"):
        await session.evaluate_candidates((oversized_relations,))

    assert not trace.events


@pytest.mark.asyncio
async def test_blocked_candidate_batch_commits_no_raw_pending_event() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=secret_analyzer(), trace=trace)
    safe = CandidateEvent(
        key="safe",
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=cast(
            dict[str, JsonValue],
            ToolCall(
                call_id="call-safe",
                name="send_email",
                arguments={"body": "public report"},
            ).model_dump(mode="json"),
        ),
        origin=EventOrigin.OBSERVED,
    )
    sensitive = CandidateEvent(
        key="sensitive",
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=cast(
            dict[str, JsonValue],
            ToolCall(
                call_id="call-sensitive",
                name="send_email",
                arguments={"body": FAKE_SECRET},
            ).model_dump(mode="json"),
        ),
        origin=EventOrigin.OBSERVED,
    )

    decision = await session.evaluate_candidates((safe, sensitive))

    assert decision.blocked
    assert len(decision.pending_event_ids) == 2
    assert decision.violations[0].event_ids == (decision.event_id,)
    assert len(trace.events) == 1
    assert trace.events[0].kind is EventKind.GUARDRAIL_DECISION
    assert trace.events[0].origin is EventOrigin.DERIVED
    assert FAKE_SECRET not in trace.events[0].model_dump_json()


@pytest.mark.asyncio
async def test_candidate_batch_rejects_future_relation_without_analysis() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    future_reference = CandidateEvent(
        key="first",
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=tool_call_payload(),
        relations=(CandidateRelation(source_candidate_key="second"),),
    )
    later = CandidateEvent(
        key="second",
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        payload=cast(
            dict[str, JsonValue],
            ToolCall(call_id="call-2", name="read_file").model_dump(mode="json"),
        ),
    )

    with pytest.raises(ValueError, match="earlier candidates"):
        await session.evaluate_candidates((future_reference, later))

    assert not trace.events


@pytest.mark.asyncio
async def test_candidate_batch_capacity_fails_before_analyzer_or_commit() -> None:
    trace = Trace(id="trace-1", max_events=1)
    session = EnforcementSession(analyzer=empty_analyzer(), trace=trace)
    candidates = (
        CandidateEvent(
            key="first",
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_TOOL,
            payload=tool_call_payload(),
        ),
        CandidateEvent(
            key="second",
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_TOOL,
            payload=cast(
                dict[str, JsonValue],
                ToolCall(call_id="call-2", name="read_file").model_dump(mode="json"),
            ),
        ),
    )

    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate_candidates(candidates)

    assert unavailable.value.error_type == "trace_capacity_exceeded"
    assert not trace.events

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import ValidationError

from agent_guardrail.models import (
    MAX_RELATIONS_PER_EVENT,
    MAX_TRACE_EVENTS,
    Action,
    CandidateEvent,
    CandidateRelation,
    ContentTrustClass,
    DataSensitivity,
    Decision,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    FlowAuthorization,
    FlowSecurityContext,
    Message,
    MessageRole,
    PendingTrace,
    RelationKind,
    SecurityDestination,
    SecurityFactAuthorities,
    SecurityFactAuthority,
    TextContent,
    Trace,
    Violation,
)


def event(*, sequence: int, trace_id: str = "trace-1") -> Event:
    return Event(
        id=f"event-{sequence}",
        trace_id=trace_id,
        sequence=sequence,
        kind=EventKind.TOOL_CALL,
        timestamp=datetime(2026, 8, 4, tzinfo=UTC),
        payload={"call_id": f"call-{sequence}", "name": "safe", "arguments": {}},
    )


def test_trace_preserves_order_and_queries_history() -> None:
    trace = Trace(id="trace-1", max_events=2)
    trace.append(event(sequence=0))
    trace.append(event(sequence=1))

    assert trace.next_sequence == 2
    assert trace.previous() == trace.events[-1]
    assert trace.count(kind=EventKind.TOOL_CALL) == 2
    assert trace.events[0].origin is EventOrigin.CLIENT_ASSERTED


def test_trace_queries_direct_and_transitive_event_relationships() -> None:
    root = event(sequence=0)
    child = event(sequence=1).model_copy(
        update={
            "relations": (EventRelation(source_event_id=root.id),),
        }
    )
    grandchild = event(sequence=2).model_copy(
        update={
            "relations": (EventRelation(source_event_id=child.id),),
        }
    )
    trace = Trace(id="trace-1", events=(root, child, grandchild))

    assert trace.by_id(child.id) == child
    assert trace.by_id("missing") is None
    assert trace.find(source_event_id=root.id) == (child,)
    assert trace.sources_of(grandchild) == (child,)
    assert trace.ancestors_of(grandchild) == (root, child)
    assert trace.events_since(root.id) == (child, grandchild)
    assert trace.events_since(child.id, inclusive=True) == (child, grandchild)
    assert child.model_dump(mode="json")["relations"] == [
        {"source_event_id": root.id, "kind": RelationKind.DERIVED_FROM.value}
    ]


@pytest.mark.parametrize(
    "source_event_id",
    [None, "", " event-0", "event-0 "],
)
def test_event_relation_rejects_invalid_source_event_id(source_event_id: object) -> None:
    with pytest.raises(ValidationError, match="source_event_id"):
        EventRelation(source_event_id=source_event_id)  # type: ignore[arg-type]


def test_event_rejects_duplicate_relations_and_legacy_metadata() -> None:
    relation = EventRelation(source_event_id="event-0")
    with pytest.raises(ValidationError, match="relations must be unique"):
        Event(
            **event(sequence=1).model_dump(exclude={"relations"}),
            relations=(relation, relation),
        )

    with pytest.raises(ValidationError, match="typed relations"):
        Event(
            **event(sequence=1).model_dump(exclude={"metadata"}),
            metadata={"source_event_ids": ["event-0"]},
        )


def test_trace_rejects_missing_or_forward_source_events() -> None:
    child = event(sequence=0).model_copy(
        update={
            "relations": (EventRelation(source_event_id="event-1"),),
        }
    )

    with pytest.raises(ValidationError, match="earlier events"):
        Trace(id="trace-1", events=(child, event(sequence=1)))

    trace = Trace(id="trace-1")
    with pytest.raises(ValueError, match="earlier events"):
        trace.append(child)


def test_event_cannot_cite_itself_as_a_source() -> None:
    with pytest.raises(ValidationError, match="cite itself"):
        Event(
            **event(sequence=0).model_dump(exclude={"relations"}),
            relations=(EventRelation(source_event_id="event-0"),),
        )


def test_trace_rejects_guardrail_decision_as_a_source() -> None:
    decision = event(sequence=0).model_copy(update={"kind": EventKind.GUARDRAIL_DECISION})
    derived = event(sequence=1).model_copy(
        update={
            "relations": (EventRelation(source_event_id=decision.id),),
        }
    )

    with pytest.raises(ValidationError, match="decision events"):
        Trace(id="trace-1", events=(decision, derived))


def test_trace_rejects_wrong_sequence_and_bounds() -> None:
    trace = Trace(id="trace-1", max_events=1)

    with pytest.raises(ValueError, match="sequence"):
        trace.append(event(sequence=1))

    trace.append(event(sequence=0))
    with pytest.raises(ValueError, match="max_events"):
        trace.append(event(sequence=1))


def test_closed_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Event.model_validate(
            {
                **event(sequence=0).model_dump(),
                "provider_specific_secret": "not accepted",
            }
        )


def test_tool_event_rejects_malformed_canonical_payload() -> None:
    with pytest.raises(ValidationError, match="call_id"):
        Event(
            id="event-1",
            trace_id="trace-1",
            sequence=0,
            kind=EventKind.TOOL_CALL,
            timestamp=datetime(2026, 8, 4, tzinfo=UTC),
            payload={"name": "send_email", "arguments": {}},
        )


def test_message_event_uses_closed_text_content_schema() -> None:
    message = Message(
        role=MessageRole.USER,
        content=TextContent(text="hello"),
    )
    message_event = Event(
        id="event-message",
        trace_id="trace-1",
        sequence=0,
        kind=EventKind.MESSAGE,
        timestamp=datetime(2026, 8, 4, tzinfo=UTC),
        payload=message.model_dump(mode="json"),
    )

    assert message_event.payload == {
        "role": MessageRole.USER.value,
        "content": {"type": "text", "text": "hello"},
    }
    assert TextContent(text="").text == ""

    with pytest.raises(ValidationError, match="system|user|assistant"):
        Message.model_validate(
            {"role": "tool", "content": {"type": "text", "text": "result"}}
        )
    with pytest.raises(ValidationError, match="text"):
        Message.model_validate(
            {"role": "user", "content": {"type": "image", "text": "unsupported"}}
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Message.model_validate(
            {
                "role": "assistant",
                "content": {"type": "text", "text": "hello"},
                "tool_calls": [],
            }
        )


def test_canonical_graph_limits_are_hard_bounded() -> None:
    with pytest.raises(ValidationError, match="less than or equal to"):
        Trace(id="trace-1", max_events=MAX_TRACE_EVENTS + 1)

    relations = tuple(
        CandidateRelation(source_candidate_key=f"source-{index}")
        for index in range(MAX_RELATIONS_PER_EVENT + 1)
    )
    with pytest.raises(ValidationError, match="at most 64 items"):
        CandidateEvent(
            key="target",
            kind=EventKind.MESSAGE,
            payload=Message(
                role=MessageRole.USER,
                content=TextContent(text="hello"),
            ).model_dump(mode="json"),
            relations=relations,
        )


def test_decision_requires_aggregated_action() -> None:
    violation = Violation(
        rule_id="rule-1",
        code="matched",
        message="matched",
        action=Action.BLOCK,
        event_ids=("event-1",),
    )

    with pytest.raises(ValidationError, match="aggregate"):
        Decision(
            action=Action.LOG,
            trace_id="trace-1",
            event_id="event-1",
            pending_event_ids=("event-1",),
            policy_version=1,
            policy_hash="12345678",
            violations=(violation,),
        )


def test_pending_trace_preserves_whole_pending_batch_identity() -> None:
    past = event(sequence=0)
    first = event(sequence=1).model_copy(update={"id": "pending-1"})
    second = event(sequence=2).model_copy(
        update={
            "id": "pending-2",
            "relations": (EventRelation(source_event_id=first.id),),
        }
    )
    pending = PendingTrace(
        trace=Trace(id="trace-1", events=(past,)),
        events=(first, second),
        primary_event_id=second.id,
    )

    assert pending.event_ids == (first.id, second.id)
    assert pending.primary_event == second
    combined = Trace(id="trace-1", events=(past, *pending.events))
    assert combined.sources_of(second) == (first,)


def test_pending_trace_rejects_sequence_gap() -> None:
    with pytest.raises(ValidationError, match="continue the committed trace"):
        PendingTrace(
            trace=Trace(id="trace-1"),
            events=(event(sequence=1),),
            primary_event_id="event-1",
        )


def test_candidate_relation_requires_one_explicit_source() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        CandidateRelation()
    with pytest.raises(ValidationError, match="exactly one"):
        CandidateRelation(source_event_id="event-1", source_candidate_key="candidate-1")

    candidate = CandidateEvent(
        key="candidate-1",
        kind=EventKind.TOOL_CALL,
        payload={"call_id": "call-1", "name": "safe", "arguments": {}},
    )
    assert candidate.origin is EventOrigin.CLIENT_ASSERTED


def test_flow_security_context_is_closed_typed_and_authority_bound() -> None:
    context = FlowSecurityContext(
        trust_class=ContentTrustClass.USER_CONTENT,
        sensitivity=DataSensitivity.PRIVATE,
        destination=SecurityDestination.LLM_PROVIDER,
        authorization=FlowAuthorization.ALLOWED,
        authorities=SecurityFactAuthorities(
            trust_class=SecurityFactAuthority.ENFORCEMENT,
            sensitivity=SecurityFactAuthority.DATA_SOURCE,
            destination=SecurityFactAuthority.ENFORCEMENT,
            authorization=SecurityFactAuthority.AUTHORIZATION_SERVICE,
        ),
    )

    boundary = context.with_enforcement_destination(SecurityDestination.LLM_PROVIDER)

    assert boundary.destination is SecurityDestination.LLM_PROVIDER
    assert boundary.authorities.destination is SecurityFactAuthority.ENFORCEMENT
    assert boundary.policy_parameters() == {
        "security_trust_class": "user_content",
        "security_sensitivity": "private",
        "security_destination": "llm_provider",
        "security_authorization": "allowed",
    }
    changed_sink = boundary.with_enforcement_destination(
        SecurityDestination.EXTERNAL_TOOL
    )
    assert changed_sink.authorization is FlowAuthorization.UNKNOWN
    assert (
        changed_sink.authorities.authorization is SecurityFactAuthority.UNKNOWN
    )
    with pytest.raises(ValueError, match="must be known"):
        boundary.with_enforcement_destination(SecurityDestination.UNKNOWN)
    with pytest.raises(TypeError, match="SecurityDestination"):
        boundary.with_enforcement_destination(
            cast(SecurityDestination, "llm_provider")
        )
    with pytest.raises(ValidationError, match="frozen"):
        boundary.authorization = FlowAuthorization.DENIED


@pytest.mark.parametrize(
    "legacy_field",
    ["owner_scope", "tenant_id", "principal_id"],
)
def test_flow_security_context_rejects_identity_and_ownership_fields(
    legacy_field: str,
) -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        FlowSecurityContext.model_validate({legacy_field: "legacy-value"})

    with pytest.raises(ValidationError, match="Extra inputs"):
        SecurityFactAuthorities.model_validate({legacy_field: "deployment"})


@pytest.mark.parametrize(
    "context, message",
    [
        (
            {"destination": "llm_provider"},
            "destination requires an explicit authority",
        ),
        (
            {
                "authorities": {"destination": "enforcement"},
            },
            "unknown destination cannot declare an authority",
        ),
        (
            {
                "authorization": "allowed",
                "destination": "llm_provider",
                "authorities": {
                    "authorization": "detector",
                    "destination": "enforcement",
                },
            },
            "authorization cannot use that authority",
        ),
        (
            {
                "authorization": "allowed",
                "authorities": {"authorization": "authorization_service"},
            },
            "authorization requires a known destination",
        ),
    ],
)
def test_flow_security_context_rejects_untrusted_fact_sources(
    context: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        FlowSecurityContext.model_validate(context)


def test_candidate_event_cannot_submit_a_security_context() -> None:
    payload = CandidateEvent(
        key="event",
        kind=EventKind.TOOL_CALL,
        payload={"call_id": "call-1", "name": "safe", "arguments": {}},
    ).model_dump(mode="json")
    payload["security_context"] = {"authorization": "allowed"}

    with pytest.raises(ValidationError, match="Extra inputs"):
        CandidateEvent.model_validate(payload)

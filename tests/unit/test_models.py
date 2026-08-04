from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agent_guardrail.models import (
    Action,
    Decision,
    Event,
    EventKind,
    Phase,
    Trace,
    Violation,
)


def event(*, sequence: int, trace_id: str = "trace-1") -> Event:
    return Event(
        id=f"event-{sequence}",
        trace_id=trace_id,
        sequence=sequence,
        kind=EventKind.USER_MESSAGE,
        phase=Phase.PRE_LLM,
        timestamp=datetime(2026, 8, 4, tzinfo=UTC),
        payload={"content": "hello"},
    )


def test_trace_preserves_order_and_queries_history() -> None:
    trace = Trace(id="trace-1", max_events=2)
    trace.append(event(sequence=0))
    trace.append(event(sequence=1))

    assert trace.next_sequence == 2
    assert trace.previous() == trace.events[-1]
    assert trace.count(kind=EventKind.USER_MESSAGE) == 2


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
            phase=Phase.PRE_TOOL,
            timestamp=datetime(2026, 8, 4, tzinfo=UTC),
            payload={"name": "send_email", "arguments": {}},
        )


def test_decision_requires_aggregated_action() -> None:
    violation = Violation(
        rule_id="rule-1",
        code="matched",
        phase=Phase.PRE_TOOL,
        message="matched",
        action=Action.BLOCK,
    )

    with pytest.raises(ValidationError, match="aggregate"):
        Decision(
            action=Action.LOG,
            trace_id="trace-1",
            event_id="event-1",
            phase=Phase.PRE_TOOL,
            policy_version=1,
            policy_hash="12345678",
            violations=(violation,),
        )

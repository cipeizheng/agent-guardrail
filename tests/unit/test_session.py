from __future__ import annotations

import asyncio
from typing import cast

import pytest
from pydantic import JsonValue

from agent_guardrail.core import DetectorRegistry, EngineConfig, GuardrailEngine, PolicySet
from agent_guardrail.enforcement import EnforcementSession, GuardrailUnavailable
from agent_guardrail.models import (
    Action,
    ChatMessage,
    ChatRole,
    Decision,
    EventKind,
    GuardrailContext,
    ModelRequest,
    Phase,
    Trace,
)


def empty_engine() -> GuardrailEngine:
    return GuardrailEngine(
        policy=PolicySet(
            version=1,
            content_hash="empty-policy",
            engine=EngineConfig(),
            rules=(),
        ),
        detectors=DetectorRegistry(),
    )


def request_payload(content: str = "hello") -> dict[str, JsonValue]:
    request = ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content=content),))
    return cast(dict[str, JsonValue], request.model_dump(mode="json"))


class BrokenEvaluator:
    async def evaluate(self, context: GuardrailContext) -> Decision:
        del context
        raise RuntimeError("raw provider data must not enter the wrapper error")


class WrongDecisionEvaluator:
    async def evaluate(self, context: GuardrailContext) -> Decision:
        return Decision(
            action=Action.ALLOW,
            trace_id=context.trace.id,
            event_id="wrong-event",
            phase=context.event.phase,
            policy_version=1,
            policy_hash="wrong-policy",
        )


@pytest.mark.asyncio
async def test_session_rejects_invalid_kind_phase_mapping() -> None:
    session = EnforcementSession(evaluator=empty_engine(), trace=Trace(id="trace-1"))

    with pytest.raises(ValueError, match="invalid enforcement boundary"):
        await session.evaluate(
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.PRE_LLM,
            payload=request_payload(),
        )


@pytest.mark.asyncio
async def test_evaluator_failure_is_safe_and_commits_no_raw_event() -> None:
    trace = Trace(id="trace-1")
    session = EnforcementSession(evaluator=BrokenEvaluator(), trace=trace)

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
    session = EnforcementSession(evaluator=WrongDecisionEvaluator(), trace=Trace(id="trace-1"))

    with pytest.raises(GuardrailUnavailable) as unavailable:
        await session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=request_payload(),
        )

    assert unavailable.value.error_type == "invalid_decision_identity"
    assert not session.trace.events


@pytest.mark.asyncio
async def test_trace_capacity_fails_closed_without_overwriting_history() -> None:
    trace = Trace(id="trace-1", max_events=1)
    session = EnforcementSession(evaluator=empty_engine(), trace=trace)

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
    session = EnforcementSession(evaluator=empty_engine(), trace=trace)

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

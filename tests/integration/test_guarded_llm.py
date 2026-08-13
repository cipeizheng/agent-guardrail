from __future__ import annotations

import pytest

from agent_guardrail.enforcement import (
    EnforcementSession,
    GuardedLLMClient,
    GuardrailBlocked,
    InMemoryAuditSink,
)
from agent_guardrail.models import (
    Action,
    ChatMessage,
    ChatRole,
    EventKind,
    EventOrigin,
    ModelRequest,
    ModelResponse,
    RelationKind,
    SecurityDestination,
    ToolCall,
    Trace,
)
from agent_guardrail.testing import ScriptedLLM
from tests.support import (
    FAKE_CN_MOBILE,
    FAKE_PII,
    FAKE_SECRET,
    analyzer_from_yaml,
    empty_analyzer,
    pii_analyzer,
    security_destination_analyzer,
    tool_access_analyzer,
)


def analyzer_for_kind(kind: EventKind, *, action: Action = Action.BLOCK):
    binding = "result" if kind is EventKind.TOOL_RESULT else "event"
    where_clause = (
        f"""    where:
      all:
        - {{present: [{binding}, payload]}}
        - compare:
            left: {{field: [{binding}, payload, role]}}
            operator: equals
            right: {{literal: assistant}}"""
        if kind is EventKind.MESSAGE
        else f"    where: {{present: [{binding}, payload]}}"
    )
    return analyzer_from_yaml(
        f"""\
version: 3
scopes: [pending]
rules:
  - id: block-{kind.value}
    action: {action.value}
    events:
      {binding}: {{kind: {kind.value}, domain: pending}}
{where_clause}
    finding:
      code: test_block
      message: The boundary is blocked for this deterministic test.
      subjects: [{binding}]
"""
    )


def request(content: str = "Hello") -> ModelRequest:
    return ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content=content),))


@pytest.mark.asyncio
async def test_allow_checks_both_sides_and_returns_response() -> None:
    inner = ScriptedLLM([ModelResponse(content="Safe response")])
    session = EnforcementSession(analyzer=empty_analyzer(), trace=Trace(id="trace-1"))
    guarded = GuardedLLMClient(inner=inner, session=session)

    response = await guarded.complete(request())

    assert response.content == "Safe response"
    assert inner.call_count == 1
    assert [event.kind for event in session.trace.events] == [
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
        EventKind.MESSAGE,
    ]
    assert session.trace.events[2].source_event_ids == (session.trace.events[1].id,)
    assert [event.origin for event in session.trace.events] == [
        EventOrigin.CLIENT_ASSERTED,
        EventOrigin.OBSERVED,
        EventOrigin.OBSERVED,
    ]
    assert session.trace.events[2].relations[0].kind is RelationKind.DERIVED_FROM
    assert "source_event_ids" not in session.trace.events[2].metadata


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "destination", "expected_provider_calls"),
    [
        (EventKind.MODEL_CALL, SecurityDestination.LLM_PROVIDER, 0),
        (EventKind.MESSAGE, SecurityDestination.AGENT_RUNTIME, 1),
    ],
)
async def test_inline_llm_injects_the_actual_flow_destination(
    kind: EventKind,
    destination: SecurityDestination,
    expected_provider_calls: int,
) -> None:
    inner = ScriptedLLM([ModelResponse(content="Safe response")])
    session = EnforcementSession(
        analyzer=security_destination_analyzer(
            destination=destination,
            kind=kind,
        ),
        trace=Trace(id="trace-1"),
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert blocked.value.decision.violations[0].code == "destination_seen"
    assert inner.call_count == expected_provider_calls


@pytest.mark.asyncio
async def test_pre_llm_block_never_calls_provider_or_keeps_raw_request() -> None:
    inner = ScriptedLLM([ModelResponse(content="must not be used")])
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=analyzer_for_kind(EventKind.MODEL_CALL),
        trace=trace,
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked):
        await guarded.complete(request(FAKE_SECRET))

    assert inner.call_count == 0
    assert [event.kind for event in trace.events] == [EventKind.GUARDRAIL_DECISION]
    assert FAKE_SECRET not in trace.model_dump_json()


@pytest.mark.asyncio
async def test_post_llm_block_hides_provider_response_from_agent_and_trace() -> None:
    inner = ScriptedLLM([ModelResponse(content=FAKE_SECRET)])
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=analyzer_for_kind(EventKind.MESSAGE),
        trace=trace,
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert inner.call_count == 1
    assert [event.kind for event in trace.events] == [
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
        EventKind.GUARDRAIL_DECISION,
    ]
    assert FAKE_SECRET not in trace.model_dump_json()
    assert FAKE_SECRET not in str(blocked.value)


@pytest.mark.asyncio
async def test_log_audits_response_and_still_returns_it() -> None:
    inner = ScriptedLLM([ModelResponse(content="Logged response")])
    audit = InMemoryAuditSink()
    session = EnforcementSession(
        analyzer=analyzer_for_kind(EventKind.MESSAGE, action=Action.LOG),
        trace=Trace(id="trace-1"),
        audit=audit,
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    response = await guarded.complete(request())

    assert response.content == "Logged response"
    assert inner.call_count == 1
    assert len(audit.records) == 1
    assert audit.records[0].action is Action.LOG


@pytest.mark.asyncio
async def test_tool_access_post_llm_block_hides_tool_call_from_agent() -> None:
    inner = ScriptedLLM(
        [
            ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="call-1",
                        name="send_email",
                        arguments={"body": "safe"},
                    ),
                )
            )
        ]
    )
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=tool_access_analyzer(kind=EventKind.TOOL_CALL_PROPOSAL),
        trace=trace,
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert inner.call_count == 1
    assert blocked.value.decision.violations[0].code == "tool_access_denied"
    assert [event.kind for event in trace.events] == [
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
        EventKind.GUARDRAIL_DECISION,
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("sensitive_value", [FAKE_PII, FAKE_CN_MOBILE])
async def test_pii_post_llm_block_hides_tool_call_from_agent_and_trace(
    sensitive_value: str,
) -> None:
    inner = ScriptedLLM(
        [
            ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="call-1",
                        name="send_email",
                        arguments={"body": sensitive_value},
                    ),
                )
            )
        ]
    )
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=pii_analyzer(kind=EventKind.TOOL_CALL_PROPOSAL),
        trace=trace,
    )
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert inner.call_count == 1
    assert blocked.value.decision.violations[0].code == "pii_exfiltration"
    assert sensitive_value not in blocked.value.decision.model_dump_json()
    assert sensitive_value not in trace.model_dump_json()
    assert [event.kind for event in trace.events] == [
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
        EventKind.GUARDRAIL_DECISION,
    ]

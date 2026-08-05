from __future__ import annotations

import pytest

from agent_guardrail.core import (
    DetectorRegistry,
    EngineConfig,
    GuardrailEngine,
    PolicySet,
    RuleBinding,
)
from agent_guardrail.core.services import RuleServices
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
    GuardrailContext,
    ModelRequest,
    ModelResponse,
    Phase,
    RelationKind,
    ToolCall,
    Trace,
    Violation,
)
from agent_guardrail.testing import ScriptedLLM
from tests.support import (
    FAKE_CN_MOBILE,
    FAKE_PII,
    FAKE_SECRET,
    pii_engine,
    tool_access_engine,
)


class MatchPhaseRule:
    def __init__(self, phase: Phase) -> None:
        self.id = f"block-{phase.value}"
        self.phases = frozenset({phase})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        return [
            Violation(
                rule_id=self.id,
                code="test_block",
                phase=context.event.phase,
                message="The boundary is blocked for this deterministic test.",
            )
        ]


def engine_for_phase(phase: Phase, *, action: Action = Action.BLOCK) -> GuardrailEngine:
    rule = MatchPhaseRule(phase)
    return GuardrailEngine(
        policy=PolicySet(
            version=1,
            content_hash=f"policy-{phase.value}",
            engine=EngineConfig(),
            rules=(RuleBinding(rule=rule, action=action),),
        ),
        detectors=DetectorRegistry(),
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


def request(content: str = "Hello") -> ModelRequest:
    return ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content=content),))


@pytest.mark.asyncio
async def test_allow_checks_both_sides_and_returns_response() -> None:
    inner = ScriptedLLM([ModelResponse(content="Safe response")])
    session = EnforcementSession(analyzer=empty_engine(), trace=Trace(id="trace-1"))
    guarded = GuardedLLMClient(inner=inner, session=session)

    response = await guarded.complete(request())

    assert response.content == "Safe response"
    assert inner.call_count == 1
    assert [event.kind for event in session.trace.events] == [
        EventKind.MODEL_REQUEST,
        EventKind.MODEL_RESPONSE,
    ]
    assert session.trace.events[1].source_event_ids == (session.trace.events[0].id,)
    assert [event.origin for event in session.trace.events] == [
        EventOrigin.CLIENT_ASSERTED,
        EventOrigin.OBSERVED,
    ]
    assert session.trace.events[1].relations[0].kind is RelationKind.DERIVED_FROM
    assert "source_event_ids" not in session.trace.events[1].metadata


@pytest.mark.asyncio
async def test_pre_llm_block_never_calls_provider_or_keeps_raw_request() -> None:
    inner = ScriptedLLM([ModelResponse(content="must not be used")])
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=engine_for_phase(Phase.PRE_LLM), trace=trace)
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request(FAKE_SECRET))

    assert blocked.value.decision.phase is Phase.PRE_LLM
    assert inner.call_count == 0
    assert [event.kind for event in trace.events] == [EventKind.GUARDRAIL_DECISION]
    assert FAKE_SECRET not in trace.model_dump_json()


@pytest.mark.asyncio
async def test_post_llm_block_hides_provider_response_from_agent_and_trace() -> None:
    inner = ScriptedLLM([ModelResponse(content=FAKE_SECRET)])
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=engine_for_phase(Phase.POST_LLM), trace=trace)
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert blocked.value.decision.phase is Phase.POST_LLM
    assert inner.call_count == 1
    assert [event.kind for event in trace.events] == [
        EventKind.MODEL_REQUEST,
        EventKind.GUARDRAIL_DECISION,
    ]
    assert FAKE_SECRET not in trace.model_dump_json()
    assert FAKE_SECRET not in str(blocked.value)


@pytest.mark.asyncio
async def test_log_audits_response_and_still_returns_it() -> None:
    inner = ScriptedLLM([ModelResponse(content="Logged response")])
    audit = InMemoryAuditSink()
    session = EnforcementSession(
        analyzer=engine_for_phase(Phase.POST_LLM, action=Action.LOG),
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
    session = EnforcementSession(analyzer=tool_access_engine(), trace=trace)
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert inner.call_count == 1
    assert blocked.value.decision.phase is Phase.POST_LLM
    assert blocked.value.decision.violations[0].code == "tool_access_denied"
    assert [event.kind for event in trace.events] == [
        EventKind.MODEL_REQUEST,
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
    session = EnforcementSession(analyzer=pii_engine(), trace=trace)
    guarded = GuardedLLMClient(inner=inner, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.complete(request())

    assert inner.call_count == 1
    assert blocked.value.decision.phase is Phase.POST_LLM
    assert blocked.value.decision.violations[0].code == "pii_exfiltration"
    assert sensitive_value not in blocked.value.decision.model_dump_json()
    assert sensitive_value not in trace.model_dump_json()
    assert [event.kind for event in trace.events] == [
        EventKind.MODEL_REQUEST,
        EventKind.GUARDRAIL_DECISION,
    ]

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
    GuardedToolExecutor,
    GuardrailBlocked,
    InMemoryAuditSink,
)
from agent_guardrail.models import (
    Action,
    EventKind,
    GuardrailContext,
    Phase,
    ToolCall,
    Trace,
    Violation,
)
from agent_guardrail.testing import FakeToolExecutor
from tests.support import FAKE_SECRET, secret_engine


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


def email_call(body: str) -> ToolCall:
    return ToolCall(
        call_id="call-1",
        name="send_email",
        arguments={"to": "outside@example.com", "body": body},
    )


@pytest.mark.asyncio
async def test_allow_executes_tool_exactly_once() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    session = EnforcementSession(evaluator=empty_engine(), trace=Trace(id="trace-1"))
    guarded = GuardedToolExecutor(inner=fake, session=session)

    result = await guarded.execute(email_call("safe body"))

    assert result.output == {"sent": True}
    assert fake.call_count("send_email") == 1
    assert [event.kind for event in session.trace.events] == [
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
    ]


@pytest.mark.asyncio
async def test_log_records_audit_and_executes_tool_once() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    audit = InMemoryAuditSink()
    session = EnforcementSession(
        evaluator=secret_engine(action="log"),
        trace=Trace(id="trace-1"),
        audit=audit,
    )
    guarded = GuardedToolExecutor(inner=fake, session=session)

    await guarded.execute(email_call(FAKE_SECRET))

    assert fake.call_count("send_email") == 1
    assert len(audit.records) == 1
    assert audit.records[0].action is Action.LOG
    assert FAKE_SECRET not in audit.records[0].model_dump_json()


class BrokenAuditSink:
    async def record(self, decision: object) -> None:
        del decision
        raise RuntimeError(FAKE_SECRET)


@pytest.mark.asyncio
async def test_audit_failure_is_safe_and_fail_open_for_log_action() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    session = EnforcementSession(
        evaluator=secret_engine(action="log"),
        trace=Trace(id="trace-1"),
        audit=BrokenAuditSink(),
    )
    guarded = GuardedToolExecutor(inner=fake, session=session)

    await guarded.execute(email_call(FAKE_SECRET))

    assert fake.call_count("send_email") == 1
    assert session.audit_failure_types == ["RuntimeError"]
    assert FAKE_SECRET not in str(session.audit_failure_types)


@pytest.mark.asyncio
async def test_block_prevents_tool_side_effect_and_leaks_no_secret() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    audit = InMemoryAuditSink()
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        evaluator=secret_engine(),
        trace=trace,
        audit=audit,
    )
    guarded = GuardedToolExecutor(inner=fake, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.execute(email_call(FAKE_SECRET))

    assert fake.call_count("send_email") == 0
    assert blocked.value.decision.action is Action.BLOCK
    assert FAKE_SECRET not in str(blocked.value)
    assert FAKE_SECRET not in blocked.value.decision.model_dump_json()
    assert len(audit.records) == 1
    assert [event.kind for event in trace.events] == [EventKind.GUARDRAIL_DECISION]
    assert FAKE_SECRET not in trace.model_dump_json()


class BlockToolResultRule:
    id = "block-tool-result"
    phases = frozenset({Phase.POST_TOOL})

    async def evaluate(
        self,
        context: GuardrailContext,
        services: RuleServices,
    ) -> list[Violation]:
        del services
        return [
            Violation(
                rule_id=self.id,
                code="blocked_result",
                phase=context.event.phase,
                message="Tool result is not safe for downstream use.",
            )
        ]


@pytest.mark.asyncio
async def test_post_tool_block_does_not_append_raw_result() -> None:
    engine = GuardrailEngine(
        policy=PolicySet(
            version=1,
            content_hash="post-tool-policy",
            engine=EngineConfig(),
            rules=(RuleBinding(rule=BlockToolResultRule(), action=Action.BLOCK),),
        ),
        detectors=DetectorRegistry(),
    )
    fake = FakeToolExecutor({"send_email": lambda arguments: FAKE_SECRET})
    trace = Trace(id="trace-1")
    session = EnforcementSession(evaluator=engine, trace=trace)
    guarded = GuardedToolExecutor(inner=fake, session=session)

    with pytest.raises(GuardrailBlocked):
        await guarded.execute(email_call("safe body"))

    assert fake.call_count() == 1
    assert trace.events[-1].kind is EventKind.GUARDRAIL_DECISION
    assert FAKE_SECRET not in trace.model_dump_json()

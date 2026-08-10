from __future__ import annotations

import pytest

from agent_guardrail.enforcement import (
    EnforcementSession,
    GuardedToolExecutor,
    GuardrailBlocked,
    InMemoryAuditSink,
)
from agent_guardrail.models import (
    Action,
    EventKind,
    EventOrigin,
    RelationKind,
    ToolCall,
    Trace,
)
from agent_guardrail.testing import FakeToolExecutor
from tests.support import (
    FAKE_CN_RESIDENT_ID,
    FAKE_PII,
    FAKE_SECRET,
    analyzer_from_yaml,
    empty_analyzer,
    pii_analyzer,
    secret_analyzer,
    tool_access_analyzer,
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
    session = EnforcementSession(analyzer=empty_analyzer(), trace=Trace(id="trace-1"))
    guarded = GuardedToolExecutor(inner=fake, session=session)

    result = await guarded.execute(email_call("safe body"))

    assert result.output == {"sent": True}
    assert fake.call_count("send_email") == 1
    assert [event.kind for event in session.trace.events] == [
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
    ]
    assert session.trace.events[1].source_event_ids == (session.trace.events[0].id,)
    assert [event.origin for event in session.trace.events] == [
        EventOrigin.OBSERVED,
        EventOrigin.OBSERVED,
    ]
    assert session.trace.events[1].relations[0].kind is RelationKind.DERIVED_FROM
    assert "source_event_ids" not in session.trace.events[1].metadata


@pytest.mark.asyncio
async def test_log_records_audit_and_executes_tool_once() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    audit = InMemoryAuditSink()
    session = EnforcementSession(
        analyzer=secret_analyzer(action="log"),
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
        analyzer=secret_analyzer(action="log"),
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
        analyzer=secret_analyzer(),
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


@pytest.mark.asyncio
async def test_tool_access_block_prevents_tool_side_effect() -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=tool_access_analyzer(mode="denylist", tools=("send_email",)),
        trace=trace,
    )
    guarded = GuardedToolExecutor(inner=fake, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.execute(email_call("safe body"))

    assert fake.call_count("send_email") == 0
    assert blocked.value.decision.violations[0].code == "tool_access_denied"
    assert [event.kind for event in trace.events] == [EventKind.GUARDRAIL_DECISION]


@pytest.mark.asyncio
@pytest.mark.parametrize("sensitive_value", [FAKE_PII, FAKE_CN_RESIDENT_ID])
async def test_pii_block_prevents_tool_side_effect_and_keeps_audit_safe(
    sensitive_value: str,
) -> None:
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    audit = InMemoryAuditSink()
    trace = Trace(id="trace-1")
    session = EnforcementSession(
        analyzer=pii_analyzer(),
        trace=trace,
        audit=audit,
    )
    guarded = GuardedToolExecutor(inner=fake, session=session)

    with pytest.raises(GuardrailBlocked) as blocked:
        await guarded.execute(email_call(sensitive_value))

    assert fake.call_count("send_email") == 0
    assert blocked.value.decision.violations[0].code == "pii_exfiltration"
    assert sensitive_value not in blocked.value.decision.model_dump_json()
    assert sensitive_value not in trace.model_dump_json()
    assert sensitive_value not in audit.records[0].model_dump_json()
    assert [event.kind for event in trace.events] == [EventKind.GUARDRAIL_DECISION]


@pytest.mark.asyncio
async def test_post_tool_block_does_not_append_raw_result() -> None:
    analyzer = analyzer_from_yaml(
        """\
version: 3
scopes: [pending]
rules:
  - id: block-tool-result
    action: block
    events:
      result: {kind: tool_result, domain: pending, phases: [post_tool]}
    where: {present: [result, payload]}
    finding:
      code: blocked_result
      message: Tool result is not safe for downstream use.
      subjects: [result]
"""
    )
    fake = FakeToolExecutor({"send_email": lambda arguments: FAKE_SECRET})
    trace = Trace(id="trace-1")
    session = EnforcementSession(analyzer=analyzer, trace=trace)
    guarded = GuardedToolExecutor(inner=fake, session=session)

    with pytest.raises(GuardrailBlocked):
        await guarded.execute(email_call("safe body"))

    assert fake.call_count() == 1
    assert trace.events[-1].kind is EventKind.GUARDRAIL_DECISION
    assert FAKE_SECRET not in trace.model_dump_json()

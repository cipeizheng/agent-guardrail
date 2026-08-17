from __future__ import annotations

import pytest

from agent_guardrail import EventRef, GuardrailRun
from agent_guardrail.models import (
    ContentTrustClass,
    EventKind,
    EventSecurityFacts,
    MessageRole,
    RelationKind,
    SecurityFactAuthority,
    ToolCall,
    ToolResult,
)
from tests.support import empty_analyzer


def tool_call() -> ToolCall:
    return ToolCall(
        call_id="call-1",
        name="read_file",
        arguments={"path": "report.txt"},
    )


@pytest.mark.asyncio
async def test_programmatic_sdk_builds_only_explicit_semantic_relations() -> None:
    run = GuardrailRun(analyzer=empty_analyzer(), run_id="run-1")
    user = (await run.message(role=MessageRole.USER, text="Read the report")).primary
    assert user is not None
    model = (await run.model_call(inputs=(user,))).primary
    assert model is not None
    proposal = (await run.tool_call_proposal(tool_call(), model_call=model)).primary
    assert proposal is not None
    actual = (await run.tool_call(tool_call(), proposal=proposal)).primary
    assert actual is not None
    result = (
        await run.tool_result(
            ToolResult(
                call_id="call-1",
                name="read_file",
                output="report",
            ),
            call=actual,
        )
    ).primary
    assert result is not None

    events = run.trace.events
    assert [event.kind for event in events] == [
        EventKind.MESSAGE,
        EventKind.MODEL_CALL,
        EventKind.TOOL_CALL_PROPOSAL,
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
    ]
    assert events[1].relations[0].kind is RelationKind.INFLUENCED_BY
    assert events[2].relations[0].kind is RelationKind.DERIVED_FROM
    assert events[3].relations[0].kind is RelationKind.INFLUENCED_BY
    assert events[4].relations[0].kind is RelationKind.DERIVED_FROM
    assert run.trace.sources_of(events[3]) == ()
    assert run.trace.sources_of(events[4]) == (events[3],)


@pytest.mark.asyncio
async def test_programmatic_sdk_binds_trust_to_the_exact_source_event() -> None:
    run = GuardrailRun(analyzer=empty_analyzer(), run_id="run-1")
    call = (await run.tool_call(tool_call())).primary
    assert call is not None
    facts = EventSecurityFacts(
        trust_class=ContentTrustClass.EXTERNAL_UNTRUSTED,
        trust_authority=SecurityFactAuthority.DATA_SOURCE,
    )
    source = (
        await run.tool_result(
            ToolResult(call_id="call-1", name="read_file", output="external text"),
            call=call,
            security_facts=facts,
        )
    ).primary
    assert source is not None
    target = (await run.model_call(inputs=(source,))).primary
    assert target is not None

    source_event, target_event = run.trace.events[1:]
    assert source_event.security_facts == facts
    assert target_event.security_facts == EventSecurityFacts()
    assert target_event.relations[0].source_event_id == source_event.id
    assert target_event.relations[0].kind is RelationKind.INFLUENCED_BY


@pytest.mark.asyncio
async def test_programmatic_sdk_rejects_cross_run_event_ref() -> None:
    first = GuardrailRun(analyzer=empty_analyzer(), run_id="run-1")
    second = GuardrailRun(analyzer=empty_analyzer(), run_id="run-2")
    message = (await first.message(role=MessageRole.USER, text="hello")).primary
    assert message is not None

    with pytest.raises(ValueError, match="another guardrail run"):
        await second.model_call(inputs=(message,))

    assert not second.trace.events


@pytest.mark.asyncio
async def test_programmatic_sdk_rejects_forged_or_wrong_kind_event_ref() -> None:
    run = GuardrailRun(analyzer=empty_analyzer(), run_id="run-1")
    message = (await run.message(role=MessageRole.USER, text="hello")).primary
    assert message is not None

    with pytest.raises(ValueError, match="must identify model_call"):
        await run.tool_call_proposal(tool_call(), model_call=message)

    forged = EventRef(
        trace_id="run-1",
        event_id="not-committed",
        kind=EventKind.MESSAGE,
    )
    with pytest.raises(ValueError, match="committed run Event"):
        await run.model_call(inputs=(forged,))

    assert [event.kind for event in run.trace.events] == [EventKind.MESSAGE]

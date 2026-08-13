from __future__ import annotations

import pytest

from agent_guardrail import GuardrailRun
from agent_guardrail.models import (
    ContentTrustClass,
    EventKind,
    EventSecurityFacts,
    MessageRole,
    SecurityFactAuthority,
    ToolCall,
    ToolResult,
)
from agent_guardrail.runtime import GuardrailRuntime
from agent_guardrail.testing import FakeToolExecutor
from tests.support import FAKE_SECRET, secret_policy_yaml, tool_result_flow_policy_yaml


@pytest.mark.asyncio
async def test_programmatic_run_blocks_secret_tool_call_before_side_effect() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    call = ToolCall(
        call_id="call-1",
        name="send_email",
        arguments={"to": "outside@example.com", "body": FAKE_SECRET},
    )

    async with runtime:
        run = GuardrailRun(analyzer=runtime, run_id="trace-1")
        user = (await run.message(role=MessageRole.USER, text="Email the credential")).primary
        assert user is not None
        model = (await run.model_call(model="test-model", inputs=(user,))).primary
        assert model is not None
        proposal = (await run.tool_call_proposal(call, model_call=model)).primary
        assert proposal is not None
        decision = await run.tool_call(call, proposal=proposal)
        if not decision.decision.blocked:
            await fake.execute(call)

    assert decision.decision.blocked
    assert fake.call_count("send_email") == 0
    assert FAKE_SECRET not in decision.decision.model_dump_json()
    assert all(event.kind is not EventKind.TOOL_CALL for event in run.trace.events)


@pytest.mark.asyncio
async def test_programmatic_run_completes_safe_tool_exchange() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    call = ToolCall(
        call_id="call-1",
        name="send_email",
        arguments={"body": "Quarterly report attached."},
    )

    async with runtime:
        run = GuardrailRun(analyzer=runtime, run_id="trace-1")
        actual = (await run.tool_call(call)).primary
        assert actual is not None
        result = await fake.execute(call)
        committed = await run.tool_result(result, call=actual)

    assert committed.primary is not None
    assert fake.call_count("send_email") == 1


@pytest.mark.asyncio
async def test_programmatic_cross_event_flow_blocks_derived_side_effect() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(tool_result_flow_policy_yaml())
    fake = FakeToolExecutor(
        {
            "read_private_file": lambda arguments: "private report",
            "send_email": lambda arguments: {"sent": True},
        }
    )
    read = ToolCall(
        call_id="read-call",
        name="read_private_file",
        arguments={"path": "report.txt"},
    )
    email = ToolCall(
        call_id="email-call",
        name="send_email",
        arguments={"body": "private report"},
    )

    async with runtime:
        run = GuardrailRun(analyzer=runtime, run_id="trace-1")
        read_ref = (await run.tool_call(read)).primary
        assert read_ref is not None
        read_output = await fake.execute(read)
        result_ref = (
            await run.tool_result(
                ToolResult(
                    call_id=read.call_id,
                    name=read.name,
                    output=read_output.output,
                ),
                call=read_ref,
            )
        ).primary
        assert result_ref is not None
        blocked = await run.tool_call(email, influenced_by=(result_ref,))
        if not blocked.decision.blocked:
            await fake.execute(email)

    assert blocked.decision.blocked
    assert blocked.decision.violations[0].code == "tool_result_flow_denied"
    assert fake.call_count("read_private_file") == 1
    assert fake.call_count("send_email") == 0


@pytest.mark.asyncio
async def test_persisted_untrusted_source_fact_blocks_later_side_effect() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(
        """\
version: 3
scopes: [pending]
rules:
  - id: block-untrusted-source-to-email
    action: block
    events:
      source: {kind: tool_result, domain: past}
      destination: {kind: tool_call, domain: pending}
    where:
      all:
        - compare:
            left: {field: [source, security_facts, trust_class]}
            operator: equals
            right: {literal: external_untrusted}
        - relation:
            source: source
            target: destination
            operator: may_influence
        - tool: {binding: destination, name: send_email}
    finding:
      code: untrusted_source_flow_denied
      message: Untrusted external content cannot drive this tool.
      subjects: [destination]
"""
    )
    fake = FakeToolExecutor(
        {
            "search": lambda arguments: "external instructions",
            "send_email": lambda arguments: {"sent": True},
        }
    )
    search = ToolCall(call_id="search-call", name="search", arguments={"q": "report"})
    email = ToolCall(
        call_id="email-call",
        name="send_email",
        arguments={"body": "external instructions"},
    )

    async with runtime:
        run = GuardrailRun(analyzer=runtime, run_id="trace-1")
        search_ref = (await run.tool_call(search)).primary
        assert search_ref is not None
        search_output = await fake.execute(search)
        source_ref = (
            await run.tool_result(
                search_output,
                call=search_ref,
                security_facts=EventSecurityFacts(
                    trust_class=ContentTrustClass.EXTERNAL_UNTRUSTED,
                    trust_authority=SecurityFactAuthority.ENFORCEMENT,
                ),
            )
        ).primary
        assert source_ref is not None
        decision = await run.tool_call(email, influenced_by=(source_ref,))
        if not decision.decision.blocked:
            await fake.execute(email)

    assert decision.decision.blocked
    assert decision.decision.violations[0].code == "untrusted_source_flow_denied"
    assert fake.call_count("search") == 1
    assert fake.call_count("send_email") == 0

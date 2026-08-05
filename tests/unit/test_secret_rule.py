from __future__ import annotations

import pytest

from agent_guardrail.models import Action, EventKind, Phase
from tests.support import FAKE_SECRET, model_response_context, secret_engine, tool_context


@pytest.mark.asyncio
async def test_safe_email_is_allowed() -> None:
    decision = await secret_engine().evaluate(tool_context(body="Quarterly report attached."))

    assert decision.action is Action.ALLOW
    assert not decision.violations


@pytest.mark.asyncio
async def test_secret_email_is_blocked_with_only_masked_evidence() -> None:
    decision = await secret_engine().evaluate(
        tool_context(body=f"Use {FAKE_SECRET} to access the service.")
    )

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert decision.blocked
    assert decision.violations[0].code == "secret_exfiltration"
    assert decision.violations[0].evidence[0].path == "$.arguments.body"
    assert FAKE_SECRET not in serialized
    assert "openai_api_key" in serialized


@pytest.mark.asyncio
async def test_rule_action_can_be_log_without_changing_detection() -> None:
    decision = await secret_engine(action="log").evaluate(tool_context(body=FAKE_SECRET))

    assert decision.action is Action.LOG
    assert decision.violations[0].action is Action.LOG


@pytest.mark.asyncio
async def test_non_target_tool_and_non_applicable_event_are_allowed() -> None:
    engine = secret_engine()

    other_tool = await engine.evaluate(tool_context(body=FAKE_SECRET, tool_name="save_draft"))
    wrong_phase = await engine.evaluate(tool_context(body=FAKE_SECRET, phase=Phase.POST_TOOL))
    wrong_kind = await engine.evaluate(tool_context(body=FAKE_SECRET, kind=EventKind.TOOL_RESULT))

    assert other_tool.action is Action.ALLOW
    assert wrong_phase.action is Action.ALLOW
    assert wrong_kind.action is Action.ALLOW


@pytest.mark.asyncio
async def test_secret_tool_call_is_blocked_before_model_response_reaches_agent() -> None:
    decision = await secret_engine().evaluate(model_response_context(body=FAKE_SECRET))

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert decision.phase is Phase.POST_LLM
    assert decision.violations[0].evidence[0].path == "$.tool_calls[0].arguments.body"
    assert FAKE_SECRET not in serialized


@pytest.mark.asyncio
async def test_nested_json_argument_is_scanned() -> None:
    decision = await secret_engine().evaluate(
        tool_context(body={"credentials": {"key": FAKE_SECRET}})
    )

    assert decision.action is Action.BLOCK

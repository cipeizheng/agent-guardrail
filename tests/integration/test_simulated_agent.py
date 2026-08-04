from __future__ import annotations

import pytest

from agent_guardrail.enforcement import (
    EnforcementSession,
    GuardedLLMClient,
    GuardedToolExecutor,
    GuardrailBlocked,
)
from agent_guardrail.models import EventKind, ModelResponse, Phase, ToolCall, Trace
from agent_guardrail.runtime import GuardrailRuntime
from agent_guardrail.testing import FakeToolExecutor, ScriptedLLM, SimulatedAgent
from tests.support import FAKE_SECRET, secret_policy_yaml


def model_tool_call(body: str) -> ModelResponse:
    return ModelResponse(
        tool_calls=(
            ToolCall(
                call_id="call-1",
                name="send_email",
                arguments={"to": "outside@example.com", "body": body},
            ),
        )
    )


@pytest.mark.asyncio
async def test_simulated_agent_secret_scenario_executes_no_tool() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    async with runtime:
        trace = Trace(id="trace-1")
        session = EnforcementSession(evaluator=runtime, trace=trace)
        fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
        inner_llm = ScriptedLLM([model_tool_call(FAKE_SECRET)])
        llm = GuardedLLMClient(inner=inner_llm, session=session)
        tools = GuardedToolExecutor(inner=fake, session=session)
        agent = SimulatedAgent(llm=llm, tools=tools)

        with pytest.raises(GuardrailBlocked) as blocked:
            await agent.run("Email the credential")

    assert blocked.value.decision.phase is Phase.POST_LLM
    assert inner_llm.call_count == 1
    assert fake.call_count("send_email") == 0
    assert [event.kind for event in trace.events] == [
        EventKind.MODEL_REQUEST,
        EventKind.GUARDRAIL_DECISION,
    ]
    assert FAKE_SECRET not in trace.model_dump_json()


@pytest.mark.asyncio
async def test_simulated_agent_completes_safe_tool_loop() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    async with runtime:
        trace = Trace(id="trace-1")
        session = EnforcementSession(evaluator=runtime, trace=trace)
        fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
        inner_llm = ScriptedLLM(
            [
                model_tool_call("Quarterly report attached."),
                ModelResponse(content="The report was sent."),
            ]
        )
        llm = GuardedLLMClient(inner=inner_llm, session=session)
        tools = GuardedToolExecutor(inner=fake, session=session)
        agent = SimulatedAgent(llm=llm, tools=tools)

        result = await agent.run("Email the report")

    assert result == "The report was sent."
    assert inner_llm.call_count == 2
    assert fake.call_count("send_email") == 1
    assert [event.kind for event in trace.events] == [
        EventKind.MODEL_REQUEST,
        EventKind.MODEL_RESPONSE,
        EventKind.TOOL_CALL,
        EventKind.TOOL_RESULT,
        EventKind.MODEL_REQUEST,
        EventKind.MODEL_RESPONSE,
    ]


@pytest.mark.asyncio
async def test_pre_tool_remains_a_second_boundary_if_post_llm_policy_is_disabled() -> None:
    pre_tool_only = secret_policy_yaml().replace(
        "phases: [post_llm, pre_tool]",
        "phases: [pre_tool]",
    )
    runtime = GuardrailRuntime.from_policy_yaml(pre_tool_only)
    async with runtime:
        session = EnforcementSession(evaluator=runtime, trace=Trace(id="trace-1"))
        fake = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
        inner_llm = ScriptedLLM([model_tool_call(FAKE_SECRET)])
        agent = SimulatedAgent(
            llm=GuardedLLMClient(inner=inner_llm, session=session),
            tools=GuardedToolExecutor(inner=fake, session=session),
        )

        with pytest.raises(GuardrailBlocked) as blocked:
            await agent.run("Email the credential")

    assert blocked.value.decision.phase is Phase.PRE_TOOL
    assert inner_llm.call_count == 1
    assert fake.call_count("send_email") == 0

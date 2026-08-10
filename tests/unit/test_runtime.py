from __future__ import annotations

import pytest

from agent_guardrail.models import Action, PendingTrace
from agent_guardrail.runtime import GuardrailRuntime, RuntimeNotReadyError, RuntimeState
from tests.support import FAKE_SECRET, secret_policy_yaml, tool_context


@pytest.mark.asyncio
async def test_runtime_requires_start_and_exposes_safe_policy_info() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())

    assert runtime.state is RuntimeState.CREATED
    assert not runtime.ready
    assert runtime.policy_info.version == 3
    assert len(runtime.policy_info.content_hash) == 64

    context = tool_context(body=FAKE_SECRET)
    pending = PendingTrace.from_context(context)
    with pytest.raises(RuntimeNotReadyError):
        await runtime.analyze_pending(pending)

    await runtime.start()
    await runtime.start()
    decision = await runtime.analyze_pending(pending)

    assert runtime.ready
    assert decision.action is Action.BLOCK
    assert decision.pending_event_ids == (context.event.id,)


@pytest.mark.asyncio
async def test_runtime_single_context_evaluate_is_a_compatibility_bridge() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())
    context = tool_context(body=FAKE_SECRET)

    async with runtime:
        direct = await runtime.evaluate(context)
        pending = await runtime.analyze_pending(PendingTrace.from_context(context))

    assert direct == pending


@pytest.mark.asyncio
async def test_runtime_context_manager_closes_and_cannot_restart() -> None:
    runtime = GuardrailRuntime.from_policy_yaml(secret_policy_yaml())

    async with runtime:
        assert runtime.ready

    assert runtime.state is RuntimeState.CLOSED
    assert not runtime.ready
    await runtime.close()
    with pytest.raises(RuntimeNotReadyError):
        await runtime.start()

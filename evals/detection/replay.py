"""Replay one labeled case through the public GuardrailRun SDK decision path.

The event sequence mirrors the production AgentDojo adapter: user message ->
model call -> tool proposal -> tool call -> tool result (untrusted) -> model
call -> proposal -> the pending tool call whose Decision is the measurement.
"""

from __future__ import annotations

import asyncio

from corpus import Case

from agent_guardrail import GuardrailRun
from agent_guardrail.core import MatchPolicyAnalyzer
from agent_guardrail.models import (
    ContentTrustClass,
    EventSecurityFacts,
    MessageRole,
    SecurityFactAuthority,
    ToolCall,
    ToolResult,
)
from agent_guardrail.sdk import SubmissionResult

_MODEL = "detection-eval-replay"


class ReplayBlockedMidTrace(RuntimeError):
    """A policy fired on an intermediate step; the corpus or policy is invalid."""


def _untrusted_facts() -> EventSecurityFacts:
    return EventSecurityFacts(
        trust_class=ContentTrustClass.EXTERNAL_UNTRUSTED,
        trust_authority=SecurityFactAuthority.ENFORCEMENT,
    )


def _user_facts() -> EventSecurityFacts:
    return EventSecurityFacts(
        trust_class=ContentTrustClass.USER_CONTENT,
        trust_authority=SecurityFactAuthority.ENFORCEMENT,
    )


def _require_allowed(result: SubmissionResult, step: str) -> None:
    if result.decision.blocked:
        raise ReplayBlockedMidTrace(
            f"policy blocked the {step} step; intermediate events must stay allowed"
        )


async def _replay_case(analyzer: MatchPolicyAnalyzer, case: Case) -> bool:
    """Return True when the policy blocks the case's measured decision point."""

    run = GuardrailRun(analyzer=analyzer, run_id=case.case_id)
    message = await run.message(
        role=MessageRole.USER,
        text=case.goal,
        security_facts=_user_facts(),
    )
    _require_allowed(message, "user message")
    inputs = (message.primary,)

    for index, step in enumerate(case.prior, start=1):
        call = ToolCall(
            call_id=f"{case.case_id}-prior-{index}",
            name=step.tool,
            arguments=dict(step.arguments),
        )
        model_call = await run.model_call(model=_MODEL, inputs=inputs)
        _require_allowed(model_call, "prior model call")
        proposal = await run.tool_call_proposal(call, model_call=model_call.primary)
        _require_allowed(proposal, "prior proposal")
        executed = await run.tool_call(call, proposal=proposal.primary)
        _require_allowed(executed, "prior tool call")
        result = await run.tool_result(
            ToolResult(call_id=call.call_id, name=step.tool, output=step.output),
            call=executed.primary,
            security_facts=_untrusted_facts(),
        )
        if case.decision_point == "tool_result_release" and index == 1:
            return result.decision.blocked
        _require_allowed(result, "prior tool result release")
        inputs = (result.primary,)

    pending = ToolCall(
        call_id=f"{case.case_id}-pending",
        name=case.pending_tool,
        arguments=dict(case.pending_arguments),
    )
    model_call = await run.model_call(model=_MODEL, inputs=inputs)
    _require_allowed(model_call, "pending model call")
    proposal = await run.tool_call_proposal(pending, model_call=model_call.primary)
    _require_allowed(proposal, "pending proposal")
    decision = await run.tool_call(pending, proposal=proposal.primary)
    return decision.decision.blocked


def replay_case(analyzer: MatchPolicyAnalyzer, case: Case) -> bool:
    """Synchronous bridge; each case replays on its own event loop."""

    return asyncio.run(_replay_case(analyzer, case))

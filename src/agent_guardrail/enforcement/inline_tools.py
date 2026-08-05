"""Inline tool enforcement before execution and before releasing its result."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from agent_guardrail.enforcement.exceptions import GuardrailBlocked
from agent_guardrail.enforcement.protocols import ToolExecutor
from agent_guardrail.enforcement.session import EnforcementSession
from agent_guardrail.models import EventKind, EventOrigin, Phase, ToolCall, ToolResult


class GuardedToolExecutor:
    """Guard one injected ToolExecutor without owning policy or trace state."""

    def __init__(self, *, inner: ToolExecutor, session: EnforcementSession) -> None:
        self.inner = inner
        self.session = session

    async def execute(self, call: ToolCall) -> ToolResult:
        pre_decision = await self.session.evaluate(
            kind=EventKind.TOOL_CALL,
            phase=Phase.PRE_TOOL,
            payload=cast(dict[str, JsonValue], call.model_dump(mode="json")),
            metadata={"adapter": "inline_tool"},
            origin=EventOrigin.OBSERVED,
        )
        if pre_decision.blocked:
            raise GuardrailBlocked(pre_decision)

        result = await self.inner.execute(call)
        post_decision = await self.session.evaluate(
            kind=EventKind.TOOL_RESULT,
            phase=Phase.POST_TOOL,
            payload=cast(dict[str, JsonValue], result.model_dump(mode="json")),
            metadata={"adapter": "inline_tool"},
            source_event_ids=(pre_decision.event_id,),
            origin=EventOrigin.OBSERVED,
        )
        if post_decision.blocked:
            raise GuardrailBlocked(post_decision)
        return result

"""Inline LLM enforcement on both sides of the actual provider call."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from agent_guardrail.enforcement.exceptions import GuardrailBlocked
from agent_guardrail.enforcement.protocols import LLMClient
from agent_guardrail.enforcement.session import EnforcementSession
from agent_guardrail.models import EventKind, EventOrigin, ModelRequest, ModelResponse, Phase


class GuardedLLMClient:
    """Run pre_llm before the provider and post_llm before returning to the agent."""

    def __init__(self, *, inner: LLMClient, session: EnforcementSession) -> None:
        self.inner = inner
        self.session = session

    async def complete(self, request: ModelRequest) -> ModelResponse:
        pre_decision = await self.session.evaluate(
            kind=EventKind.MODEL_REQUEST,
            phase=Phase.PRE_LLM,
            payload=cast(dict[str, JsonValue], request.model_dump(mode="json")),
            metadata={"adapter": "inline_llm"},
            origin=EventOrigin.CLIENT_ASSERTED,
        )
        if pre_decision.blocked:
            raise GuardrailBlocked(pre_decision)

        response = await self.inner.complete(request)
        post_decision = await self.session.evaluate(
            kind=EventKind.MODEL_RESPONSE,
            phase=Phase.POST_LLM,
            payload=cast(dict[str, JsonValue], response.model_dump(mode="json")),
            metadata={"adapter": "inline_llm"},
            source_event_ids=(pre_decision.event_id,),
            origin=EventOrigin.OBSERVED,
        )
        if post_decision.blocked:
            raise GuardrailBlocked(post_decision)
        return response

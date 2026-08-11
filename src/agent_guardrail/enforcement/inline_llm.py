"""Inline LLM enforcement on both sides of the actual provider call."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from agent_guardrail.enforcement.exceptions import GuardrailBlocked
from agent_guardrail.enforcement.input_normalizer import InputNormalizer
from agent_guardrail.enforcement.protocols import LLMClient
from agent_guardrail.enforcement.session import EnforcementSession
from agent_guardrail.models import (
    CandidateRelation,
    EventKind,
    EventOrigin,
    ModelRequest,
    ModelResponse,
    Phase,
    SecurityDestination,
)


class GuardedLLMClient:
    """Guard an LLM with independent Events and a bounded repeated-snapshot bridge."""

    def __init__(
        self,
        *,
        inner: LLMClient,
        session: EnforcementSession,
        normalizer: InputNormalizer | None = None,
    ) -> None:
        self.inner = inner
        self.session = session
        self.normalizer = normalizer or InputNormalizer()
        self._submitted_initial_snapshot = False

    async def complete(self, request: ModelRequest) -> ModelResponse:
        if not self._submitted_initial_snapshot:
            request_batch = self.normalizer.normalize_request_snapshot(request)
            pre_decision = await self.session.evaluate_candidates(
                request_batch.candidates,
                primary_key=request_batch.primary_key,
                security_context=self.session.security_context.with_enforcement_destination(
                    SecurityDestination.LLM_PROVIDER
                ),
            )
            self._submitted_initial_snapshot = True
        else:
            pre_decision = await self.session.evaluate(
                kind=EventKind.MODEL_REQUEST,
                phase=Phase.PRE_LLM,
                payload=cast(dict[str, JsonValue], request.model_dump(mode="json")),
                metadata={"adapter": "inline_llm_repeated_snapshot"},
                origin=EventOrigin.CLIENT_ASSERTED,
                security_context=self.session.security_context.with_enforcement_destination(
                    SecurityDestination.LLM_PROVIDER
                ),
            )
        if pre_decision.blocked:
            raise GuardrailBlocked(pre_decision)

        response = await self.inner.complete(request)
        response_batch = self.normalizer.normalize_response(response)
        post_decision = await self.session.evaluate_candidates(
            tuple(
                candidate.model_copy(
                    update={
                        "relations": (
                            *candidate.relations,
                            CandidateRelation(source_event_id=pre_decision.event_id),
                        )
                    }
                )
                for candidate in response_batch.candidates
            ),
            primary_key=response_batch.primary_key,
            security_context=self.session.security_context.with_enforcement_destination(
                SecurityDestination.AGENT_RUNTIME
            ),
        )
        if post_decision.blocked:
            raise GuardrailBlocked(post_decision)
        return response

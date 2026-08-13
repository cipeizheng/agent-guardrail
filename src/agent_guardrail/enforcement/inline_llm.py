"""Inline LLM enforcement on both sides of the actual provider call."""

from __future__ import annotations

from typing import cast

from pydantic import JsonValue

from agent_guardrail.enforcement.exceptions import GuardrailBlocked
from agent_guardrail.enforcement.input_normalizer import InputNormalizer
from agent_guardrail.enforcement.protocols import LLMClient
from agent_guardrail.enforcement.session import EnforcementSession
from agent_guardrail.models import (
    CandidateEvent,
    CandidateRelation,
    EventKind,
    ModelRequest,
    ModelResponse,
    SecurityDestination,
)


class GuardedLLMClient:
    """Guard an LLM while submitting only an exact extension of request history."""

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
        self._history_signatures: list[tuple[EventKind, dict[str, JsonValue]]] = []
        self._history_event_ids: list[str] = []

    async def complete(self, request: ModelRequest) -> ModelResponse:
        request_batch = self.normalizer.normalize_model_call(request)
        history = request_batch.candidates[:-1]
        history_signatures = [self._signature(candidate) for candidate in history]
        if history_signatures[: len(self._history_signatures)] != self._history_signatures:
            raise ValueError("inline LLM request history must be an exact extension")
        delta = history[len(self._history_signatures) :]
        committed_by_key = {
            candidate.key: event_id
            for candidate, event_id in zip(
                history[: len(self._history_event_ids)],
                self._history_event_ids,
                strict=True,
            )
        }
        submitted = tuple(
            self._resolve_committed_relations(candidate, committed_by_key)
            for candidate in (*delta, request_batch.candidates[-1])
        )
        pre_decision = await self.session.submit_candidates(
            submitted,
            primary_key=request_batch.primary_key,
            security_context=self.session.security_context.with_enforcement_destination(
                SecurityDestination.LLM_PROVIDER
            ),
        )
        if pre_decision.blocked:
            raise GuardrailBlocked(pre_decision)
        delta_event_ids = pre_decision.pending_event_ids[: len(delta)]
        self._history_signatures.extend(self._signature(candidate) for candidate in delta)
        self._history_event_ids.extend(delta_event_ids)

        response = await self.inner.complete(request)
        response_batch = self.normalizer.normalize_model_output(
            response,
            model_call_event_id=pre_decision.event_id,
        )
        post_decision = await self.session.submit_candidates(
            response_batch.candidates,
            primary_key=response_batch.primary_key,
            security_context=self.session.security_context.with_enforcement_destination(
                SecurityDestination.AGENT_RUNTIME
            ),
        )
        if post_decision.blocked:
            raise GuardrailBlocked(post_decision)
        self._history_signatures.extend(
            self._signature(candidate) for candidate in response_batch.candidates
        )
        self._history_event_ids.extend(post_decision.pending_event_ids)
        return response

    @staticmethod
    def _signature(candidate: CandidateEvent) -> tuple[EventKind, dict[str, JsonValue]]:
        return candidate.kind, cast(dict[str, JsonValue], candidate.payload)

    @staticmethod
    def _resolve_committed_relations(
        candidate: CandidateEvent,
        committed_by_key: dict[str, str],
    ) -> CandidateEvent:
        relations = tuple(
            CandidateRelation(
                source_event_id=committed_by_key[relation.source_candidate_key],
                kind=relation.kind,
            )
            if relation.source_candidate_key in committed_by_key
            else relation
            for relation in candidate.relations
        )
        return candidate.model_copy(update={"relations": relations})

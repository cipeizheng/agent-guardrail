"""Request/task-scoped event sequencing, evaluation and sanitized auditing."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from pydantic import JsonValue

from agent_guardrail.enforcement.audit import NullAuditSink
from agent_guardrail.enforcement.exceptions import GuardrailUnavailable
from agent_guardrail.enforcement.protocols import AuditSink
from agent_guardrail.models import (
    Decision,
    Event,
    EventKind,
    GuardrailContext,
    Phase,
    Trace,
)
from agent_guardrail.runtime import DecisionEvaluator

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]

_VALID_BOUNDARIES: frozenset[tuple[EventKind, Phase]] = frozenset(
    {
        (EventKind.MODEL_REQUEST, Phase.PRE_LLM),
        (EventKind.MODEL_RESPONSE, Phase.POST_LLM),
        (EventKind.TOOL_CALL, Phase.PRE_TOOL),
        (EventKind.TOOL_RESULT, Phase.POST_TOOL),
    }
)


class EnforcementSession:
    """Own one trace and serialize evaluate-and-commit operations within it."""

    def __init__(
        self,
        *,
        evaluator: DecisionEvaluator,
        trace: Trace,
        audit: AuditSink | None = None,
        attributes: Mapping[str, JsonValue] | None = None,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        self.evaluator = evaluator
        self.trace = trace
        self.audit = audit or NullAuditSink()
        self.attributes = dict(attributes or {})
        self.clock = clock or (lambda: datetime.now(UTC))
        self.id_factory = id_factory or (lambda: uuid4().hex)
        self.audit_failure_types: list[str] = []
        self._evaluation_lock = asyncio.Lock()

    async def evaluate(
        self,
        *,
        kind: EventKind,
        phase: Phase,
        payload: Mapping[str, JsonValue],
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> Decision:
        """Evaluate and atomically commit a safe trace representation."""

        if (kind, phase) not in _VALID_BOUNDARIES:
            raise ValueError(f"invalid enforcement boundary: {kind.value}/{phase.value}")

        async with self._evaluation_lock:
            if len(self.trace.events) >= self.trace.max_events:
                raise GuardrailUnavailable(
                    trace_id=self.trace.id,
                    phase=phase,
                    error_type="trace_capacity_exceeded",
                )

            candidate = Event(
                id=self.id_factory(),
                trace_id=self.trace.id,
                sequence=self.trace.next_sequence,
                kind=kind,
                phase=phase,
                timestamp=self.clock(),
                payload=dict(payload),
                metadata=dict(metadata or {}),
            )
            context = GuardrailContext(
                event=candidate,
                trace=self.trace,
                attributes=self.attributes,
            )
            try:
                decision = await self.evaluator.evaluate(context)
            except Exception as exc:
                raise GuardrailUnavailable(
                    trace_id=self.trace.id,
                    phase=phase,
                    error_type=type(exc).__name__,
                ) from exc

            self._validate_decision(decision, candidate)
            committed = self._blocked_event(decision, candidate) if decision.blocked else candidate
            self.trace.append(committed)

        await self._audit_if_needed(decision)
        return decision

    def _validate_decision(self, decision: Decision, candidate: Event) -> None:
        if (
            decision.trace_id != self.trace.id
            or decision.event_id != candidate.id
            or decision.phase is not candidate.phase
        ):
            raise GuardrailUnavailable(
                trace_id=self.trace.id,
                phase=candidate.phase,
                error_type="invalid_decision_identity",
            )

    def _blocked_event(self, decision: Decision, candidate: Event) -> Event:
        violations = [
            {"rule_id": violation.rule_id, "code": violation.code}
            for violation in decision.violations
        ]
        payload = cast(
            dict[str, JsonValue],
            {
                "action": decision.action.value,
                "phase": decision.phase.value,
                "event_id": candidate.id,
                "policy_version": decision.policy_version,
                "policy_hash": decision.policy_hash,
                "violations": violations,
            },
        )
        return Event(
            id=self.id_factory(),
            trace_id=self.trace.id,
            sequence=candidate.sequence,
            kind=EventKind.GUARDRAIL_DECISION,
            phase=candidate.phase,
            timestamp=self.clock(),
            payload=payload,
            metadata={"sanitized": True},
        )

    async def _audit_if_needed(self, decision: Decision) -> None:
        if not decision.violations:
            return
        try:
            await self.audit.record(decision)
        except Exception as exc:  # Audit is fail-open; only retain the safe error type.
            self.audit_failure_types.append(type(exc).__name__)

"""Request/task-scoped event sequencing, evaluation and sanitized auditing."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from pydantic import JsonValue

from agent_guardrail.enforcement.audit import NullAuditSink
from agent_guardrail.enforcement.exceptions import GuardrailUnavailable
from agent_guardrail.enforcement.protocols import AuditSink
from agent_guardrail.enforcement.provenance import infer_source_event_ids
from agent_guardrail.models import (
    MAX_PENDING_EVENTS,
    MAX_RELATIONS_PER_EVENT,
    CandidateEvent,
    CandidateRelation,
    Decision,
    Event,
    EventKind,
    EventOrigin,
    EventRelation,
    FlowSecurityContext,
    PendingTrace,
    Phase,
    Trace,
)
from agent_guardrail.runtime import PolicyAnalyzer

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]
_LEGACY_SOURCE_EVENT_IDS_METADATA_KEY = "source_event_ids"

_COMPATIBLE_SINGLE_BOUNDARIES: frozenset[tuple[EventKind, Phase]] = frozenset(
    {
        (EventKind.MODEL_REQUEST, Phase.PRE_LLM),
        (EventKind.MODEL_RESPONSE, Phase.POST_LLM),
        (EventKind.TOOL_CALL, Phase.PRE_TOOL),
        (EventKind.TOOL_RESULT, Phase.POST_TOOL),
    }
)

_AGGREGATE_MODEL_EVENT_KINDS = frozenset(
    {EventKind.MODEL_REQUEST, EventKind.MODEL_RESPONSE}
)

# Aggregate model kinds remain here only because the single-candidate API delegates
# to evaluate_candidates. Multi-event production batches use independent kinds.
_VALID_CANDIDATE_PHASES: dict[Phase, frozenset[EventKind]] = {
    Phase.PRE_LLM: frozenset(
        {
            EventKind.MESSAGE,
            EventKind.MODEL_REQUEST,
            EventKind.TOOL_CALL,
            EventKind.TOOL_RESULT,
        }
    ),
    Phase.POST_LLM: frozenset(
        {EventKind.MESSAGE, EventKind.MODEL_RESPONSE, EventKind.TOOL_CALL}
    ),
    Phase.PRE_TOOL: frozenset({EventKind.TOOL_CALL}),
    Phase.POST_TOOL: frozenset({EventKind.TOOL_RESULT}),
}


class EnforcementSession:
    """Own one trace and serialize evaluate-and-commit operations within it."""

    def __init__(
        self,
        *,
        analyzer: PolicyAnalyzer,
        trace: Trace,
        audit: AuditSink | None = None,
        attributes: Mapping[str, JsonValue] | None = None,
        security_context: FlowSecurityContext | None = None,
        clock: Clock | None = None,
        id_factory: IdFactory | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.trace = trace
        self.audit = audit or NullAuditSink()
        self.attributes = dict(attributes or {})
        if security_context is not None and not isinstance(
            security_context, FlowSecurityContext
        ):
            raise TypeError("security_context must be a FlowSecurityContext")
        self.security_context = (security_context or FlowSecurityContext()).model_copy(
            deep=True
        )
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
        source_event_ids: Sequence[str] = (),
        origin: EventOrigin = EventOrigin.CLIENT_ASSERTED,
        security_context: FlowSecurityContext | None = None,
    ) -> Decision:
        """Evaluate one compatibility candidate through the atomic batch path."""

        if (kind, phase) not in _COMPATIBLE_SINGLE_BOUNDARIES:
            raise ValueError(f"invalid enforcement boundary: {kind.value}/{phase.value}")
        if metadata is not None and _LEGACY_SOURCE_EVENT_IDS_METADATA_KEY in metadata:
            raise ValueError(
                "source_event_ids metadata is reserved; pass trusted IDs through source_event_ids"
            )

        if isinstance(source_event_ids, (str, bytes)):
            raise ValueError("source_event_ids must be a sequence of event IDs")
        declared_source_ids = tuple(source_event_ids)
        if any(
            not isinstance(source_event_id, str)
            or not source_event_id.strip()
            or source_event_id != source_event_id.strip()
            for source_event_id in declared_source_ids
        ):
            raise ValueError("source_event_ids must contain non-blank event IDs")
        if len(declared_source_ids) != len(set(declared_source_ids)):
            raise ValueError("source_event_ids must be unique")

        candidate = CandidateEvent(
            key="event",
            kind=kind,
            phase=phase,
            payload=dict(payload),
            metadata=dict(metadata or {}),
            origin=origin,
            relations=tuple(
                CandidateRelation(source_event_id=source_event_id)
                for source_event_id in declared_source_ids
            ),
        )
        return await self.evaluate_candidates(
            (candidate,),
            primary_key=candidate.key,
            security_context=security_context,
        )

    async def evaluate_candidates(
        self,
        candidates: Sequence[CandidateEvent],
        *,
        primary_key: str | None = None,
        security_context: FlowSecurityContext | None = None,
    ) -> Decision:
        """Analyze and atomically commit a bounded batch of candidate events."""

        if isinstance(candidates, (str, bytes)):
            raise ValueError("candidates must be a sequence of CandidateEvent values")
        if security_context is not None and not isinstance(
            security_context, FlowSecurityContext
        ):
            raise TypeError("security_context must be a FlowSecurityContext")
        if len(candidates) > MAX_PENDING_EVENTS:
            raise ValueError(f"candidate batch cannot exceed {MAX_PENDING_EVENTS} events")
        candidate_batch = tuple(candidates)
        if not candidate_batch:
            raise ValueError("candidate batch must not be empty")
        if any(not isinstance(candidate, CandidateEvent) for candidate in candidate_batch):
            raise TypeError("candidate batch must contain only CandidateEvent values")
        if len(candidate_batch) != 1 and any(
            candidate.kind in _AGGREGATE_MODEL_EVENT_KINDS
            for candidate in candidate_batch
        ):
            raise ValueError(
                "aggregate model events are supported only as single-candidate "
                "compatibility inputs"
            )
        if any(
            len(candidate.relations) > MAX_RELATIONS_PER_EVENT
            for candidate in candidate_batch
        ):
            raise ValueError(
                f"candidate relations cannot exceed {MAX_RELATIONS_PER_EVENT} per event"
            )

        candidate_keys = [candidate.key for candidate in candidate_batch]
        if len(candidate_keys) != len(set(candidate_keys)):
            raise ValueError("candidate keys must be unique within a batch")
        selected_primary_key = primary_key or candidate_batch[-1].key
        if selected_primary_key not in candidate_keys:
            raise ValueError("primary_key must identify a candidate in the batch")
        phase = candidate_batch[0].phase
        if any(candidate.phase is not phase for candidate in candidate_batch):
            raise ValueError("all candidates must use the same enforcement phase")
        for candidate in candidate_batch:
            if candidate.kind not in _VALID_CANDIDATE_PHASES[candidate.phase]:
                raise ValueError(
                    "invalid candidate enforcement phase: "
                    f"{candidate.kind.value}/{candidate.phase.value}"
                )

        async with self._evaluation_lock:
            if len(self.trace.events) + len(candidate_batch) > self.trace.max_events:
                raise GuardrailUnavailable(
                    trace_id=self.trace.id,
                    phase=phase,
                    error_type="trace_capacity_exceeded",
                )

            candidate_ids = {candidate.key: self.id_factory() for candidate in candidate_batch}
            candidate_positions = {
                candidate.key: index for index, candidate in enumerate(candidate_batch)
            }
            pending_events: list[Event] = []
            for index, candidate in enumerate(candidate_batch):
                prefix = Trace(
                    id=self.trace.id,
                    events=(*self.trace.events, *pending_events),
                    metadata=self.trace.metadata,
                    max_events=self.trace.max_events,
                )
                event_relations = self._candidate_relations(
                    candidate,
                    candidate_ids=candidate_ids,
                    candidate_positions=candidate_positions,
                    current_position=index,
                    prefix=prefix,
                )
                pending_events.append(
                    Event(
                        id=candidate_ids[candidate.key],
                        trace_id=self.trace.id,
                        sequence=self.trace.next_sequence + index,
                        kind=candidate.kind,
                        phase=candidate.phase,
                        timestamp=self.clock(),
                        origin=candidate.origin,
                        payload=dict(candidate.payload),
                        metadata=dict(candidate.metadata),
                        relations=event_relations,
                    )
                )

            pending = PendingTrace(
                trace=self.trace.model_copy(deep=True),
                events=tuple(pending_events),
                primary_event_id=candidate_ids[selected_primary_key],
                attributes=dict(self.attributes),
                security_context=(
                    security_context or self.security_context
                ).model_copy(deep=True),
            )
            pending_snapshot = pending.model_dump(mode="json")
            try:
                decision = await self.analyzer.analyze_pending(pending)
            except Exception as exc:
                raise GuardrailUnavailable(
                    trace_id=self.trace.id,
                    phase=phase,
                    error_type=type(exc).__name__,
                ) from exc

            if pending.model_dump(mode="json") != pending_snapshot:
                raise GuardrailUnavailable(
                    trace_id=self.trace.id,
                    phase=phase,
                    error_type="invalid_pending_snapshot",
                )

            self._validate_decision(decision, pending)
            if decision.blocked:
                self.trace.append(self._blocked_event(decision, pending))
            else:
                for event in pending.events:
                    self.trace.append(event)

        await self._audit_if_needed(decision)
        return decision

    def _candidate_relations(
        self,
        candidate: CandidateEvent,
        *,
        candidate_ids: Mapping[str, str],
        candidate_positions: Mapping[str, int],
        current_position: int,
        prefix: Trace,
    ) -> tuple[EventRelation, ...]:
        declared_relations: list[EventRelation] = []
        for relation in candidate.relations:
            source_event_id = relation.source_event_id
            if relation.source_candidate_key is not None:
                source_key = relation.source_candidate_key
                source_position = candidate_positions.get(source_key)
                if source_position is None:
                    raise ValueError("candidate relation references an unknown candidate")
                if source_position >= current_position:
                    raise ValueError("candidate relations must reference earlier candidates")
                source_event_id = candidate_ids[source_key]
            if source_event_id is None:  # CandidateRelation validation makes this unreachable.
                raise ValueError("candidate relation has no source")
            source = prefix.by_id(source_event_id)
            if source is None:
                raise ValueError("source_event_id does not exist in this trace")
            if source.kind is EventKind.GUARDRAIL_DECISION:
                raise ValueError("guardrail decision events cannot be provenance sources")
            declared_relations.append(
                EventRelation(source_event_id=source_event_id, kind=relation.kind)
            )

        inferred_source_event_ids = infer_source_event_ids(
            trace=prefix,
            kind=candidate.kind,
            payload=dict(candidate.payload),
        )
        all_relations = [
            *(
                EventRelation(source_event_id=source_event_id)
                for source_event_id in inferred_source_event_ids
            ),
            *declared_relations,
        ]
        unique_relations: dict[tuple[str, object], EventRelation] = {}
        for relation in all_relations:
            unique_relations[(relation.source_event_id, relation.kind)] = relation
        if len(unique_relations) > MAX_RELATIONS_PER_EVENT:
            raise ValueError(
                f"resolved event relations cannot exceed {MAX_RELATIONS_PER_EVENT}"
            )
        return tuple(unique_relations.values())

    def _validate_decision(self, decision: Decision, pending: PendingTrace) -> None:
        if (
            decision.trace_id != self.trace.id
            or decision.event_id != pending.primary_event_id
            or decision.pending_event_ids != pending.event_ids
            or decision.phase is not pending.primary_event.phase
        ):
            raise GuardrailUnavailable(
                trace_id=self.trace.id,
                phase=pending.primary_event.phase,
                error_type="invalid_decision_identity",
            )

    def _blocked_event(self, decision: Decision, pending: PendingTrace) -> Event:
        violations = [
            {"rule_id": violation.rule_id, "code": violation.code}
            for violation in decision.violations
        ]
        payload = cast(
            dict[str, JsonValue],
            {
                "action": decision.action.value,
                "phase": decision.phase.value,
                "event_id": pending.primary_event_id,
                "pending_event_ids": list(pending.event_ids),
                "policy_version": decision.policy_version,
                "policy_hash": decision.policy_hash,
                "violations": violations,
            },
        )
        return Event(
            id=self.id_factory(),
            trace_id=self.trace.id,
            sequence=self.trace.next_sequence,
            kind=EventKind.GUARDRAIL_DECISION,
            phase=pending.primary_event.phase,
            timestamp=self.clock(),
            origin=EventOrigin.DERIVED,
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

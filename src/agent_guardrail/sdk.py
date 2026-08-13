"""Framework-neutral programmatic trace submission API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from uuid import uuid4

from pydantic import JsonValue

from agent_guardrail.enforcement import AuditSink, EnforcementSession
from agent_guardrail.models import (
    CandidateEvent,
    CandidateRelation,
    Decision,
    EventKind,
    EventOrigin,
    FlowSecurityContext,
    Message,
    MessageRole,
    ModelCall,
    RelationKind,
    TextContent,
    ToolCall,
    ToolResult,
    Trace,
)
from agent_guardrail.runtime import PolicyAnalyzer


@dataclass(frozen=True, slots=True)
class EventRef:
    """An opaque reference to one committed Event in exactly one run."""

    trace_id: str
    event_id: str
    kind: EventKind


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """A Decision and refs for Events committed by an allowed submission."""

    decision: Decision
    events: tuple[EventRef, ...]

    @property
    def primary(self) -> EventRef | None:
        if self.decision.blocked:
            return None
        return next(
            event for event in self.events if event.event_id == self.decision.event_id
        )


class GuardrailRun:
    """Own one in-memory Trace and expose phase-free semantic Event helpers."""

    def __init__(
        self,
        *,
        analyzer: PolicyAnalyzer,
        run_id: str | None = None,
        audit: AuditSink | None = None,
        attributes: Mapping[str, JsonValue] | None = None,
        security_context: FlowSecurityContext | None = None,
        max_events: int | None = None,
    ) -> None:
        trace_id = run_id or f"trc_{uuid4().hex}"
        trace = (
            Trace(id=trace_id)
            if max_events is None
            else Trace(id=trace_id, max_events=max_events)
        )
        self._session = EnforcementSession(
            analyzer=analyzer,
            trace=trace,
            audit=audit,
            attributes=attributes,
            security_context=security_context,
        )

    @property
    def trace(self) -> Trace:
        """Return the run-owned trace for bounded inspection."""

        return self._session.trace

    @property
    def security_context(self) -> FlowSecurityContext:
        return self._session.security_context

    async def submit(
        self,
        candidate: CandidateEvent,
        *,
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        """Submit one expert-level CandidateEvent."""

        return await self.submit_batch(
            (candidate,),
            primary_key=candidate.key,
            security_context=security_context,
        )

    async def submit_batch(
        self,
        candidates: Sequence[CandidateEvent],
        *,
        primary_key: str | None = None,
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        """Atomically analyze and, when allowed, commit a bounded Event batch."""

        candidate_batch = tuple(candidates)
        decision = await self._session.submit_candidates(
            candidate_batch,
            primary_key=primary_key,
            security_context=security_context,
        )
        refs = ()
        if not decision.blocked:
            refs = tuple(
                EventRef(trace_id=self.trace.id, event_id=event_id, kind=candidate.kind)
                for candidate, event_id in zip(
                    candidate_batch,
                    decision.pending_event_ids,
                    strict=True,
                )
            )
        return SubmissionResult(decision=decision, events=refs)

    async def message(
        self,
        *,
        role: MessageRole,
        text: str,
        origin: EventOrigin = EventOrigin.CLIENT_ASSERTED,
        derived_from: Sequence[EventRef] = (),
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        message = Message(role=role, content=TextContent(text=text))
        return await self._submit_typed(
            kind=EventKind.MESSAGE,
            payload=message.model_dump(mode="json"),
            origin=origin,
            derived_from=derived_from,
            security_context=security_context,
        )

    async def model_call(
        self,
        *,
        model: str | None = None,
        inputs: Sequence[EventRef] = (),
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        call = ModelCall(model=model)
        return await self._submit_typed(
            kind=EventKind.MODEL_CALL,
            payload=call.model_dump(mode="json"),
            origin=EventOrigin.OBSERVED,
            may_influence=inputs,
            security_context=security_context,
        )

    async def tool_call_proposal(
        self,
        call: ToolCall,
        *,
        model_call: EventRef,
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        self._require_kind(model_call, EventKind.MODEL_CALL)
        return await self._submit_typed(
            kind=EventKind.TOOL_CALL_PROPOSAL,
            payload=call.model_dump(mode="json"),
            origin=EventOrigin.OBSERVED,
            derived_from=(model_call,),
            security_context=security_context,
        )

    async def tool_call(
        self,
        call: ToolCall,
        *,
        proposal: EventRef | None = None,
        influenced_by: Sequence[EventRef] = (),
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        sources = tuple(influenced_by)
        if proposal is not None:
            self._require_kind(proposal, EventKind.TOOL_CALL_PROPOSAL)
            sources = (*sources, proposal)
        return await self._submit_typed(
            kind=EventKind.TOOL_CALL,
            payload=call.model_dump(mode="json"),
            origin=EventOrigin.OBSERVED,
            may_influence=sources,
            security_context=security_context,
        )

    async def tool_result(
        self,
        result: ToolResult,
        *,
        call: EventRef,
        security_context: FlowSecurityContext | None = None,
    ) -> SubmissionResult:
        self._require_kind(call, EventKind.TOOL_CALL)
        return await self._submit_typed(
            kind=EventKind.TOOL_RESULT,
            payload=result.model_dump(mode="json"),
            origin=EventOrigin.OBSERVED,
            derived_from=(call,),
            security_context=security_context,
        )

    async def _submit_typed(
        self,
        *,
        kind: EventKind,
        payload: dict[str, JsonValue],
        origin: EventOrigin,
        derived_from: Sequence[EventRef] = (),
        may_influence: Sequence[EventRef] = (),
        security_context: FlowSecurityContext | None,
    ) -> SubmissionResult:
        candidate = CandidateEvent(
            key="event",
            kind=kind,
            payload=payload,
            origin=origin,
            relations=(
                *self._relations(derived_from, RelationKind.DERIVED_FROM),
                *self._relations(may_influence, RelationKind.MAY_INFLUENCE),
            ),
        )
        return await self.submit(candidate, security_context=security_context)

    def _relations(
        self,
        refs: Sequence[EventRef],
        kind: RelationKind,
    ) -> tuple[CandidateRelation, ...]:
        relations: list[CandidateRelation] = []
        for ref in refs:
            self._require_committed(ref)
            relations.append(CandidateRelation(source_event_id=ref.event_id, kind=kind))
        return tuple(relations)

    def _require_committed(self, ref: EventRef) -> None:
        if not isinstance(ref, EventRef):
            raise TypeError("event relations require EventRef values")
        if ref.trace_id != self.trace.id:
            raise ValueError("EventRef belongs to another guardrail run")
        event = self.trace.by_id(ref.event_id)
        if event is None or event.kind is not ref.kind:
            raise ValueError("EventRef does not identify a committed run Event")

    def _require_kind(self, ref: EventRef, kind: EventKind) -> None:
        self._require_committed(ref)
        if ref.kind is not kind:
            raise ValueError(f"EventRef must identify {kind.value}")

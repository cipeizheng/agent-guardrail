"""Provider-neutral models shared by the guardrail core and adapters."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class CanonicalModel(BaseModel):
    """Base model with a closed schema suitable for a public API boundary."""

    model_config = ConfigDict(extra="forbid")


class Phase(StrEnum):
    """A point at which guardrail evaluation can occur."""

    PRE_LLM = "pre_llm"
    POST_LLM = "post_llm"
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"


class EventKind(StrEnum):
    """Provider-neutral categories; aggregate model kinds are compatibility-only."""

    MESSAGE = "message"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    GUARDRAIL_DECISION = "guardrail_decision"


class EventOrigin(StrEnum):
    """How an enforcement boundary learned about an event."""

    CLIENT_ASSERTED = "client_asserted"
    OBSERVED = "observed"
    DERIVED = "derived"


class Action(StrEnum):
    """An enforcement action ordered from least to most restrictive."""

    ALLOW = "allow"
    LOG = "log"
    BLOCK = "block"


ACTION_PRIORITY: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.LOG: 1,
    Action.BLOCK: 2,
}

MAX_PENDING_EVENTS = 1_000
MAX_RELATIONS_PER_EVENT = 64
MAX_TRACE_EVENTS = 1_000
_LEGACY_SOURCE_EVENT_IDS_METADATA_KEY = "source_event_ids"


class RelationKind(StrEnum):
    """A typed, explicitly observed relationship between canonical events."""

    DERIVED_FROM = "derived_from"


class MessageRole(StrEnum):
    """Roles represented by independent canonical message events."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class EventRelation(CanonicalModel):
    """One direct edge from the target event to an earlier source event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_event_id: str = Field(min_length=1)
    kind: RelationKind = RelationKind.DERIVED_FROM

    @model_validator(mode="after")
    def validate_source_event_id(self) -> Self:
        if not self.source_event_id.strip() or self.source_event_id != self.source_event_id.strip():
            raise ValueError("relation source_event_id must be a non-blank trimmed string")
        return self


class CandidateRelation(CanonicalModel):
    """A typed relation to committed history or an earlier batch candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_event_id: str | None = None
    source_candidate_key: str | None = None
    kind: RelationKind = RelationKind.DERIVED_FROM

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        references = (self.source_event_id, self.source_candidate_key)
        if sum(reference is not None for reference in references) != 1:
            raise ValueError("a candidate relation must reference exactly one event or candidate")
        reference = next(reference for reference in references if reference is not None)
        if not reference.strip() or reference != reference.strip():
            raise ValueError("candidate relation references must be non-blank and trimmed")
        return self


class TextContent(CanonicalModel):
    """The only content variant supported by independent messages in v0.1."""

    type: Literal["text"] = "text"
    text: str


class Message(CanonicalModel):
    """A provider-neutral conversational message without embedded tool fields."""

    role: MessageRole
    content: TextContent


class ToolCall(CanonicalModel):
    """A normalized request to execute a tool."""

    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)


class ToolResult(CanonicalModel):
    """A normalized tool execution result."""

    call_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    output: JsonValue


class CandidateEvent(CanonicalModel):
    """An uncommitted event description submitted by trusted enforcement code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1)
    kind: EventKind
    phase: Phase
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    origin: EventOrigin = EventOrigin.CLIENT_ASSERTED
    relations: tuple[CandidateRelation, ...] = Field(
        default=(),
        max_length=MAX_RELATIONS_PER_EVENT,
    )

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if not self.key.strip() or self.key != self.key.strip():
            raise ValueError("candidate key must be a non-blank trimmed string")
        if self.kind is EventKind.GUARDRAIL_DECISION:
            raise ValueError("guardrail decision events are created only by the session")
        if _LEGACY_SOURCE_EVENT_IDS_METADATA_KEY in self.metadata:
            raise ValueError("source_event_ids metadata is reserved; use typed relations")
        relation_keys = [
            (
                relation.source_event_id,
                relation.source_candidate_key,
                relation.kind,
            )
            for relation in self.relations
        ]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("candidate relations must be unique")
        if any(relation.source_candidate_key == self.key for relation in self.relations):
            raise ValueError("a candidate cannot cite itself as a relation source")
        return self


class Event(CanonicalModel):
    """One immutable canonical event in an agent trace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_version: Literal[2] = 2
    id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    sequence: int = Field(ge=0)
    kind: EventKind
    phase: Phase
    timestamp: datetime
    origin: EventOrigin = EventOrigin.CLIENT_ASSERTED
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    relations: tuple[EventRelation, ...] = Field(
        default=(),
        max_length=MAX_RELATIONS_PER_EVENT,
    )

    @model_validator(mode="after")
    def validate_typed_payload(self) -> Self:
        if self.kind is EventKind.MESSAGE:
            Message.model_validate(self.payload)
        elif self.kind is EventKind.MODEL_REQUEST:
            from agent_guardrail.models.chat import ModelRequest

            ModelRequest.model_validate(self.payload)
        elif self.kind is EventKind.MODEL_RESPONSE:
            from agent_guardrail.models.chat import ModelResponse

            ModelResponse.model_validate(self.payload)
        elif self.kind is EventKind.TOOL_CALL:
            ToolCall.model_validate(self.payload)
        elif self.kind is EventKind.TOOL_RESULT:
            ToolResult.model_validate(self.payload)

        if _LEGACY_SOURCE_EVENT_IDS_METADATA_KEY in self.metadata:
            raise ValueError("source_event_ids metadata is reserved; use typed relations")
        relation_keys = [(relation.source_event_id, relation.kind) for relation in self.relations]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("event relations must be unique")
        if self.id in {relation.source_event_id for relation in self.relations}:
            raise ValueError("an event cannot cite itself as a relation source")
        return self

    @property
    def source_event_ids(self) -> tuple[str, ...]:
        """Return unique direct source IDs from the event's typed relations."""

        return tuple(dict.fromkeys(relation.source_event_id for relation in self.relations))


class Trace(CanonicalModel):
    """A bounded, ordered in-memory collection of canonical events."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    events: tuple[Event, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    max_events: int = Field(default=MAX_TRACE_EVENTS, ge=1, le=MAX_TRACE_EVENTS, exclude=True)

    @model_validator(mode="after")
    def validate_events(self) -> Self:
        previous_sequence = -1
        seen_events: dict[str, Event] = {}
        for event in self.events:
            if event.trace_id != self.id:
                raise ValueError("all events must belong to this trace")
            if event.sequence <= previous_sequence:
                raise ValueError("event sequences must be strictly increasing")
            if event.id in seen_events:
                raise ValueError("event IDs must be unique within a trace")
            self._validate_relations(event, seen_events)
            previous_sequence = event.sequence
            seen_events[event.id] = event
        if len(self.events) > self.max_events:
            raise ValueError("trace exceeds max_events")
        return self

    @property
    def next_sequence(self) -> int:
        """Return the next monotonically increasing sequence number."""

        return self.events[-1].sequence + 1 if self.events else 0

    def append(self, event: Event) -> None:
        """Append an event while preserving trace invariants."""

        if event.trace_id != self.id:
            raise ValueError("event belongs to another trace")
        if event.sequence != self.next_sequence:
            raise ValueError("event sequence is not the next trace sequence")
        if len(self.events) >= self.max_events:
            raise ValueError("trace exceeds max_events")
        known_events = {existing.id: existing for existing in self.events}
        if event.id in known_events:
            raise ValueError("event ID already exists in this trace")
        self._validate_relations(event, known_events)
        self.events = (*self.events, event)

    def by_id(self, event_id: str) -> Event | None:
        """Return one historical event by its trace-local unique ID."""

        for event in self.events:
            if event.id == event_id:
                return event
        return None

    def find(
        self,
        *,
        kind: EventKind | None = None,
        phase: Phase | None = None,
        tool_name: str | None = None,
        source_event_id: str | None = None,
    ) -> tuple[Event, ...]:
        """Return ordered events matching explicit canonical fields or a direct edge."""

        matches: list[Event] = []
        for event in self.events:
            if kind is not None and event.kind is not kind:
                continue
            if phase is not None and event.phase is not phase:
                continue
            if tool_name is not None and event.payload.get("name") != tool_name:
                continue
            if source_event_id is not None and source_event_id not in event.source_event_ids:
                continue
            matches.append(event)
        return tuple(matches)

    def events_since(self, event_id: str, *, inclusive: bool = False) -> tuple[Event, ...]:
        """Return ordered events after a known event, optionally including that event."""

        for index, event in enumerate(self.events):
            if event.id == event_id:
                start = index if inclusive else index + 1
                return self.events[start:]
        raise ValueError("event ID does not exist in this trace")

    def sources_of(self, event: Event) -> tuple[Event, ...]:
        """Resolve the direct, explicitly declared sources of an event."""

        if event.trace_id != self.id:
            raise ValueError("event belongs to another trace")
        sources: list[Event] = []
        for source_event_id in event.source_event_ids:
            source = self.by_id(source_event_id)
            if source is None or source.kind is EventKind.GUARDRAIL_DECISION:
                raise ValueError("source event is not available in this trace")
            if source.sequence >= event.sequence:
                raise ValueError("source events must precede the current event")
            sources.append(source)
        return tuple(sources)

    def ancestors_of(
        self,
        event: Event,
        *,
        kind: EventKind | None = None,
    ) -> tuple[Event, ...]:
        """Resolve transitive provenance ancestors in their original trace order."""

        pending = [source.id for source in self.sources_of(event)]
        ancestor_ids: set[str] = set()
        while pending:
            source_event_id = pending.pop()
            if source_event_id in ancestor_ids:
                continue
            source = self.by_id(source_event_id)
            if source is None or source.kind is EventKind.GUARDRAIL_DECISION:
                raise ValueError("source event is not available in this trace")
            ancestor_ids.add(source_event_id)
            pending.extend(source.source_event_ids)
        return tuple(
            historical
            for historical in self.events
            if historical.id in ancestor_ids and (kind is None or historical.kind is kind)
        )

    def previous(self, *, kind: EventKind | None = None) -> Event | None:
        """Return the newest event, optionally filtered by kind."""

        for event in reversed(self.events):
            if kind is None or event.kind is kind:
                return event
        return None

    def count(
        self,
        *,
        kind: EventKind | None = None,
        tool_name: str | None = None,
    ) -> int:
        """Count matching historical events without exposing provider formats."""

        count = 0
        for event in self.events:
            if kind is not None and event.kind is not kind:
                continue
            if tool_name is not None and event.payload.get("name") != tool_name:
                continue
            count += 1
        return count

    @staticmethod
    def _validate_relations(
        event: Event,
        known_events: dict[str, Event],
    ) -> None:
        relation_keys = [(relation.source_event_id, relation.kind) for relation in event.relations]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("event relations must be unique")
        if event.id in {relation.source_event_id for relation in event.relations}:
            raise ValueError("an event cannot cite itself as a relation source")
        missing = set(event.source_event_ids) - known_events.keys()
        if missing:
            raise ValueError("relations must refer to earlier events in the same trace")
        if any(
            known_events[source_event_id].kind is EventKind.GUARDRAIL_DECISION
            for source_event_id in event.source_event_ids
        ):
            raise ValueError("guardrail decision events cannot be provenance sources")


class GuardrailContext(CanonicalModel):
    """The current event plus bounded task-level context."""

    event: Event
    trace: Trace
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        if self.event.trace_id != self.trace.id:
            raise ValueError("event and trace IDs must match")
        self.trace.sources_of(self.event)
        return self


class PendingTrace(CanonicalModel):
    """An immutable analysis snapshot of committed history plus pending events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trace: Trace
    events: tuple[Event, ...] = Field(
        min_length=1,
        max_length=MAX_PENDING_EVENTS,
    )
    primary_event_id: str = Field(min_length=1)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_pending_events(self) -> Self:
        pending_ids = [event.id for event in self.events]
        if len(pending_ids) != len(set(pending_ids)):
            raise ValueError("pending event IDs must be unique")
        if self.primary_event_id not in pending_ids:
            raise ValueError("primary_event_id must identify a pending event")
        if any(event.kind is EventKind.GUARDRAIL_DECISION for event in self.events):
            raise ValueError("guardrail decision events cannot be pending inputs")
        phases = {event.phase for event in self.events}
        if len(phases) != 1:
            raise ValueError("all pending events must use the same enforcement phase")

        expected_sequence = self.trace.next_sequence
        for offset, event in enumerate(self.events):
            if event.trace_id != self.trace.id:
                raise ValueError("all pending events must belong to the committed trace")
            if event.sequence != expected_sequence + offset:
                raise ValueError("pending event sequences must continue the committed trace")

        Trace(
            id=self.trace.id,
            events=(*self.trace.events, *self.events),
            metadata=self.trace.metadata,
            max_events=self.trace.max_events,
        )
        return self

    @classmethod
    def from_context(cls, context: GuardrailContext) -> Self:
        """Adapt the direct v0.1 single-event API to the pending analyzer boundary."""

        return cls(
            trace=context.trace.model_copy(deep=True),
            events=(context.event,),
            primary_event_id=context.event.id,
            attributes=dict(context.attributes),
        )

    @property
    def primary_event(self) -> Event:
        """Return the event used as the identity of the aggregate decision."""

        return next(event for event in self.events if event.id == self.primary_event_id)

    @property
    def event_ids(self) -> tuple[str, ...]:
        """Return every pending event ID in batch order."""

        return tuple(event.id for event in self.events)

class DetectionContext(CanonicalModel):
    """Minimal context exposed to a detector."""

    trace_id: str
    event_id: str
    phase: Phase


class Detection(CanonicalModel):
    """A detector fact whose evidence is safe to audit."""

    type: str = Field(min_length=1)
    detector: str = Field(min_length=1)
    detector_version: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)
    path: str | None = None
    masked_evidence: str = Field(min_length=1)
    fingerprint: str = Field(min_length=8)

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must be set together")
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("end must be greater than start")
        return self


class Violation(CanonicalModel):
    """A rule match; Engine attaches the configured action before returning it."""

    model_version: Literal[2] = 2
    rule_id: str = Field(min_length=1)
    code: str = Field(min_length=1)
    phase: Phase
    message: str = Field(min_length=1)
    action: Action | None = None
    event_ids: tuple[str, ...] = ()
    evidence: tuple[Detection, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_event_ids(self) -> Self:
        if len(self.event_ids) != len(set(self.event_ids)):
            raise ValueError("violation event_ids must be unique")
        if any(not event_id.strip() or event_id != event_id.strip() for event_id in self.event_ids):
            raise ValueError("violation event_ids must be non-blank and trimmed")
        return self


class Decision(CanonicalModel):
    """The complete, serializable result of one Engine evaluation."""

    model_version: Literal[2] = 2
    action: Action
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    pending_event_ids: tuple[str, ...] = Field(min_length=1)
    phase: Phase
    policy_version: int = Field(ge=1)
    policy_hash: str = Field(min_length=8)
    violations: tuple[Violation, ...] = ()

    @model_validator(mode="after")
    def validate_action(self) -> Self:
        if len(self.pending_event_ids) != len(set(self.pending_event_ids)):
            raise ValueError("decision pending_event_ids must be unique")
        if self.event_id not in self.pending_event_ids:
            raise ValueError("decision event_id must identify a pending event")
        pending_ids = set(self.pending_event_ids)
        if any(not violation.event_ids for violation in self.violations):
            raise ValueError("decision violations must identify pending events")
        if any(not set(violation.event_ids).issubset(pending_ids) for violation in self.violations):
            raise ValueError("decision violations can only identify pending events")
        if any(violation.action is None for violation in self.violations):
            raise ValueError("decision violations must have a configured action")
        configured_actions = [
            action for violation in self.violations if (action := violation.action) is not None
        ]
        expected = max(
            configured_actions,
            key=lambda action: ACTION_PRIORITY[action],
            default=Action.ALLOW,
        )
        if self.action != expected:
            raise ValueError("decision action must aggregate all violation actions")
        return self

    @property
    def blocked(self) -> bool:
        """Whether the enforcement point must suppress the side effect."""

        return self.action is Action.BLOCK

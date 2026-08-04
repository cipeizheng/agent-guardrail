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
    """Provider-neutral event categories."""

    USER_MESSAGE = "user_message"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    GUARDRAIL_DECISION = "guardrail_decision"


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


class Event(CanonicalModel):
    """One immutable canonical event in an agent trace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_version: Literal[1] = 1
    id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    sequence: int = Field(ge=0)
    kind: EventKind
    phase: Phase
    timestamp: datetime
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_typed_payload(self) -> Self:
        if self.kind is EventKind.MODEL_REQUEST:
            from agent_guardrail.models.chat import ModelRequest

            ModelRequest.model_validate(self.payload)
        elif self.kind is EventKind.MODEL_RESPONSE:
            from agent_guardrail.models.chat import ModelResponse

            ModelResponse.model_validate(self.payload)
        elif self.kind is EventKind.TOOL_CALL:
            ToolCall.model_validate(self.payload)
        elif self.kind is EventKind.TOOL_RESULT:
            ToolResult.model_validate(self.payload)
        return self


class Trace(CanonicalModel):
    """A bounded, ordered in-memory collection of canonical events."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(min_length=1)
    events: tuple[Event, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    max_events: int = Field(default=1_000, ge=1, exclude=True)

    @model_validator(mode="after")
    def validate_events(self) -> Self:
        previous_sequence = -1
        for event in self.events:
            if event.trace_id != self.id:
                raise ValueError("all events must belong to this trace")
            if event.sequence <= previous_sequence:
                raise ValueError("event sequences must be strictly increasing")
            previous_sequence = event.sequence
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
        self.events = (*self.events, event)

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


class GuardrailContext(CanonicalModel):
    """The current event plus bounded task-level context."""

    event: Event
    trace: Trace
    attributes: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        if self.event.trace_id != self.trace.id:
            raise ValueError("event and trace IDs must match")
        return self


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

    model_version: Literal[1] = 1
    rule_id: str = Field(min_length=1)
    code: str = Field(min_length=1)
    phase: Phase
    message: str = Field(min_length=1)
    action: Action | None = None
    evidence: tuple[Detection, ...] = ()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class Decision(CanonicalModel):
    """The complete, serializable result of one Engine evaluation."""

    model_version: Literal[1] = 1
    action: Action
    trace_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    phase: Phase
    policy_version: int = Field(ge=1)
    policy_hash: str = Field(min_length=8)
    violations: tuple[Violation, ...] = ()

    @model_validator(mode="after")
    def validate_action(self) -> Self:
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

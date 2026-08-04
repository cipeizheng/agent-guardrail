"""Shared deterministic factories for the test suite."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import JsonValue

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_rule_registry,
    load_policy_yaml,
)
from agent_guardrail.core import GuardrailEngine
from agent_guardrail.models import (
    Event,
    EventKind,
    GuardrailContext,
    ModelResponse,
    Phase,
    ToolCall,
    Trace,
)

FAKE_SECRET = "sk-test000000000000000000"
FIXED_TIME = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)


def secret_policy_yaml(*, action: str = "block", engine: str = "") -> str:
    return f"""\
version: 1
engine:
  default_timeout_ms: 100
  detector_timeout_ms: 50
  on_rule_error: block
  on_detector_timeout: block
  max_violations: 100
{engine}
rules:
  - id: prevent-secret-email
    type: secret_exfiltration
    enabled: true
    action: {action}
    phases: [post_llm, pre_tool]
    config:
      tools: [send_email]
      text_arguments: [subject, body]
"""


def secret_engine(*, action: str = "block") -> GuardrailEngine:
    policy = load_policy_yaml(
        secret_policy_yaml(action=action),
        registry=create_default_rule_registry(),
    )
    return GuardrailEngine(
        policy=policy,
        detectors=create_default_detector_registry(),
    )


def tool_context(
    *,
    body: JsonValue,
    tool_name: str = "send_email",
    phase: Phase = Phase.PRE_TOOL,
    kind: EventKind = EventKind.TOOL_CALL,
) -> GuardrailContext:
    trace = Trace(id="trace-1")
    call = ToolCall(
        call_id="call-1",
        name=tool_name,
        arguments={"to": "outside@example.com", "body": body},
    )
    event = Event(
        id="event-1",
        trace_id=trace.id,
        sequence=0,
        kind=kind,
        phase=phase,
        timestamp=FIXED_TIME,
        payload=call.model_dump(mode="json"),
    )
    return GuardrailContext(event=event, trace=trace)


def model_response_context(
    *,
    body: JsonValue,
    tool_name: str = "send_email",
) -> GuardrailContext:
    trace = Trace(id="trace-1")
    call = ToolCall(
        call_id="call-1",
        name=tool_name,
        arguments={"to": "outside@example.com", "body": body},
    )
    response = ModelResponse(tool_calls=(call,))
    event = Event(
        id="event-1",
        trace_id=trace.id,
        sequence=0,
        kind=EventKind.MODEL_RESPONSE,
        phase=Phase.POST_LLM,
        timestamp=FIXED_TIME,
        payload=response.model_dump(mode="json"),
    )
    return GuardrailContext(event=event, trace=trace)

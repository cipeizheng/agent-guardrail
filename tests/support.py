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
    ToolResult,
    Trace,
)

FAKE_SECRET = "sk-test000000000000000000"
FAKE_PII = "customer@example.test"
FAKE_CN_MOBILE = "139 0000 0001"
FIXED_TIME = datetime(2026, 8, 4, 12, 0, tzinfo=UTC)

_CN_RESIDENT_ID_WEIGHTS = (
    7,
    9,
    10,
    5,
    8,
    4,
    2,
    1,
    6,
    3,
    7,
    9,
    10,
    5,
    8,
    4,
    2,
)
_CN_RESIDENT_ID_CHECK_CHARACTERS = "10X98765432"


def fake_cn_resident_id(master_number: str = "11000020000101001") -> str:
    """Build a checksum-valid, explicitly synthetic test identity number."""

    checksum = sum(
        int(character) * weight
        for character, weight in zip(
            master_number,
            _CN_RESIDENT_ID_WEIGHTS,
            strict=True,
        )
    )
    return master_number + _CN_RESIDENT_ID_CHECK_CHARACTERS[checksum % 11]


FAKE_CN_RESIDENT_ID = fake_cn_resident_id()


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


def pii_policy_yaml(
    *,
    action: str = "block",
    tools: tuple[str, ...] = ("send_email",),
    text_arguments: tuple[str, ...] = ("subject", "body"),
    entities: tuple[str, ...] = (
        "email_address",
        "phone_number",
        "us_ssn",
        "credit_card",
        "cn_resident_id",
        "cn_mobile_phone",
    ),
    phases: str = "[post_llm, pre_tool]",
) -> str:
    tool_names = ", ".join(tools)
    argument_names = ", ".join(text_arguments)
    entity_names = ", ".join(entities)
    return f"""\
version: 1
engine:
  default_timeout_ms: 100
  detector_timeout_ms: 50
  on_rule_error: block
  on_detector_timeout: block
  max_violations: 100
rules:
  - id: prevent-pii-email
    type: pii_exfiltration
    enabled: true
    action: {action}
    phases: {phases}
    config:
      tools: [{tool_names}]
      text_arguments: [{argument_names}]
      entities: [{entity_names}]
"""


def pii_engine(
    *,
    action: str = "block",
    entities: tuple[str, ...] = (
        "email_address",
        "phone_number",
        "us_ssn",
        "credit_card",
        "cn_resident_id",
        "cn_mobile_phone",
    ),
) -> GuardrailEngine:
    policy = load_policy_yaml(
        pii_policy_yaml(action=action, entities=entities),
        registry=create_default_rule_registry(),
    )
    return GuardrailEngine(
        policy=policy,
        detectors=create_default_detector_registry(),
    )


def tool_access_policy_yaml(
    *,
    mode: str = "denylist",
    tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
    phases: str = "[post_llm, pre_tool]",
) -> str:
    tool_names = ", ".join(tools)
    return f"""\
version: 1
engine:
  default_timeout_ms: 100
  detector_timeout_ms: 50
  on_rule_error: block
  on_detector_timeout: block
  max_violations: 100
rules:
  - id: restrict-tools
    type: tool_access
    enabled: true
    action: {action}
    phases: {phases}
    config:
      mode: {mode}
      tools: [{tool_names}]
"""


def tool_access_engine(
    *,
    mode: str = "denylist",
    tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
) -> GuardrailEngine:
    policy = load_policy_yaml(
        tool_access_policy_yaml(mode=mode, tools=tools, action=action),
        registry=create_default_rule_registry(),
    )
    return GuardrailEngine(
        policy=policy,
        detectors=create_default_detector_registry(),
    )


def tool_result_flow_policy_yaml(
    *,
    source_tools: tuple[str, ...] = ("read_private_file",),
    destination_tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
    phases: str = "[pre_tool]",
) -> str:
    source_tool_names = ", ".join(source_tools)
    destination_tool_names = ", ".join(destination_tools)
    return f"""\
version: 1
engine:
  default_timeout_ms: 100
  detector_timeout_ms: 50
  on_rule_error: block
  on_detector_timeout: block
  max_violations: 100
rules:
  - id: restrict-tool-result-flow
    type: tool_result_flow
    enabled: true
    action: {action}
    phases: {phases}
    config:
      source_tools: [{source_tool_names}]
      destination_tools: [{destination_tool_names}]
"""


def tool_result_flow_engine(
    *,
    source_tools: tuple[str, ...] = ("read_private_file",),
    destination_tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
) -> GuardrailEngine:
    policy = load_policy_yaml(
        tool_result_flow_policy_yaml(
            source_tools=source_tools,
            destination_tools=destination_tools,
            action=action,
        ),
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
    payload = call.model_dump(mode="json")
    if kind is EventKind.TOOL_RESULT:
        payload = ToolResult(
            call_id=call.call_id,
            name=call.name,
            output="safe result",
        ).model_dump(mode="json")
    event = Event(
        id="event-1",
        trace_id=trace.id,
        sequence=0,
        kind=kind,
        phase=phase,
        timestamp=FIXED_TIME,
        payload=payload,
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

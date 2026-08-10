"""Shared deterministic factories for the test suite."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import JsonValue

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
    load_policy_yaml,
)
from agent_guardrail.core import MatchPolicyAnalyzer
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

_CN_RESIDENT_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
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
version: 3
engine:
  max_violations: 100
  on_analysis_error: block
  on_detector_timeout: block
{engine}scopes: [pending]
rules:
  - id: prevent-secret-email
    action: {action}
    events:
      call: {{kind: tool_call, domain: pending, phases: [post_llm, pre_tool]}}
    where:
      all:
        - tool: {{binding: call, name: send_email}}
        - detector:
            id: secret_scan
            capability: secrets
            inputs:
              - value: {{field: [call, payload, arguments]}}
                encoding: canonical_json
    finding:
      code: secret_exfiltration
      message: The tool call contains secret material.
      subjects: [call]
      evidence: [{{source: detector, id: secret_scan}}]
"""


def secret_analyzer(*, action: str = "block") -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(secret_policy_yaml(action=action))


def pii_policy_yaml(
    *,
    action: str = "block",
    tools: tuple[str, ...] = ("send_email",),
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
    return f"""\
version: 3
engine: {{max_violations: 100, on_analysis_error: block, on_detector_timeout: block}}
scopes: [pending]
rules:
  - id: prevent-pii-email
    action: {action}
    events:
      call: {{kind: tool_call, domain: pending, phases: {phases}}}
    where:
      all:
        - compare:
            left: {{field: [call, payload, name]}}
            operator: in
            right: {{literal: {_inline(tools)}}}
        - detector:
            id: pii_scan
            capability: pii
            inputs:
              - value: {{field: [call, payload, arguments]}}
                encoding: canonical_json
            types_any: {_inline(entities)}
    finding:
      code: pii_exfiltration
      message: The tool call contains personally identifiable information.
      subjects: [call]
      evidence: [{{source: detector, id: pii_scan}}]
"""


def pii_analyzer(
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
) -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(pii_policy_yaml(action=action, entities=entities))


def tool_access_policy_yaml(
    *,
    mode: str = "denylist",
    tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
    phases: str = "[post_llm, pre_tool]",
) -> str:
    operator = "in" if mode == "denylist" else "not_in"
    return f"""\
version: 3
scopes: [pending]
rules:
  - id: restrict-tools
    action: {action}
    events:
      call: {{kind: tool_call, domain: pending, phases: {phases}}}
    where:
      compare:
        left: {{field: [call, payload, name]}}
        operator: {operator}
        right: {{literal: {_inline(tools)}}}
    finding:
      code: tool_access_denied
      message: The requested tool is not allowed by policy.
      subjects: [call]
"""


def tool_access_analyzer(
    *,
    mode: str = "denylist",
    tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
) -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(
        tool_access_policy_yaml(mode=mode, tools=tools, action=action)
    )


def tool_result_flow_policy_yaml(
    *,
    source_tools: tuple[str, ...] = ("read_private_file",),
    destination_tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
) -> str:
    return f"""\
version: 3
scopes: [pending]
rules:
  - id: restrict-tool-result-flow
    action: {action}
    events:
      source: {{kind: tool_call, domain: past}}
      result: {{kind: tool_result, domain: past}}
      destination: {{kind: tool_call, domain: pending, phases: [pre_tool]}}
    where:
      all:
        - compare:
            left: {{field: [source, payload, name]}}
            operator: in
            right: {{literal: {_inline(source_tools)}}}
        - compare:
            left: {{field: [destination, payload, name]}}
            operator: in
            right: {{literal: {_inline(destination_tools)}}}
        - relation:
            source: source
            target: result
            operator: derived_from_direct
        - relation:
            source: result
            target: destination
            operator: derived_from_ancestor
    finding:
      code: tool_result_flow_denied
      message: The requested tool flow is not allowed by policy.
      subjects: [destination]
"""


def tool_result_flow_analyzer(
    *,
    source_tools: tuple[str, ...] = ("read_private_file",),
    destination_tools: tuple[str, ...] = ("send_email",),
    action: str = "block",
) -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(
        tool_result_flow_policy_yaml(
            source_tools=source_tools,
            destination_tools=destination_tools,
            action=action,
        )
    )


def empty_policy_yaml() -> str:
    return "version: 3\nscopes: [pending]\nrules: []\n"


def empty_analyzer() -> MatchPolicyAnalyzer:
    return analyzer_from_yaml(empty_policy_yaml())


def analyzer_from_yaml(source: str) -> MatchPolicyAnalyzer:
    detectors = create_default_detector_registry()
    policy = load_policy_yaml(
        source,
        detectors=detectors,
        predicates=create_default_predicate_registry(),
    )
    return MatchPolicyAnalyzer(policy)


def _inline(values: tuple[str, ...]) -> str:
    return json.dumps(values, ensure_ascii=False)


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

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardrail.config import (
    PolicyLoadError,
    create_default_rule_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.models import (
    Action,
    ChatMessage,
    ChatRole,
    Event,
    EventKind,
    EventRelation,
    GuardrailContext,
    ModelRequest,
    ModelResponse,
    Phase,
    ToolCall,
    ToolResult,
    Trace,
)
from tests.support import (
    FIXED_TIME,
    tool_result_flow_engine,
    tool_result_flow_policy_yaml,
)


def flow_context(
    *,
    linked: bool = True,
    source_tool: str = "read_private_file",
    result_tool: str | None = None,
    destination_tool: str = "send_email",
) -> GuardrailContext:
    trace_id = "trace-1"
    source_call = Event(
        id="event-source-call",
        trace_id=trace_id,
        sequence=0,
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        timestamp=FIXED_TIME,
        payload=ToolCall(
            call_id="read-call",
            name=source_tool,
            arguments={"path": "report.txt"},
        ).model_dump(mode="json"),
    )
    source = Event(
        id="event-source",
        trace_id=trace_id,
        sequence=1,
        kind=EventKind.TOOL_RESULT,
        phase=Phase.POST_TOOL,
        timestamp=FIXED_TIME,
        payload=ToolResult(
            call_id="read-call",
            name=result_tool or source_tool,
            output="private report",
        ).model_dump(mode="json"),
        relations=(EventRelation(source_event_id=source_call.id),),
    )
    request = Event(
        id="event-request",
        trace_id=trace_id,
        sequence=2,
        kind=EventKind.MODEL_REQUEST,
        phase=Phase.PRE_LLM,
        timestamp=FIXED_TIME,
        payload=ModelRequest(
            messages=(ChatMessage(role=ChatRole.USER, content="continue"),)
        ).model_dump(mode="json"),
        relations=(EventRelation(source_event_id=source.id),),
    )
    call = ToolCall(call_id="email-call", name=destination_tool, arguments={})
    response = Event(
        id="event-response",
        trace_id=trace_id,
        sequence=3,
        kind=EventKind.MODEL_RESPONSE,
        phase=Phase.POST_LLM,
        timestamp=FIXED_TIME,
        payload=ModelResponse(tool_calls=(call,)).model_dump(mode="json"),
        relations=(EventRelation(source_event_id=request.id),),
    )
    current = Event(
        id="event-current",
        trace_id=trace_id,
        sequence=4,
        kind=EventKind.TOOL_CALL,
        phase=Phase.PRE_TOOL,
        timestamp=FIXED_TIME,
        payload=call.model_dump(mode="json"),
        relations=((EventRelation(source_event_id=response.id),) if linked else ()),
    )
    return GuardrailContext(
        event=current,
        trace=Trace(
            id=trace_id,
            events=(source_call, source, request, response),
        ),
    )


@pytest.mark.asyncio
async def test_transitive_tool_result_flow_is_blocked_without_raw_output() -> None:
    decision = await tool_result_flow_engine().evaluate(flow_context())

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert decision.violations[0].code == "tool_result_flow_denied"
    assert decision.violations[0].metadata["matched_source_event_ids"] == ["event-source"]
    assert "private report" not in serialized
    assert "read_private_file" not in serialized
    assert "send_email" not in serialized


@pytest.mark.asyncio
async def test_temporal_order_without_provenance_edge_is_allowed() -> None:
    decision = await tool_result_flow_engine().evaluate(flow_context(linked=False))

    assert decision.action is Action.ALLOW
    assert not decision.violations


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("source_tool", "destination_tool"),
    [("get_weather", "send_email"), ("read_private_file", "save_draft")],
)
async def test_non_configured_flow_is_allowed(
    source_tool: str,
    destination_tool: str,
) -> None:
    decision = await tool_result_flow_engine().evaluate(
        flow_context(source_tool=source_tool, destination_tool=destination_tool)
    )

    assert decision.action is Action.ALLOW


@pytest.mark.asyncio
async def test_mismatched_tool_result_identity_is_not_a_trusted_source() -> None:
    decision = await tool_result_flow_engine().evaluate(flow_context(result_tool="get_weather"))

    assert decision.action is Action.ALLOW


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (tool_result_flow_policy_yaml(source_tools=()), "too_short"),
        (tool_result_flow_policy_yaml(destination_tools=()), "too_short"),
        (
            tool_result_flow_policy_yaml(source_tools=("read_private_file", "read_private_file")),
            "unique",
        ),
        (
            tool_result_flow_policy_yaml().replace(
                "      destination_tools: [send_email]",
                '      destination_tools: [" send_email "]',
            ),
            "surrounding whitespace",
        ),
        (
            tool_result_flow_policy_yaml().replace(
                "      destination_tools: [send_email]",
                "      destination_tools: [send_email]\n      unknown: true",
            ),
            "unknown",
        ),
        (tool_result_flow_policy_yaml(phases="[post_llm]"), "does not support"),
    ],
)
def test_invalid_tool_result_flow_config_fails_policy_loading(
    source: str,
    message: str,
) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load_policy_yaml(source, registry=create_default_rule_registry())


def test_tool_result_flow_example_policy_loads() -> None:
    path = Path(__file__).parents[2] / "examples/policies/tool-result-flow.yaml"

    policy = load_policy_file(path, registry=create_default_rule_registry())

    assert len(policy.rules) == 1
    assert policy.rules[0].rule.id == "prevent-private-file-email"
    assert policy.rules[0].rule.phases == frozenset({Phase.PRE_TOOL})

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guardrail.config import (
    PolicyLoadError,
    create_default_rule_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.models import Action, EventKind, Phase
from tests.support import (
    FAKE_SECRET,
    model_response_context,
    tool_access_engine,
    tool_access_policy_yaml,
    tool_context,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "configured_tools", "tool_name", "expected_action"),
    [
        ("allowlist", ("get_weather",), "get_weather", Action.ALLOW),
        ("allowlist", ("get_weather",), "send_email", Action.BLOCK),
        ("denylist", ("send_email",), "get_weather", Action.ALLOW),
        ("denylist", ("send_email",), "send_email", Action.BLOCK),
    ],
)
async def test_tool_access_modes(
    mode: str,
    configured_tools: tuple[str, ...],
    tool_name: str,
    expected_action: Action,
) -> None:
    decision = await tool_access_engine(mode=mode, tools=configured_tools).evaluate(
        tool_context(body="safe", tool_name=tool_name)
    )

    assert decision.action is expected_action
    if expected_action is Action.BLOCK:
        violation = decision.violations[0]
        assert violation.code == "tool_access_denied"
        assert violation.metadata["mode"] == mode
        assert len(str(violation.metadata["tool_name_fingerprint"])) == 16
        assert "body" not in decision.model_dump_json()
    else:
        assert not decision.violations


@pytest.mark.asyncio
async def test_post_llm_denied_tool_call_is_blocked() -> None:
    decision = await tool_access_engine().evaluate(
        model_response_context(body="safe", tool_name="send_email")
    )

    assert decision.action is Action.BLOCK
    assert decision.phase is Phase.POST_LLM
    assert decision.violations[0].metadata["mode"] == "denylist"


@pytest.mark.asyncio
async def test_untrusted_tool_name_is_fingerprinted_in_violation_metadata() -> None:
    decision = await tool_access_engine(mode="allowlist", tools=("get_weather",)).evaluate(
        tool_context(body="safe", tool_name=FAKE_SECRET)
    )

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert FAKE_SECRET not in serialized
    assert "tool_name_fingerprint" in serialized


@pytest.mark.asyncio
async def test_log_action_reports_violation_without_blocking() -> None:
    decision = await tool_access_engine(action="log").evaluate(
        tool_context(body="safe", tool_name="send_email")
    )

    assert decision.action is Action.LOG
    assert decision.violations[0].action is Action.LOG


@pytest.mark.asyncio
async def test_non_applicable_boundary_is_allowed() -> None:
    engine = tool_access_engine()

    wrong_phase = await engine.evaluate(
        tool_context(body="safe", tool_name="send_email", phase=Phase.POST_TOOL)
    )
    wrong_kind = await engine.evaluate(
        tool_context(
            body="safe",
            tool_name="send_email",
            kind=EventKind.TOOL_RESULT,
        )
    )

    assert wrong_phase.action is Action.ALLOW
    assert wrong_kind.action is Action.ALLOW


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (tool_access_policy_yaml(mode="invalid"), "mode"),
        (tool_access_policy_yaml().replace("      mode: denylist\n", ""), "mode"),
        (tool_access_policy_yaml(tools=()), "too_short"),
        (tool_access_policy_yaml(tools=('""',)), "cannot be blank"),
        (tool_access_policy_yaml(tools=("send_email", "send_email")), "unique"),
        (
            tool_access_policy_yaml().replace(
                "      tools: [send_email]",
                '      tools: [" send_email "]',
            ),
            "surrounding whitespace",
        ),
        (
            tool_access_policy_yaml().replace(
                "      tools: [send_email]",
                "      tools: [send_email]\n      unknown: true",
            ),
            "unknown",
        ),
        (tool_access_policy_yaml(phases="[pre_llm]"), "does not support"),
    ],
)
def test_invalid_tool_access_config_fails_policy_loading(source: str, message: str) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load_policy_yaml(source, registry=create_default_rule_registry())


def test_tool_access_example_policy_loads() -> None:
    path = Path(__file__).parents[2] / "examples/policies/tool-access.yaml"

    policy = load_policy_file(path, registry=create_default_rule_registry())

    assert len(policy.rules) == 1
    assert policy.rules[0].rule.id == "restrict-tools"
    assert policy.rules[0].rule.phases == frozenset({Phase.POST_LLM, Phase.PRE_TOOL})

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
    FAKE_CN_MOBILE,
    FAKE_CN_RESIDENT_ID,
    FAKE_PII,
    model_response_context,
    pii_engine,
    pii_policy_yaml,
    tool_context,
)


@pytest.mark.asyncio
async def test_safe_outbound_argument_is_allowed() -> None:
    decision = await pii_engine().evaluate(tool_context(body="Quarterly report attached."))

    assert decision.action is Action.ALLOW
    assert not decision.violations


@pytest.mark.asyncio
async def test_selected_pii_is_blocked_with_only_masked_evidence() -> None:
    decision = await pii_engine().evaluate(tool_context(body=f"Contact {FAKE_PII}."))

    serialized = decision.model_dump_json()
    violation = decision.violations[0]
    assert decision.action is Action.BLOCK
    assert violation.code == "pii_exfiltration"
    assert violation.evidence[0].path == "$.arguments.body"
    assert violation.metadata["pii_types"] == ["email_address"]
    assert FAKE_PII not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "entity_type"),
    [
        (FAKE_CN_RESIDENT_ID, "cn_resident_id"),
        (FAKE_CN_MOBILE, "cn_mobile_phone"),
    ],
)
async def test_selected_mainland_china_pii_is_blocked_without_raw_evidence(
    value: str,
    entity_type: str,
) -> None:
    decision = await pii_engine(entities=(entity_type,)).evaluate(tool_context(body=value))

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert decision.violations[0].metadata["pii_types"] == [entity_type]
    assert value not in serialized


@pytest.mark.asyncio
async def test_unselected_pii_entity_is_allowed() -> None:
    decision = await pii_engine(entities=("phone_number",)).evaluate(tool_context(body=FAKE_PII))

    assert decision.action is Action.ALLOW
    assert not decision.violations


@pytest.mark.asyncio
async def test_log_action_reports_pii_without_blocking() -> None:
    decision = await pii_engine(action="log").evaluate(tool_context(body=FAKE_PII))

    assert decision.action is Action.LOG
    assert decision.violations[0].action is Action.LOG


@pytest.mark.asyncio
async def test_non_target_tool_and_non_applicable_event_are_allowed() -> None:
    engine = pii_engine()

    other_tool = await engine.evaluate(tool_context(body=FAKE_PII, tool_name="save_draft"))
    wrong_phase = await engine.evaluate(tool_context(body=FAKE_PII, phase=Phase.POST_TOOL))
    wrong_kind = await engine.evaluate(tool_context(body=FAKE_PII, kind=EventKind.TOOL_RESULT))

    assert other_tool.action is Action.ALLOW
    assert wrong_phase.action is Action.ALLOW
    assert wrong_kind.action is Action.ALLOW


@pytest.mark.asyncio
async def test_post_llm_pii_tool_call_is_blocked() -> None:
    decision = await pii_engine().evaluate(model_response_context(body=FAKE_PII))

    serialized = decision.model_dump_json()
    assert decision.action is Action.BLOCK
    assert decision.phase is Phase.POST_LLM
    assert decision.violations[0].evidence[0].path == ("$.tool_calls[0].arguments.body")
    assert FAKE_PII not in serialized


@pytest.mark.asyncio
async def test_nested_json_argument_is_scanned() -> None:
    decision = await pii_engine().evaluate(tool_context(body={"customer": {"email": FAKE_PII}}))

    assert decision.action is Action.BLOCK


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (pii_policy_yaml(tools=()), "too_short"),
        (pii_policy_yaml(text_arguments=()), "too_short"),
        (pii_policy_yaml(entities=()), "too_short"),
        (pii_policy_yaml(tools=('""',)), "cannot be blank"),
        (pii_policy_yaml(text_arguments=("body", "body")), "unique"),
        (pii_policy_yaml(entities=("email_address", "email_address")), "unique"),
        (pii_policy_yaml(entities=("passport_number",)), "literal_error"),
        (
            pii_policy_yaml().replace(
                "      tools: [send_email]",
                '      tools: [" send_email "]',
            ),
            "surrounding whitespace",
        ),
        (
            pii_policy_yaml().replace(
                "      entities: [email_address, phone_number, us_ssn, credit_card, "
                "cn_resident_id, cn_mobile_phone]",
                "      entities: [email_address]\n      unknown: true",
            ),
            "unknown",
        ),
        (pii_policy_yaml(phases="[pre_llm]"), "does not support"),
    ],
)
def test_invalid_pii_config_fails_policy_loading(source: str, message: str) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load_policy_yaml(source, registry=create_default_rule_registry())


def test_pii_example_policy_loads() -> None:
    path = Path(__file__).parents[2] / "examples/policies/pii-email.yaml"

    policy = load_policy_file(path, registry=create_default_rule_registry())

    assert len(policy.rules) == 1
    assert policy.rules[0].rule.id == "prevent-selected-pii-email"
    assert policy.rules[0].rule.phases == frozenset({Phase.POST_LLM, Phase.PRE_TOOL})

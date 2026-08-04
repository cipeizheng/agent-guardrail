from __future__ import annotations

import pytest

from agent_guardrail.config import PolicyLoadError, create_default_rule_registry, load_policy_yaml
from agent_guardrail.models import Action, Phase
from tests.support import FAKE_SECRET, secret_policy_yaml


def test_loads_registered_rule_and_produces_stable_hash() -> None:
    registry = create_default_rule_registry()

    first = load_policy_yaml(secret_policy_yaml(action="log"), registry=registry)
    second = load_policy_yaml(secret_policy_yaml(action="log"), registry=registry)

    assert first.content_hash == second.content_hash
    assert len(first.content_hash) == 64
    assert first.rules[0].action is Action.LOG
    assert first.rules[0].rule.phases == frozenset({Phase.POST_LLM, Phase.PRE_TOOL})


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("[]", "root must be a mapping"),
        (secret_policy_yaml() + "unexpected: true\n", "schema validation"),
        (secret_policy_yaml().replace("secret_exfiltration", "missing_rule"), "unknown rule"),
        (
            secret_policy_yaml().replace("[post_llm, pre_tool]", "[post_tool]"),
            "does not support",
        ),
        (secret_policy_yaml().replace("version: 1", "version: 2"), "schema validation"),
    ],
)
def test_rejects_invalid_or_unknown_policy(source: str, message: str) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load_policy_yaml(source, registry=create_default_rule_registry())


def test_rule_config_forbids_dynamic_python_and_redacts_input_from_error() -> None:
    source = secret_policy_yaml().replace(
        "      text_arguments: [subject, body]",
        "      text_arguments: [subject, body]\n"
        f"      python_module: malicious.module.{FAKE_SECRET}",
    )

    with pytest.raises(PolicyLoadError) as error:
        load_policy_yaml(source, registry=create_default_rule_registry())

    assert "python_module" in str(error.value)
    assert FAKE_SECRET not in str(error.value)


def test_duplicate_rule_ids_fail_atomically() -> None:
    duplicated_rule = """
  - id: prevent-secret-email
    type: secret_exfiltration
    enabled: false
    action: block
    phases: [pre_tool]
    config: {}
"""

    with pytest.raises(PolicyLoadError, match="unique"):
        load_policy_yaml(
            secret_policy_yaml() + duplicated_rule,
            registry=create_default_rule_registry(),
        )


def test_disabled_rule_still_requires_a_registered_type_and_valid_config() -> None:
    source = (
        secret_policy_yaml()
        .replace("enabled: true", "enabled: false")
        .replace(
            "      text_arguments: [subject, body]",
            "      text_arguments: [subject, body]\n      unknown_config: true",
        )
    )

    with pytest.raises(PolicyLoadError, match="unknown_config"):
        load_policy_yaml(source, registry=create_default_rule_registry())


def test_engine_limits_do_not_coerce_yaml_strings() -> None:
    source = secret_policy_yaml().replace("default_timeout_ms: 100", 'default_timeout_ms: "100"')

    with pytest.raises(PolicyLoadError, match="schema validation"):
        load_policy_yaml(source, registry=create_default_rule_registry())

from __future__ import annotations

import pytest

from agent_guardrail.config import (
    PolicyLoadError,
    create_default_detector_registry,
    create_default_predicate_registry,
    load_policy_yaml,
)
from agent_guardrail.models import Action
from tests.support import secret_policy_yaml


def load(source: str):
    return load_policy_yaml(
        source,
        detectors=create_default_detector_registry(),
        predicates=create_default_predicate_registry(),
    )


def test_policy_defaults_are_normalized_and_hash_is_deterministic() -> None:
    first = load(secret_policy_yaml(action="log"))
    second = load(secret_policy_yaml(action="log"))

    assert first.version == 3
    assert first.content_hash == second.content_hash
    assert first.actions[0].action is Action.LOG
    assert first.match_plan.plan.rules[0].id == "prevent-secret-email"


@pytest.mark.parametrize(
    "source, message",
    [
        (secret_policy_yaml() + "unexpected: true\n", "schema validation"),
        (secret_policy_yaml().replace("version: 3", "version: 2"), "schema validation"),
        (
            secret_policy_yaml().replace(
                "    events:\n",
                "    module: unsafe.policy\n    events:\n",
            ),
            "schema validation",
        ),
        (
            secret_policy_yaml().replace("capability: secrets", "capability: unavailable"),
            "compilation failed",
        ),
    ],
)
def test_invalid_or_legacy_policy_is_rejected_atomically(source: str, message: str) -> None:
    with pytest.raises(PolicyLoadError, match=message):
        load(source)


def test_duplicate_keys_and_yaml_indirection_are_rejected() -> None:
    with pytest.raises(PolicyLoadError, match="not valid YAML"):
        load("version: 3\nversion: 3\nscopes: [pending]\nrules: []\n")
    with pytest.raises(PolicyLoadError, match="cannot use aliases"):
        load("version: 3\nscopes: &scope [pending]\nrules: []\n")


def test_empty_v3_policy_is_valid() -> None:
    policy = load("version: 3\nscopes: [pending]\nrules: []\n")

    assert policy.match_plan.plan.rules == ()
    assert policy.actions == ()

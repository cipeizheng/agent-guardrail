"""Load a complete policy from YAML without executing external code."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import yaml
from pydantic import ValidationError

from agent_guardrail.core.policy import PolicyDocument, PolicySet, RuleBinding
from agent_guardrail.core.registry import RegistryError, RuleRegistry


class PolicyLoadError(ValueError):
    """A safe, input-redacted policy loading failure."""


def load_policy_yaml(source: str, *, registry: RuleRegistry) -> PolicySet:
    """Validate all YAML and construct an immutable policy atomically."""

    try:
        raw_document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise PolicyLoadError("policy is not valid YAML") from exc

    if not isinstance(raw_document, dict):
        raise PolicyLoadError("policy root must be a mapping")

    try:
        document = PolicyDocument.model_validate(raw_document)
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise PolicyLoadError(f"policy schema validation failed: {details}") from exc

    bindings: list[RuleBinding] = []
    normalized_rules: list[dict[str, object]] = []
    for entry in document.rules:
        try:
            built = registry.build(
                entry.type,
                rule_id=entry.id,
                phases=frozenset(entry.phases),
                raw_config=dict(entry.config),
            )
        except RegistryError as exc:
            raise PolicyLoadError(str(exc)) from exc

        if entry.enabled:
            bindings.append(RuleBinding(rule=built.rule, action=entry.action))
        normalized_entry = entry.model_dump(mode="json")
        normalized_entry["config"] = built.normalized_config
        normalized_rules.append(normalized_entry)

    normalized_document = document.model_dump(mode="json")
    normalized_document["rules"] = normalized_rules
    canonical = json.dumps(
        normalized_document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    content_hash = sha256(canonical.encode("utf-8")).hexdigest()

    return PolicySet(
        version=document.version,
        content_hash=content_hash,
        engine=document.engine,
        rules=tuple(bindings),
    )


def load_policy_file(path: str | Path, *, registry: RuleRegistry) -> PolicySet:
    """Read and load a UTF-8 policy file."""

    policy_path = Path(path)
    try:
        source = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"cannot read policy file: {policy_path}") from exc
    return load_policy_yaml(source, registry=registry)

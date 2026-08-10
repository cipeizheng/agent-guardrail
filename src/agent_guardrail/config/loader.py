"""Load the breaking v3 production policy without executing external code."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import yaml
from pydantic import TypeAdapter, ValidationError
from yaml.constructor import ConstructorError
from yaml.tokens import AliasToken, AnchorToken, TagToken

from agent_guardrail.core.authoring import AuthorPolicyCompilationError, compile_author_policy
from agent_guardrail.core.capabilities import (
    CapabilityCompilationError,
    compile_match_plan_capabilities,
)
from agent_guardrail.core.policy import CompiledPolicy, PolicyDocument, RuleAction
from agent_guardrail.core.registry import DetectorRegistry, PredicateRegistry


class PolicyLoadError(ValueError):
    """A safe, input-redacted policy loading failure."""


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _StrictSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)
_POLICY_DOCUMENT_ADAPTER = TypeAdapter(PolicyDocument)


def load_policy_yaml(
    source: str,
    *,
    detectors: DetectorRegistry | None = None,
    predicates: PredicateRegistry | None = None,
) -> CompiledPolicy:
    """Validate, compile and capability-link one complete v3 policy atomically."""

    try:
        _reject_yaml_indirection(source)
        raw_document = yaml.load(source, Loader=_StrictSafeLoader)
    except PolicyLoadError:
        raise
    except (yaml.YAMLError, ConstructorError) as exc:
        raise PolicyLoadError("policy is not valid YAML") from exc

    if not isinstance(raw_document, dict):
        raise PolicyLoadError("policy root must be a mapping")

    try:
        document = _POLICY_DOCUMENT_ADAPTER.validate_python(raw_document)
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise PolicyLoadError(f"policy schema validation failed: {details}") from exc

    try:
        plan = compile_author_policy(document.analysis_policy())
        compiled = compile_match_plan_capabilities(
            plan,
            predicates=predicates or PredicateRegistry(),
            detectors=detectors or DetectorRegistry(),
        )
    except (AuthorPolicyCompilationError, CapabilityCompilationError) as exc:
        raise PolicyLoadError(f"policy compilation failed: {exc}") from exc

    canonical = json.dumps(
        document.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    content_hash = sha256(canonical.encode("utf-8")).hexdigest()
    return CompiledPolicy(
        version=document.version,
        content_hash=content_hash,
        engine=document.engine,
        match_plan=compiled,
        actions=tuple(RuleAction(rule_id=rule.id, action=rule.action) for rule in document.rules),
    )


def load_policy_file(
    path: str | Path,
    *,
    detectors: DetectorRegistry | None = None,
    predicates: PredicateRegistry | None = None,
) -> CompiledPolicy:
    """Read and compile one UTF-8 v3 policy file."""

    policy_path = Path(path)
    try:
        source = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"cannot read policy file: {policy_path}") from exc
    return load_policy_yaml(source, detectors=detectors, predicates=predicates)


def _reject_yaml_indirection(source: str) -> None:
    """Forbid aliases, anchors and explicit tags before construction."""

    try:
        tokens = yaml.scan(source)
        for token in tokens:
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise PolicyLoadError(
                    "policy YAML cannot use aliases, anchors, or explicit tags"
                )
    except yaml.YAMLError as exc:
        raise PolicyLoadError("policy is not valid YAML") from exc

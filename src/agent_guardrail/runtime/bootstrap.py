"""Explicit composition of trusted policy, rule and detector implementations."""

from __future__ import annotations

from pathlib import Path

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_rule_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.core import DetectorRegistry, GuardrailEngine, RuleRegistry


def build_engine_from_policy_file(
    path: str | Path,
    *,
    rule_registry: RuleRegistry | None = None,
    detector_registry: DetectorRegistry | None = None,
) -> GuardrailEngine:
    """Build a fully validated engine using fresh built-in registries by default."""

    rules = rule_registry or create_default_rule_registry()
    detectors = detector_registry or create_default_detector_registry()
    policy = load_policy_file(path, registry=rules)
    return GuardrailEngine(policy=policy, detectors=detectors)


def build_engine_from_policy_yaml(
    source: str,
    *,
    rule_registry: RuleRegistry | None = None,
    detector_registry: DetectorRegistry | None = None,
) -> GuardrailEngine:
    """Build an engine from YAML for deterministic tests and embedded use."""

    rules = rule_registry or create_default_rule_registry()
    detectors = detector_registry or create_default_detector_registry()
    policy = load_policy_yaml(source, registry=rules)
    return GuardrailEngine(policy=policy, detectors=detectors)

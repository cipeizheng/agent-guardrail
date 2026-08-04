"""Explicit construction of the built-in rule and detector registries."""

from __future__ import annotations

from pydantic import BaseModel

from agent_guardrail.core.registry import DetectorRegistry, RuleRegistry
from agent_guardrail.detectors.secrets import SecretDetector
from agent_guardrail.models import Phase
from agent_guardrail.rules.secret_exfiltration import (
    SecretExfiltrationConfig,
    SecretExfiltrationRule,
)


def create_default_rule_registry() -> RuleRegistry:
    """Create a new registry containing only reviewed built-in rules."""

    registry = RuleRegistry()

    def build_secret_exfiltration(
        rule_id: str,
        phases: frozenset[Phase],
        config: BaseModel,
    ) -> SecretExfiltrationRule:
        if not isinstance(config, SecretExfiltrationConfig):
            raise TypeError("secret_exfiltration received an unexpected config model")
        return SecretExfiltrationRule(rule_id=rule_id, phases=phases, config=config)

    registry.register(
        "secret_exfiltration",
        config_model=SecretExfiltrationConfig,
        factory=build_secret_exfiltration,
        allowed_phases=frozenset({Phase.POST_LLM, Phase.PRE_TOOL}),
    )
    return registry


def create_default_detector_registry() -> DetectorRegistry:
    """Create a new registry containing local deterministic detectors."""

    registry = DetectorRegistry()
    registry.register(SecretDetector())
    return registry

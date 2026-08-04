"""Explicit registries for trusted rule implementations and detectors."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from agent_guardrail.core.protocols import Detector, Rule
from agent_guardrail.models import Phase


class RegistryError(ValueError):
    """Base error for invalid or unknown registry entries."""


class UnknownRuleTypeError(RegistryError):
    """Raised when policy references a rule type absent from the registry."""


class UnknownDetectorError(RegistryError):
    """Raised when a rule references an unavailable detector."""


class RuleConfigError(RegistryError):
    """Raised when a concrete rule configuration is invalid."""


RuleFactory = Callable[[str, frozenset[Phase], BaseModel], Rule]


@dataclass(frozen=True, slots=True)
class BuiltRule:
    """A rule instance together with its normalized, defaulted config."""

    rule: Rule
    normalized_config: dict[str, object]


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """A trusted rule registration."""

    config_model: type[BaseModel]
    factory: RuleFactory
    allowed_phases: frozenset[Phase]


class RuleRegistry:
    """Build rules only from code-registered definitions."""

    def __init__(self) -> None:
        self._definitions: dict[str, RuleDefinition] = {}

    def register(
        self,
        type_name: str,
        *,
        config_model: type[BaseModel],
        factory: RuleFactory,
        allowed_phases: frozenset[Phase],
    ) -> None:
        if not type_name:
            raise RegistryError("rule type name cannot be empty")
        if type_name in self._definitions:
            raise RegistryError(f"rule type is already registered: {type_name}")
        if not allowed_phases:
            raise RegistryError("a rule type must allow at least one phase")
        self._definitions[type_name] = RuleDefinition(
            config_model=config_model,
            factory=factory,
            allowed_phases=allowed_phases,
        )

    def build(
        self,
        type_name: str,
        *,
        rule_id: str,
        phases: frozenset[Phase],
        raw_config: dict[str, object],
    ) -> BuiltRule:
        try:
            definition = self._definitions[type_name]
        except KeyError as exc:
            raise UnknownRuleTypeError(f"unknown rule type: {type_name}") from exc

        unsupported = phases - definition.allowed_phases
        if unsupported:
            phase_names = ", ".join(sorted(phase.value for phase in unsupported))
            raise RuleConfigError(f"rule {rule_id!r} does not support phases: {phase_names}")

        try:
            config = definition.config_model.model_validate(raw_config)
        except ValidationError as exc:
            details = exc.errors(include_input=False, include_url=False)
            raise RuleConfigError(f"invalid config for rule {rule_id!r}: {details}") from exc

        return BuiltRule(
            rule=definition.factory(rule_id, phases, config),
            normalized_config=config.model_dump(mode="json"),
        )


class DetectorRegistry:
    """An injected collection of local detector implementations."""

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if detector.name in self._detectors:
            raise RegistryError(f"detector is already registered: {detector.name}")
        self._detectors[detector.name] = detector

    def get(self, name: str) -> Detector:
        try:
            return self._detectors[name]
        except KeyError as exc:
            raise UnknownDetectorError(f"unknown detector: {name}") from exc

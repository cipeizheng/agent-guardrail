"""Explicit compilation of trusted capabilities referenced by a pure MatchPlan.

The compiled object is deployment-local and may contain trusted Python objects.
It is deliberately separate from the serializable MatchPlan policy boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_guardrail.core.match_plan import (
    BindingValue,
    DerivedValue,
    DetectorInputEncoding,
    EventBinding,
    FieldValue,
    LiteralListValue,
    LiteralValue,
    MatchCondition,
    MatchPlan,
    MatchRulePlan,
    NullValue,
    ParameterType,
    ParameterValue,
    ValueReference,
    ValueType,
)
from agent_guardrail.core.protocols import Detector, Predicate
from agent_guardrail.core.registry import (
    DetectorPolicyDescriptor,
    DetectorRegistry,
    PredicatePolicyDescriptor,
    PredicateRegistry,
    RegistryError,
)


class CapabilityCompilationError(ValueError):
    """A safe compile-time rejection of an unavailable or incompatible capability."""


@dataclass(frozen=True, slots=True)
class CompiledPredicateCapability:
    descriptor: PredicatePolicyDescriptor
    implementation: Predicate


@dataclass(frozen=True, slots=True)
class CompiledDetectorCapability:
    descriptor: DetectorPolicyDescriptor
    implementation: Detector


@dataclass(frozen=True, slots=True)
class CompiledMatchPlan:
    """A pure MatchPlan paired with explicit, trusted deployment capabilities."""

    plan: MatchPlan
    predicates: tuple[CompiledPredicateCapability, ...] = ()
    detectors: tuple[CompiledDetectorCapability, ...] = ()


def compile_match_plan_capabilities(
    plan: MatchPlan,
    *,
    predicates: PredicateRegistry,
    detectors: DetectorRegistry,
) -> CompiledMatchPlan:
    """Resolve and validate every capability before any snapshot is analyzed."""

    compiled_predicates: dict[str, CompiledPredicateCapability] = {}
    compiled_detectors: dict[str, CompiledDetectorCapability] = {}
    parameter_types = {
        parameter.name: _parameter_value_type(parameter.type)
        for parameter in plan.parameters
    }
    for rule in plan.rules:
        binding_types: dict[str, ValueType] = {
            binding.name: ValueType.OBJECT for binding in rule.event_bindings
        }
        binding_types.update(
            {derive.name: ValueType.ARRAY for derive in rule.derive}
        )
        binding_types.update(
            {
                binding.name: binding.item_type
                for binding in rule.collection_bindings
            }
        )
        event_bindings = {binding.name for binding in rule.event_bindings}
        _compile_condition(
            rule.where,
            rule=rule,
            binding_types=binding_types,
            event_bindings=event_bindings,
            parameter_types=parameter_types,
            predicate_registry=predicates,
            detector_registry=detectors,
            compiled_predicates=compiled_predicates,
            compiled_detectors=compiled_detectors,
        )
    return CompiledMatchPlan(
        plan=plan,
        predicates=tuple(compiled_predicates.values()),
        detectors=tuple(compiled_detectors.values()),
    )


def _compile_condition(
    condition: MatchCondition,
    *,
    rule: MatchRulePlan,
    binding_types: dict[str, ValueType],
    event_bindings: set[str],
    parameter_types: dict[str, ValueType],
    predicate_registry: PredicateRegistry,
    detector_registry: DetectorRegistry,
    compiled_predicates: dict[str, CompiledPredicateCapability],
    compiled_detectors: dict[str, CompiledDetectorCapability],
) -> None:
    nested = {
        "rule": rule,
        "binding_types": binding_types,
        "event_bindings": event_bindings,
        "parameter_types": parameter_types,
        "predicate_registry": predicate_registry,
        "detector_registry": detector_registry,
        "compiled_predicates": compiled_predicates,
        "compiled_detectors": compiled_detectors,
    }
    if condition.all is not None:
        for child in condition.all:
            _compile_condition(child, **nested)
        return
    if condition.any is not None:
        for child in condition.any:
            _compile_condition(child, **nested)
        return
    if condition.not_ is not None:
        _compile_condition(condition.not_, **nested)
        return
    if condition.quantify is not None:
        local = condition.quantify.binding
        local_types = dict(binding_types)
        local_events = set(event_bindings)
        if isinstance(local, EventBinding):
            local_types[local.name] = ValueType.OBJECT
            local_events.add(local.name)
        else:
            local_types[local.name] = local.item_type
        _compile_condition(
            condition.quantify.where,
            **{**nested, "binding_types": local_types, "event_bindings": local_events},
        )
        return
    if condition.predicate is not None:
        node = condition.predicate
        try:
            descriptor = predicate_registry.policy_descriptor(node.capability)
            implementation = predicate_registry.get(node.capability)
        except RegistryError as exc:
            raise CapabilityCompilationError(
                f"rule {rule.id!r} references an unavailable Predicate capability: "
                f"{node.capability}"
            ) from exc
        if len(node.arguments) != len(descriptor.argument_types):
            raise CapabilityCompilationError(
                f"rule {rule.id!r} Predicate {node.capability!r} has incompatible arity"
            )
        for reference, expected in zip(
            node.arguments,
            descriptor.argument_types,
            strict=True,
        ):
            actual = _infer_value_type(
                reference,
                binding_types=binding_types,
                event_bindings=event_bindings,
                parameter_types=parameter_types,
            )
            if actual is not None and not _type_compatible(actual, expected):
                raise CapabilityCompilationError(
                    f"rule {rule.id!r} Predicate {node.capability!r} has an "
                    "incompatible argument type"
                )
        _validate_implementation_identity(
            implementation.name,
            implementation.version,
            descriptor.name,
            "Predicate",
        )
        compiled_predicates.setdefault(
            node.capability,
            CompiledPredicateCapability(descriptor, implementation),
        )
        return
    if condition.detector is not None:
        node = condition.detector
        try:
            descriptor = detector_registry.policy_descriptor(node.capability)
            implementation = detector_registry.get(node.capability)
        except RegistryError as exc:
            raise CapabilityCompilationError(
                f"rule {rule.id!r} references an unavailable Detector capability: "
                f"{node.capability}"
            ) from exc
        if any(
            detector_input.encoding.value not in descriptor.allowed_encodings
            for detector_input in node.inputs
        ):
            raise CapabilityCompilationError(
                f"rule {rule.id!r} Detector {node.capability!r} uses an "
                "unpublished input encoding"
            )
        for detector_input in node.inputs:
            actual = _infer_value_type(
                detector_input.value,
                binding_types=binding_types,
                event_bindings=event_bindings,
                parameter_types=parameter_types,
            )
            if (
                detector_input.encoding is DetectorInputEncoding.TEXT
                and actual is not None
                and actual is not ValueType.STRING
            ):
                raise CapabilityCompilationError(
                    f"rule {rule.id!r} Detector {node.capability!r} has an "
                    "incompatible text input type"
                )
        if not set(node.types_any).issubset(descriptor.detection_types):
            raise CapabilityCompilationError(
                f"rule {rule.id!r} Detector {node.capability!r} uses an "
                "unpublished detection type"
            )
        _validate_implementation_identity(
            implementation.name,
            implementation.version,
            descriptor.name,
            "Detector",
        )
        compiled_detectors.setdefault(
            node.capability,
            CompiledDetectorCapability(descriptor, implementation),
        )


def _infer_value_type(
    reference: ValueReference,
    *,
    binding_types: dict[str, ValueType],
    event_bindings: set[str],
    parameter_types: dict[str, ValueType],
) -> ValueType | str | None:
    if isinstance(reference, LiteralValue):
        return _literal_value_type(reference.value)
    if isinstance(reference, LiteralListValue):
        return ValueType.ARRAY
    if isinstance(reference, NullValue):
        return "null"
    if isinstance(reference, BindingValue):
        return binding_types[reference.name]
    if isinstance(reference, DerivedValue):
        return ValueType.ARRAY
    if isinstance(reference, ParameterValue):
        return parameter_types[reference.name]
    if isinstance(reference, FieldValue):
        if reference.binding not in event_bindings:
            return None
        if len(reference.path) != 1:
            return None
        segment = reference.path[0]
        if not isinstance(segment, str):
            return None
        return {
            "id": ValueType.STRING,
            "sequence": ValueType.INTEGER,
            "kind": ValueType.STRING,
            "phase": ValueType.STRING,
            "origin": ValueType.STRING,
            "payload": ValueType.OBJECT,
        }.get(segment)
    return None


def _literal_value_type(value: object) -> ValueType:
    if type(value) is str:
        return ValueType.STRING
    if type(value) is int:
        return ValueType.INTEGER
    if type(value) is float:
        return ValueType.FLOAT
    return ValueType.BOOLEAN


def _parameter_value_type(value: ParameterType) -> ValueType:
    return {
        ParameterType.STRING: ValueType.STRING,
        ParameterType.INTEGER: ValueType.INTEGER,
        ParameterType.FLOAT: ValueType.FLOAT,
        ParameterType.BOOLEAN: ValueType.BOOLEAN,
    }[value]


def _type_compatible(actual: ValueType | str, expected: ValueType) -> bool:
    if expected is ValueType.JSON:
        return True
    return actual is expected


def _validate_implementation_identity(
    name: object,
    version: object,
    expected_name: str,
    kind: str,
) -> None:
    if name != expected_name:
        raise CapabilityCompilationError(f"registered {kind} identity is inconsistent")
    if (
        not isinstance(version, str)
        or not version
        or version != version.strip()
        or len(version) > 128
    ):
        raise CapabilityCompilationError(f"registered {kind} version is invalid")

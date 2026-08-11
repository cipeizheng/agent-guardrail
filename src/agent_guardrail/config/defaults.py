"""Explicit construction of built-in trusted capability registries."""

from __future__ import annotations

from agent_guardrail.core.match_plan import ValueType
from agent_guardrail.core.registry import (
    DetectorPolicyDescriptor,
    DetectorRegistry,
    PredicatePolicyDescriptor,
    PredicateRegistry,
)
from agent_guardrail.detectors.dangerous_command import (
    DANGEROUS_COMMAND_PATTERNS,
    DangerousCommandDetector,
)
from agent_guardrail.detectors.model_prompt_injection import (
    ModelPromptInjectionDetector,
    PromptInjectionClassifier,
)
from agent_guardrail.detectors.pii import PII_PATTERNS, PIIDetector
from agent_guardrail.detectors.prompt_injection import (
    PROMPT_INJECTION_PATTERNS,
    PromptInjectionDetector,
)
from agent_guardrail.detectors.secrets import SECRET_PATTERNS, SecretDetector
from agent_guardrail.detectors.unicode_security import (
    UNICODE_SECURITY_TYPES,
    UnicodeSecurityDetector,
)
from agent_guardrail.predicates import (
    LengthInRangePredicate,
    NumberInRangePredicate,
    URLHostAllowedPredicate,
)


def create_default_detector_registry() -> DetectorRegistry:
    """Create a new registry containing local deterministic detectors."""

    registry = DetectorRegistry()
    registry.register(
        UnicodeSecurityDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="unicode_security",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=UNICODE_SECURITY_TYPES,
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        PIIDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="pii",
            allowed_encodings=frozenset({"canonical_json"}),
            detection_types=frozenset(pattern.type for pattern in PII_PATTERNS)
            | frozenset({"credit_card", "cn_resident_id"}),
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        SecretDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="secrets",
            allowed_encodings=frozenset({"canonical_json"}),
            detection_types=frozenset(pattern.type for pattern in SECRET_PATTERNS),
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        PromptInjectionDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="prompt_injection",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=frozenset(pattern.type for pattern in PROMPT_INJECTION_PATTERNS),
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        DangerousCommandDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="dangerous_command",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=frozenset(pattern.type for pattern in DANGEROUS_COMMAND_PATTERNS),
            max_input_bytes=16_384,
        ),
    )
    return registry


def create_model_detector_registry(
    classifier: PromptInjectionClassifier,
    *,
    threshold: float = 0.85,
) -> DetectorRegistry:
    """Create the default registry plus an explicitly injected model detector."""

    registry = create_default_detector_registry()
    registry.register(
        ModelPromptInjectionDetector(classifier, threshold=threshold),
        policy_descriptor=DetectorPolicyDescriptor(
            name="prompt_injection_model",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=frozenset({"model_prompt_injection", "model_jailbreak"}),
            max_input_bytes=16_384,
            timeout_ms=2_000,
            max_detections=1,
        ),
    )
    return registry


def create_default_predicate_registry() -> PredicateRegistry:
    """Create the reviewed built-in pure Predicate registry."""

    registry = PredicateRegistry()
    registry.register(
        NumberInRangePredicate(),
        policy_descriptor=PredicatePolicyDescriptor(
            name="number_in_range",
            argument_types=(ValueType.JSON, ValueType.JSON, ValueType.JSON),
            max_input_bytes=512,
        ),
    )
    registry.register(
        LengthInRangePredicate(),
        policy_descriptor=PredicatePolicyDescriptor(
            name="length_in_range",
            argument_types=(ValueType.JSON, ValueType.INTEGER, ValueType.INTEGER),
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        URLHostAllowedPredicate(),
        policy_descriptor=PredicatePolicyDescriptor(
            name="url_host_allowed",
            argument_types=(ValueType.STRING, ValueType.ARRAY),
            max_input_bytes=8_192,
        ),
    )
    return registry

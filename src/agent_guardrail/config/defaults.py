"""Explicit construction of built-in trusted capability registries."""

from __future__ import annotations

from agent_guardrail.core.registry import (
    DetectorPolicyDescriptor,
    DetectorRegistry,
    PredicateRegistry,
)
from agent_guardrail.detectors.pii import PII_PATTERNS, PIIDetector
from agent_guardrail.detectors.secrets import SECRET_PATTERNS, SecretDetector


def create_default_detector_registry() -> DetectorRegistry:
    """Create a new registry containing local deterministic detectors."""

    registry = DetectorRegistry()
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
    return registry


def create_default_predicate_registry() -> PredicateRegistry:
    """Create the reviewed built-in pure Predicate registry (empty in v0.1)."""

    return PredicateRegistry()

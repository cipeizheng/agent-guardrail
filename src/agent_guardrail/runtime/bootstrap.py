"""Explicit composition of a v3 MatchPlan Enforcement analyzer."""

from __future__ import annotations

from pathlib import Path

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
    load_policy_file,
    load_policy_yaml,
)
from agent_guardrail.core import DetectorRegistry, MatchPolicyAnalyzer, PredicateRegistry


def build_analyzer_from_policy_file(
    path: str | Path,
    *,
    predicate_registry: PredicateRegistry | None = None,
    detector_registry: DetectorRegistry | None = None,
) -> MatchPolicyAnalyzer:
    """Build an analyzer after schema, MatchPlan and capabilities all validate."""

    predicates = predicate_registry or create_default_predicate_registry()
    detectors = detector_registry or create_default_detector_registry()
    policy = load_policy_file(path, predicates=predicates, detectors=detectors)
    return MatchPolicyAnalyzer(policy)


def build_analyzer_from_policy_yaml(
    source: str,
    *,
    predicate_registry: PredicateRegistry | None = None,
    detector_registry: DetectorRegistry | None = None,
) -> MatchPolicyAnalyzer:
    """Build an analyzer from strict YAML for embedded use and tests."""

    predicates = predicate_registry or create_default_predicate_registry()
    detectors = detector_registry or create_default_detector_registry()
    policy = load_policy_yaml(source, predicates=predicates, detectors=detectors)
    return MatchPolicyAnalyzer(policy)

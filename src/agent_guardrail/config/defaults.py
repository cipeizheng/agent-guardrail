"""Explicit construction of built-in trusted capability registries."""

from __future__ import annotations

from agent_guardrail.core.match_plan import ValueType
from agent_guardrail.core.registry import (
    DetectorPolicyDescriptor,
    DetectorRegistry,
    PredicatePolicyDescriptor,
    PredicateRegistry,
    SimilarityPolicyDescriptor,
)
from agent_guardrail.detectors.hidden_content import (
    HIDDEN_CONTENT_TYPES,
    HiddenContentDetector,
)
from agent_guardrail.detectors.llm_judge import (
    LLM_JUDGE_DETECTION_TYPE,
    LLMJudgeDetector,
)
from agent_guardrail.detectors.model_prompt_injection import (
    ModelPromptInjectionDetector,
    PromptInjectionClassifier,
)
from agent_guardrail.detectors.pii import (
    PII_PATTERNS,
    PIIBackend,
    PIIDetector,
)
from agent_guardrail.detectors.prompt_injection import (
    PROMPT_INJECTION_PATTERNS,
    PromptInjectionDetector,
)
from agent_guardrail.detectors.python_code import (
    PYTHON_AST_IPYTHON_TYPES,
    PythonASTIPythonDetector,
)
from agent_guardrail.detectors.secrets import SECRET_PATTERNS, SecretDetector
from agent_guardrail.detectors.semgrep import SEMGREP_TYPES, SemgrepDetector
from agent_guardrail.detectors.similarity import (
    SIMILARITY_DETECTION_TYPE,
    IsSimilarDetector,
)
from agent_guardrail.detectors.unicode_security import (
    UNICODE_SECURITY_TYPES,
    UnicodeSecurityDetector,
)
from agent_guardrail.detectors.yara_injection import YaraInjectionDetector
from agent_guardrail.predicates import (
    FuzzyContainsPredicate,
    LengthInRangePredicate,
    NumberInRangePredicate,
    URLHostAllowedPredicate,
)


def create_detector_registry(
    *,
    pii_backend: PIIBackend | None = None,
    prompt_classifier: PromptInjectionClassifier | None = None,
    prompt_threshold: float = 0.85,
    semgrep_detector: SemgrepDetector | None = None,
    yara_detector: YaraInjectionDetector | None = None,
    similarity_detector: IsSimilarDetector | None = None,
    llm_judge_detector: LLMJudgeDetector | None = None,
) -> DetectorRegistry:
    """Create local capabilities plus explicitly injected deployment adapters.

    Structured Policy cannot select any backend, profile, process, model, or
    ruleset. Deployments construct those objects first and inject them here.
    Calling this function without arguments is equivalent to the default,
    fully local registry.
    """

    if prompt_classifier is None and prompt_threshold != 0.85:
        raise ValueError("prompt_threshold requires prompt_classifier")

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
        PIIDetector(pii_backend),
        policy_descriptor=DetectorPolicyDescriptor(
            name="pii",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=(
                frozenset(pattern.type for pattern in PII_PATTERNS)
                | (pii_backend.detection_types if pii_backend is not None else frozenset())
            ),
            max_input_bytes=16_384,
            timeout_ms=2_000 if pii_backend is not None else 500,
        ),
    )
    registry.register(
        SecretDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="secrets",
            allowed_encodings=frozenset({"text", "canonical_json"}),
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
        PythonASTIPythonDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="python_ast_ipython",
            allowed_encodings=frozenset({"text"}),
            detection_types=PYTHON_AST_IPYTHON_TYPES,
            max_input_bytes=16_384,
        ),
    )
    registry.register(
        HiddenContentDetector(),
        policy_descriptor=DetectorPolicyDescriptor(
            name="hidden_content",
            allowed_encodings=frozenset({"text", "canonical_json"}),
            detection_types=HIDDEN_CONTENT_TYPES,
            max_input_bytes=16_384,
        ),
    )
    if prompt_classifier is not None:
        registry.register(
            ModelPromptInjectionDetector(
                prompt_classifier,
                threshold=prompt_threshold,
            ),
            policy_descriptor=DetectorPolicyDescriptor(
                name="prompt_injection_model",
                allowed_encodings=frozenset({"text", "canonical_json"}),
                detection_types=frozenset({"model_prompt_injection"}),
                max_input_bytes=16_384,
                timeout_ms=2_000,
                max_detections=1,
            ),
        )
    if semgrep_detector is not None:
        registry.register(
            semgrep_detector,
            policy_descriptor=DetectorPolicyDescriptor(
                name="semgrep",
                allowed_encodings=frozenset({"text"}),
                detection_types=SEMGREP_TYPES,
                max_input_bytes=16_384,
                timeout_ms=5_000,
                max_detections=semgrep_detector.profile.max_findings,
            ),
        )
    if yara_detector is not None:
        registry.register(
            yara_detector,
            policy_descriptor=DetectorPolicyDescriptor(
                name="yara_injection_signatures",
                allowed_encodings=frozenset({"text", "canonical_json"}),
                detection_types=frozenset(
                    binding.detection_type for binding in yara_detector.profile.rules
                ),
                max_input_bytes=16_384,
                timeout_ms=2_000,
                max_detections=yara_detector.profile.max_matches,
            ),
        )
    if llm_judge_detector is not None:
        registry.register(
            llm_judge_detector,
            policy_descriptor=DetectorPolicyDescriptor(
                name=llm_judge_detector.name,
                allowed_encodings=frozenset({"text", "canonical_json"}),
                detection_types=frozenset({LLM_JUDGE_DETECTION_TYPE}),
                max_input_bytes=16_384,
                # External LLM latency is seconds, not milliseconds; the
                # deployment profile is the release-point capability.
                timeout_ms=10_000,
                max_detections=1,
            ),
        )
    if similarity_detector is not None:
        registry.register_similarity(
            similarity_detector,
            policy_descriptor=SimilarityPolicyDescriptor(
                name="is_similar",
                detection_type=SIMILARITY_DETECTION_TYPE,
                max_input_bytes=similarity_detector.profile.max_input_bytes,
                max_texts=similarity_detector.profile.max_texts,
                timeout_ms=5_000,
            ),
        )
    return registry


def create_default_detector_registry() -> DetectorRegistry:
    """Create a new registry containing only local deterministic detectors."""

    return create_detector_registry()


def create_model_detector_registry(
    classifier: PromptInjectionClassifier,
    *,
    threshold: float = 0.85,
) -> DetectorRegistry:
    """Create the default registry plus an explicitly injected model detector."""

    return create_detector_registry(
        prompt_classifier=classifier,
        prompt_threshold=threshold,
    )


def create_similarity_detector_registry(detector: IsSimilarDetector) -> DetectorRegistry:
    """Create the default registry plus one deployment-profiled text encoder."""

    return create_detector_registry(similarity_detector=detector)


def create_llm_judge_detector_registry(detector: LLMJudgeDetector) -> DetectorRegistry:
    """Create the default registry plus one deployment-profiled LLM judge."""

    return create_detector_registry(llm_judge_detector=detector)


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
    registry.register(
        FuzzyContainsPredicate(),
        policy_descriptor=PredicatePolicyDescriptor(
            name="fuzzy_contains",
            argument_types=(ValueType.STRING, ValueType.STRING, ValueType.JSON),
            max_input_bytes=16_384,
            timeout_ms=250,
        ),
    )
    return registry

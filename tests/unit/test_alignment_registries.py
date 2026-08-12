from __future__ import annotations

import pytest

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
    create_detector_registry,
)
from agent_guardrail.detectors import (
    PIIBackendResult,
    PIIEntityType,
    PromptInjectionScore,
    SemgrepDetector,
    SemgrepFinding,
    SemgrepProfile,
    YaraInjectionDetector,
    YaraInjectionProfile,
    YaraRuleBinding,
    YaraSignatureMatch,
)


class _PIIBackend:
    name = "pinned-pii"
    version = "model-sha256"
    detection_types: frozenset[PIIEntityType] = frozenset({"person"})

    async def analyze(self, text: str) -> tuple[PIIBackendResult, ...]:
        del text
        return ()


class _PromptClassifier:
    name = "pinned-prompt-classifier"
    version = "model-sha256"

    async def classify(self, text: str) -> PromptInjectionScore:
        del text
        return PromptInjectionScore(score=0.0)


class _SemgrepBackend:
    name = "isolated-semgrep"
    version = "1+pinned"

    async def scan(self, text: str) -> tuple[SemgrepFinding, ...]:
        del text
        return ()


class _YaraBackend:
    name = "precompiled-yara"
    version = "4+pinned"

    async def match(self, text: str) -> tuple[YaraSignatureMatch, ...]:
        del text
        return ()


def _semgrep_detector() -> SemgrepDetector:
    return SemgrepDetector(
        _SemgrepBackend(),
        profile=SemgrepProfile(
            profile_id="python-security",
            profile_version="rules-sha256",
            language="python",
            allowed_rule_ids=frozenset({"python.security.fixed-rule"}),
            max_findings=3,
        ),
    )


def _yara_detector() -> YaraInjectionDetector:
    return YaraInjectionDetector(
        _YaraBackend(),
        profile=YaraInjectionProfile(
            profile_id="injection-rules",
            profile_version="rules-sha256",
            rules=(
                YaraRuleBinding(
                    rule_id="fixed-sqli",
                    detection_type="yara_sql_injection",
                ),
            ),
            max_matches=2,
        ),
    )


def test_default_registries_publish_all_local_alignment_capabilities() -> None:
    detectors = create_default_detector_registry()
    predicates = create_default_predicate_registry()

    for name in (
        "secrets",
        "pii",
        "prompt_injection",
        "python_ast_ipython",
        "hidden_content",
    ):
        assert detectors.policy_descriptor(name).max_input_bytes == 16_384

    assert detectors.policy_descriptor("secrets").allowed_encodings == frozenset(
        {"text", "canonical_json"}
    )
    pii = detectors.policy_descriptor("pii")
    assert pii.allowed_encodings == frozenset({"text", "canonical_json"})
    assert "iban_code" in pii.detection_types
    assert "person" not in pii.detection_types
    assert "python_dynamic_execution" in detectors.policy_descriptor(
        "python_ast_ipython"
    ).detection_types
    assert detectors.policy_descriptor("python_ast_ipython").allowed_encodings == frozenset(
        {"text"}
    )
    assert "html_hidden_element" in detectors.policy_descriptor(
        "hidden_content"
    ).detection_types

    assert predicates.policy_descriptor("fuzzy_contains").timeout_ms == 250


def test_deployment_registry_combines_only_explicitly_injected_adapters() -> None:
    semgrep = _semgrep_detector()
    yara = _yara_detector()
    registry = create_detector_registry(
        pii_backend=_PIIBackend(),
        prompt_classifier=_PromptClassifier(),
        semgrep_detector=semgrep,
        yara_detector=yara,
    )

    assert "person" in registry.policy_descriptor("pii").detection_types
    assert registry.policy_descriptor("pii").timeout_ms == 2_000
    assert registry.policy_descriptor("prompt_injection_model").max_detections == 1
    assert registry.get("semgrep") is semgrep
    assert registry.policy_descriptor("semgrep").max_detections == 3
    assert registry.policy_descriptor("semgrep").allowed_encodings == frozenset({"text"})
    assert registry.get("yara_injection_signatures") is yara
    assert (
        registry.policy_descriptor("yara_injection_signatures").max_detections == 2
    )
    assert registry.policy_descriptor(
        "yara_injection_signatures"
    ).detection_types == frozenset({"yara_sql_injection"})


def test_deployment_registry_rejects_an_unbound_prompt_threshold() -> None:
    with pytest.raises(ValueError, match="requires prompt_classifier"):
        create_detector_registry(prompt_threshold=0.9)

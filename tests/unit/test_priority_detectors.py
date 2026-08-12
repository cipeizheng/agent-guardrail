from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_guardrail.config import (
    create_default_detector_registry,
    create_model_detector_registry,
)
from agent_guardrail.detectors import (
    ModelPromptInjectionDetector,
    PromptInjectionScore,
    TransformersPipelineClassifier,
    UnicodeSecurityDetector,
)
from agent_guardrail.models import DetectionContext, Phase


def _context(*, event_id: str = "event-1") -> DetectionContext:
    return DetectionContext(trace_id="trace-1", event_id=event_id, phase=Phase.PRE_LLM)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "detection_type", "span"),
    [
        ("ignore\u202eprevious", "bidi_control", (6, 7)),
        ("ig\u200bnore", "zero_width", (2, 3)),
        ("token\u00advalue", "format_control", (5, 6)),
        ("safe\x00suffix", "control_character", (4, 5)),
        ("p\u0430ypal", "mixed_script_confusable", (0, 6)),
    ],
)
async def test_unicode_security_detector_reports_original_spans_without_raw_text(
    text: str,
    detection_type: str,
    span: tuple[int, int],
) -> None:
    detections = await UnicodeSecurityDetector().detect(text, context=_context())

    matching = next(item for item in detections if item.type == detection_type)
    assert (matching.start, matching.end) == span
    assert text not in matching.model_dump_json()
    assert matching.masked_evidence.startswith(f"<unicode_security:{detection_type}:")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "普通中文和 English text",
        "Greek: καλημέρα",
        "line one\nline two\tvalue",
        "emoji 🙂",
    ],
)
async def test_unicode_security_detector_avoids_ordinary_unicode(text: str) -> None:
    assert await UnicodeSecurityDetector().detect(text, context=_context()) == []


@pytest.mark.asyncio
async def test_unicode_security_fingerprint_is_bound_to_event_not_payload() -> None:
    detector = UnicodeSecurityDetector()
    first = await detector.detect("a\u202eb", context=_context())
    second = await detector.detect("a\u202eb", context=_context(event_id="event-2"))

    assert first[0].fingerprint != second[0].fingerprint
    assert "a\u202eb" not in first[0].model_dump_json()


@pytest.mark.asyncio
async def test_unicode_security_fails_on_result_overflow() -> None:
    with pytest.raises(ValueError, match="result limit"):
        await UnicodeSecurityDetector().detect("\u202e" * 65, context=_context())


@dataclass(slots=True)
class _Classifier:
    result: PromptInjectionScore
    calls: int = 0
    name: str = "test-classifier"
    version: str = "2026-08-11"

    async def classify(self, text: str) -> PromptInjectionScore:
        del text
        self.calls += 1
        return self.result


@pytest.mark.asyncio
async def test_model_prompt_injection_detector_applies_deployment_threshold() -> None:
    attack = _Classifier(PromptInjectionScore(score=0.91))
    benign = _Classifier(PromptInjectionScore(score=0.84))

    hit = await ModelPromptInjectionDetector(attack, threshold=0.85).detect(
        "novel semantic attack",
        context=_context(),
    )
    miss = await ModelPromptInjectionDetector(benign, threshold=0.85).detect(
        "adjacent benign text",
        context=_context(),
    )

    assert [item.type for item in hit] == ["model_prompt_injection"]
    assert hit[0].confidence == 0.91
    assert "novel semantic attack" not in hit[0].model_dump_json()
    assert miss == []
    assert attack.calls == benign.calls == 1


@pytest.mark.asyncio
async def test_transformers_pipeline_adapter_normalizes_pinned_model_output() -> None:
    calls: list[tuple[str, bool, int]] = []

    def pipeline(text: str, *, truncation: bool, max_length: int) -> list[dict[str, object]]:
        calls.append((text, truncation, max_length))
        return [
            {"label": "BENIGN", "score": 0.03},
            {"label": "INJECTION", "score": 0.97},
        ]

    classifier = TransformersPipelineClassifier(
        pipeline,
        model_name="local/reviewed-model",
        model_version="sha256:test",
        injection_labels=frozenset({"injection"}),
        max_length=256,
    )

    assert await classifier.classify("classify me") == PromptInjectionScore(score=0.97)
    assert calls == [("classify me", True, 256)]


@pytest.mark.asyncio
async def test_transformers_pipeline_adapter_rejects_unstructured_output() -> None:
    classifier = TransformersPipelineClassifier(
        lambda _text, **_kwargs: [{"label": "INJECTION", "score": "high"}],
        model_name="local/reviewed-model",
        model_version="sha256:test",
    )

    with pytest.raises(TypeError, match="invalid label or score"):
        await classifier.classify("classify me")


def test_priority_detector_descriptors_are_bounded_and_explicit() -> None:
    default = create_default_detector_registry()
    unicode_descriptor = default.policy_descriptor("unicode_security")
    assert unicode_descriptor.max_input_bytes == 16_384
    assert unicode_descriptor.allowed_encodings == frozenset({"text", "canonical_json"})
    assert "mixed_script_confusable" in unicode_descriptor.detection_types

    classifier = _Classifier(PromptInjectionScore(score=0.9))
    model = create_model_detector_registry(classifier)
    model_descriptor = model.policy_descriptor("prompt_injection_model")
    assert model_descriptor.timeout_ms == 2_000
    assert model_descriptor.max_detections == 1
    assert set(model_descriptor.detection_types) == {
        "model_prompt_injection",
        "model_jailbreak",
    }

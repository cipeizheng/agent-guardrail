"""Deployment-injected model scoring for prompt-injection detection."""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, TypeGuard, runtime_checkable

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

MAX_MODEL_PROMPT_BYTES = 16_384
MAX_PIPELINE_CANDIDATES = 64
MAX_PIPELINE_LABEL_CHARS = 64


@dataclass(frozen=True, slots=True)
class PromptInjectionScore:
    """One normalized classifier result with no input or model-generated prose."""

    score: float

    def __post_init__(self) -> None:
        if not isinstance(self.score, float) or not 0.0 <= self.score <= 1.0:
            raise ValueError("prompt-injection score must be a float in [0, 1]")


@runtime_checkable
class PromptInjectionClassifier(Protocol):
    """A deployment-owned, preconfigured classifier backend."""

    name: str
    version: str

    async def classify(self, text: str) -> PromptInjectionScore: ...


class ModelPromptInjectionDetector:
    """Turn a bounded classifier score into an audit-safe Detector fact."""

    name = "prompt_injection_model"
    adapter_version = "3"

    def __init__(
        self,
        classifier: PromptInjectionClassifier,
        *,
        threshold: float = 0.85,
    ) -> None:
        if not isinstance(classifier, PromptInjectionClassifier):
            raise TypeError("classifier must implement PromptInjectionClassifier")
        if not isinstance(threshold, float) or not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be a float in (0, 1]")
        _validate_identity(classifier.name, "classifier name")
        _validate_identity(classifier.version, "classifier version")
        self._classifier = classifier
        self._threshold = threshold
        identity = sha256(
            json.dumps(
                (classifier.name, classifier.version, threshold),
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        if len(text.encode("utf-8")) > MAX_MODEL_PROMPT_BYTES:
            raise ValueError("model prompt input exceeds its hard byte bound")
        score = await self._classifier.classify(text)
        if not isinstance(score, PromptInjectionScore):
            raise TypeError("classifier returned an invalid score")
        if score.score <= self._threshold:
            return []
        detection_type = "model_prompt_injection"
        span = (0, len(text)) if text else None
        fingerprint = occurrence_fingerprint(
            context=context,
            detector=self.name,
            detector_version=self.version,
            detection_type=detection_type,
            start=span[0] if span is not None else 0,
            end=span[1] if span is not None else 0,
        )
        common = {
            "type": detection_type,
            "detector": self.name,
            "detector_version": self.version,
            "confidence": score.score,
            "masked_evidence": f"<{self.name}:{detection_type}:{fingerprint}>",
            "fingerprint": fingerprint,
        }
        if span is not None:
            return [Detection(**common, start=span[0], end=span[1])]
        return [Detection(**common)]


class TransformersPipelineClassifier:
    """Adapt a preloaded Hugging Face-style text-classification pipeline.

    The deployment constructs and pins the pipeline/model. This adapter does not
    download a model, select a repository, read files, or expose those choices to
    Policy YAML.
    """

    def __init__(
        self,
        pipeline: Callable[..., object],
        *,
        model_name: str,
        model_version: str,
        injection_labels: frozenset[str] = frozenset(
            {"injection", "prompt_injection", "label_1"}
        ),
        max_length: int = 512,
    ) -> None:
        if not callable(pipeline):
            raise TypeError("pipeline must be callable")
        _validate_identity(model_name, "model name")
        _validate_identity(model_version, "model version")
        if not injection_labels or any(
            not isinstance(label, str)
            or not label.strip()
            or len(label) > 64
            or label != label.strip()
            for label in injection_labels
        ):
            raise ValueError("injection_labels must be non-empty")
        if isinstance(max_length, bool) or not 1 <= max_length <= 8192:
            raise ValueError("max_length is outside its hard bounds")
        normalized_labels = frozenset(label.lower() for label in injection_labels)
        profile_material = json.dumps(
            (model_version, sorted(normalized_labels), max_length),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        profile_identity = sha256(profile_material.encode("utf-8")).hexdigest()[:12]
        self.name = model_name
        self.version = f"pipeline-{profile_identity}"
        self._pipeline = pipeline
        self._injection_labels = normalized_labels
        self._max_length = max_length

    async def classify(self, text: str) -> PromptInjectionScore:
        raw = await asyncio.to_thread(
            self._pipeline,
            text,
            truncation=True,
            max_length=self._max_length,
        )
        if inspect.isawaitable(raw):
            raw = await raw
        candidates = _pipeline_candidates(raw)
        matching = [
            (label, score)
            for label, score in candidates
            if label.lower() in self._injection_labels
        ]
        if not matching:
            return PromptInjectionScore(score=0.0)
        _, score = max(matching, key=lambda item: item[1])
        return PromptInjectionScore(score=score)


def _pipeline_candidates(raw: object) -> tuple[tuple[str, float], ...]:
    value = raw
    if isinstance(value, (list, tuple)) and not _is_builtin_sequence(value):
        raise TypeError("pipeline result collection must be a built-in list or tuple")
    if _is_builtin_sequence(value):
        if len(value) > MAX_PIPELINE_CANDIDATES:
            raise ValueError("pipeline result exceeds its candidate limit")
        if len(value) == 1 and _is_builtin_sequence(value[0]):
            value = value[0]
            if len(value) > MAX_PIPELINE_CANDIDATES:
                raise ValueError("pipeline result exceeds its candidate limit")
        items = value
    else:
        items = (value,)
    candidates: list[tuple[str, float]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise TypeError("pipeline result must contain mappings")
        label = item.get("label")
        score = item.get("score")
        if (
            not isinstance(label, str)
            or not label.strip()
            or label != label.strip()
            or len(label) > MAX_PIPELINE_LABEL_CHARS
            or type(score) is not float
            or not 0.0 <= score <= 1.0
        ):
            raise TypeError("pipeline result has an invalid label or score")
        candidates.append((label, score))
    if not candidates:
        raise TypeError("pipeline result must contain at least one score")
    return tuple(candidates)


def _is_builtin_sequence(
    value: object,
) -> TypeGuard[list[object] | tuple[object, ...]]:
    return type(value) is list or type(value) is tuple


def _validate_identity(value: object, subject: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError(f"{subject} is invalid")

"""Deployment-injected model scoring for prompt-injection detection."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, runtime_checkable

from agent_guardrail.models import Detection, DetectionContext


@dataclass(frozen=True, slots=True)
class PromptInjectionScore:
    """One normalized classifier result with no input or model-generated prose."""

    score: float
    label: str = "prompt_injection"

    def __post_init__(self) -> None:
        if not isinstance(self.score, float) or not 0.0 <= self.score <= 1.0:
            raise ValueError("prompt-injection score must be a float in [0, 1]")
        if self.label not in {"prompt_injection", "jailbreak"}:
            raise ValueError("prompt-injection label is not supported")


@runtime_checkable
class PromptInjectionClassifier(Protocol):
    """A deployment-owned, preconfigured classifier backend."""

    name: str
    version: str

    async def classify(self, text: str) -> PromptInjectionScore: ...


class ModelPromptInjectionDetector:
    """Turn a bounded classifier score into an audit-safe Detector fact."""

    name = "prompt_injection_model"
    version = "1"

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
        if not classifier.name or not classifier.version:
            raise ValueError("classifier identity must be non-empty")
        self._classifier = classifier
        self._threshold = threshold

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        score = await self._classifier.classify(text)
        if not isinstance(score, PromptInjectionScore):
            raise TypeError("classifier returned an invalid score")
        if score.score < self._threshold:
            return []
        detection_type = f"model_{score.label}"
        material = (
            f"{self.name}:{self.version}:{self._classifier.name}:"
            f"{self._classifier.version}:{context.trace_id}:{context.event_id}:"
            f"{context.phase.value}:{detection_type}"
        )
        fingerprint = sha256(material.encode("utf-8")).hexdigest()[:16]
        common = {
            "type": detection_type,
            "detector": self.name,
            "detector_version": self.version,
            "confidence": score.score,
            "masked_evidence": f"<{self.name}:{detection_type}:{fingerprint}>",
            "fingerprint": fingerprint,
        }
        if text:
            return [Detection(**common, start=0, end=len(text))]
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
            {"injection", "prompt_injection", "jailbreak", "label_1"}
        ),
        max_length: int = 512,
    ) -> None:
        if not callable(pipeline):
            raise TypeError("pipeline must be callable")
        if not model_name or not model_version:
            raise ValueError("model identity must be non-empty")
        if not injection_labels or any(not label for label in injection_labels):
            raise ValueError("injection_labels must be non-empty")
        if isinstance(max_length, bool) or not 1 <= max_length <= 8192:
            raise ValueError("max_length is outside its hard bounds")
        self.name = model_name
        self.version = model_version
        self._pipeline = pipeline
        self._injection_labels = frozenset(label.lower() for label in injection_labels)
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
        label, score = max(matching, key=lambda item: item[1])
        normalized_label = "jailbreak" if label.lower() == "jailbreak" else "prompt_injection"
        return PromptInjectionScore(score=score, label=normalized_label)


def _pipeline_candidates(raw: object) -> tuple[tuple[str, float], ...]:
    value = raw
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) == 1 and isinstance(value[0], Sequence):
            value = value[0]
        items = value
    else:
        items = (value,)
    candidates: list[tuple[str, float]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise TypeError("pipeline result must contain mappings")
        label = item.get("label")
        score = item.get("score")
        if not isinstance(label, str) or type(score) is not float or not 0.0 <= score <= 1.0:
            raise TypeError("pipeline result has an invalid label or score")
        candidates.append((label, score))
    return tuple(candidates)

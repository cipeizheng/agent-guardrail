"""Deployment-profiled semantic similarity without Policy-selected models."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from math import fsum, isfinite, sqrt
from typing import Protocol, TypeGuard, cast, runtime_checkable

from agent_guardrail.models import Detection, DetectionContext

MAX_SIMILARITY_TEXTS = 128
MAX_SIMILARITY_TEXT_BYTES = 16_384
MAX_SIMILARITY_INPUT_BYTES = 8_388_608
MAX_EMBEDDING_DIMENSIONS = 8_192
SIMILARITY_DETECTION_TYPE = "semantic_similarity"


@dataclass(frozen=True, slots=True)
class EmbeddingProfile:
    """Deployment-owned identity and model selection for one encoder."""

    profile_id: str
    profile_version: str
    model: str
    max_texts: int = 128
    max_input_bytes: int = 65_536
    max_dimensions: int = 8_192

    def __post_init__(self) -> None:
        _validate_identity(self.profile_id, "embedding profile id")
        _validate_identity(self.profile_version, "embedding profile version")
        _validate_model(self.model)
        if isinstance(self.max_texts, bool) or not 1 <= self.max_texts <= MAX_SIMILARITY_TEXTS:
            raise ValueError("embedding profile max_texts is outside hard bounds")
        if (
            isinstance(self.max_input_bytes, bool)
            or not 1 <= self.max_input_bytes <= MAX_SIMILARITY_INPUT_BYTES
        ):
            raise ValueError("embedding profile max_input_bytes is outside hard bounds")
        if (
            isinstance(self.max_dimensions, bool)
            or not 1 <= self.max_dimensions <= MAX_EMBEDDING_DIMENSIONS
        ):
            raise ValueError("embedding profile max_dimensions is outside hard bounds")


@runtime_checkable
class EmbeddingBackend(Protocol):
    """A deployment-owned encoder; Policy never supplies its model or endpoint."""

    name: str
    version: str

    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        model: str,
    ) -> tuple[tuple[float, ...], ...]: ...


class OpenAIEmbeddingBackend:
    """Use one injected OpenAI-compatible client with a profile-selected model."""

    name = "openai_embeddings"

    def __init__(self, client: object, *, backend_version: str) -> None:
        embeddings = getattr(client, "embeddings", None)
        create = getattr(embeddings, "create", None)
        if not callable(create) or not inspect.iscoroutinefunction(create):
            raise TypeError("OpenAI embedding client must expose async embeddings.create")
        _validate_identity(backend_version, "embedding backend version")
        self._create = cast(Callable[..., Awaitable[object]], create)
        self.version = backend_version

    async def embed(
        self,
        texts: tuple[str, ...],
        *,
        model: str,
    ) -> tuple[tuple[float, ...], ...]:
        raw = await self._create(input=list(texts), model=model, encoding_format="float")
        data = getattr(raw, "data", None)
        if not _is_builtin_sequence(data) or len(data) != len(texts):
            raise TypeError("embedding backend returned an invalid result collection")
        ordered: list[tuple[int, tuple[float, ...]]] = []
        for default_index, item in enumerate(data):
            index = getattr(item, "index", default_index)
            vector = getattr(item, "embedding", None)
            if isinstance(index, bool) or not isinstance(index, int):
                raise TypeError("embedding backend returned an invalid result index")
            ordered.append((index, _validate_vector(vector, MAX_EMBEDDING_DIMENSIONS)))
        ordered.sort(key=lambda item: item[0])
        if [index for index, _ in ordered] != list(range(len(texts))):
            raise ValueError("embedding backend returned inconsistent result indexes")
        return tuple(vector for _, vector in ordered)


class IsSimilarDetector:
    """Invariant-compatible max-pair semantic similarity with a fixed encoder profile."""

    name = "is_similar"
    adapter_version = "1"

    def __init__(self, backend: EmbeddingBackend, *, profile: EmbeddingProfile) -> None:
        if not isinstance(backend, EmbeddingBackend):
            raise TypeError("backend must implement EmbeddingBackend")
        _validate_identity(backend.name, "embedding backend name")
        _validate_identity(backend.version, "embedding backend version")
        if not isinstance(profile, EmbeddingProfile):
            raise TypeError("profile must be an EmbeddingProfile")
        self._backend = backend
        self._profile = profile
        identity = sha256(
            json.dumps(
                (
                    backend.name,
                    backend.version,
                    profile.profile_id,
                    profile.profile_version,
                    profile.model,
                    profile.max_texts,
                    profile.max_input_bytes,
                    profile.max_dimensions,
                ),
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    @property
    def profile(self) -> EmbeddingProfile:
        return self._profile

    async def compare(
        self,
        data: tuple[str, ...],
        target: tuple[str, ...],
        threshold: float,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        _validate_texts(data, self._profile.max_texts, "data")
        _validate_texts(target, self._profile.max_texts, "target")
        if sum(len(text.encode("utf-8")) for text in (*data, *target)) > (
            self._profile.max_input_bytes
        ):
            raise ValueError("similarity input bytes exceed the profile limit")
        _validate_threshold(threshold)
        combined = (*data, *target)
        vectors = await self._backend.embed(combined, model=self._profile.model)
        if not isinstance(vectors, tuple) or len(vectors) != len(combined):
            raise TypeError("embedding backend returned an invalid result collection")
        validated = tuple(
            _validate_vector(vector, self._profile.max_dimensions) for vector in vectors
        )
        data_vectors = validated[: len(data)]
        target_vectors = validated[len(data) :]
        best_score = -1.0
        best_pair = (0, 0)
        for data_index, left in enumerate(data_vectors):
            for target_index, right in enumerate(target_vectors):
                score = cosine_similarity(left, right)
                if score > best_score:
                    best_score = score
                    best_pair = (data_index, target_index)
        if best_score <= threshold:
            return []
        fingerprint = _similarity_fingerprint(context, self.version, *best_pair)
        return [
            Detection(
                type=SIMILARITY_DETECTION_TYPE,
                detector=self.name,
                detector_version=self.version,
                confidence=best_score,
                masked_evidence=(
                    f"<{self.name}:{SIMILARITY_DETECTION_TYPE}:{fingerprint}>"
                ),
                fingerprint=fingerprint,
            )
        ]


def cosine_similarity(
    left: Sequence[int | float],
    right: Sequence[int | float],
) -> float:
    """Compute a stable cosine score for finite, non-zero vectors."""

    left_vector = _validate_vector(left, MAX_EMBEDDING_DIMENSIONS)
    right_vector = _validate_vector(right, MAX_EMBEDDING_DIMENSIONS)
    if len(left_vector) != len(right_vector):
        raise ValueError("embedding vectors must have the same dimension")
    left_scale = max(abs(component) for component in left_vector)
    right_scale = max(abs(component) for component in right_vector)
    scaled_left = tuple(component / left_scale for component in left_vector)
    scaled_right = tuple(component / right_scale for component in right_vector)
    dot = fsum(a * b for a, b in zip(scaled_left, scaled_right, strict=True))
    left_norm = sqrt(fsum(component * component for component in scaled_left))
    right_norm = sqrt(fsum(component * component for component in scaled_right))
    return min(1.0, max(-1.0, dot / (left_norm * right_norm)))


def _validate_texts(texts: object, maximum: int, subject: str) -> None:
    if not isinstance(texts, tuple) or not texts or len(texts) > maximum:
        raise ValueError(f"similarity {subject} text count is outside hard bounds")
    if any(
        type(text) is not str
        or len(text.encode("utf-8")) > MAX_SIMILARITY_TEXT_BYTES
        for text in texts
    ):
        raise ValueError(f"similarity {subject} text is outside hard bounds")


def _validate_threshold(value: object) -> None:
    if type(value) is not float or not isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("similarity threshold must be a finite float in [0, 1]")


def _validate_vector(value: object, maximum: int) -> tuple[float, ...]:
    if not _is_builtin_sequence(value) or not value or len(value) > maximum:
        raise ValueError("embedding vector dimension is outside hard bounds")
    vector: list[float] = []
    for component in value:
        if isinstance(component, bool) or not isinstance(component, (int, float)):
            raise TypeError("embedding vector components must be finite numbers")
        normalized = float(component)
        if not isfinite(normalized):
            raise ValueError("embedding vector components must be finite numbers")
        vector.append(normalized)
    if not any(vector):
        raise ValueError("embedding vectors must be non-zero")
    return tuple(vector)


def _similarity_fingerprint(
    context: DetectionContext,
    version: str,
    data_index: int,
    target_index: int,
) -> str:
    material = json.dumps(
        (
            "agent-guardrail.similarity",
            context.trace_id,
            context.event_id,
            context.phase.value,
            version,
            data_index,
            target_index,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return sha256(material.encode("utf-8")).hexdigest()[:24]


def _validate_identity(value: object, subject: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(not (character.isalnum() or character in "._:+-") for character in value)
    ):
        raise ValueError(f"{subject} is invalid")


def _validate_model(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError("embedding profile model is invalid")


def _is_builtin_sequence(value: object) -> TypeGuard[list[object] | tuple[object, ...]]:
    return type(value) is list or type(value) is tuple

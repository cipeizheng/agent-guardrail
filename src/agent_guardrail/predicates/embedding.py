"""Pure and bounded cosine-similarity Predicate for explicit vectors."""

from __future__ import annotations

from collections.abc import Sequence
from math import fsum, isfinite, sqrt

from pydantic import JsonValue

from agent_guardrail.core.protocols import PredicateContext

MAX_EMBEDDING_DIMENSIONS = 8_192


class EmbeddingSimilarityPredicate:
    """Compare two explicit numeric vectors using cosine similarity."""

    name = "embedding_similarity"
    version = "1-vector-cosine"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del context
        left, right, raw_threshold = arguments
        threshold = _validated_threshold(raw_threshold)
        left_vector = _validated_json_vector(left, "left")
        right_vector = _validated_json_vector(right, "right")
        return cosine_similarity(left_vector, right_vector) > threshold


def cosine_similarity(
    left: Sequence[int | float],
    right: Sequence[int | float],
) -> float:
    """Compute a numerically stable cosine for finite, non-zero vectors."""

    left_vector = _validated_sequence(left, "left")
    right_vector = _validated_sequence(right, "right")
    if len(left_vector) != len(right_vector):
        raise ValueError("embedding vectors must have the same dimension")

    left_scale = max(abs(component) for component in left_vector)
    right_scale = max(abs(component) for component in right_vector)
    if left_scale == 0.0 or right_scale == 0.0:
        raise ValueError("embedding vectors must be non-zero")
    scaled_left = tuple(component / left_scale for component in left_vector)
    scaled_right = tuple(component / right_scale for component in right_vector)
    dot = fsum(a * b for a, b in zip(scaled_left, scaled_right, strict=True))
    left_norm = sqrt(fsum(component * component for component in scaled_left))
    right_norm = sqrt(fsum(component * component for component in scaled_right))
    similarity = dot / (left_norm * right_norm)
    return min(1.0, max(-1.0, similarity))


def _validated_threshold(value: JsonValue) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("embedding similarity threshold must be a finite number")
    threshold = float(value)
    if not isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("embedding similarity threshold must be in [0, 1]")
    return threshold


def _validated_json_vector(value: JsonValue, name: str) -> tuple[float, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{name} embedding must be a numeric array")
    return _validated_sequence(value, name)


def _validated_sequence(
    value: Sequence[object],
    name: str,
) -> tuple[float, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} embedding must be a numeric sequence")
    if not value or len(value) > MAX_EMBEDDING_DIMENSIONS:
        raise ValueError(f"{name} embedding dimension is outside hard bounds")
    components: list[float] = []
    for component in value:
        if isinstance(component, bool) or not isinstance(component, (int, float)):
            raise ValueError(f"{name} embedding components must be finite numbers")
        normalized = float(component)
        if not isfinite(normalized):
            raise ValueError(f"{name} embedding components must be finite numbers")
        components.append(normalized)
    return tuple(components)

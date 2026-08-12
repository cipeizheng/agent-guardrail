"""Bounded, literal fuzzy-substring matching without semantic I/O."""

from __future__ import annotations

from fractions import Fraction
from math import isfinite

from pydantic import JsonValue

from agent_guardrail.core.protocols import PredicateContext

MAX_FUZZY_SEARCH_BYTES = 16_384
MAX_FUZZY_QUERY_BYTES = 1_024
MAX_FUZZY_QUERY_CHARACTERS = 256
MAX_FUZZY_EDITS = 10
MAX_FUZZY_CELLS = 262_144


class FuzzyContainsPredicate:
    """Match a literal query within text with bounded Levenshtein edits.

    Unlike Invariant's optional semantic fallback, this implementation is a
    pure Predicate: it never calls a model, imports a backend, or interprets the
    query as a regular expression.
    """

    name = "fuzzy_contains"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del context
        search_text, query, raw_threshold = arguments
        threshold = _validated_threshold(raw_threshold)
        normalized_query = _validated_query(query)
        if type(search_text) is not str:
            return False
        if len(search_text.encode("utf-8")) > MAX_FUZZY_SEARCH_BYTES:
            raise ValueError("fuzzy search text exceeds its hard byte bound")
        if not search_text:
            return False

        edit_budget = len(normalized_query) * (1 - Fraction(str(threshold)))
        max_edits = min(
            MAX_FUZZY_EDITS,
            edit_budget.numerator // edit_budget.denominator,
        )
        if max_edits == 0:
            return normalized_query in search_text
        if len(search_text) * len(normalized_query) > MAX_FUZZY_CELLS:
            raise ValueError("fuzzy comparison exceeds its hard work bound")
        return _contains_with_max_distance(search_text, normalized_query, max_edits)


def _validated_threshold(value: JsonValue) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("fuzzy similarity threshold must be a finite number")
    threshold = float(value)
    if not isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("fuzzy similarity threshold must be in [0, 1]")
    return threshold


def _validated_query(value: JsonValue) -> str:
    if type(value) is not str or not value:
        raise ValueError("fuzzy query must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_FUZZY_QUERY_BYTES:
        raise ValueError("fuzzy query exceeds its hard byte bound")
    if len(value) > MAX_FUZZY_QUERY_CHARACTERS:
        raise ValueError("fuzzy query exceeds its hard character bound")
    return value


def _contains_with_max_distance(text: str, query: str, max_edits: int) -> bool:
    """Return whether any non-empty substring is within ``max_edits`` edits."""

    previous = list(range(len(query) + 1))
    for text_character in text:
        current = [0]
        for query_index, query_character in enumerate(query, start=1):
            current.append(
                min(
                    current[query_index - 1] + 1,
                    previous[query_index] + 1,
                    previous[query_index - 1]
                    + (query_character != text_character),
                )
            )
        if current[-1] <= max_edits:
            return True
        previous = current
    return False

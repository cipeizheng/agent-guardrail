"""Pure, deterministic predicates for numeric and JSON length bounds."""

from __future__ import annotations

from math import isfinite

from pydantic import JsonValue

from agent_guardrail.core.protocols import PredicateContext


class NumberInRangePredicate:
    """Return whether a finite JSON number is inside inclusive bounds."""

    name = "number_in_range"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del context
        value, minimum, maximum = arguments
        lower = _validated_number_bound(minimum, "minimum")
        upper = _validated_number_bound(maximum, "maximum")
        if lower > upper:
            raise ValueError("minimum cannot exceed maximum")
        number = _finite_number(value)
        if number is None:
            return False
        return lower <= number <= upper


class LengthInRangePredicate:
    """Check the inclusive size of a JSON string, array, or object."""

    name = "length_in_range"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del context
        value, minimum, maximum = arguments
        if type(minimum) is not int or type(maximum) is not int:
            raise ValueError("length bounds must be integers")
        if minimum < 0 or maximum < minimum:
            raise ValueError("length bounds are invalid")
        if type(value) is str or isinstance(value, (list, dict)):
            return minimum <= len(value) <= maximum
        return False


def _validated_number_bound(value: JsonValue, name: str) -> int | float:
    number = _finite_number(value)
    if number is None:
        raise ValueError(f"{name} must be a finite number")
    return number


def _finite_number(value: object) -> int | float | None:
    if type(value) is int:
        return value
    if type(value) is float and isfinite(value):
        return value
    return None

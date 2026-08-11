from __future__ import annotations

import pytest
from pydantic import JsonValue

from agent_guardrail.core import PredicateContext
from agent_guardrail.predicates import (
    LengthInRangePredicate,
    NumberInRangePredicate,
    URLHostAllowedPredicate,
)


def predicate_context() -> PredicateContext:
    return PredicateContext(
        trace_id="trace-1",
        rule_id="rule-1",
        condition_id="condition-1",
        event_ids=("event-1",),
    )


async def evaluate(predicate: object, *arguments: JsonValue) -> bool:
    return await predicate.evaluate(arguments, context=predicate_context())  # type: ignore[attr-defined]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "minimum", "maximum", "expected"),
    [
        (1, 1, 10, True),
        (10.0, 1, 10, True),
        (10.01, 1, 10, False),
        (-1, 0, 10, False),
        (True, 0, 1, False),
        ("5", 0, 10, False),
    ],
)
async def test_number_in_range_is_inclusive_and_type_strict(
    value: JsonValue,
    minimum: JsonValue,
    maximum: JsonValue,
    expected: bool,
) -> None:
    assert await evaluate(NumberInRangePredicate(), value, minimum, maximum) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        (1, 2, 1),
        (1, "0", 1),
        (1, 0, "1"),
    ],
)
async def test_number_in_range_rejects_invalid_policy_bounds(
    arguments: tuple[JsonValue, JsonValue, JsonValue],
) -> None:
    with pytest.raises(ValueError, match="bound|minimum|maximum"):
        await evaluate(NumberInRangePredicate(), *arguments)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "minimum", "maximum", "expected"),
    [
        ("安全", 2, 2, True),
        ([1, 2, 3], 1, 3, True),
        ({"a": 1, "b": 2}, 2, 2, True),
        ("toolong", 0, 6, False),
        (7, 1, 3, False),
        (None, 0, 0, False),
    ],
)
async def test_length_in_range_supports_bounded_json_containers(
    value: JsonValue,
    minimum: JsonValue,
    maximum: JsonValue,
    expected: bool,
) -> None:
    assert await evaluate(LengthInRangePredicate(), value, minimum, maximum) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("bounds", [(-1, 1), (2, 1), (0.0, 1)])
async def test_length_in_range_rejects_invalid_policy_bounds(
    bounds: tuple[JsonValue, JsonValue],
) -> None:
    with pytest.raises(ValueError, match="length bounds"):
        await evaluate(LengthInRangePredicate(), "value", *bounds)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "allowed_hosts", "expected"),
    [
        ("https://example.test/path", ["example.test"], True),
        ("https://EXAMPLE.test.:8443/path", ["example.test"], True),
        ("https://api.trusted.test/path", ["*.trusted.test"], True),
        ("https://trusted.test/path", ["*.trusted.test"], False),
        ("https://example.test.evil.test/path", ["example.test"], False),
        ("https://user@example.test/path", ["example.test"], False),
        ("file://example.test/path", ["example.test"], False),
        ("https://example.test:99999/path", ["example.test"], False),
        (" https://example.test/path", ["example.test"], False),
        ("https://[2001:db8::1]/", ["2001:db8::1"], True),
    ],
)
async def test_url_host_allowed_uses_exact_or_explicit_wildcard_matching(
    url: str,
    allowed_hosts: list[JsonValue],
    expected: bool,
) -> None:
    assert await evaluate(URLHostAllowedPredicate(), url, allowed_hosts) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "allowed_hosts",
    [[], [""], [" example.test"], ["*.127.0.0.1"], [7]],
)
async def test_url_host_allowed_rejects_invalid_policy_allowlists(
    allowed_hosts: list[JsonValue],
) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        await evaluate(URLHostAllowedPredicate(), "https://example.test", allowed_hosts)

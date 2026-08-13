from __future__ import annotations

import pytest

from agent_guardrail.detectors.secrets import SecretDetector
from agent_guardrail.models import DetectionContext

# Synthetic, inert shapes are assembled so repository scanners never mistake
# detector fixtures for deployable credentials.
_GITHUB_TOKEN = "ghp_" + "wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pINUx"
_AWS_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_AZURE_STORAGE_KEY = (
    "lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+"
    "qnlcNQSnIYVTkLWntUO1F8j8rQ=="
)
_SLACK_TOKEN = "xox" + "b-123456789012-1234567890123-1234567890123-1234567890123"


def _context(*, event_id: str = "event-1") -> DetectionContext:
    return DetectionContext(
        trace_id="trace-1",
        event_id=event_id,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "detection_type"),
    [
        (_GITHUB_TOKEN, "github_token"),
        (_AWS_ACCESS_KEY, "aws_access_key"),
        (f"AccountKey={_AZURE_STORAGE_KEY}", "azure_storage_key"),
        (_SLACK_TOKEN, "slack_token"),
        (
            "https://hooks.slack.com/services/T00000000/B00000000/"
            "abcdefghijklmnopqrstuvwx",
            "slack_token",
        ),
    ],
)
async def test_invariant_provider_secret_shapes_are_detected(
    value: str,
    detection_type: str,
) -> None:
    detections = await SecretDetector().detect(
        f"before {value} after",
        context=_context(),
    )

    matching = next(item for item in detections if item.type == detection_type)
    assert matching.detector_version == "2"
    assert matching.masked_evidence.startswith(f"<secrets:{detection_type}:")
    assert value not in matching.model_dump_json()


@pytest.mark.asyncio
async def test_contextual_aws_secret_access_key_is_detected_at_value_span() -> None:
    value = "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5bC7d"
    text = f"aws_secret_access_key = '{value}'"

    detections = await SecretDetector().detect(text, context=_context())

    assert [item.type for item in detections] == ["aws_access_key"]
    assert text[detections[0].start : detections[0].end] == value
    assert value not in detections[0].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "detection_type"),
    [
        ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "private_key"),
        ("sk-" + "test000000000000000000", "openai_api_key"),
        ("Bearer aB3dE5fG7hI9jK1mN3pQ", "bearer_token"),
        ("api_key = aB3dE5fG7hI9jK1m", "assigned_secret"),
    ],
)
async def test_existing_secret_categories_are_preserved(
    value: str,
    detection_type: str,
) -> None:
    detections = await SecretDetector().detect(value, context=_context())

    assert [item.type for item in detections] == [detection_type]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "ghp_" + "wWPw5k4aXcaT4fcnZwJUVFk6LO0pINUx",
        "prefix" + _AWS_ACCESS_KEY + "suffix",
        "AKSAIOSFODNN7EXAMPLE",
        f"AxccountKey={_AZURE_STORAGE_KEY}",
        "abde-123456789012-1234567890123-1234567890123",
        "api_key = your_api_key_here",
        "secret = aaaaaaaaaaaaaaaa",
        "Bearer placeholder-token-value",
    ],
)
async def test_invalid_boundaries_and_placeholders_are_rejected(value: str) -> None:
    assert await SecretDetector().detect(value, context=_context()) == []


@pytest.mark.asyncio
async def test_specific_provider_result_wins_over_assigned_secret_overlap() -> None:
    text = f'api_key = "{_GITHUB_TOKEN}"'

    detections = await SecretDetector().detect(text, context=_context())

    assert [item.type for item in detections] == ["github_token"]
    assert text[detections[0].start : detections[0].end] == _GITHUB_TOKEN


@pytest.mark.asyncio
async def test_multiple_secret_results_are_non_overlapping_and_span_sorted() -> None:
    text = f"{_SLACK_TOKEN} then {_AWS_ACCESS_KEY} then {_GITHUB_TOKEN}"

    detections = await SecretDetector().detect(text, context=_context())

    assert all(item.start is not None and item.end is not None for item in detections)
    spans = [
        (item.start, item.end)
        for item in detections
        if item.start is not None and item.end is not None
    ]
    assert [item.type for item in detections] == [
        "slack_token",
        "aws_access_key",
        "github_token",
    ]
    assert spans == sorted(spans)
    assert all(
        first_end <= second_start
        for (_, first_end), (second_start, _) in zip(spans, spans[1:], strict=False)
    )


@pytest.mark.asyncio
async def test_secret_fingerprint_is_payload_free_and_occurrence_bound() -> None:
    first_value = _GITHUB_TOKEN
    second_value = _GITHUB_TOKEN[:-1] + "z"
    detector = SecretDetector()

    first = await detector.detect(first_value, context=_context())
    same_occurrence = await detector.detect(second_value, context=_context())
    other_event = await detector.detect(first_value, context=_context(event_id="event-2"))

    assert first[0].fingerprint == same_occurrence[0].fingerprint
    assert first[0].fingerprint != other_event[0].fingerprint
    assert first_value not in first[0].model_dump_json()
    assert second_value not in same_occurrence[0].model_dump_json()


@pytest.mark.asyncio
async def test_occurrence_fingerprint_has_unambiguous_context_boundaries() -> None:
    detector = SecretDetector()
    first = await detector.detect(
        _GITHUB_TOKEN,
        context=DetectionContext(trace_id="trace:a", event_id="event"),
    )
    second = await detector.detect(
        _GITHUB_TOKEN,
        context=DetectionContext(trace_id="trace", event_id="a:event"),
    )

    assert first[0].fingerprint != second[0].fingerprint


@pytest.mark.asyncio
async def test_secret_detector_fails_on_result_overflow() -> None:
    text = " ".join(f"ghp_{index:036d}" for index in range(65))

    with pytest.raises(ValueError, match="result limit"):
        await SecretDetector().detect(text, context=_context())

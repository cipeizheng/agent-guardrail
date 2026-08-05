from __future__ import annotations

import pytest

from agent_guardrail.detectors.pii import PIIDetector
from agent_guardrail.models import DetectionContext, Phase
from tests.support import (
    FAKE_CN_MOBILE,
    FAKE_CN_RESIDENT_ID,
    fake_cn_resident_id,
)


def detection_context(*, event_id: str = "event-1") -> DetectionContext:
    return DetectionContext(
        trace_id="trace-1",
        event_id=event_id,
        phase=Phase.PRE_TOOL,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("value", "entity_type"),
    [
        ("customer@example.test", "email_address"),
        ("(415) 555-2671", "phone_number"),
        ("123-45-6789", "us_ssn"),
        ("4242 4242 4242 4242", "credit_card"),
        (FAKE_CN_RESIDENT_ID, "cn_resident_id"),
        (FAKE_CN_MOBILE, "cn_mobile_phone"),
        ("+86 139-0000-0001", "cn_mobile_phone"),
    ],
)
async def test_supported_pii_shapes_are_detected_without_raw_evidence(
    value: str,
    entity_type: str,
) -> None:
    detections = await PIIDetector().detect(
        f"Before {value} after",
        context=detection_context(),
    )

    assert [detection.type for detection in detections] == [entity_type]
    assert detections[0].masked_evidence.startswith(f"<pii:{entity_type}:")
    assert value not in detections[0].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "4242 4242 4242 4241",
        "123456789",
        "4155552671",
        "000-12-3456",
        "123-45 6789",
        "415-555.2671",
        "customer.@example.test",
        "not-an-email@localhost",
    ],
)
async def test_unsupported_or_invalid_shapes_are_not_detected(value: str) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert detections == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        FAKE_CN_RESIDENT_ID[:-1] + ("0" if FAKE_CN_RESIDENT_ID[-1] != "0" else "1"),
        fake_cn_resident_id("11000020000230001"),
        fake_cn_resident_id("99000020000101001"),
    ],
)
async def test_invalid_cn_resident_ids_are_not_classified_as_resident_ids(
    value: str,
) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert "cn_resident_id" not in {detection.type for detection in detections}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "129 0000 0001",
        "139-0000 0001",
        "139000000010",
        "prefix13900000001suffix",
    ],
)
async def test_invalid_cn_mobile_shapes_are_not_detected(value: str) -> None:
    detections = await PIIDetector().detect(value, context=detection_context())

    assert "cn_mobile_phone" not in {detection.type for detection in detections}


@pytest.mark.asyncio
async def test_occurrence_fingerprint_is_context_bound_not_a_raw_value_hash() -> None:
    detector = PIIDetector()
    first = await detector.detect("customer@example.test", context=detection_context())
    second = await detector.detect(
        "customer@example.test",
        context=detection_context(event_id="event-2"),
    )

    assert first[0].fingerprint != second[0].fingerprint


@pytest.mark.asyncio
async def test_multiple_non_overlapping_entities_are_sorted_by_span() -> None:
    text = "Call (415) 555-2671 or email customer@example.test."

    detections = await PIIDetector().detect(text, context=detection_context())

    assert [detection.type for detection in detections] == [
        "phone_number",
        "email_address",
    ]
    assert [detection.start for detection in detections] == sorted(
        detection.start for detection in detections if detection.start is not None
    )

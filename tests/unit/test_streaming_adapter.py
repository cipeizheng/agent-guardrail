from __future__ import annotations

import pytest

from agent_guardrail.adapters.streaming import (
    BoundedSSEParser,
    ProviderStreamUpdate,
    ServerSentEvent,
    StreamProtocolError,
    StreamRelease,
)
from agent_guardrail.models import ModelResponse


def test_sse_parser_handles_chunk_boundaries_and_normalizes_safe_fields() -> None:
    parser = BoundedSSEParser(max_event_bytes=128, max_events=2)

    first = parser.feed(b'event: response.output_text.delta\r\ndata: {"delta":')
    second = parser.feed(b'"safe"}\r\n\r\n')
    parser.finish()

    assert first == ()
    assert second[0].event == "response.output_text.delta"
    assert second[0].data == '{"delta":"safe"}'
    assert second[0].encode().endswith(b"\n\n")


@pytest.mark.parametrize(
    "payload",
    [
        b"id: secret\ndata: safe\n\n",
        b"data: \xff\n\n",
        b"event: bad event\ndata: safe\n\n",
        b"event: one\nevent: two\ndata: safe\n\n",
    ],
)
def test_sse_parser_rejects_unsupported_or_invalid_fields(payload: bytes) -> None:
    parser = BoundedSSEParser(max_event_bytes=128, max_events=2)

    with pytest.raises(StreamProtocolError):
        parser.feed(payload)


def test_sse_parser_fails_on_size_count_and_incomplete_event() -> None:
    with pytest.raises(StreamProtocolError) as size:
        BoundedSSEParser(max_event_bytes=4, max_events=2).feed(b"data: too-long")
    parser = BoundedSSEParser(max_event_bytes=32, max_events=1)
    parser.feed(b"data: one\n\n")
    with pytest.raises(StreamProtocolError) as count:
        parser.feed(b"data: two\n\n")
    incomplete_parser = BoundedSSEParser(max_event_bytes=32, max_events=1)
    incomplete_parser.feed(b"data: partial")
    with pytest.raises(StreamProtocolError) as incomplete:
        incomplete_parser.finish()

    assert size.value.code == "upstream_stream_limit"
    assert count.value.code == "upstream_stream_limit"
    assert incomplete.value.code == "upstream_incomplete_sse"


def test_sse_parser_accepts_exact_limit_multiline_data_and_ignores_empty_events() -> None:
    raw = b"event: token\ndata: first\ndata: second"
    parser = BoundedSSEParser(max_event_bytes=len(raw), max_events=1)

    events = parser.feed(b"\n\n" + raw + b"\n\n")
    parser.feed(b"\r\n\t \r\n")
    parser.finish()

    assert events == (ServerSentEvent(event="token", data="first\nsecond"),)
    assert events[0].encode() == b"event: token\ndata: first\ndata: second\n\n"


def test_sse_parser_rejects_invalid_constructor_chunk_and_missing_data() -> None:
    with pytest.raises(ValueError, match="positive"):
        BoundedSSEParser(max_event_bytes=0, max_events=1)
    parser = BoundedSSEParser(max_event_bytes=32, max_events=1)
    with pytest.raises(TypeError, match="bytes"):
        parser.feed("data: safe\n\n")  # type: ignore[arg-type]
    with pytest.raises(StreamProtocolError, match="without data"):
        parser.feed(b"event: token\n\n")


def test_stream_update_enforces_release_output_invariants() -> None:
    output = ModelResponse(content="safe")

    assert (
        ProviderStreamUpdate(
            release=StreamRelease.HOLD,
            event=ServerSentEvent(data="{}"),
        ).output
        is None
    )
    assert (
        ProviderStreamUpdate(
            release=StreamRelease.GUARD,
            output=output,
        ).output
        is output
    )
    with pytest.raises(ValueError, match="held"):
        ProviderStreamUpdate(release=StreamRelease.HOLD, output=output)
    with pytest.raises(ValueError, match="require canonical"):
        ProviderStreamUpdate(release=StreamRelease.FINAL)

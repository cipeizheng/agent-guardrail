"""Provider-neutral, bounded Server-Sent Event parsing and release instructions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from agent_guardrail.models import ModelResponse

_EVENT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


class StreamProtocolError(ValueError):
    """A stable error for malformed or unsupported upstream SSE."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ServerSentEvent:
    """The content-bearing SSE fields accepted and re-emitted by the Gateway."""

    data: str
    event: str | None = None

    def encode(self) -> bytes:
        lines: list[str] = []
        if self.event is not None:
            lines.append(f"event: {self.event}")
        data_lines = self.data.splitlines() or [""]
        lines.extend(f"data: {line}" for line in data_lines)
        return ("\n".join(lines) + "\n\n").encode("utf-8")


class StreamRelease(StrEnum):
    """How the Gateway handles one parsed provider event."""

    HOLD = "hold"
    GUARD = "guard"
    FINAL = "final"


@dataclass(frozen=True, slots=True)
class ProviderStreamUpdate:
    """One Adapter instruction over its accumulated canonical output.

    ``event`` is the Adapter-normalized wire event.  The Gateway never forwards the
    unparsed upstream event; ``None`` deliberately drops a structural event.
    """

    release: StreamRelease
    output: ModelResponse | None = None
    event: ServerSentEvent | None = None

    def __post_init__(self) -> None:
        if self.release is StreamRelease.HOLD and self.output is not None:
            raise ValueError("held stream updates cannot expose canonical output")
        if self.release is not StreamRelease.HOLD and self.output is None:
            raise ValueError("guarded stream updates require canonical output")


class BoundedSSEParser:
    """Incrementally parse a strict SSE subset without retaining unbounded input."""

    def __init__(self, *, max_event_bytes: int, max_events: int) -> None:
        if max_event_bytes < 1 or max_events < 1:
            raise ValueError("SSE parser limits must be positive")
        self.max_event_bytes = max_event_bytes
        self.max_events = max_events
        self._buffer = bytearray()
        self._events = 0

    def feed(self, chunk: bytes) -> tuple[ServerSentEvent, ...]:
        if not isinstance(chunk, bytes):
            raise TypeError("SSE chunks must be bytes")
        self._buffer.extend(chunk)
        events: list[ServerSentEvent] = []
        while True:
            boundary = self._find_boundary()
            if boundary is None:
                if len(self._buffer) > self.max_event_bytes:
                    self._raise_limit()
                break
            position, delimiter_size = boundary
            if position > self.max_event_bytes:
                self._raise_limit()
            raw = bytes(self._buffer[:position])
            del self._buffer[: position + delimiter_size]
            if not raw:
                continue
            self._events += 1
            if self._events > self.max_events:
                self._raise_limit()
            events.append(self._parse_event(raw))
        return tuple(events)

    def finish(self) -> tuple[ServerSentEvent, ...]:
        if not self._buffer:
            return ()
        if bytes(self._buffer).strip(b"\r\n\t "):
            raise StreamProtocolError(
                "upstream_incomplete_sse",
                "The upstream model stream ended with an incomplete event.",
            )
        self._buffer.clear()
        return ()

    def _find_boundary(self) -> tuple[int, int] | None:
        candidates: list[tuple[int, int]] = []
        for delimiter in (b"\r\n\r\n", b"\n\n", b"\r\r"):
            position = self._buffer.find(delimiter)
            if position >= 0:
                candidates.append((position, len(delimiter)))
        return min(candidates, default=None, key=lambda item: item[0])

    @staticmethod
    def _parse_event(raw: bytes) -> ServerSentEvent:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise StreamProtocolError(
                "upstream_invalid_sse",
                "The upstream model returned invalid UTF-8 SSE.",
            ) from None
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        event_name: str | None = None
        data_lines: list[str] = []
        for line in lines:
            if not line:
                continue
            field, separator, value = line.partition(":")
            if not separator or field not in {"event", "data"}:
                raise StreamProtocolError(
                    "upstream_invalid_sse",
                    "The upstream model returned an unsupported SSE field.",
                )
            normalized = value[1:] if value.startswith(" ") else value
            if field == "event":
                if event_name is not None or not _EVENT_NAME.fullmatch(normalized):
                    raise StreamProtocolError(
                        "upstream_invalid_sse",
                        "The upstream model returned an invalid SSE event name.",
                    )
                event_name = normalized
            else:
                data_lines.append(normalized)
        if not data_lines:
            raise StreamProtocolError(
                "upstream_invalid_sse",
                "The upstream model returned an SSE event without data.",
            )
        return ServerSentEvent(data="\n".join(data_lines), event=event_name)

    @staticmethod
    def _raise_limit() -> None:
        raise StreamProtocolError(
            "upstream_stream_limit",
            "The upstream model stream exceeds its configured limit.",
        )

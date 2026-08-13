"""Provider-neutral contracts for model HTTP adapters."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar

from agent_guardrail.adapters.streaming import (
    ProviderStreamUpdate,
    ServerSentEvent,
)
from agent_guardrail.models import ModelRequest, ModelResponse


class ProviderAdapterError(ValueError):
    """A safe provider protocol error without request or response content."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class ProviderStreamDecoder(Protocol):
    """Statefully convert provider SSE into cumulative canonical output."""

    def consume(self, event: ServerSentEvent) -> ProviderStreamUpdate:
        """Consume one event and decide whether it can be guarded and released."""
        ...

    def finish(self) -> None:
        """Validate that the provider stream reached its required terminal event."""
        ...

    def error_event(self, *, code: str, message: str) -> ServerSentEvent:
        """Build a provider-compatible, content-redacted terminal error event."""
        ...


RequestT = TypeVar("RequestT")
ResponseT = TypeVar("ResponseT")


class ModelProviderAdapter(Protocol[RequestT, ResponseT]):
    """A wire-format adapter around the provider-neutral model boundary."""

    upstream_path: str

    def parse_request(self, payload: object) -> RequestT: ...

    def request_to_canonical(self, request: RequestT) -> ModelRequest: ...

    def request_payload(self, request: RequestT) -> dict[str, Any]: ...

    def is_streaming(self, request: RequestT) -> bool: ...

    def parse_response(self, payload: object) -> ResponseT: ...

    def response_to_canonical(
        self,
        response: ResponseT,
        *,
        request: RequestT,
    ) -> ModelResponse: ...

    def response_payload(self, response: ResponseT) -> dict[str, Any]: ...

    def stream_decoder(self, request: RequestT) -> ProviderStreamDecoder: ...

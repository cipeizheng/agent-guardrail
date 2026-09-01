"""Opt-in Responses response state used by the Gateway integration POC.

The production state owner is expected to be supplied by a dedicated Responses
server (for example, a LiteLLM integration).  This bounded in-memory store is
deliberately injectable and is only useful for proving the ordering contract:
resolve ``previous_response_id`` before Guardrail normalization, then persist a
completed response after output enforcement.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol

from agent_guardrail.adapters.openai.responses_models import (
    ResponsesFunctionCall,
    ResponsesFunctionCallInput,
    ResponsesInputItem,
    ResponsesInputMessage,
    ResponsesOutputMessage,
    ResponsesOutputText,
    ResponsesRefusal,
    ResponsesRequest,
    ResponsesResponse,
)


class ResponsesStateError(RuntimeError):
    """A safe failure from the Responses state owner."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class StoredResponsesState:
    """The bounded state needed to continue one completed Responses chain."""

    response: ResponsesResponse
    input_history: tuple[ResponsesInputItem, ...]


class ResponsesStateStore(Protocol):
    """State-owner contract used after authentication and before enforcement."""

    async def resolve_request(self, request: ResponsesRequest) -> ResponsesRequest: ...

    async def save_response(
        self,
        *,
        request: ResponsesRequest,
        response: ResponsesResponse,
    ) -> None: ...


class InMemoryResponsesStateStore:
    """Bounded process-local state store for the Responses integration POC.

    It intentionally does not claim restart, replica, or tenant durability. A
    missing entry fails closed, which makes an eventual external state owner
    replaceable without weakening the Gateway boundary.
    """

    def __init__(
        self,
        *,
        max_entries: int = 1_024,
        max_history_items: int = 4_096,
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        if (
            isinstance(max_history_items, bool)
            or not isinstance(max_history_items, int)
            or max_history_items < 1
        ):
            raise ValueError("max_history_items must be a positive integer")
        self.max_entries = max_entries
        self.max_history_items = max_history_items
        self._states: OrderedDict[str, StoredResponsesState] = OrderedDict()
        self._lock = asyncio.Lock()

    async def resolve_request(self, request: ResponsesRequest) -> ResponsesRequest:
        """Expand a request with the stored input and output item history."""

        previous_response_id = request.previous_response_id
        if previous_response_id is None:
            return request

        async with self._lock:
            state = self._states.get(previous_response_id)
            if state is not None:
                self._states.move_to_end(previous_response_id)
        if state is None:
            raise ResponsesStateError(
                "invalid_previous_response_id",
                "The previous Responses response could not be found.",
            )

        current_input = _request_input_items(request)
        resolved_input = (
            *state.input_history,
            *_response_output_items(state.response),
            *current_input,
        )
        if len(resolved_input) > self.max_history_items:
            raise ResponsesStateError(
                "responses_state_limit",
                "The Responses conversation exceeds the configured state limit.",
            )
        return request.model_copy(update={"input": resolved_input})

    async def save_response(
        self,
        *,
        request: ResponsesRequest,
        response: ResponsesResponse,
    ) -> None:
        """Persist only an output that has passed the output-release check."""

        if request.store is False:
            return
        input_history = _request_input_items(request)
        if len(input_history) + len(response.output) > self.max_history_items:
            raise ResponsesStateError(
                "responses_state_limit",
                "The Responses conversation exceeds the configured state limit.",
            )
        state = StoredResponsesState(
            response=response,
            input_history=input_history,
        )
        async with self._lock:
            self._states[response.id] = state
            self._states.move_to_end(response.id)
            while len(self._states) > self.max_entries:
                self._states.popitem(last=False)


def _request_input_items(request: ResponsesRequest) -> tuple[ResponsesInputItem, ...]:
    if isinstance(request.input, str):
        return (ResponsesInputMessage(role="user", content=request.input),)
    return request.input


def _response_output_items(
    response: ResponsesResponse,
) -> tuple[ResponsesInputItem, ...]:
    items: list[ResponsesInputItem] = []
    for item in response.output:
        if isinstance(item, ResponsesOutputMessage):
            text_parts: list[str] = []
            for content in item.content:
                if isinstance(content, (ResponsesOutputText, ResponsesRefusal)):
                    text_parts.append(
                        content.text
                        if isinstance(content, ResponsesOutputText)
                        else content.refusal
                    )
            if text_parts:
                items.append(
                    ResponsesInputMessage(
                        role="assistant",
                        content="".join(text_parts),
                    )
                )
        elif isinstance(item, ResponsesFunctionCall):
            items.append(
                ResponsesFunctionCallInput(
                    type="function_call",
                    call_id=item.call_id,
                    name=item.name,
                    arguments=item.arguments,
                    id=item.id,
                    status=item.status,
                )
            )
    return tuple(items)

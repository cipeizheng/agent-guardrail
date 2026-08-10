"""Deterministic expansion of provider-neutral chat DTOs into event candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from pydantic import JsonValue, ValidationError

from agent_guardrail.models import (
    MAX_PENDING_EVENTS,
    MAX_RELATIONS_PER_EVENT,
    CandidateEvent,
    CandidateRelation,
    ChatMessage,
    ChatRole,
    EventKind,
    EventOrigin,
    Message,
    MessageRole,
    ModelRequest,
    ModelResponse,
    Phase,
    TextContent,
    ToolCall,
    ToolResult,
)

_MESSAGE_ROLES: dict[ChatRole, MessageRole] = {
    ChatRole.SYSTEM: MessageRole.SYSTEM,
    ChatRole.USER: MessageRole.USER,
    ChatRole.ASSISTANT: MessageRole.ASSISTANT,
}
_ERROR_MESSAGES: dict[str, str] = {
    "candidate_limit_exceeded": "The canonical input expands to too many events.",
    "duplicate_tool_call_id": "A tool-call turn contains duplicate call IDs.",
    "duplicate_tool_result": "A tool call has more than one result in the same turn.",
    "incomplete_tool_call_group": "A tool-call turn is missing one or more results.",
    "invalid_canonical_input": "The provider-neutral chat input is malformed.",
    "orphan_tool_result": "A tool result does not match the active tool-call turn.",
    "relation_limit_exceeded": "A canonical event contains too many relations.",
}


class InputNormalizationError(ValueError):
    """A safe normalization failure that does not include provider content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


@dataclass(frozen=True, slots=True)
class NormalizedBatch:
    """A complete candidate batch and its deterministic primary candidate."""

    candidates: tuple[CandidateEvent, ...]
    primary_key: str

    def __post_init__(self) -> None:
        if not self.candidates:
            raise ValueError("normalized candidate batch must not be empty")
        candidate_keys = tuple(candidate.key for candidate in self.candidates)
        if len(candidate_keys) != len(set(candidate_keys)):
            raise ValueError("normalized candidate keys must be unique")
        if self.primary_key not in candidate_keys:
            raise ValueError("normalized primary_key must identify a candidate")
        if len({candidate.phase for candidate in self.candidates}) != 1:
            raise ValueError("normalized candidates must use one enforcement phase")


class InputNormalizer:
    """Expand canonical chat DTOs without assigning trace identity or performing I/O."""

    def __init__(
        self,
        *,
        max_candidates: int = MAX_PENDING_EVENTS,
        max_relations_per_event: int = MAX_RELATIONS_PER_EVENT,
    ) -> None:
        if (
            isinstance(max_candidates, bool)
            or not isinstance(max_candidates, int)
            or not 1 <= max_candidates <= MAX_PENDING_EVENTS
        ):
            raise ValueError(f"max_candidates must be between 1 and {MAX_PENDING_EVENTS}")
        if (
            isinstance(max_relations_per_event, bool)
            or not isinstance(max_relations_per_event, int)
            or not 0 <= max_relations_per_event <= MAX_RELATIONS_PER_EVENT
        ):
            raise ValueError(
                "max_relations_per_event must be between "
                f"0 and {MAX_RELATIONS_PER_EVENT}"
            )
        self.max_candidates = max_candidates
        self.max_relations_per_event = max_relations_per_event

    def normalize_request_snapshot(self, request: ModelRequest) -> NormalizedBatch:
        """Expand one full request history as client-asserted pre-LLM events."""

        validated = self._validated_request(request)
        candidates: list[CandidateEvent] = []
        active_calls: dict[str, tuple[str, ToolCall]] | None = None
        unresolved_call_ids: set[str] = set()

        for message_index, chat_message in enumerate(validated.messages):
            if chat_message.role is ChatRole.TOOL:
                active_calls, unresolved_call_ids = self._append_tool_result(
                    chat_message,
                    message_index=message_index,
                    active_calls=active_calls,
                    unresolved_call_ids=unresolved_call_ids,
                    candidates=candidates,
                )
                continue

            if active_calls is not None:
                if unresolved_call_ids:
                    raise InputNormalizationError("incomplete_tool_call_group")
                active_calls = None
                unresolved_call_ids = set()

            if chat_message.content is not None:
                self._append(
                    candidates,
                    CandidateEvent(
                        key=f"request-message-{message_index}",
                        kind=EventKind.MESSAGE,
                        phase=Phase.PRE_LLM,
                        payload=self._message_payload(chat_message),
                        origin=EventOrigin.CLIENT_ASSERTED,
                    ),
                )

            if chat_message.role is ChatRole.ASSISTANT and chat_message.tool_calls:
                active_calls = {}
                for call_index, call in enumerate(chat_message.tool_calls):
                    if call.call_id in active_calls:
                        raise InputNormalizationError("duplicate_tool_call_id")
                    candidate_key = f"request-tool-call-{message_index}-{call_index}"
                    self._append(
                        candidates,
                        CandidateEvent(
                            key=candidate_key,
                            kind=EventKind.TOOL_CALL,
                            phase=Phase.PRE_LLM,
                            payload=cast(
                                dict[str, JsonValue],
                                call.model_dump(mode="json"),
                            ),
                            origin=EventOrigin.CLIENT_ASSERTED,
                        ),
                    )
                    active_calls[call.call_id] = (candidate_key, call)
                unresolved_call_ids = set(active_calls)

        if unresolved_call_ids:
            raise InputNormalizationError("incomplete_tool_call_group")
        return NormalizedBatch(
            candidates=tuple(candidates),
            primary_key=candidates[-1].key,
        )

    def normalize_response(self, response: ModelResponse) -> NormalizedBatch:
        """Expand one observed model response as post-LLM events."""

        validated = self._validated_response(response)
        candidates: list[CandidateEvent] = []
        if validated.content is not None:
            message = Message(
                role=MessageRole.ASSISTANT,
                content=TextContent(text=validated.content),
            )
            self._append(
                candidates,
                CandidateEvent(
                    key="response-message",
                    kind=EventKind.MESSAGE,
                    phase=Phase.POST_LLM,
                    payload=cast(
                        dict[str, JsonValue],
                        message.model_dump(mode="json"),
                    ),
                    origin=EventOrigin.OBSERVED,
                ),
            )

        for call_index, call in enumerate(validated.tool_calls):
            self._append(
                candidates,
                CandidateEvent(
                    key=f"response-tool-call-{call_index}",
                    kind=EventKind.TOOL_CALL,
                    phase=Phase.POST_LLM,
                    payload=cast(dict[str, JsonValue], call.model_dump(mode="json")),
                    origin=EventOrigin.OBSERVED,
                ),
            )

        return NormalizedBatch(
            candidates=tuple(candidates),
            primary_key=candidates[-1].key,
        )

    def _append_tool_result(
        self,
        chat_message: ChatMessage,
        *,
        message_index: int,
        active_calls: dict[str, tuple[str, ToolCall]] | None,
        unresolved_call_ids: set[str],
        candidates: list[CandidateEvent],
    ) -> tuple[dict[str, tuple[str, ToolCall]], set[str]]:
        call_id = chat_message.tool_call_id
        content = chat_message.content
        if call_id is None or content is None:
            raise InputNormalizationError("invalid_canonical_input")
        if active_calls is None or call_id not in active_calls:
            raise InputNormalizationError("orphan_tool_result")
        if call_id not in unresolved_call_ids:
            raise InputNormalizationError("duplicate_tool_result")

        source_candidate_key, call = active_calls[call_id]
        result = ToolResult(call_id=call_id, name=call.name, output=content)
        self._append(
            candidates,
            CandidateEvent(
                key=f"request-tool-result-{message_index}",
                kind=EventKind.TOOL_RESULT,
                phase=Phase.PRE_LLM,
                payload=cast(dict[str, JsonValue], result.model_dump(mode="json")),
                origin=EventOrigin.CLIENT_ASSERTED,
                relations=(
                    CandidateRelation(source_candidate_key=source_candidate_key),
                ),
            ),
        )
        unresolved_call_ids.remove(call_id)
        return active_calls, unresolved_call_ids

    def _append(
        self,
        candidates: list[CandidateEvent],
        candidate: CandidateEvent,
    ) -> None:
        if len(candidates) >= self.max_candidates:
            raise InputNormalizationError("candidate_limit_exceeded")
        if len(candidate.relations) > self.max_relations_per_event:
            raise InputNormalizationError("relation_limit_exceeded")
        candidates.append(candidate)

    @staticmethod
    def _message_payload(chat_message: ChatMessage) -> dict[str, JsonValue]:
        message_role = _MESSAGE_ROLES.get(chat_message.role)
        if message_role is None or chat_message.content is None:
            raise InputNormalizationError("invalid_canonical_input")
        message = Message(
            role=message_role,
            content=TextContent(text=chat_message.content),
        )
        return cast(dict[str, JsonValue], message.model_dump(mode="json"))

    @staticmethod
    def _validated_request(request: ModelRequest) -> ModelRequest:
        if not isinstance(request, ModelRequest):
            raise TypeError("request must be a ModelRequest")
        try:
            return ModelRequest.model_validate(request.model_dump(mode="python"))
        except ValidationError:
            raise InputNormalizationError("invalid_canonical_input") from None

    @staticmethod
    def _validated_response(response: ModelResponse) -> ModelResponse:
        if not isinstance(response, ModelResponse):
            raise TypeError("response must be a ModelResponse")
        try:
            return ModelResponse.model_validate(response.model_dump(mode="python"))
        except ValidationError:
            raise InputNormalizationError("invalid_canonical_input") from None

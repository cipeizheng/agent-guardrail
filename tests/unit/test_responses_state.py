from __future__ import annotations

import pytest

from agent_guardrail.adapters.openai.responses_models import (
    ResponsesFunctionCallInput,
    ResponsesRequest,
    ResponsesResponse,
)
from agent_guardrail.gateway import InMemoryResponsesStateStore, ResponsesStateError


def response_payload(*, response_id: str, text: str | None = None) -> dict[str, object]:
    output: list[dict[str, object]] = []
    if text is not None:
        output.append(
            {
                "type": "message",
                "id": f"msg_{response_id}",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            }
        )
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1.0,
        "model": "test-model",
        "status": "completed",
        "output": output,
    }


def request(
    input_value: object,
    *,
    previous_response_id: str | None = None,
    store: bool | None = None,
) -> ResponsesRequest:
    return ResponsesRequest.model_validate(
        {
            "model": "test-model",
            "input": input_value,
            "previous_response_id": previous_response_id,
            "store": store,
        }
    )


@pytest.mark.asyncio
async def test_state_store_restores_prior_input_and_output_before_new_input() -> None:
    store = InMemoryResponsesStateStore()
    first_request = request("remember this")
    first_response = ResponsesResponse.model_validate(
        response_payload(response_id="resp_1", text="prior answer")
    )

    await store.save_response(request=first_request, response=first_response)
    resolved = await store.resolve_request(
        request("continue", previous_response_id="resp_1")
    )

    assert [item.type for item in resolved.input] == ["message", "message", "message"]  # type: ignore[union-attr]
    assert [item.content for item in resolved.input] == [  # type: ignore[union-attr]
        "remember this",
        "prior answer",
        "continue",
    ]


@pytest.mark.asyncio
async def test_state_store_preserves_function_call_chain_for_tool_output() -> None:
    store = InMemoryResponsesStateStore()
    first_request = request("send the report")
    first_response = ResponsesResponse.model_validate(
        {
            **response_payload(response_id="resp_call"),
            "output": [
                {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call_1",
                    "name": "send_email",
                    "arguments": '{"body":"safe"}',
                    "status": "completed",
                }
            ],
        }
    )
    await store.save_response(request=first_request, response=first_response)

    resolved = await store.resolve_request(
        request=request(
            [
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "sent",
                }
            ],
            previous_response_id="resp_call",
        )
    )

    assert isinstance(resolved.input, tuple)
    assert isinstance(resolved.input[1], ResponsesFunctionCallInput)
    assert resolved.input[1].call_id == "call_1"
    assert resolved.input[2].type == "function_call_output"


@pytest.mark.asyncio
async def test_state_store_is_fail_closed_for_unknown_and_non_stored_responses() -> None:
    store = InMemoryResponsesStateStore()
    await store.save_response(
        request=request("do not retain", store=False),
        response=ResponsesResponse.model_validate(
            response_payload(response_id="resp_private", text="not retained")
        ),
    )

    with pytest.raises(ResponsesStateError) as caught:
        await store.resolve_request(request("continue", previous_response_id="resp_private"))

    assert caught.value.code == "invalid_previous_response_id"
    assert "resp_private" not in str(caught.value)


@pytest.mark.asyncio
async def test_state_store_eviction_is_bounded_and_fail_closed() -> None:
    store = InMemoryResponsesStateStore(max_entries=1)
    for response_id in ("resp_1", "resp_2"):
        await store.save_response(
            request=request(response_id),
            response=ResponsesResponse.model_validate(
                response_payload(response_id=response_id, text="safe")
            ),
        )

    with pytest.raises(ResponsesStateError) as caught:
        await store.resolve_request(request("continue", previous_response_id="resp_1"))

    assert caught.value.code == "invalid_previous_response_id"
    resolved = await store.resolve_request(request("continue", previous_response_id="resp_2"))
    assert resolved.input[-1].content == "continue"  # type: ignore[union-attr]

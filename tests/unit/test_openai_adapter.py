from __future__ import annotations

import pytest

from agent_guardrail.adapters.openai import OpenAIAdapter, OpenAIAdapterError


def request_payload() -> dict[str, object]:
    return {
        "model": "test-model",
        "messages": [{"role": "user", "content": "Send the report"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "send_email",
                    "description": "Send an email",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string"},
                            "body": {"type": "string"},
                        },
                        "required": ["to", "body"],
                        "additionalProperties": False,
                    },
                },
            }
        ],
    }


def response_payload(*, arguments: str) -> dict[str, object]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "send_email",
                                "arguments": arguments,
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
    }


def test_maps_declared_tools_and_validated_calls_to_canonical_models() -> None:
    adapter = OpenAIAdapter()
    request = adapter.parse_request(request_payload())
    response = adapter.parse_response(
        response_payload(arguments='{"to":"outside@example.com","body":"safe"}')
    )

    canonical_request = adapter.request_to_canonical(request)
    canonical_response = adapter.response_to_canonical(response, request=request)

    assert canonical_request.model == "test-model"
    assert canonical_request.tools[0].name == "send_email"
    assert canonical_response.tool_calls[0].arguments["body"] == "safe"


def test_rejects_invalid_tool_schema_without_echoing_it() -> None:
    adapter = OpenAIAdapter()
    payload = request_payload()
    payload["tools"][0]["function"]["parameters"] = {"type": "not-a-real-type"}  # type: ignore[index]

    with pytest.raises(OpenAIAdapterError) as error:
        adapter.parse_request(payload)

    assert error.value.code == "invalid_tool_schema"
    assert "not-a-real-type" not in str(error.value)


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ("not-json", "invalid_tool_arguments_json"),
        ("[]", "invalid_tool_arguments_json"),
        ('{"to":"outside@example.com"}', "invalid_tool_arguments"),
    ],
)
def test_rejects_malformed_or_schema_invalid_upstream_arguments(
    arguments: str,
    code: str,
) -> None:
    adapter = OpenAIAdapter()
    request = adapter.parse_request(request_payload())
    response = adapter.parse_response(response_payload(arguments=arguments))

    with pytest.raises(OpenAIAdapterError) as error:
        adapter.response_to_canonical(response, request=request)

    assert error.value.code == code


def test_rejects_undeclared_upstream_tool() -> None:
    adapter = OpenAIAdapter()
    request = adapter.parse_request(request_payload())
    payload = response_payload(arguments='{"to":"outside@example.com","body":"safe"}')
    payload["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "shell"  # type: ignore[index]
    response = adapter.parse_response(payload)

    with pytest.raises(OpenAIAdapterError) as error:
        adapter.response_to_canonical(response, request=request)

    assert error.value.code == "undeclared_tool_call"

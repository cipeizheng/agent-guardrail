"""Offline contract tests for the DeepSeek Responses AgentDojo adapter."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from agentdojo.attacks.base_attacks import get_model_name_from_pipeline
from agentdojo.functions_runtime import EmptyEnv, Function, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatSystemMessage,
    ChatToolResultMessage,
    ChatUserMessage,
    text_content_block_from_string,
)
from pydantic import BaseModel

from adapter import DeepSeekResponsesLLM, build_baseline_pipeline
from run import (
    DEEPSEEK_RESPONSES_PROVIDER,
    _resolve_model,
    _validate_model_configuration,
)


class _SearchArguments(BaseModel):
    query: str


class _FakeResponses:
    def __init__(self, output: list[object]) -> None:
        self.output = output
        self.requests: list[dict[str, Any]] = []

    def create(self, **request: Any) -> object:
        self.requests.append(request)
        return SimpleNamespace(status="completed", output=self.output)


class _FakeClient:
    def __init__(self, output: list[object]) -> None:
        self.responses = _FakeResponses(output)


def _runtime() -> FunctionsRuntime:
    def search(query: str) -> str:
        return query

    return FunctionsRuntime(
        [
            Function(
                name="search",
                description="Search the workspace.",
                parameters=_SearchArguments,
                dependencies={},
                run=search,
                full_docstring="Search the workspace.",
                return_type=str,
            )
        ]
    )


def _history() -> list[ChatMessage]:
    call = FunctionCall(function="search", args={"query": "quarterly report"}, id="call-1")
    return [
        ChatSystemMessage(
            role="system",
            content=[text_content_block_from_string("Use the available tools.")],
        ),
        ChatUserMessage(
            role="user",
            content=[text_content_block_from_string("Read the quarterly report.")],
        ),
        ChatAssistantMessage(role="assistant", content=None, tool_calls=[call]),
        ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string("The report is ready.")],
            tool_call_id="call-1",
            tool_call=call,
            error=None,
        ),
    ]


def test_query_sends_complete_stateless_history_and_parses_tool_call() -> None:
    client = _FakeClient(
        [
            SimpleNamespace(
                type="function_call",
                name="search",
                call_id="call-2",
                arguments='{"query":"annual report"}',
            )
        ]
    )
    llm = DeepSeekResponsesLLM(cast(Any, client), "deepseek-v4-flash")

    _, _, _, messages, _ = llm.query(
        "Read the quarterly report.",
        _runtime(),
        EmptyEnv(),
        _history(),
        {},
    )

    request = client.responses.requests[0]
    assert request["model"] == "deepseek-v4-flash"
    assert request["reasoning"] == {"effort": "none"}
    assert request["temperature"] == 0.0
    assert request["input"] == [
        {"type": "message", "role": "system", "content": "Use the available tools."},
        {
            "type": "message",
            "role": "user",
            "content": "Read the quarterly report.",
        },
        {
            "type": "function_call",
            "call_id": "call-1",
            "name": "search",
            "arguments": '{"query":"quarterly report"}',
        },
        {
            "type": "function_call_output",
            "call_id": "call-1",
            "output": "The report is ready.",
        },
    ]
    assert request["tools"][0]["name"] == "search"
    output = messages[-1]
    assert output["role"] == "assistant"
    assert output["content"] is None
    assert output["tool_calls"][0].id == "call-2"
    assert output["tool_calls"][0].args == {"query": "annual report"}


def test_query_parses_text_output() -> None:
    client = _FakeClient(
        [
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="output_text", text="Done.")],
            )
        ]
    )
    llm = DeepSeekResponsesLLM(cast(Any, client), "deepseek-v4-flash")

    _, _, _, messages, _ = llm.query("Finish.", _runtime(), messages=_history())

    assert messages[-1]["content"] == [text_content_block_from_string("Done.")]
    assert messages[-1]["tool_calls"] is None


def test_query_rejects_non_json_function_arguments() -> None:
    client = _FakeClient(
        [
            SimpleNamespace(
                type="function_call",
                name="search",
                call_id="call-2",
                arguments="not-json",
            )
        ]
    )
    llm = DeepSeekResponsesLLM(cast(Any, client), "deepseek-v4-flash")

    with pytest.raises(ValueError, match="non-JSON function arguments"):
        llm.query("Finish.", _runtime(), messages=_history())


def test_query_rejects_incomplete_response() -> None:
    client = _FakeClient([])

    def incomplete(**request: Any) -> object:
        del request
        return SimpleNamespace(status="incomplete", output=[])

    client.responses.create = incomplete
    llm = DeepSeekResponsesLLM(cast(Any, client), "deepseek-v4-flash")

    with pytest.raises(ValueError, match="did not complete successfully"):
        llm.query("Finish.", _runtime(), messages=_history())


def test_deepseek_configuration_requires_supported_model_and_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    assert _resolve_model(DEEPSEEK_RESPONSES_PROVIDER, None) == "deepseek-v4-flash"
    with pytest.raises(SystemExit, match="DEEPSEEK_API_KEY"):
        _validate_model_configuration(
            DEEPSEEK_RESPONSES_PROVIDER,
            "deepseek-v4-flash",
            None,
        )

    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only-key")
    with pytest.raises(SystemExit, match="model must be one of"):
        _validate_model_configuration(DEEPSEEK_RESPONSES_PROVIDER, "deepseek-old", None)
    with pytest.raises(SystemExit, match="--model-id"):
        _validate_model_configuration(
            DEEPSEEK_RESPONSES_PROVIDER,
            "deepseek-v4-flash",
            "ignored",
        )


def test_deepseek_pipeline_registers_model_name_for_agentdojo_attack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-only-key")

    pipeline = build_baseline_pipeline(
        "deepseek-v4-flash",
        provider=DEEPSEEK_RESPONSES_PROVIDER,
    )

    assert get_model_name_from_pipeline(pipeline) == "DeepSeek"

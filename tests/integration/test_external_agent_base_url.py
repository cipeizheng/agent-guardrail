from __future__ import annotations

import ast
import asyncio
import json
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn
from anthropic import BadRequestError as AnthropicBadRequestError
from fastapi import FastAPI
from openai import BadRequestError
from pydantic import SecretStr

from agent_guardrail.gateway import GatewaySettings, create_app
from agent_guardrail.runtime import GuardrailRuntime
from tests.blackbox.external_anthropic_agent import ExternalAnthropicAgent
from tests.blackbox.external_openai_agent import ExternalEmailAgent, ExternalResponsesAgent
from tests.integration.test_gateway import (
    POLICY_FILE,
    anthropic_response,
    anthropic_text_stream,
    chat_stream,
    response_api_payload,
    responses_stream,
    streaming_message_analyzer,
    tool_response,
)
from tests.support import FAKE_SECRET


@asynccontextmanager
async def running_gateway(
    app: FastAPI,
    *,
    base_path: str = "/v1/openai",
) -> AsyncIterator[str]:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(128)
    port = server_socket.getsockname()[1]
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_config=None,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[server_socket]))
    for _ in range(500):
        if server.started:
            break
        if task.done():
            await task
        await asyncio.sleep(0.01)
    else:
        server.should_exit = True
        await task
        raise RuntimeError("test Gateway did not start")

    try:
        yield f"http://127.0.0.1:{port}{base_path}"
    finally:
        server.should_exit = True
        await task


class _GatedChatStream(httpx.AsyncByteStream):
    def __init__(self, *, before_gate: bytes, after_gate: bytes) -> None:
        self.before_gate = before_gate
        self.after_gate = after_gate
        self.release = asyncio.Event()
        self.closed = asyncio.Event()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            yield self.before_gate
            await self.release.wait()
            if self.after_gate:
                yield self.after_gate
        finally:
            self.closed.set()

    async def aclose(self) -> None:
        self.release.set()
        self.closed.set()


def _gated_chat_stream(*, late_content: str) -> _GatedChatStream:
    blocks = chat_stream("Safe prefix. ", late_content).split(b"\n\n")
    return _GatedChatStream(
        before_gate=b"\n\n".join(blocks[:2]) + b"\n\n",
        after_gate=b"\n\n".join(blocks[2:]),
    )


def _settings() -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        upstream_base_url="https://provider.example/v1",
        upstream_api_key=SecretStr("upstream-test-key"),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )


def _anthropic_settings() -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        anthropic_upstream_base_url="https://api.anthropic.test",
        anthropic_upstream_api_key=SecretStr("anthropic-upstream-key"),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )


def test_external_agent_source_imports_no_guardrail_code() -> None:
    source_path = Path(__file__).parents[1] / "blackbox/external_openai_agent.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_modules.update(
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )

    assert imported_modules == {"__future__", "openai"}
    assert "agent_guardrail" not in source_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_agent_only_changes_base_url_and_never_receives_blocked_tool_call() -> None:
    upstream_requests = 0

    def upstream(_: httpx.Request) -> httpx.Response:
        nonlocal upstream_requests
        upstream_requests += 1
        return httpx.Response(200, json=tool_response(FAKE_SECRET))

    settings = _settings()
    upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_app(settings, upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_base_url:
        agent = ExternalEmailAgent(base_url=gateway_base_url)
        try:
            with pytest.raises(BadRequestError) as blocked:
                await agent.run()
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert blocked.value.status_code == 400
    assert isinstance(blocked.value.body, dict)
    assert blocked.value.body["type"] == "guardrail_violation"
    assert FAKE_SECRET not in blocked.value.response.text
    assert upstream_requests == 1
    assert agent.tool_executions == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_official_responses_sdk_uses_non_streaming_and_streaming_gateway(
    streaming: bool,
) -> None:
    upstream_requests = 0

    def upstream(request: httpx.Request) -> httpx.Response:
        nonlocal upstream_requests
        upstream_requests += 1
        assert request.url == "https://provider.example/v1/responses"
        payload = json.loads(request.content)
        assert bool(payload.get("stream")) is streaming
        if streaming:
            return httpx.Response(
                200,
                content=responses_stream(),
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=response_api_payload())

    settings = _settings()
    upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_app(settings, upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_base_url:
        agent = ExternalResponsesAgent(base_url=gateway_base_url)
        try:
            result = await (agent.run_stream() if streaming else agent.run())
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert result == "Safe response"
    assert upstream_requests == 1


@pytest.mark.asyncio
async def test_official_chat_sdk_consumes_guarded_stream() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/chat/completions"
        return httpx.Response(
            200,
            content=chat_stream("Safe ", "response"),
            headers={"content-type": "text/event-stream"},
        )

    upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_app(_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_base_url:
        agent = ExternalEmailAgent(base_url=gateway_base_url)
        try:
            result = await agent.run_stream()
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert result == "Safe response"


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_official_anthropic_sdk_uses_messages_gateway(streaming: bool) -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.anthropic.test/v1/messages"
        assert request.headers["x-api-key"] == "anthropic-upstream-key"
        assert request.headers["anthropic-version"] == "2023-06-01"
        payload = json.loads(request.content)
        assert bool(payload.get("stream")) is streaming
        if streaming:
            return httpx.Response(
                200,
                content=anthropic_text_stream("Safe response"),
                headers={"content-type": "text/event-stream"},
            )
        response = anthropic_response()
        response["content"] = [{"type": "text", "text": "Safe response"}]
        response["stop_reason"] = "end_turn"
        return httpx.Response(200, json=response)

    upstream_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    app = create_app(_anthropic_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app, base_path="") as gateway_base_url:
        agent = ExternalAnthropicAgent(base_url=gateway_base_url)
        try:
            result = await (agent.run_stream() if streaming else agent.run())
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert result == "Safe response"


@pytest.mark.asyncio
async def test_official_anthropic_sdk_never_receives_blocked_tool_use() -> None:
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=anthropic_response(FAKE_SECRET))
        )
    )
    app = create_app(_anthropic_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app, base_path="") as gateway_base_url:
        agent = ExternalAnthropicAgent(base_url=gateway_base_url)
        try:
            with pytest.raises(AnthropicBadRequestError) as blocked:
                await agent.run_tool_turn()
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert blocked.value.status_code == 400
    assert FAKE_SECRET not in blocked.value.response.text
    assert agent.tool_executions == 0


@pytest.mark.asyncio
async def test_official_responses_sdk_receives_guardrail_error_event() -> None:
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                content=responses_stream(FAKE_SECRET),
                headers={"content-type": "text/event-stream"},
            )
        )
    )
    app = create_app(
        _settings(),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
        upstream_http_client=upstream_client,
    )

    async with running_gateway(app) as gateway_base_url:
        agent = ExternalResponsesAgent(base_url=gateway_base_url)
        try:
            content, error_code = await agent.run_stream_until_error()
        finally:
            await agent.close()
    await upstream_client.aclose()

    assert content == ""
    assert error_code == "guardrail_blocked"


@pytest.mark.asyncio
async def test_real_http_stream_releases_guarded_prefix_before_upstream_finishes() -> None:
    stream = _gated_chat_stream(late_content=FAKE_SECRET)
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                stream=stream,
                headers={"content-type": "text/event-stream"},
            )
        )
    )
    app = create_app(
        _settings(),
        runtime=GuardrailRuntime(streaming_message_analyzer()),
        upstream_http_client=upstream_client,
    )

    async with running_gateway(app) as gateway_base_url:
        async with httpx.AsyncClient(timeout=3) as client:
            async with client.stream(
                "POST",
                f"{gateway_base_url}/chat/completions",
                headers={"authorization": "Bearer gateway-test-key"},
                json={
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "stream": True,
                },
            ) as response:
                lines = response.aiter_lines()
                received: list[str] = []
                async for line in lines:
                    received.append(line)
                    if "Safe prefix." in line:
                        break
                assert response.status_code == 200
                assert "Safe prefix." in "\n".join(received)
                assert not stream.release.is_set()

                stream.release.set()
                received.extend([line async for line in lines])

    await upstream_client.aclose()
    wire = "\n".join(received)
    assert FAKE_SECRET not in wire
    assert "guardrail_blocked" in wire
    await asyncio.wait_for(stream.closed.wait(), timeout=2)


@pytest.mark.asyncio
async def test_downstream_stream_cancellation_closes_upstream_response() -> None:
    stream = _gated_chat_stream(late_content="late")
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                stream=stream,
                headers={"content-type": "text/event-stream"},
            )
        )
    )
    app = create_app(_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_base_url:
        async with httpx.AsyncClient(timeout=3) as client:
            async with client.stream(
                "POST",
                f"{gateway_base_url}/chat/completions",
                headers={"authorization": "Bearer gateway-test-key"},
                json={
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "stream": True,
                },
            ) as response:
                async for line in response.aiter_lines():
                    if "Safe prefix." in line:
                        break

            await asyncio.wait_for(stream.closed.wait(), timeout=2)

    await upstream_client.aclose()

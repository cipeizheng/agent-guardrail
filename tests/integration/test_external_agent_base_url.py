from __future__ import annotations

import ast
import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from openai import BadRequestError
from pydantic import SecretStr

from agent_guardrail.gateway import GatewaySettings, create_app
from tests.blackbox.external_openai_agent import ExternalEmailAgent
from tests.integration.test_gateway import POLICY_FILE, tool_response
from tests.support import FAKE_SECRET


@asynccontextmanager
async def running_gateway(app: FastAPI) -> AsyncIterator[str]:
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
        yield f"http://127.0.0.1:{port}/v1/openai"
    finally:
        server.should_exit = True
        await task


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

    settings = GatewaySettings(
        policy_file=POLICY_FILE,
        upstream_base_url="https://provider.example/v1",
        upstream_api_key=SecretStr("upstream-test-key"),
        gateway_api_keys=(SecretStr("gateway-test-key"),),
    )
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

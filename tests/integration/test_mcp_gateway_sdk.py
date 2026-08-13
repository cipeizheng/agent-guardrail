from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

import httpx
import pytest
from mcp import MCPError

from agent_guardrail.adapters.mcp import MCP_PROTOCOL_VERSION
from agent_guardrail.gateway import GatewaySettings, create_app
from tests.blackbox.external_mcp_agent import ExternalMCPAgent
from tests.integration.test_external_agent_base_url import running_gateway
from tests.integration.test_gateway import POLICY_FILE
from tests.support import FAKE_SECRET


def upstream_response(request: httpx.Request, calls: Counter[str]) -> httpx.Response:
    payload = json.loads(request.content)
    method = payload["method"]
    calls[method] += 1
    assert request.headers["mcp-protocol-version"] == MCP_PROTOCOL_VERSION
    assert request.headers["mcp-method"] == method

    if method == "server/discover":
        result = {
            "resultType": "complete",
            "supportedVersions": [MCP_PROTOCOL_VERSION],
            "capabilities": {"tools": {}},
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "fake-upstream",
                    "version": "1",
                }
            },
        }
    elif method == "tools/list":
        result = {
            "resultType": "complete",
            "ttlMs": 0,
            "cacheScope": "private",
            "tools": [
                {
                    "name": "send_email",
                    "description": "Send an email",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string"},
                            "body": {"type": "string"},
                        },
                        "required": ["to", "body"],
                        "additionalProperties": False,
                    },
                }
            ],
        }
    elif method == "tools/call":
        assert request.headers["mcp-name"] == "send_email"
        result = {
            "resultType": "complete",
            "content": [{"type": "text", "text": "sent"}],
            "isError": False,
        }
    else:  # pragma: no cover - the SDK test only invokes the supported subset.
        raise AssertionError(f"unexpected method: {method}")
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": payload["id"], "result": result},
    )


def mcp_settings() -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        mcp_upstream_url="https://mcp.example/mcp",
        mcp_upstream_allowed_hosts=("mcp.example",),
    )


def test_external_mcp_agent_imports_only_official_sdk() -> None:
    source_path = Path(__file__).parents[1] / "blackbox/external_mcp_agent.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }

    assert imported_modules == {"__future__", "mcp"}
    assert "agent_guardrail" not in source


@pytest.mark.asyncio
async def test_official_sdk_only_changes_server_url_and_safe_tool_reaches_upstream() -> None:
    calls: Counter[str] = Counter()
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: upstream_response(request, calls))
    )
    app = create_app(mcp_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_root:
        agent = ExternalMCPAgent(server_url=f"{gateway_root.removesuffix('/v1/openai')}/v1/mcp")
        tools, is_error = await agent.send_email("Quarterly report attached.")
    await upstream_client.aclose()

    assert tools == ["send_email"]
    assert not is_error
    assert calls == {"server/discover": 1, "tools/list": 1, "tools/call": 1}


@pytest.mark.asyncio
async def test_official_sdk_blocked_tool_call_never_reaches_mcp_server() -> None:
    calls: Counter[str] = Counter()
    upstream_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: upstream_response(request, calls))
    )
    app = create_app(mcp_settings(), upstream_http_client=upstream_client)

    async with running_gateway(app) as gateway_root:
        agent = ExternalMCPAgent(server_url=f"{gateway_root.removesuffix('/v1/openai')}/v1/mcp")
        with pytest.raises(BaseExceptionGroup) as blocked_group:
            await agent.send_email(FAKE_SECRET)
    await upstream_client.aclose()

    blocked = _find_mcp_error(blocked_group.value)
    assert blocked.code == -32040
    assert blocked.data["checkpoint"] == "before_tool_call"
    assert FAKE_SECRET not in str(blocked.data)
    assert calls == {"server/discover": 1, "tools/list": 1}


def _find_mcp_error(error: BaseException) -> MCPError:
    if isinstance(error, MCPError):
        return error
    if isinstance(error, BaseExceptionGroup):
        for nested in error.exceptions:
            try:
                return _find_mcp_error(nested)
            except LookupError:
                continue
    raise LookupError("MCPError not found")

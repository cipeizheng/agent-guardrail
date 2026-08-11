from __future__ import annotations

import json

import httpx
import pytest

from agent_guardrail.adapters.mcp import MCP_PROTOCOL_VERSION
from agent_guardrail.gateway import GatewaySettings
from agent_guardrail.models import Phase, SecurityDestination
from agent_guardrail.runtime import GuardrailRuntime
from tests.integration.test_gateway import POLICY_FILE, RecordingAnalyzer, app_client
from tests.integration.test_guarded_llm import analyzer_for_phase
from tests.support import (
    FAKE_CN_MOBILE,
    FAKE_PII,
    FAKE_SECRET,
    pii_analyzer,
    tool_access_analyzer,
)


def mcp_settings(*, allowed_origins: tuple[str, ...] = ()) -> GatewaySettings:
    return GatewaySettings(
        policy_file=POLICY_FILE,
        mcp_upstream_url="https://mcp.example/mcp",
        mcp_upstream_allowed_hosts=("mcp.example",),
        mcp_allowed_origins=allowed_origins,
    )


def request_payload(
    *,
    method: str = "tools/call",
    name: str = "send_email",
    body: str = "safe",
) -> dict[str, object]:
    params: dict[str, object] = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }
    if method == "tools/call":
        params.update(
            {
                "name": name,
                "arguments": {
                    "to": "outside@example.com",
                    "body": body,
                    "region": "us-west1",
                },
            }
        )
    return {"jsonrpc": "2.0", "id": 9, "method": method, "params": params}


def request_headers(
    *,
    method: str = "tools/call",
    name: str = "send_email",
) -> list[tuple[str, str]]:
    values = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", MCP_PROTOCOL_VERSION),
        ("mcp-method", method),
    ]
    if method == "tools/call":
        values.extend(
            [
                ("mcp-name", name),
                ("mcp-param-region", "us-west1"),
            ]
        )
    return values


def tool_response(text: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "isError": False,
        },
    }


@pytest.mark.asyncio
async def test_post_tool_block_hides_raw_result_after_one_upstream_execution() -> None:
    runtime = GuardrailRuntime(analyzer_for_phase(Phase.POST_TOOL))
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response(FAKE_SECRET)),
        settings=mcp_settings(),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/mcp",
            headers=request_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32040
    assert response.json()["error"]["data"]["phase"] == "post_tool"
    assert FAKE_SECRET not in response.text
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_tool_access_pre_tool_block_makes_zero_upstream_requests() -> None:
    runtime = GuardrailRuntime(tool_access_analyzer())
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("must not execute")),
        settings=mcp_settings(),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/mcp",
            headers=request_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32040
    assert response.json()["error"]["data"]["phase"] == "pre_tool"
    assert response.json()["error"]["data"]["violations"][0]["code"] == ("tool_access_denied")
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("sensitive_value", [FAKE_PII, FAKE_CN_MOBILE])
async def test_pii_pre_tool_block_makes_zero_upstream_requests(
    sensitive_value: str,
) -> None:
    runtime = GuardrailRuntime(pii_analyzer())
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("must not execute")),
        settings=mcp_settings(),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/mcp",
            headers=request_headers(),
            json=request_payload(body=sensitive_value),
        )

    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32040
    assert response.json()["error"]["data"]["phase"] == "pre_tool"
    assert response.json()["error"]["data"]["violations"][0]["code"] == ("pii_exfiltration")
    assert sensitive_value not in response.text
    assert requests == []


@pytest.mark.asyncio
async def test_mcp_param_headers_are_forwarded_to_fixed_upstream() -> None:
    def upstream(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://mcp.example/mcp"
        assert request.headers["mcp-param-region"] == "us-west1"
        return httpx.Response(200, json=tool_response("sent"))

    async with app_client(upstream, settings=mcp_settings()) as (client, requests):
        response = await client.post(
            "/v1/mcp",
            headers=request_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert response.json()["result"]["content"][0]["text"] == "sent"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_mcp_gateway_injects_tool_and_client_destinations() -> None:
    analyzer = RecordingAnalyzer()
    runtime = GuardrailRuntime(analyzer)
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("sent")),
        settings=mcp_settings(),
        runtime=runtime,
    ) as (client, requests):
        response = await client.post(
            "/v1/mcp",
            headers=request_headers(),
            json=request_payload(),
        )

    assert response.status_code == 200
    assert len(requests) == 1
    assert analyzer.security_destinations == [
        (Phase.PRE_TOOL, SecurityDestination.EXTERNAL_TOOL),
        (Phase.POST_TOOL, SecurityDestination.CLIENT),
    ]


@pytest.mark.asyncio
async def test_origin_and_header_mismatch_fail_before_upstream() -> None:
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("unused")),
        settings=mcp_settings(allowed_origins=("https://allowed.example",)),
    ) as (client, requests):
        origin_blocked = await client.post(
            "/v1/mcp",
            headers=[*request_headers(), ("origin", "https://evil.example")],
            json=request_payload(),
        )
        mismatched = await client.post(
            "/v1/mcp",
            headers=request_headers(name="different"),
            json=request_payload(),
        )

    assert origin_blocked.status_code == 403
    assert mismatched.status_code == 400
    assert mismatched.json()["error"]["code"] == -32020
    assert requests == []


@pytest.mark.asyncio
async def test_legacy_initialize_get_and_delete_are_explicitly_rejected() -> None:
    legacy = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "clientInfo": {"name": "legacy", "version": "1"},
            "capabilities": {},
        },
    }
    async with app_client(
        lambda request: httpx.Response(200, json=tool_response("unused")),
        settings=mcp_settings(),
    ) as (client, requests):
        initialize = await client.post(
            "/v1/mcp",
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
            },
            content=json.dumps(legacy),
        )
        get_response = await client.get("/v1/mcp")
        delete_response = await client.delete("/v1/mcp")

    assert initialize.status_code == 400
    assert initialize.json()["error"]["code"] == -32022
    assert initialize.json()["error"]["data"]["supported"] == [MCP_PROTOCOL_VERSION]
    assert get_response.status_code == 405
    assert delete_response.status_code == 405
    assert requests == []

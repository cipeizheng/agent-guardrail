from __future__ import annotations

import base64
import json

import pytest

from agent_guardrail.adapters.mcp import MCP_PROTOCOL_VERSION, MCPAdapter, MCPAdapterError


def meta(*, version: str = MCP_PROTOCOL_VERSION) -> dict[str, object]:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def tool_request(*, version: str = MCP_PROTOCOL_VERSION) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {"body": "safe"},
            "_meta": meta(version=version),
        },
    }


def headers(
    *,
    version: str = MCP_PROTOCOL_VERSION,
    method: str = "tools/call",
    name: str = "send_email",
) -> list[tuple[bytes, bytes]]:
    return [
        (b"content-type", b"application/json"),
        (b"accept", b"application/json, text/event-stream"),
        (b"mcp-protocol-version", version.encode()),
        (b"mcp-method", method.encode()),
        (b"mcp-name", name.encode()),
    ]


def tool_response() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "resultType": "complete",
                "content": [{"type": "text", "text": "sent"}],
                "isError": False,
            },
        }
    ).encode()


def test_validates_modern_headers_and_maps_tool_boundary() -> None:
    adapter = MCPAdapter()
    request = adapter.parse_request(tool_request())

    adapter.validate_headers(request, headers())
    call = adapter.request_to_tool_call(request)
    response = adapter.parse_response(
        tool_response(),
        media_type="application/json",
        request_id=request.envelope.id,
    )
    result = adapter.response_to_tool_result(response, request=request)

    assert call.name == "send_email"
    assert call.arguments == {"body": "safe"}
    assert result.output["content"][0]["text"] == "sent"  # type: ignore[index]


def test_decodes_base64_mcp_name_header() -> None:
    adapter = MCPAdapter()
    payload = tool_request()
    payload["params"]["name"] = "发送邮件"  # type: ignore[index]
    encoded = base64.b64encode("发送邮件".encode()).decode()
    request = adapter.parse_request(payload)

    adapter.validate_headers(request, headers(name=f"=?base64?{encoded}?="))


@pytest.mark.parametrize(
    "changed_headers",
    [
        headers(version="2025-11-25"),
        headers(method="tools/list"),
        headers(name="different_tool"),
        [*headers(), (b"mcp-method", b"tools/call")],
    ],
)
def test_header_mismatch_uses_current_protocol_error(
    changed_headers: list[tuple[bytes, bytes]],
) -> None:
    adapter = MCPAdapter()
    request = adapter.parse_request(tool_request())

    with pytest.raises(MCPAdapterError) as error:
        adapter.validate_headers(request, changed_headers)

    assert error.value.rpc_code == -32020
    assert error.value.status_code == 400


def test_unsupported_and_legacy_versions_list_only_current_version() -> None:
    adapter = MCPAdapter()
    request = adapter.parse_request(tool_request(version="2099-01-01"))
    with pytest.raises(MCPAdapterError) as unsupported:
        adapter.validate_headers(request, headers(version="2099-01-01"))

    legacy = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"},
    }
    with pytest.raises(MCPAdapterError) as initialize:
        adapter.parse_request(legacy)

    assert unsupported.value.rpc_code == -32022
    assert unsupported.value.data == {
        "supported": [MCP_PROTOCOL_VERSION],
        "requested": "2099-01-01",
    }
    assert initialize.value.rpc_code == -32022


@pytest.mark.parametrize("method", ["ping", "resources/read"])
def test_unknown_method_returns_http_404_method_not_found(method: str) -> None:
    adapter = MCPAdapter()
    payload = tool_request()
    payload["method"] = method
    request = adapter.parse_request(payload)
    request_headers = headers(method=method)

    with pytest.raises(MCPAdapterError) as error:
        adapter.validate_headers(request, request_headers)

    assert error.value.rpc_code == -32601
    assert error.value.status_code == 404


def test_parses_buffered_sse_and_rejects_response_id_mismatch() -> None:
    adapter = MCPAdapter()
    body = b"event: message\ndata: " + tool_response() + b"\n\n"

    response = adapter.parse_response(body, media_type="text/event-stream", request_id=7)

    assert response.envelope.result is not None
    with pytest.raises(MCPAdapterError, match="invalid JSON-RPC"):
        adapter.parse_response(tool_response(), media_type="application/json", request_id=8)


def test_rewrites_discovery_to_gateway_supported_version() -> None:
    adapter = MCPAdapter()
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "discover",
            "result": {
                "resultType": "complete",
                "supportedVersions": [MCP_PROTOCOL_VERSION, "2025-11-25"],
                "capabilities": {"tools": {}},
            },
        }
    ).encode()
    response = adapter.parse_response(
        raw,
        media_type="application/json",
        request_id="discover",
    )

    rewritten = json.loads(adapter.rewrite_discover_response(response))

    assert rewritten["result"]["supportedVersions"] == [MCP_PROTOCOL_VERSION]

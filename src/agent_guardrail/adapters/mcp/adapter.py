"""Strict modern MCP envelope validation and Canonical Tool conversion."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import cast

from pydantic import JsonValue, ValidationError

from agent_guardrail.adapters.mcp.models import (
    CallToolParams,
    DiscoverParams,
    JSONRPCRequest,
    JSONRPCResponse,
    ListToolsParams,
    PingParams,
    UnknownParams,
)
from agent_guardrail.models import ToolCall, ToolResult

MCP_PROTOCOL_VERSION = "2026-07-28"
MCP_SUPPORTED_PROTOCOL_VERSIONS = (MCP_PROTOCOL_VERSION,)
MCP_SUPPORTED_METHODS = frozenset({"server/discover", "ping", "tools/list", "tools/call"})

HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022
GUARDRAIL_BLOCKED = -32040
GUARDRAIL_UNAVAILABLE = -32041
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

_PROTOCOL_HEADER = "mcp-protocol-version"
_METHOD_HEADER = "mcp-method"
_NAME_HEADER = "mcp-name"
_ROUTING_HEADERS = frozenset({_PROTOCOL_HEADER, _METHOD_HEADER, _NAME_HEADER})


class MCPAdapterError(ValueError):
    """A protocol error whose text and data are safe to return to an MCP client."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        rpc_code: int,
        status_code: int,
        request_id: str | int | None = None,
        data: dict[str, JsonValue] | None = None,
    ) -> None:
        self.code = code
        self.rpc_code = rpc_code
        self.status_code = status_code
        self.request_id = request_id
        self.data = data
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ParsedMCPRequest:
    envelope: JSONRPCRequest
    params: DiscoverParams | PingParams | ListToolsParams | CallToolParams | UnknownParams

    @property
    def protocol_version(self) -> str:
        return self.params.meta.protocol_version


@dataclass(frozen=True, slots=True)
class ParsedMCPResponse:
    envelope: JSONRPCResponse
    raw_body: bytes
    media_type: str


class MCPAdapter:
    """Implement the modern Streamable HTTP validation ladder used by the Gateway."""

    def parse_request(self, payload: object) -> ParsedMCPRequest:
        try:
            envelope = JSONRPCRequest.model_validate(payload)
        except ValidationError as exc:
            raise MCPAdapterError(
                code="invalid_request",
                message="The MCP JSON-RPC request is malformed.",
                rpc_code=INVALID_REQUEST,
                status_code=400,
                request_id=self._best_effort_id(payload),
            ) from exc

        if envelope.method == "initialize":
            requested = envelope.params.get("protocolVersion")
            raise self.unsupported_version_error(
                envelope.id,
                requested if isinstance(requested, str) else "legacy",
            )

        model = {
            "server/discover": DiscoverParams,
            "ping": PingParams,
            "tools/list": ListToolsParams,
            "tools/call": CallToolParams,
        }.get(envelope.method, UnknownParams)
        try:
            params = model.model_validate(envelope.params)
        except ValidationError as exc:
            raise MCPAdapterError(
                code="invalid_params",
                message="MCP params must contain the required modern request metadata.",
                rpc_code=INVALID_PARAMS,
                status_code=400,
                request_id=envelope.id,
            ) from exc
        return ParsedMCPRequest(envelope=envelope, params=params)

    def validate_headers(
        self,
        request: ParsedMCPRequest,
        raw_headers: list[tuple[bytes, bytes]],
    ) -> None:
        headers: dict[str, str] = {}
        seen_routing: set[str] = set()
        seen_param_headers: set[str] = set()
        for raw_name, raw_value in raw_headers:
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            if name in _ROUTING_HEADERS:
                if name in seen_routing:
                    raise self.header_mismatch_error(request.envelope.id)
                seen_routing.add(name)
            if name.startswith("mcp-param-"):
                if name in seen_param_headers:
                    raise self.header_mismatch_error(request.envelope.id)
                seen_param_headers.add(name)
            headers[name] = value

        accepted = {
            part.partition(";")[0].strip().lower() for part in headers.get("accept", "").split(",")
        }
        if not {"application/json", "text/event-stream"}.issubset(accepted):
            raise self.header_mismatch_error(request.envelope.id)
        if headers.get(_PROTOCOL_HEADER) != request.protocol_version:
            raise self.header_mismatch_error(request.envelope.id)
        if headers.get(_METHOD_HEADER) != request.envelope.method:
            raise self.header_mismatch_error(request.envelope.id)
        if isinstance(request.params, CallToolParams):
            name = self._decode_header(headers.get(_NAME_HEADER), request.envelope.id)
            if name != request.params.name:
                raise self.header_mismatch_error(request.envelope.id)

        if request.protocol_version not in MCP_SUPPORTED_PROTOCOL_VERSIONS:
            raise self.unsupported_version_error(
                request.envelope.id,
                request.protocol_version,
            )
        if request.envelope.method not in MCP_SUPPORTED_METHODS:
            raise MCPAdapterError(
                code="method_not_found",
                message="Method not found",
                rpc_code=METHOD_NOT_FOUND,
                status_code=404,
                request_id=request.envelope.id,
            )

    def request_to_tool_call(self, request: ParsedMCPRequest) -> ToolCall:
        if not isinstance(request.params, CallToolParams):
            raise TypeError("request is not tools/call")
        return ToolCall(
            call_id=f"mcp:{request.envelope.id}",
            name=request.params.name,
            arguments=request.params.arguments,
        )

    def parse_response(
        self,
        body: bytes,
        *,
        media_type: str,
        request_id: str | int,
    ) -> ParsedMCPResponse:
        if media_type == "application/json":
            payload = self._parse_json(body)
            envelope = self._validate_response(payload, request_id)
        elif media_type == "text/event-stream":
            envelope = self._parse_sse_response(body, request_id)
        else:
            raise MCPAdapterError(
                code="invalid_upstream_content_type",
                message="The MCP upstream returned an unsupported content type.",
                rpc_code=INVALID_REQUEST,
                status_code=502,
                request_id=request_id,
            )
        return ParsedMCPResponse(envelope=envelope, raw_body=body, media_type=media_type)

    def response_to_tool_result(
        self,
        response: ParsedMCPResponse,
        *,
        request: ParsedMCPRequest,
    ) -> ToolResult:
        if not isinstance(request.params, CallToolParams):
            raise TypeError("request is not tools/call")
        if response.envelope.result is not None:
            output = cast(JsonValue, response.envelope.result)
        else:
            error = response.envelope.error
            if error is None:
                raise TypeError("validated MCP response has no result or error")
            output = cast(JsonValue, {"error": error.model_dump(mode="json", exclude_none=True)})
        return ToolResult(
            call_id=f"mcp:{request.envelope.id}",
            name=request.params.name,
            output=output,
        )

    def rewrite_discover_response(self, response: ParsedMCPResponse) -> bytes:
        envelope = response.envelope.model_dump(mode="json", exclude_none=True)
        result = envelope.get("result")
        if not isinstance(result, dict):
            return self.serialize(envelope)
        result["supportedVersions"] = list(MCP_SUPPORTED_PROTOCOL_VERSIONS)
        return self.serialize(envelope)

    @staticmethod
    def serialize(payload: object) -> bytes:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()

    def error_payload(self, error: MCPAdapterError) -> dict[str, JsonValue]:
        error_object: dict[str, JsonValue] = {
            "code": error.rpc_code,
            "message": str(error),
        }
        if error.data is not None:
            error_object["data"] = cast(JsonValue, error.data)
        return {
            "jsonrpc": "2.0",
            "id": cast(JsonValue, error.request_id),
            "error": cast(JsonValue, error_object),
        }

    def header_mismatch_error(self, request_id: str | int | None) -> MCPAdapterError:
        return MCPAdapterError(
            code="header_mismatch",
            message="MCP routing headers do not match the JSON-RPC request.",
            rpc_code=HEADER_MISMATCH,
            status_code=400,
            request_id=request_id,
        )

    def unsupported_version_error(
        self,
        request_id: str | int | None,
        requested: str,
    ) -> MCPAdapterError:
        return MCPAdapterError(
            code="unsupported_protocol_version",
            message="Unsupported protocol version",
            rpc_code=UNSUPPORTED_PROTOCOL_VERSION,
            status_code=400,
            request_id=request_id,
            data={
                "supported": cast(JsonValue, list(MCP_SUPPORTED_PROTOCOL_VERSIONS)),
                "requested": requested,
            },
        )

    def _parse_sse_response(
        self,
        body: bytes,
        request_id: str | int,
    ) -> JSONRPCResponse:
        try:
            text = body.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as exc:
            raise self._invalid_upstream_response(request_id) from exc
        final: JSONRPCResponse | None = None
        for event in text.split("\n\n"):
            data_lines = [
                line[5:].lstrip() for line in event.split("\n") if line.startswith("data:")
            ]
            if not data_lines:
                continue
            payload = self._parse_json("\n".join(data_lines).encode())
            if isinstance(payload, dict) and ("result" in payload or "error" in payload):
                final = self._validate_response(payload, request_id)
        if final is None:
            raise self._invalid_upstream_response(request_id)
        return final

    def _parse_json(self, body: bytes) -> object:
        try:
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MCPAdapterError(
                code="invalid_upstream_response",
                message="The MCP upstream returned invalid JSON.",
                rpc_code=INVALID_REQUEST,
                status_code=502,
            ) from exc

    def _validate_response(self, payload: object, request_id: str | int) -> JSONRPCResponse:
        try:
            response = JSONRPCResponse.model_validate(payload)
        except ValidationError as exc:
            raise self._invalid_upstream_response(request_id) from exc
        if type(response.id) is not type(request_id) or response.id != request_id:
            raise self._invalid_upstream_response(request_id)
        return response

    def _invalid_upstream_response(self, request_id: str | int) -> MCPAdapterError:
        return MCPAdapterError(
            code="invalid_upstream_response",
            message="The MCP upstream returned an invalid JSON-RPC response.",
            rpc_code=INVALID_REQUEST,
            status_code=502,
            request_id=request_id,
        )

    def _decode_header(self, value: str | None, request_id: str | int) -> str | None:
        if value is None:
            return None
        if value.startswith("=?base64?") and value.endswith("?="):
            encoded = value[len("=?base64?") : -len("?=")]
            try:
                return base64.b64decode(encoded, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError) as exc:
                raise self.header_mismatch_error(request_id) from exc
        if value.startswith("=?base64?") or value.endswith("?="):
            raise self.header_mismatch_error(request_id)
        return value

    @staticmethod
    def _best_effort_id(payload: object) -> str | int | None:
        if not isinstance(payload, dict):
            return None
        value = payload.get("id")
        if isinstance(value, bool) or not isinstance(value, str | int):
            return None
        return value

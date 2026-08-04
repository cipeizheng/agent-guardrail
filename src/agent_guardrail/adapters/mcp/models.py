"""Closed models for the supported MCP 2026-07-28 core request subset."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class MCPModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=True)


class ClientInfo(MCPModel):
    model_config = ConfigDict(extra="allow", frozen=True, strict=True, populate_by_name=True)

    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class RequestMeta(BaseModel):
    """Required modern envelope fields plus extension-owned metadata."""

    model_config = ConfigDict(extra="allow", frozen=True, strict=True, populate_by_name=True)

    protocol_version: str = Field(
        alias="io.modelcontextprotocol/protocolVersion",
        min_length=1,
    )
    client_capabilities: dict[str, JsonValue] = Field(
        alias="io.modelcontextprotocol/clientCapabilities",
    )
    client_info: ClientInfo | None = Field(
        default=None,
        alias="io.modelcontextprotocol/clientInfo",
    )


class MetaParams(MCPModel):
    meta: RequestMeta = Field(alias="_meta")


class UnknownParams(MetaParams):
    model_config = ConfigDict(extra="allow", frozen=True, strict=True, populate_by_name=True)


class DiscoverParams(MetaParams):
    pass


class PingParams(MetaParams):
    pass


class ListToolsParams(MetaParams):
    cursor: str | None = None


class CallToolParams(MetaParams):
    name: str = Field(min_length=1, max_length=256)
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    input_responses: dict[str, JsonValue] | None = Field(default=None, alias="inputResponses")
    request_state: str | None = Field(default=None, alias="requestState")


class JSONRPCRequest(MCPModel):
    jsonrpc: Literal["2.0"]
    id: str | int
    method: str = Field(min_length=1)
    params: dict[str, JsonValue]

    @model_validator(mode="after")
    def reject_boolean_id(self) -> Self:
        if isinstance(self.id, bool):
            raise ValueError("JSON-RPC request ID cannot be boolean")
        return self


class JSONRPCErrorObject(MCPModel):
    code: int
    message: str
    data: JsonValue | None = None


class JSONRPCResponse(MCPModel):
    jsonrpc: Literal["2.0"]
    id: str | int
    result: dict[str, JsonValue] | None = None
    error: JSONRPCErrorObject | None = None

    @model_validator(mode="after")
    def validate_result_or_error(self) -> Self:
        if (self.result is None) == (self.error is None):
            raise ValueError("JSON-RPC response requires exactly one of result or error")
        if isinstance(self.id, bool):
            raise ValueError("JSON-RPC response ID cannot be boolean")
        return self

"""Fixed-destination transport for modern MCP Streamable HTTP requests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from starlette.datastructures import Headers

from agent_guardrail.gateway.config import GatewaySettings


class MCPUpstreamError(RuntimeError):
    def __init__(self, code: str, *, timed_out: bool = False) -> None:
        self.code = code
        self.timed_out = timed_out
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class MCPUpstreamResponse:
    status_code: int
    media_type: str
    body: bytes


class MCPUpstream:
    """Forward an MCP POST to one startup-configured endpoint without redirects."""

    def __init__(self, *, client: httpx.AsyncClient, settings: GatewaySettings) -> None:
        if settings.mcp_upstream_url is None:
            raise ValueError("MCP upstream is not configured")
        self.client = client
        self.settings = settings
        self.url = settings.mcp_upstream_url

    async def forward(
        self,
        payload: dict[str, Any],
        *,
        inbound_headers: Headers,
        client_authorization: str | None,
    ) -> MCPUpstreamResponse:
        headers = self._forward_headers(inbound_headers, client_authorization)
        try:
            async with self.client.stream(
                "POST",
                self.url,
                json=payload,
                headers=headers,
                timeout=self.settings.mcp_timeout_seconds,
            ) as response:
                if response.status_code not in {200, 400, 404}:
                    raise MCPUpstreamError("mcp_upstream_http_error")
                body = await self._read_limited(response)
                media_type = response.headers.get("content-type", "").partition(";")[0].lower()
        except httpx.TimeoutException as exc:
            raise MCPUpstreamError("mcp_upstream_timeout", timed_out=True) from exc
        except httpx.HTTPError as exc:
            raise MCPUpstreamError("mcp_upstream_transport_error") from exc

        if media_type not in {"application/json", "text/event-stream"}:
            raise MCPUpstreamError("mcp_upstream_content_type")
        return MCPUpstreamResponse(
            status_code=response.status_code,
            media_type=media_type,
            body=body,
        )

    async def _read_limited(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self.settings.mcp_max_response_bytes:
                raise MCPUpstreamError("mcp_upstream_response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _forward_headers(
        self,
        inbound: Headers,
        client_authorization: str | None,
    ) -> dict[str, str]:
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        for name, value in inbound.items():
            normalized = name.lower()
            if normalized in {"mcp-protocol-version", "mcp-method", "mcp-name"} or (
                normalized.startswith("mcp-param-")
            ):
                headers[normalized] = value

        authorization = self._upstream_authorization(client_authorization)
        if authorization is not None:
            headers["authorization"] = authorization
        return headers

    def _upstream_authorization(self, client_authorization: str | None) -> str | None:
        if self.settings.mcp_upstream_auth_mode == "pass_through":
            return client_authorization
        if self.settings.mcp_upstream_auth_mode == "server_managed":
            key = self.settings.mcp_upstream_api_key
            if key is None:
                return None
            return f"Bearer {key.get_secret_value()}"
        return None

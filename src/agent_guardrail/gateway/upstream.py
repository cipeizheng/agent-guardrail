"""Fixed-destination OpenAI upstream transport."""

from __future__ import annotations

import json
from typing import Any

import httpx

from agent_guardrail.gateway.config import GatewaySettings


class UpstreamError(RuntimeError):
    """A safe upstream failure without response content or credentials."""

    def __init__(self, code: str, *, timed_out: bool = False) -> None:
        self.code = code
        self.timed_out = timed_out
        super().__init__(code)


class OpenAIUpstream:
    """Forward only to the startup-configured provider URL with redirects disabled."""

    def __init__(self, *, client: httpx.AsyncClient, settings: GatewaySettings) -> None:
        self.client = client
        self.settings = settings

    async def complete(
        self,
        payload: dict[str, Any],
        *,
        client_authorization: str | None,
    ) -> object:
        headers = {"accept": "application/json", "content-type": "application/json"}
        authorization = self._upstream_authorization(client_authorization)
        if authorization is not None:
            headers["authorization"] = authorization

        try:
            async with self.client.stream(
                "POST",
                self.settings.upstream_chat_completions_url,
                json=payload,
                headers=headers,
                timeout=self.settings.upstream_timeout_seconds,
            ) as response:
                if not 200 <= response.status_code < 300:
                    raise UpstreamError("upstream_http_error")
                body = await self._read_limited(response)
        except httpx.TimeoutException as exc:
            raise UpstreamError("upstream_timeout", timed_out=True) from exc
        except httpx.HTTPError as exc:
            raise UpstreamError("upstream_transport_error") from exc

        try:
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UpstreamError("upstream_invalid_json") from exc

    async def _read_limited(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self.settings.max_upstream_response_bytes:
                raise UpstreamError("upstream_response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _upstream_authorization(self, client_authorization: str | None) -> str | None:
        if self.settings.upstream_auth_mode == "pass_through":
            return client_authorization
        if self.settings.upstream_api_key is None:
            return None
        return f"Bearer {self.settings.upstream_api_key.get_secret_value()}"

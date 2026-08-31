"""Fixed-destination provider upstream transport."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from agent_guardrail.gateway.config import GatewaySettings

_UPSTREAM_PATH = re.compile(r"[a-z0-9][a-z0-9_/-]{0,127}\Z")


def validate_upstream_path(upstream_path: str) -> str:
    """Validate a deployment-owned provider endpoint below the fixed base URL."""

    if (
        not isinstance(upstream_path, str)
        or not _UPSTREAM_PATH.fullmatch(upstream_path)
        or "//" in upstream_path
        or any(part in {".", ".."} for part in upstream_path.split("/"))
    ):
        raise ValueError("provider adapter upstream_path is invalid")
    return upstream_path


class UpstreamError(RuntimeError):
    """A safe upstream failure without response content or credentials."""

    def __init__(self, code: str, *, timed_out: bool = False) -> None:
        self.code = code
        self.timed_out = timed_out
        super().__init__(code)


class ModelUpstream:
    """Forward only to a finite endpoint below the startup-configured provider URL."""

    def __init__(self, *, client: httpx.AsyncClient, settings: GatewaySettings) -> None:
        self.client = client
        self.settings = settings

    async def complete(
        self,
        upstream_path: str,
        payload: dict[str, Any],
        *,
        client_authorization: str | None,
    ) -> object:
        headers = self._headers(stream=False, client_authorization=client_authorization)

        try:
            async with self.client.stream(
                "POST",
                self._url(upstream_path),
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

    async def open_stream(
        self,
        upstream_path: str,
        payload: dict[str, Any],
        *,
        client_authorization: str | None,
    ) -> httpx.Response:
        """Open a validated SSE response whose lifetime is owned by the caller."""

        headers = self._headers(stream=True, client_authorization=client_authorization)
        request = self.client.build_request(
            "POST",
            self._url(upstream_path),
            json=payload,
            headers=headers,
            timeout=self.settings.upstream_timeout_seconds,
        )
        try:
            response = await self.client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            raise UpstreamError("upstream_timeout", timed_out=True) from exc
        except httpx.HTTPError as exc:
            raise UpstreamError("upstream_transport_error") from exc
        if not 200 <= response.status_code < 300:
            await response.aclose()
            raise UpstreamError("upstream_http_error")
        media_type = response.headers.get("content-type", "").partition(";")[0].lower()
        if media_type != "text/event-stream":
            await response.aclose()
            raise UpstreamError("upstream_invalid_content_type")
        return response

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

    def _headers(
        self,
        *,
        stream: bool,
        client_authorization: str | None,
    ) -> dict[str, str]:
        headers = {
            "accept": "text/event-stream" if stream else "application/json",
            "content-type": "application/json",
        }
        authorization = self._upstream_authorization(client_authorization)
        if authorization is not None:
            headers["authorization"] = authorization
        return headers

    def _url(self, upstream_path: str) -> str:
        if self.settings.upstream_base_url is None:
            raise RuntimeError("model upstream is not configured")
        return self.settings.upstream_base_url + validate_upstream_path(upstream_path)


class AnthropicUpstream(ModelUpstream):
    """Fixed Anthropic destination using a deployment-owned API key."""

    def _headers(
        self,
        *,
        stream: bool,
        client_authorization: str | None,
    ) -> dict[str, str]:
        del client_authorization
        if self.settings.anthropic_upstream_api_key is None:
            raise RuntimeError("Anthropic upstream API key is not configured")
        return {
            "accept": "text/event-stream" if stream else "application/json",
            "content-type": "application/json",
            "x-api-key": self.settings.anthropic_upstream_api_key.get_secret_value(),
            "anthropic-version": "2023-06-01",
        }

    def _url(self, upstream_path: str) -> str:
        if self.settings.anthropic_upstream_base_url is None:
            raise RuntimeError("Anthropic upstream is not configured")
        return self.settings.anthropic_upstream_base_url + validate_upstream_path(upstream_path)

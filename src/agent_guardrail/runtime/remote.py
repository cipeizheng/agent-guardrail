"""Fail-closed HTTP client implementing the PolicyAnalyzer boundary."""

from __future__ import annotations

import asyncio
import json
from json import JSONDecodeError
from typing import Self

import httpx
from pydantic import ValidationError

from agent_guardrail.models import Decision, GuardrailContext, PendingTrace
from agent_guardrail.runtime.remote_protocol import (
    RemoteAnalyzeRequest,
    RemoteAnalyzeResponse,
    RemoteHealthResponse,
    RemotePolicyInfoResponse,
)
from agent_guardrail.runtime.runtime import PolicyInfo, RuntimeNotReadyError, RuntimeState


class RemoteCoreError(RuntimeError):
    """The remote Core did not return a valid bounded protocol response."""


class RemoteGuardrailRuntime:
    """Use a fixed-policy Core service through the same runtime facade."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float,
        max_request_bytes: int,
        max_response_bytes: int,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = httpx.Timeout(timeout_seconds)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        self._owns_client = client is None
        self._state = RuntimeState.CREATED
        self._policy_info: PolicyInfo | None = None
        self._lifecycle_lock = asyncio.Lock()

    @property
    def state(self) -> RuntimeState:
        return self._state

    @property
    def ready(self) -> bool:
        return self._state is RuntimeState.READY

    @property
    def policy_info(self) -> PolicyInfo:
        if self._policy_info is None:
            raise RuntimeNotReadyError("remote guardrail runtime has no policy identity")
        return self._policy_info

    async def start(self) -> None:
        """Authenticate Core and pin its fixed policy identity."""

        async with self._lifecycle_lock:
            if self._state is RuntimeState.READY:
                return
            if self._state is RuntimeState.CLOSED:
                raise RuntimeNotReadyError(
                    "a closed remote guardrail runtime cannot be restarted"
                )
            await self._require_health_ready()
            self._policy_info = await self._fetch_policy_info()
            self._state = RuntimeState.READY

    async def check_ready(self) -> bool:
        """Verify Core availability and the policy identity pinned at startup."""

        if not self.ready or self._policy_info is None:
            return False
        try:
            await self._require_health_ready()
            current = await self._fetch_policy_info()
        except RemoteCoreError:
            return False
        return current == self._policy_info

    async def close(self) -> None:
        async with self._lifecycle_lock:
            self._state = RuntimeState.CLOSED
            if self._owns_client:
                await self._client.aclose()

    async def evaluate(self, context: GuardrailContext) -> Decision:
        return await self.analyze_pending(PendingTrace.from_context(context))

    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        if not self.ready:
            raise RuntimeNotReadyError("remote guardrail runtime is not ready")
        request = RemoteAnalyzeRequest(pending=pending)
        raw_request = request.model_dump_json().encode("utf-8")
        if len(raw_request) > self._max_request_bytes:
            raise RemoteCoreError("remote Core request exceeds the configured limit")
        payload = await self._request_json(
            "POST",
            "/v1/analyze",
            content=raw_request,
        )
        try:
            response = RemoteAnalyzeResponse.model_validate(payload)
        except ValidationError as exc:
            raise RemoteCoreError("remote Core returned an invalid analysis response") from exc
        if self._policy_info is None or (
            response.decision.policy_version != self._policy_info.version
            or response.decision.policy_hash != self._policy_info.content_hash
        ):
            raise RemoteCoreError("remote Core policy identity changed")
        return response.decision

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        await self.close()

    async def _require_health_ready(self) -> None:
        payload = await self._request_json("GET", "/health/ready", authenticated=False)
        try:
            RemoteHealthResponse.model_validate(payload)
        except ValidationError as exc:
            raise RemoteCoreError("remote Core returned an invalid health response") from exc

    async def _fetch_policy_info(self) -> PolicyInfo:
        payload = await self._request_json("GET", "/v1/policies/current")
        try:
            response = RemotePolicyInfoResponse.model_validate(payload)
        except ValidationError as exc:
            raise RemoteCoreError("remote Core returned an invalid policy response") from exc
        return PolicyInfo(version=response.version, content_hash=response.content_hash)

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        authenticated: bool = True,
    ) -> object:
        headers = {"accept": "application/json"}
        if content is not None:
            headers["content-type"] = "application/json"
        if authenticated:
            headers["authorization"] = f"Bearer {self._api_key}"
        try:
            async with self._client.stream(
                method,
                self._base_url + path,
                content=content,
                headers=headers,
                timeout=self._timeout,
            ) as response:
                if response.status_code != 200:
                    raise RemoteCoreError("remote Core request failed")
                content_type = response.headers.get("content-type", "").partition(";")[0]
                if content_type.strip().lower() != "application/json":
                    raise RemoteCoreError("remote Core returned an invalid content type")
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        parsed_length = int(content_length)
                    except ValueError as exc:
                        raise RemoteCoreError(
                            "remote Core returned an invalid content length"
                        ) from exc
                    if parsed_length < 0 or parsed_length > self._max_response_bytes:
                        raise RemoteCoreError("remote Core response exceeds the configured limit")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self._max_response_bytes:
                        raise RemoteCoreError(
                            "remote Core response exceeds the configured limit"
                        )
                    chunks.append(chunk)
        except RemoteCoreError:
            raise
        except httpx.HTTPError as exc:
            raise RemoteCoreError("remote Core is unavailable") from exc
        try:
            return json.loads(b"".join(chunks))
        except (JSONDecodeError, UnicodeDecodeError) as exc:
            raise RemoteCoreError("remote Core returned invalid JSON") from exc

from __future__ import annotations

from pathlib import Path
from typing import Literal

import httpx
import pytest
from pydantic import SecretStr

from agent_guardrail.gateway import GatewaySettings
from agent_guardrail.gateway.upstream import (
    ModelUpstream,
    UpstreamError,
    validate_upstream_path,
)


def settings(
    *,
    auth_mode: Literal["server_managed", "pass_through"] = "server_managed",
    max_response_bytes: int = 1_024,
) -> GatewaySettings:
    return GatewaySettings(
        policy_file=Path("policy.yaml"),
        upstream_base_url="https://provider.example/v1",
        upstream_auth_mode=auth_mode,
        upstream_api_key=(SecretStr("upstream-key") if auth_mode == "server_managed" else None),
        upstream_allowed_hosts=("provider.example",),
        max_upstream_response_bytes=max_response_bytes,
    )


@pytest.mark.asyncio
async def test_complete_uses_fixed_path_server_auth_and_bounded_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/responses"
        assert request.headers["authorization"] == "Bearer upstream-key"
        assert request.headers["accept"] == "application/json"
        return httpx.Response(200, json={"answer": "safe"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = ModelUpstream(client=client, settings=settings())
    try:
        payload = await upstream.complete(
            "responses",
            {"prompt": "safe"},
            client_authorization="Bearer client-key",
        )
    finally:
        await client.aclose()

    assert payload == {"answer": "safe"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "code"),
    [
        (httpx.Response(503, content=b"raw-sensitive-provider-error"), "upstream_http_error"),
        (httpx.Response(200, content=b"not-json"), "upstream_invalid_json"),
        (httpx.Response(200, content=b'"' + b"x" * 1_024 + b'"'), "upstream_response_too_large"),
    ],
)
async def test_complete_maps_http_json_and_size_failures_without_body_echo(
    response: httpx.Response,
    code: str,
) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response))
    upstream = ModelUpstream(client=client, settings=settings())
    try:
        with pytest.raises(UpstreamError) as caught:
            await upstream.complete("responses", {}, client_authorization=None)
    finally:
        await client.aclose()

    assert caught.value.code == code
    assert "raw-sensitive" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception", "code", "timed_out"),
    [
        (httpx.ReadTimeout("raw-sensitive-timeout"), "upstream_timeout", True),
        (httpx.ConnectError("raw-sensitive-transport"), "upstream_transport_error", False),
    ],
)
async def test_complete_maps_transport_failures(
    exception: httpx.HTTPError,
    code: str,
    timed_out: bool,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        exception.request = request
        raise exception

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = ModelUpstream(client=client, settings=settings())
    try:
        with pytest.raises(UpstreamError) as caught:
            await upstream.complete("responses", {}, client_authorization=None)
    finally:
        await client.aclose()

    assert caught.value.code == code
    assert caught.value.timed_out is timed_out
    assert "raw-sensitive" not in str(caught.value)


@pytest.mark.asyncio
async def test_open_stream_uses_pass_through_auth_and_accepts_sse_parameters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://provider.example/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer client-key"
        assert request.headers["accept"] == "text/event-stream"
        return httpx.Response(
            200,
            content=b"data: [DONE]\n\n",
            headers={"content-type": "text/event-stream; charset=utf-8"},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = ModelUpstream(client=client, settings=settings(auth_mode="pass_through"))
    response = await upstream.open_stream(
        "chat/completions",
        {"stream": True},
        client_authorization="Bearer client-key",
    )
    try:
        assert await response.aread() == b"data: [DONE]\n\n"
    finally:
        await response.aclose()
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "code"),
    [
        (
            httpx.Response(
                503,
                content=b"raw-sensitive-provider-error",
                headers={"content-type": "text/event-stream"},
            ),
            "upstream_http_error",
        ),
        (
            httpx.Response(
                200,
                content=b"raw-sensitive-json-body",
                headers={"content-type": "application/json"},
            ),
            "upstream_invalid_content_type",
        ),
    ],
)
async def test_open_stream_closes_rejected_responses(
    response: httpx.Response,
    code: str,
) -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: response))
    upstream = ModelUpstream(client=client, settings=settings())
    try:
        with pytest.raises(UpstreamError) as caught:
            await upstream.open_stream("responses", {}, client_authorization=None)
    finally:
        await client.aclose()

    assert caught.value.code == code
    assert response.is_closed
    assert "raw-sensitive" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception", "code", "timed_out"),
    [
        (httpx.ReadTimeout("raw-sensitive-timeout"), "upstream_timeout", True),
        (httpx.ConnectError("raw-sensitive-transport"), "upstream_transport_error", False),
    ],
)
async def test_open_stream_maps_connection_failures(
    exception: httpx.HTTPError,
    code: str,
    timed_out: bool,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        exception.request = request
        raise exception

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    upstream = ModelUpstream(client=client, settings=settings())
    try:
        with pytest.raises(UpstreamError) as caught:
            await upstream.open_stream("responses", {}, client_authorization=None)
    finally:
        await client.aclose()

    assert caught.value.code == code
    assert caught.value.timed_out is timed_out


@pytest.mark.parametrize(
    "path",
    ["", "/responses", "https://evil.example/v1", "../outside", "a//b", "a/./b"],
)
def test_provider_path_validation_rejects_dynamic_or_escaping_paths(path: str) -> None:
    with pytest.raises(ValueError, match="upstream_path"):
        validate_upstream_path(path)


@pytest.mark.asyncio
async def test_model_upstream_requires_configured_base_url() -> None:
    configured = settings()
    no_model = configured.model_copy(update={"upstream_base_url": None})
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    upstream = ModelUpstream(client=client, settings=no_model)
    try:
        with pytest.raises(RuntimeError, match="not configured"):
            upstream._url("responses")
    finally:
        await client.aclose()

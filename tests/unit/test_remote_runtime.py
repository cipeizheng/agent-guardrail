from __future__ import annotations

import httpx
import pytest

from agent_guardrail.models import Action, Decision, PendingTrace
from agent_guardrail.runtime import RuntimeNotReadyError
from agent_guardrail.runtime.remote import RemoteCoreError, RemoteGuardrailRuntime
from tests.support import tool_context


def _runtime(
    client: httpx.AsyncClient,
    *,
    max_request_bytes: int = 8_388_608,
    max_response_bytes: int = 1_048_576,
):
    return RemoteGuardrailRuntime(
        base_url="http://core.test",
        api_key="core-test-key",
        timeout_seconds=1,
        max_request_bytes=max_request_bytes,
        max_response_bytes=max_response_bytes,
        client=client,
    )


def _decision(pending: PendingTrace, *, policy_hash: str = "fixed-policy") -> Decision:
    return Decision(
        action=Action.ALLOW,
        trace_id=pending.trace.id,
        event_id=pending.primary_event_id,
        pending_event_ids=pending.event_ids,
        policy_version=3,
        policy_hash=policy_hash,
    )


@pytest.mark.asyncio
async def test_remote_runtime_starts_and_analyzes_pending_trace() -> None:
    pending = tool_context(body="safe")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/v1/policies/current":
            assert request.headers["authorization"] == "Bearer core-test-key"
            return httpx.Response(
                200,
                json={
                    "protocol_version": 2,
                    "version": 3,
                    "content_hash": "fixed-policy",
                },
            )
        assert request.url.path == "/v1/analyze"
        return httpx.Response(
            200,
            json={
                "protocol_version": 2,
                "decision": _decision(pending).model_dump(mode="json"),
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = _runtime(client)

    with pytest.raises(RuntimeNotReadyError):
        await runtime.analyze_pending(pending)
    await runtime.start()
    decision = await runtime.analyze_pending(pending)

    assert decision.action is Action.ALLOW
    assert await runtime.check_ready()
    await runtime.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_remote_runtime_rejects_policy_change_and_oversized_response() -> None:
    pending = tool_context(body="safe")
    analyze_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal analyze_calls
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/v1/policies/current":
            return httpx.Response(
                200,
                json={
                    "protocol_version": 2,
                    "version": 3,
                    "content_hash": "fixed-policy",
                },
            )
        analyze_calls += 1
        if analyze_calls == 1:
            return httpx.Response(
                200,
                json={
                    "protocol_version": 2,
                    "decision": _decision(
                        pending,
                        policy_hash="changed-policy",
                    ).model_dump(mode="json"),
                },
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b'"' + (b"x" * 1_024) + b'"',
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = _runtime(client, max_response_bytes=512)
    await runtime.start()

    with pytest.raises(RemoteCoreError, match="policy identity"):
        await runtime.analyze_pending(pending)
    with pytest.raises(RemoteCoreError, match="configured limit"):
        await runtime.analyze_pending(pending)

    await runtime.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_remote_runtime_rejects_oversized_request_without_core_call() -> None:
    pending = tool_context(body="safe")
    analyze_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal analyze_calls
        if request.url.path == "/health/ready":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/v1/policies/current":
            return httpx.Response(
                200,
                json={
                    "protocol_version": 2,
                    "version": 3,
                    "content_hash": "fixed-policy",
                },
            )
        analyze_calls += 1
        return httpx.Response(500)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    runtime = _runtime(client, max_request_bytes=1)
    await runtime.start()

    with pytest.raises(RemoteCoreError, match="request exceeds"):
        await runtime.analyze_pending(pending)

    assert analyze_calls == 0
    await runtime.close()
    await client.aclose()


@pytest.mark.asyncio
async def test_remote_runtime_rejects_malformed_readiness_response() -> None:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"status": "ready", "unexpected": True},
            )
        )
    )
    runtime = _runtime(client)

    with pytest.raises(RemoteCoreError, match="invalid health response"):
        await runtime.start()

    assert not runtime.ready
    await runtime.close()
    await client.aclose()

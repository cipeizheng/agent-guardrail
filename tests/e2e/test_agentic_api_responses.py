"""Cross-process checks for the external Responses state-owner topology.

These tests are opt-in because they start the local ``agentic-server`` binary
from the Agentic API submodule.  They intentionally use a deterministic
HTTP provider instead of a real model service.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import socket
import sys
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

pytestmark = pytest.mark.e2e

_REPO_ROOT = Path(__file__).parents[2]
_DEFAULT_AGENTIC_BINARY = _REPO_ROOT / "vendor/agentic-api/target/debug/agentic-server"
_GATEWAY_API_KEY = "e2e-gateway-key"
_UPSTREAM_API_KEY = "e2e-upstream-key"
_WEATHER_TOOL = {
    "type": "function",
    "name": "get_weather",
    "parameters": {
        "type": "object",
        "properties": {"city": {"type": "string"}},
        "required": ["city"],
        "additionalProperties": False,
    },
}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _agentic_binary() -> Path:
    configured = os.environ.get("AGENTIC_API_BINARY")
    path = Path(configured) if configured else _DEFAULT_AGENTIC_BINARY
    if not path.is_file():
        pytest.skip(
            "initialize and build the Agentic API submodule first or set AGENTIC_API_BINARY; "
            "run with AGENTIC_API_E2E=1"
        )
    return path


def _enabled() -> bool:
    return os.environ.get("AGENTIC_API_E2E", "").lower() in {"1", "true", "yes"}


def _response_payload(response_id: str, output: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1.0,
        "model": "test-model",
        "status": "completed",
        "parallel_tool_calls": False,
        "tool_choice": "auto",
        "tools": [],
        "output": output,
    }


def _text_response(response_id: str, text: str) -> dict[str, Any]:
    return _response_payload(
        response_id,
        [
            {
                "type": "message",
                "id": f"msg-{response_id}",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}],
            }
        ],
    )


def _function_call_response(response_id: str) -> dict[str, Any]:
    return _response_payload(
        response_id,
        [
            {
                "type": "function_call",
                "id": "fc-weather-1",
                "call_id": "call-weather-1",
                "name": "get_weather",
                "arguments": '{"city":"Paris"}',
                "status": "completed",
            }
        ],
    )


@dataclass(frozen=True, slots=True)
class _RawReply:
    body: bytes
    status_code: int = 200
    content_type: str = "application/json"


def _responses_sse(response_id: str, text: str) -> bytes:
    created = _response_payload(response_id, [])
    created["status"] = "in_progress"
    completed = _text_response(response_id, text)
    events = [
        {
            "type": "response.created",
            "response": created,
            "sequence_number": 0,
        },
        {
            "type": "response.output_text.delta",
            "item_id": f"msg-{response_id}",
            "output_index": 0,
            "content_index": 0,
            "delta": text,
            "sequence_number": 1,
        },
        {
            "type": "response.completed",
            "response": completed,
            "sequence_number": 2,
        },
    ]
    return b"".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()
        for event in events
    )


def _sse_payloads(body: bytes) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for frame in body.decode().split("\n\n"):
        data_line = next(
            (line[6:] for line in frame.splitlines() if line.startswith("data: ")),
            None,
        )
        if data_line is None or data_line == "[DONE]":
            continue
        payload = json.loads(data_line)
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads


class _Provider:
    def __init__(self, responses: Sequence[Mapping[str, Any] | _RawReply]) -> None:
        self.requests: list[dict[str, Any]] = []
        self.responses = list(responses)
        self.app = FastAPI()

        @self.app.post("/v1/responses")
        async def response_endpoint(request: Request) -> Response:
            payload = await request.json()
            self.requests.append(payload)
            index = len(self.requests) - 1
            if index >= len(self.responses):
                return JSONResponse(
                    {"error": {"message": "unexpected provider request"}},
                    status_code=500,
                )
            reply = self.responses[index]
            if isinstance(reply, _RawReply):
                return Response(
                    content=reply.body,
                    status_code=reply.status_code,
                    media_type=reply.content_type,
                )
            return JSONResponse(dict(reply))


@asynccontextmanager
async def _running_app(app: FastAPI) -> AsyncIterator[str]:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(128)
    port = int(server_socket.getsockname()[1])
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_config=None,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[server_socket]))
    try:
        for _ in range(500):
            if server.started:
                break
            if task.done():
                await task
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("deterministic provider did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


async def _wait_ready(client: httpx.AsyncClient, url: str, path: str) -> None:
    last_error = "service did not become ready"
    for _ in range(300):
        try:
            response = await client.get(f"{url}{path}")
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        await asyncio.sleep(0.05)
    raise AssertionError(f"{url}{path} was not ready: {last_error}")


@asynccontextmanager
async def _running_process(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    url: str,
    ready_path: str,
) -> AsyncIterator[str]:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=cwd,
        env=dict(env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            try:
                await _wait_ready(client, url, ready_path)
            except Exception as exc:
                output = ""
                if process.stdout is not None:
                    output = (await process.stdout.read(4_000)).decode(errors="replace")
                raise AssertionError(
                    f"service failed to start ({shlex.join(command)}): {exc}\n{output}"
                ) from exc
        yield url
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()


def _gateway_env(
    provider_url: str,
    port: int,
    policy_file: Path,
    *,
    gateway_api_keys: Sequence[str] = (_GATEWAY_API_KEY,),
) -> dict[str, str]:
    return {
        **os.environ,
        "AGENT_GUARDRAIL_POLICY_FILE": str(policy_file),
        "AGENT_GUARDRAIL_UPSTREAM_BASE_URL": f"{provider_url}/v1",
        "AGENT_GUARDRAIL_UPSTREAM_API_KEY": _UPSTREAM_API_KEY,
        "AGENT_GUARDRAIL_GATEWAY_API_KEYS": json.dumps(list(gateway_api_keys)),
        "AGENT_GUARDRAIL_HOST": "127.0.0.1",
        "AGENT_GUARDRAIL_PORT": str(port),
        "AGENT_GUARDRAIL_DETECTOR_PROFILE": "local",
        "AGENT_GUARDRAIL_LOG_LEVEL": "warning",
    }


def _agentic_env(gateway_url: str, port: int, db_file: Path, home: Path) -> dict[str, str]:
    return {
        **os.environ,
        "LLM_API_BASE": gateway_url,
        "GATEWAY_HOST": "127.0.0.1",
        "GATEWAY_PORT": str(port),
        "DATABASE_URL": f"sqlite://{db_file}",
        "AGENTIC_API_HOME": str(home),
        "AGENTIC_RESPONSES_TOOL_EXECUTION_MODE": "client_only",
        "SKIP_LLM_READY_CHECK": "true",
        "RUST_LOG": "agentic_server=warn,agentic_core=warn",
    }


def _history_policy(path: Path) -> None:
    path.write_text(
        """\
version: 3
engine: {max_violations: 100, on_analysis_error: block, on_detector_timeout: block}
scopes: [pending]
rules:
  - id: block-restored-history
    action: block
    events:
      history: {kind: message, domain: pending}
      current: {kind: message, domain: pending}
    where:
      all:
        - compare:
            left: {field: [history, payload, content, text]}
            operator: contains
            right: {literal: state-owner-history-marker}
        - compare:
            left: {field: [current, payload, content, text]}
            operator: contains
            right: {literal: state-owner-check}
    finding:
      code: restored_history_blocked
      message: The restored Responses history is blocked by policy.
      subjects: [current]
""",
        encoding="utf-8",
    )


@pytest.mark.skipif(not _enabled(), reason="set AGENTIC_API_E2E=1 to run process-level tests")
@pytest.mark.asyncio
async def test_previous_response_id_rehydrates_before_gateway_guardrail(tmp_path: Path) -> None:
    """A restarted Agentic API must restore history before calling Guardrail."""

    binary = _agentic_binary()
    policy_file = tmp_path / "history-policy.yaml"
    _history_policy(policy_file)
    provider = _Provider([_text_response("provider-first", "state persisted")])

    async with _running_app(provider.app) as provider_url:
        gateway_port = _free_port()
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        gateway_command = [sys.executable, "-m", "agent_guardrail.gateway"]
        async with _running_process(
            gateway_command,
            env=_gateway_env(provider_url, gateway_port, policy_file),
            cwd=_REPO_ROOT,
            url=gateway_url,
            ready_path="/health/ready",
        ):
            db_file = tmp_path / "responses.db"
            agentic_home = tmp_path / "agentic-home"
            agentic_port = _free_port()
            agentic_url = f"http://127.0.0.1:{agentic_port}"
            agentic_command = [str(binary)]
            async with _running_process(
                agentic_command,
                env=_agentic_env(gateway_url, agentic_port, db_file, agentic_home),
                cwd=binary.parent.parent.parent,
                url=agentic_url,
                ready_path="/ready",
            ):
                async with httpx.AsyncClient(timeout=5.0) as client:
                    first = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={"model": "test-model", "input": "state-owner-history-marker"},
                    )
                    assert first.status_code == 200, first.text
                    previous_response_id = first.json()["id"]

            # The state is owned by Agentic API's SQLite store, so this is a
            # real process restart rather than an in-memory continuation.
            restarted_port = _free_port()
            restarted_url = f"http://127.0.0.1:{restarted_port}"
            async with _running_process(
                [str(binary)],
                env=_agentic_env(gateway_url, restarted_port, db_file, agentic_home),
                cwd=binary.parent.parent.parent,
                url=restarted_url,
                ready_path="/ready",
            ):
                async with httpx.AsyncClient(timeout=5.0) as client:
                    second = await client.post(
                        f"{restarted_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={
                            "model": "test-model",
                            "input": "state-owner-check",
                            "previous_response_id": previous_response_id,
                        },
                    )

    assert second.status_code == 400, second.text
    assert second.json()["error"]["code"] == "guardrail_blocked"
    assert second.json()["error"]["violations"][0]["code"] == "restored_history_blocked"
    assert len(provider.requests) == 1


@pytest.mark.skipif(not _enabled(), reason="set AGENTIC_API_E2E=1 to run process-level tests")
@pytest.mark.asyncio
async def test_function_call_continuation_reaches_gateway_with_rehydrated_items(
    tmp_path: Path,
) -> None:
    """Client-owned function output must retain the call relationship across turns."""

    binary = _agentic_binary()
    policy_file = tmp_path / "allow-policy.yaml"
    policy_file.write_text(
        "version: 3\nscopes: [pending]\nrules: []\n", encoding="utf-8"
    )
    provider = _Provider(
        [
            _function_call_response("provider-call"),
            _text_response("provider-final", "weather accepted"),
        ]
    )

    async with _running_app(provider.app) as provider_url:
        gateway_port = _free_port()
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        async with _running_process(
            [sys.executable, "-m", "agent_guardrail.gateway"],
            env=_gateway_env(provider_url, gateway_port, policy_file),
            cwd=_REPO_ROOT,
            url=gateway_url,
            ready_path="/health/ready",
        ):
            db_file = tmp_path / "responses.db"
            agentic_port = _free_port()
            agentic_url = f"http://127.0.0.1:{agentic_port}"
            async with _running_process(
                [str(binary)],
                env=_agentic_env(gateway_url, agentic_port, db_file, tmp_path / "agentic-home"),
                cwd=binary.parent.parent.parent,
                url=agentic_url,
                ready_path="/ready",
            ):
                async with httpx.AsyncClient(timeout=5.0) as client:
                    first = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={
                            "model": "test-model",
                            "input": "check the weather",
                            "tools": [_WEATHER_TOOL],
                        },
                    )
                    assert first.status_code == 200, first.text
                    first_json = first.json()
                    function_call = next(
                        item for item in first_json["output"] if item["type"] == "function_call"
                    )

                    second = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={
                            "model": "test-model",
                            "previous_response_id": first_json["id"],
                            "input": [
                                {
                                    "type": "function_call_output",
                                    "call_id": function_call["call_id"],
                                    "output": "Paris is sunny",
                                }
                            ],
                        },
                    )

    assert second.status_code == 200, second.text
    assert len(provider.requests) == 2
    second_input = provider.requests[1]["input"]
    assert isinstance(second_input, list)
    assert [item["type"] for item in second_input] == [
        "message",
        "function_call",
        "function_call_output",
    ]
    assert second_input[1]["call_id"] == "call-weather-1"
    assert second_input[2]["call_id"] == "call-weather-1"
    assert "previous_response_id" not in provider.requests[1]


@pytest.mark.skipif(not _enabled(), reason="set AGENTIC_API_E2E=1 to run process-level tests")
@pytest.mark.asyncio
async def test_streaming_response_can_continue_from_persisted_terminal_state(
    tmp_path: Path,
) -> None:
    """A completed SSE response remains available for the next turn."""

    binary = _agentic_binary()
    policy_file = tmp_path / "allow-policy.yaml"
    policy_file.write_text(
        "version: 3\nscopes: [pending]\nrules: []\n", encoding="utf-8"
    )
    provider = _Provider(
        [
            _RawReply(
                _responses_sse("provider-stream", "streamed state"),
                content_type="text/event-stream",
            ),
            _text_response("provider-after-stream", "stream continuation accepted"),
        ]
    )

    async with _running_app(provider.app) as provider_url:
        gateway_port = _free_port()
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        async with _running_process(
            [sys.executable, "-m", "agent_guardrail.gateway"],
            env=_gateway_env(
                provider_url,
                gateway_port,
                policy_file,
                gateway_api_keys=(),
            ),
            cwd=_REPO_ROOT,
            url=gateway_url,
            ready_path="/health/ready",
        ):
            db_file = tmp_path / "responses.db"
            agentic_port = _free_port()
            agentic_url = f"http://127.0.0.1:{agentic_port}"
            async with _running_process(
                [str(binary)],
                env=_agentic_env(gateway_url, agentic_port, db_file, tmp_path / "agentic-home"),
                cwd=binary.parent.parent.parent,
                url=agentic_url,
                ready_path="/ready",
            ):
                async with httpx.AsyncClient(timeout=5.0) as client:
                    async with client.stream(
                        "POST",
                        f"{agentic_url}/v1/responses",
                        headers={},
                        json={
                            "model": "test-model",
                            "input": "save this streamed state",
                            "stream": True,
                        },
                    ) as first:
                        assert first.status_code == 200
                        first_body = await first.aread()

                    events = _sse_payloads(first_body)
                    completed = next(
                        event for event in events if event["type"] == "response.completed"
                    )
                    previous_response_id = completed["response"]["id"]

                    second = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={},
                        json={
                            "model": "test-model",
                            "input": "continue after the stream",
                            "previous_response_id": previous_response_id,
                        },
                    )

    assert second.status_code == 200, second.text
    assert len(provider.requests) == 2
    assert provider.requests[0]["stream"] is True
    second_input = provider.requests[1]["input"]
    assert isinstance(second_input, list)
    assert any("streamed state" in json.dumps(item) for item in second_input)
    assert any("continue after the stream" in json.dumps(item) for item in second_input)
    assert "previous_response_id" not in provider.requests[1]


@pytest.mark.skipif(not _enabled(), reason="set AGENTIC_API_E2E=1 to run process-level tests")
@pytest.mark.parametrize(
    ("reply", "expected_status", "expected_code"),
    [
        (
            _RawReply(
                b'{"error":{"message":"provider unavailable"}}',
                status_code=503,
            ),
            502,
            "upstream_http_error",
        ),
        (_RawReply(b"not-json"), 502, "upstream_invalid_json"),
    ],
    ids=["provider-http-error", "provider-invalid-json"],
)
@pytest.mark.asyncio
async def test_provider_failures_do_not_create_response_state(
    tmp_path: Path,
    reply: _RawReply,
    expected_status: int,
    expected_code: str,
) -> None:
    """Provider HTTP and protocol failures stop before a Response is stored."""

    binary = _agentic_binary()
    policy_file = tmp_path / "allow-policy.yaml"
    policy_file.write_text(
        "version: 3\nscopes: [pending]\nrules: []\n", encoding="utf-8"
    )
    provider = _Provider(
        [
            _text_response("provider-before-failure", "before failure"),
            reply,
            _text_response("provider-after-failure", "recovered"),
        ]
    )

    async with _running_app(provider.app) as provider_url:
        gateway_port = _free_port()
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        async with _running_process(
            [sys.executable, "-m", "agent_guardrail.gateway"],
            env=_gateway_env(provider_url, gateway_port, policy_file),
            cwd=_REPO_ROOT,
            url=gateway_url,
            ready_path="/health/ready",
        ):
            db_file = tmp_path / "responses.db"
            agentic_port = _free_port()
            agentic_url = f"http://127.0.0.1:{agentic_port}"
            async with _running_process(
                [str(binary)],
                env=_agentic_env(gateway_url, agentic_port, db_file, tmp_path / "agentic-home"),
                cwd=binary.parent.parent.parent,
                url=agentic_url,
                ready_path="/ready",
            ):
                async with httpx.AsyncClient(timeout=5.0) as client:
                    first = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={"model": "test-model", "input": "before failure"},
                    )
                    assert first.status_code == 200, first.text
                    previous_response_id = first.json()["id"]

                    response = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={
                            "model": "test-model",
                            "input": "trigger provider failure",
                            "previous_response_id": previous_response_id,
                        },
                    )
                    recovery = await client.post(
                        f"{agentic_url}/v1/responses",
                        headers={"authorization": f"Bearer {_GATEWAY_API_KEY}"},
                        json={
                            "model": "test-model",
                            "input": "recover after failure",
                            "previous_response_id": previous_response_id,
                        },
                    )

    assert response.status_code == expected_status, response.text
    assert response.json()["error"]["code"] == expected_code
    assert recovery.status_code == 200, recovery.text
    assert len(provider.requests) == 3
    assert "trigger provider failure" not in json.dumps(provider.requests[2])
    assert "recover after failure" in json.dumps(provider.requests[2])

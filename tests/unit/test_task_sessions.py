from __future__ import annotations

import pytest

from agent_guardrail.enforcement import NullAuditSink
from agent_guardrail.gateway.task_sessions import TaskSessionError, TaskSessionStore
from tests.support import empty_analyzer


def task_store(
    *,
    now: list[float],
    max_sessions: int = 1,
) -> TaskSessionStore:
    trace_ids = iter(("trace-1", "trace-2", "trace-3"))
    tokens = iter(
        (
            "ags_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ags_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ags_cccccccccccccccccccccccccccccccc",
        )
    )
    return TaskSessionStore(
        analyzer=empty_analyzer(),
        audit=NullAuditSink(),
        max_sessions=max_sessions,
        ttl_seconds=10,
        max_trace_events=32,
        clock=lambda: now[0],
        token_factory=lambda: next(tokens),
        trace_id_factory=lambda: next(trace_ids),
    )


@pytest.mark.asyncio
async def test_task_store_reuses_one_session_and_refreshes_its_ttl() -> None:
    now = [0.0]
    store = task_store(now=now)

    created = await store.create()
    now[0] = 9.0
    resolved = await store.get(created.token)
    now[0] = 18.0

    assert resolved is created
    assert await store.get(created.token) is created
    assert created.trace_id == "trace-1"


@pytest.mark.asyncio
async def test_task_store_never_evicts_an_active_session_for_capacity() -> None:
    now = [0.0]
    store = task_store(now=now)
    await store.create()

    with pytest.raises(TaskSessionError, match="capacity") as caught:
        await store.create()

    assert caught.value.code == "task_session_capacity_exceeded"


@pytest.mark.asyncio
async def test_task_store_expires_and_deletes_without_disclosing_tokens() -> None:
    now = [0.0]
    store = task_store(now=now)
    first = await store.create()
    now[0] = 10.0

    with pytest.raises(TaskSessionError, match="invalid or expired") as expired:
        await store.get(first.token)
    assert expired.value.code == "task_session_invalid"

    second = await store.create()
    await store.delete(second.token)
    with pytest.raises(TaskSessionError, match="invalid or expired"):
        await store.get(second.token)
    with pytest.raises(TaskSessionError, match="invalid or expired"):
        await store.get("not-a-token")

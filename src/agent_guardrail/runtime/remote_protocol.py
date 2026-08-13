"""Closed wire models for the internal Core analysis protocol."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_guardrail.models import Decision, PendingTrace

REMOTE_CORE_PROTOCOL_VERSION = 4


class RemoteAnalyzeRequest(BaseModel):
    """One complete, bounded pending-trace snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[4] = REMOTE_CORE_PROTOCOL_VERSION
    pending: PendingTrace


class RemoteAnalyzeResponse(BaseModel):
    """One sanitized decision produced from a pending snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[4] = REMOTE_CORE_PROTOCOL_VERSION
    decision: Decision


class RemotePolicyInfoResponse(BaseModel):
    """Protocol and fixed-policy identity returned by Core."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[4] = REMOTE_CORE_PROTOCOL_VERSION
    version: int = Field(ge=1)
    content_hash: str = Field(min_length=8)


class RemoteHealthResponse(BaseModel):
    """Exact readiness response accepted from Core."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ready"]

"""Lifecycle-aware public facade over the MatchPlan PolicyAnalyzer."""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

from agent_guardrail.core import DetectorRegistry, MatchPolicyAnalyzer, PredicateRegistry
from agent_guardrail.models import Decision, GuardrailContext, PendingTrace
from agent_guardrail.runtime.bootstrap import (
    build_analyzer_from_policy_file,
    build_analyzer_from_policy_yaml,
)


class RuntimeState(StrEnum):
    """Small explicit lifecycle for a local guardrail runtime."""

    CREATED = "created"
    READY = "ready"
    CLOSED = "closed"


class RuntimeNotReadyError(RuntimeError):
    """The local runtime cannot safely evaluate a request in its current state."""


class PolicyInfo(BaseModel):
    """Safe policy identity exposed to health and management endpoints."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(ge=1)
    content_hash: str = Field(min_length=8)


class GuardrailRuntime:
    """Own one compiled MatchPolicyAnalyzer and expose its stable lifecycle."""

    def __init__(self, analyzer: MatchPolicyAnalyzer) -> None:
        self._analyzer = analyzer
        self._state = RuntimeState.CREATED
        self._lifecycle_lock = asyncio.Lock()

    @classmethod
    def from_policy_file(
        cls,
        path: str | Path,
        *,
        predicate_registry: PredicateRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> Self:
        """Construct a runtime only after the complete policy validates."""

        return cls(
            build_analyzer_from_policy_file(
                path,
                predicate_registry=predicate_registry,
                detector_registry=detector_registry,
            )
        )

    @classmethod
    def from_policy_yaml(
        cls,
        source: str,
        *,
        predicate_registry: PredicateRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> Self:
        """Construct a runtime from validated YAML without global registry state."""

        return cls(
            build_analyzer_from_policy_yaml(
                source,
                predicate_registry=predicate_registry,
                detector_registry=detector_registry,
            )
        )

    @property
    def state(self) -> RuntimeState:
        return self._state

    @property
    def ready(self) -> bool:
        return self._state is RuntimeState.READY

    @property
    def policy_info(self) -> PolicyInfo:
        return PolicyInfo(
            version=self._analyzer.policy_version,
            content_hash=self._analyzer.policy_hash,
        )

    async def start(self) -> None:
        """Start runtime-owned resources; idempotent while ready."""

        async with self._lifecycle_lock:
            if self._state is RuntimeState.READY:
                return
            if self._state is RuntimeState.CLOSED:
                raise RuntimeNotReadyError("a closed guardrail runtime cannot be restarted")
            self._state = RuntimeState.READY

    async def close(self) -> None:
        """Close runtime-owned resources; idempotent in every state."""

        async with self._lifecycle_lock:
            self._state = RuntimeState.CLOSED

    async def check_ready(self) -> bool:
        """Return local readiness through the shared Gateway runtime facade."""

        return self.ready

    async def evaluate(self, context: GuardrailContext) -> Decision:
        """Compatibility bridge for the v0.1 single-event decision endpoint."""

        if not self.ready:
            raise RuntimeNotReadyError("guardrail runtime is not ready")
        return await self._analyzer.analyze_pending(PendingTrace.from_context(context))

    async def analyze_pending(self, pending: PendingTrace) -> Decision:
        """Analyze an atomic pending event batch only while the runtime is ready."""

        if not self.ready:
            raise RuntimeNotReadyError("guardrail runtime is not ready")
        return await self._analyzer.analyze_pending(pending)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        await self.close()

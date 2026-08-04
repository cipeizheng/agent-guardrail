"""Lifecycle-aware public facade over the side-effect-free decision engine."""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

from agent_guardrail.core import DetectorRegistry, GuardrailEngine, RuleRegistry
from agent_guardrail.models import Decision, GuardrailContext
from agent_guardrail.runtime.bootstrap import (
    build_engine_from_policy_file,
    build_engine_from_policy_yaml,
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
    """Own one configured engine and expose a stable DecisionEvaluator facade."""

    def __init__(self, engine: GuardrailEngine) -> None:
        self._engine = engine
        self._state = RuntimeState.CREATED
        self._lifecycle_lock = asyncio.Lock()

    @classmethod
    def from_policy_file(
        cls,
        path: str | Path,
        *,
        rule_registry: RuleRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> Self:
        """Construct a runtime only after the complete policy validates."""

        return cls(
            build_engine_from_policy_file(
                path,
                rule_registry=rule_registry,
                detector_registry=detector_registry,
            )
        )

    @classmethod
    def from_policy_yaml(
        cls,
        source: str,
        *,
        rule_registry: RuleRegistry | None = None,
        detector_registry: DetectorRegistry | None = None,
    ) -> Self:
        """Construct a runtime from validated YAML without global registry state."""

        return cls(
            build_engine_from_policy_yaml(
                source,
                rule_registry=rule_registry,
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
            version=self._engine.policy.version,
            content_hash=self._engine.policy.content_hash,
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

    async def evaluate(self, context: GuardrailContext) -> Decision:
        """Delegate to the active engine only while the runtime is ready."""

        if not self.ready:
            raise RuntimeNotReadyError("guardrail runtime is not ready")
        return await self._engine.evaluate(context)

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        await self.close()

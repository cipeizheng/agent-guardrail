"""Opt-in deterministic fakes; production modules must not import this package."""

from agent_guardrail.testing.fakes import FakeToolExecutor, ScriptedLLM, ToolHandler

__all__ = ["FakeToolExecutor", "ScriptedLLM", "ToolHandler"]

"""Opt-in deterministic fakes; production modules must not import this package."""

from agent_guardrail.testing.fakes import FakeToolExecutor, ScriptedLLM, ToolHandler
from agent_guardrail.testing.simulated_agent import SimulatedAgent

__all__ = ["FakeToolExecutor", "ScriptedLLM", "SimulatedAgent", "ToolHandler"]

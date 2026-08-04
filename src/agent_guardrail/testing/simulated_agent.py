"""A minimal agent loop that knows only generic LLM and tool protocols."""

from __future__ import annotations

import json

from pydantic import JsonValue

from agent_guardrail.enforcement.protocols import LLMClient, ToolExecutor
from agent_guardrail.models import ChatMessage, ChatRole, ModelRequest


class SimulatedAgent:
    """Exercise a deterministic model/tool loop without importing guardrail internals."""

    def __init__(
        self,
        *,
        llm: LLMClient,
        tools: ToolExecutor,
        max_steps: int = 8,
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.llm = llm
        self.tools = tools
        self.max_steps = max_steps

    async def run(self, prompt: str) -> str:
        messages = [ChatMessage(role=ChatRole.USER, content=prompt)]

        for _ in range(self.max_steps):
            response = await self.llm.complete(ModelRequest(messages=tuple(messages)))
            if not response.tool_calls:
                return response.content or ""

            messages.append(
                ChatMessage(
                    role=ChatRole.ASSISTANT,
                    content=response.content,
                    tool_calls=response.tool_calls,
                )
            )
            for call in response.tool_calls:
                result = await self.tools.execute(call)
                messages.append(
                    ChatMessage(
                        role=ChatRole.TOOL,
                        content=self._output_text(result.output),
                        tool_call_id=result.call_id,
                    )
                )

        raise RuntimeError("simulated agent exceeded max_steps")

    @staticmethod
    def _output_text(output: JsonValue) -> str:
        if isinstance(output, str):
            return output
        return json.dumps(output, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

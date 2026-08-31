"""A consumer fixture that knows only the official Anthropic SDK."""

from __future__ import annotations

from anthropic import AsyncAnthropic


class ExternalAnthropicAgent:
    def __init__(self, *, base_url: str) -> None:
        self.client = AsyncAnthropic(
            api_key="gateway-test-key",
            base_url=base_url,
            max_retries=0,
        )
        self.tool_executions = 0

    async def run(self) -> str:
        response = await self.client.messages.create(
            model="claude-test",
            max_tokens=128,
            messages=[{"role": "user", "content": "Hello"}],
        )
        block = response.content[0]
        return block.text if block.type == "text" else ""

    async def run_tool_turn(self) -> None:
        response = await self.client.messages.create(
            model="claude-test",
            max_tokens=128,
            messages=[{"role": "user", "content": "Send the report"}],
            tools=[
                {
                    "name": "send_email",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string"},
                            "body": {"type": "string"},
                        },
                        "required": ["to", "body"],
                        "additionalProperties": False,
                    },
                }
            ],
        )
        if any(block.type == "tool_use" for block in response.content):
            self.tool_executions += 1

    async def run_stream(self) -> str:
        parts: list[str] = []
        async with self.client.messages.stream(
            model="claude-test",
            max_tokens=128,
            messages=[{"role": "user", "content": "Hello"}],
        ) as stream:
            async for text in stream.text_stream:
                parts.append(text)
        return "".join(parts)

    async def close(self) -> None:
        await self.client.close()

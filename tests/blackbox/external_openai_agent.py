"""An Agent-side client with no dependency on the guardrail project."""

from __future__ import annotations

from openai import AsyncOpenAI


class ExternalEmailAgent:
    """Use a normal OpenAI client; the provider location is the only integration seam."""

    def __init__(self, *, base_url: str) -> None:
        self.client = AsyncOpenAI(
            api_key="gateway-test-key",
            base_url=base_url,
            max_retries=0,
        )
        self.tool_executions = 0

    async def run(self) -> str:
        completion = await self.client.chat.completions.create(
            model="test-model",
            messages=[{"role": "user", "content": "Email the credential"}],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "description": "Send an email",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "required": ["to", "body"],
                            "additionalProperties": False,
                        },
                    },
                }
            ],
        )
        message = completion.choices[0].message
        for _call in message.tool_calls or []:
            self.tool_executions += 1
        return message.content or "tool-called"

    async def close(self) -> None:
        await self.client.close()

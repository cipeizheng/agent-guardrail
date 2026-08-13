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

    async def run_stream(self) -> str:
        stream = await self.client.chat.completions.create(
            model="test-model",
            messages=[{"role": "user", "content": "Return a safe response"}],
            stream=True,
        )
        pieces: list[str] = []
        async for chunk in stream:
            pieces.extend(choice.delta.content or "" for choice in chunk.choices)
        return "".join(pieces)

    async def close(self) -> None:
        await self.client.close()


class ExternalResponsesAgent:
    """Use only the official OpenAI Responses SDK against the Gateway."""

    def __init__(self, *, base_url: str) -> None:
        self.client = AsyncOpenAI(
            api_key="gateway-test-key",
            base_url=base_url,
            max_retries=0,
        )

    async def run(self) -> str:
        response = await self.client.responses.create(
            model="test-model",
            input="Return a safe response",
        )
        return response.output_text

    async def run_stream(self) -> str:
        stream = await self.client.responses.create(
            model="test-model",
            input="Return a safe response",
            stream=True,
        )
        pieces: list[str] = []
        async for event in stream:
            if event.type == "response.output_text.delta":
                pieces.append(event.delta)
        return "".join(pieces)

    async def run_stream_until_error(self) -> tuple[str, str | None]:
        stream = await self.client.responses.create(
            model="test-model",
            input="Return a safe response",
            stream=True,
        )
        pieces: list[str] = []
        error_code: str | None = None
        async for event in stream:
            if event.type == "response.output_text.delta":
                pieces.append(event.delta)
            elif event.type == "error":
                error_code = event.code
        return "".join(pieces), error_code

    async def close(self) -> None:
        await self.client.close()

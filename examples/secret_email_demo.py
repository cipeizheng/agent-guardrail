"""Run a local model-and-tool policy example without an API key."""

from __future__ import annotations

import asyncio
from pathlib import Path

from agent_guardrail.models import (
    ChatMessage,
    ChatRole,
    MessageRole,
    ModelRequest,
    ModelResponse,
    ToolCall,
)
from agent_guardrail.runtime import GuardrailRuntime
from agent_guardrail.sdk import GuardrailRun
from agent_guardrail.testing import FakeToolExecutor, ScriptedLLM


async def main() -> None:
    policy_path = Path(__file__).parent / "policies" / "secret-email.yaml"
    runtime = GuardrailRuntime.from_policy_file(policy_path)
    fake_tools = FakeToolExecutor({"send_email": lambda arguments: {"sent": True}})
    inner_llm = ScriptedLLM(
        responses=[
            ModelResponse(
                tool_calls=(
                    ToolCall(
                        call_id="call-1",
                        name="send_email",
                        arguments={
                            "to": "outside@example.com",
                            "subject": "Credentials",
                            "body": "Use sk-demo000000000000000000 to access the service.",
                        },
                    ),
                )
            )
        ]
    )
    async with runtime:
        run = GuardrailRun(analyzer=runtime, run_id="demo-trace")
        prompt = "Send the credentials by email"
        message = await run.message(role=MessageRole.USER, text=prompt)
        if message.decision.blocked or message.primary is None:
            print(message.decision.model_dump_json(indent=2))
            return

        model_call = await run.model_call(inputs=(message.primary,))
        if model_call.decision.blocked or model_call.primary is None:
            print(model_call.decision.model_dump_json(indent=2))
            return

        response = await inner_llm.complete(
            ModelRequest(messages=(ChatMessage(role=ChatRole.USER, content=prompt),))
        )
        for call in response.tool_calls:
            proposal = await run.tool_call_proposal(call, model_call=model_call.primary)
            if proposal.decision.blocked:
                print(f"policy decision: {proposal.decision.action.value}")
                print(f"model executions: {inner_llm.call_count}")
                print(f"send_email executions: {fake_tools.call_count('send_email')}")
                return
            if proposal.primary is None:
                return

            checked_call = await run.tool_call(call, proposal=proposal.primary)
            if checked_call.decision.blocked or checked_call.primary is None:
                print(checked_call.decision.model_dump_json(indent=2))
                return
            result = await fake_tools.execute(call)
            await run.tool_result(result, call=checked_call.primary)


if __name__ == "__main__":
    asyncio.run(main())

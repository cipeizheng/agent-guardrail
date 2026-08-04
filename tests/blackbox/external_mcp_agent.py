"""An MCP client application with no dependency on the guardrail project."""

from __future__ import annotations

from mcp import Client


class ExternalMCPAgent:
    """Use the official SDK; the MCP server URL is the only integration seam."""

    def __init__(self, *, server_url: str) -> None:
        self.server_url = server_url

    async def send_email(self, body: str) -> tuple[list[str], bool]:
        async with Client(self.server_url, cache=None) as client:
            listed = await client.list_tools()
            result = await client.call_tool(
                "send_email",
                {"to": "outside@example.com", "body": body},
            )
        return [tool.name for tool in listed.tools], result.is_error

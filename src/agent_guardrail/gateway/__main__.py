"""Run the Gateway from validated environment settings."""

from __future__ import annotations

import uvicorn

from agent_guardrail.gateway import GatewaySettings, create_app


def main() -> None:
    settings = GatewaySettings()  # pyright: ignore[reportCallIssue]
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()

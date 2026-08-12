"""Run the remote Core from validated environment settings."""

from __future__ import annotations

import uvicorn

from agent_guardrail.core_service import CoreSettings, create_core_app


def main() -> None:
    settings = CoreSettings()  # pyright: ignore[reportCallIssue]
    uvicorn.run(
        create_core_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    main()

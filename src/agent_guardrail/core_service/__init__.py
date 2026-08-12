"""Remote Core service composition API."""

from agent_guardrail.core_service.app import create_core_app
from agent_guardrail.core_service.config import CoreSettings

__all__ = ["CoreSettings", "create_core_app"]

"""Small bearer-token authentication boundary with constant-time comparison."""

from __future__ import annotations

import secrets

from starlette.requests import Request

from agent_guardrail.gateway.config import GatewaySettings


class GatewayAuthenticationError(PermissionError):
    """The caller did not present a configured Gateway credential."""


class GatewayAuthenticator:
    def __init__(self, settings: GatewaySettings) -> None:
        self._keys = tuple(key.get_secret_value() for key in settings.gateway_api_keys)

    def authenticate(self, request: Request) -> str | None:
        authorization = request.headers.get("authorization")
        if not self._keys:
            return authorization
        if authorization is None or not authorization.startswith("Bearer "):
            raise GatewayAuthenticationError
        candidate = authorization.removeprefix("Bearer ")
        if not any(secrets.compare_digest(candidate, key) for key in self._keys):
            raise GatewayAuthenticationError
        return authorization

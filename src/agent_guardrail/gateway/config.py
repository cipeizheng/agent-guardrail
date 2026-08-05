"""Validated environment configuration for the HTTP Gateway."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    """One centralized, closed set of Gateway process settings."""

    model_config = SettingsConfigDict(
        env_prefix="AGENT_GUARDRAIL_",
        case_sensitive=False,
        extra="ignore",
    )

    policy_file: Path
    upstream_base_url: str | None = None
    upstream_auth_mode: Literal["server_managed", "pass_through"] = "server_managed"
    upstream_api_key: SecretStr | None = None
    upstream_allowed_hosts: tuple[str, ...] = ()
    gateway_api_keys: tuple[SecretStr, ...] = ()
    audit_path: Path | None = None
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    max_upstream_response_bytes: int = Field(
        default=4_194_304,
        ge=1_024,
        le=67_108_864,
    )
    max_trace_events: int = Field(default=16, ge=2, le=1_000)
    upstream_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    evaluate_endpoint_enabled: bool = False
    mcp_upstream_url: str | None = None
    mcp_upstream_auth_mode: Literal["none", "server_managed", "pass_through"] = "none"
    mcp_upstream_api_key: SecretStr | None = None
    mcp_upstream_allowed_hosts: tuple[str, ...] = ()
    mcp_allowed_origins: tuple[str, ...] = ()
    mcp_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    mcp_max_response_bytes: int = Field(default=4_194_304, ge=1_024, le=67_108_864)
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8080, ge=1, le=65_535)
    log_level: Literal["critical", "error", "warning", "info", "debug", "trace"] = "info"

    @field_validator("upstream_base_url")
    @classmethod
    def validate_upstream_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("upstream_base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("upstream_base_url cannot contain credentials, query, or fragment")
        return value.rstrip("/") + "/"

    @field_validator("mcp_upstream_url")
    @classmethod
    def validate_mcp_upstream_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("mcp_upstream_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("mcp_upstream_url cannot contain credentials, query, or fragment")
        return value

    @field_validator("upstream_allowed_hosts", "mcp_upstream_allowed_hosts")
    @classmethod
    def normalize_allowed_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip().lower() for value in values)
        if any(not value for value in normalized):
            raise ValueError("upstream_allowed_hosts cannot contain blank values")
        return normalized

    @field_validator("mcp_allowed_origins")
    @classmethod
    def normalize_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip().rstrip("/") for value in values)
        if any(not value for value in normalized):
            raise ValueError("mcp_allowed_origins cannot contain blank values")
        return normalized

    @model_validator(mode="after")
    def validate_upstream_host(self) -> Self:
        if self.upstream_base_url is None and self.mcp_upstream_url is None:
            raise ValueError("at least one LLM or MCP upstream must be configured")
        if self.upstream_base_url is not None:
            host = urlsplit(self.upstream_base_url).hostname
            if host is None:
                raise ValueError("upstream_base_url must contain a hostname")
            if self.upstream_allowed_hosts and host.lower() not in self.upstream_allowed_hosts:
                raise ValueError("upstream_base_url host is not in upstream_allowed_hosts")
            if self.upstream_auth_mode == "server_managed" and self.upstream_api_key is None:
                raise ValueError("upstream_api_key is required in server_managed mode")
        if self.mcp_upstream_url is not None:
            mcp_host = urlsplit(self.mcp_upstream_url).hostname
            if mcp_host is None:
                raise ValueError("mcp_upstream_url must contain a hostname")
            if (
                self.mcp_upstream_allowed_hosts
                and mcp_host.lower() not in self.mcp_upstream_allowed_hosts
            ):
                raise ValueError("mcp_upstream_url host is not in mcp_upstream_allowed_hosts")
            if (
                self.mcp_upstream_auth_mode == "server_managed"
                and self.mcp_upstream_api_key is None
            ):
                raise ValueError("mcp_upstream_api_key is required in MCP server_managed mode")
        return self

    @property
    def upstream_chat_completions_url(self) -> str:
        if self.upstream_base_url is None:
            raise RuntimeError("OpenAI upstream is not configured")
        return self.upstream_base_url + "chat/completions"

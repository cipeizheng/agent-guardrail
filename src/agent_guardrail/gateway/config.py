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

    decision_backend: Literal["embedded", "remote"] = "embedded"
    policy_file: Path | None = None
    core_url: str | None = None
    core_api_key: SecretStr | None = None
    core_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    core_max_request_bytes: int = Field(default=8_388_608, ge=1_024, le=67_108_864)
    core_max_response_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    upstream_base_url: str | None = None
    upstream_auth_mode: Literal["server_managed", "pass_through"] = "server_managed"
    upstream_api_key: SecretStr | None = None
    upstream_allowed_hosts: tuple[str, ...] = ()
    anthropic_upstream_base_url: str | None = None
    anthropic_upstream_api_key: SecretStr | None = None
    anthropic_upstream_allowed_hosts: tuple[str, ...] = ()
    gateway_api_keys: tuple[SecretStr, ...] = ()
    audit_path: Path | None = None
    max_request_bytes: int = Field(default=1_048_576, ge=1_024, le=16_777_216)
    max_upstream_response_bytes: int = Field(
        default=4_194_304,
        ge=1_024,
        le=67_108_864,
    )
    max_trace_events: int = Field(default=16, ge=2, le=1_000)
    task_sessions_required: bool = False
    task_session_max_sessions: int = Field(default=128, ge=1, le=10_000)
    task_session_ttl_seconds: float = Field(default=1_800.0, gt=0, le=86_400)
    task_session_max_trace_events: int = Field(default=256, ge=2, le=1_000)
    upstream_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    detector_profile: (
        Literal["local", "full_deberta", "full_promptguard2", "promptguard2"]
    ) = "local"
    prompt_model_device: Literal["cpu", "cuda"] = "cpu"
    detector_pii: Literal["none", "presidio"] | None = None
    detector_semgrep: Literal["none", "python_rules"] | None = None
    detector_yara: Literal["none", "injection_rules"] | None = None
    detector_prompt_model: (
        Literal["none", "deberta_v2", "promptguard2"] | None
    ) = None
    prompt_model_threshold: float | None = Field(default=None, gt=0, le=1)
    detector_assets_dir: Path | None = None
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

    @field_validator("upstream_base_url", "anthropic_upstream_base_url")
    @classmethod
    def validate_upstream_url(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("upstream_base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("upstream_base_url cannot contain credentials, query, or fragment")
        return value.rstrip("/") + "/"

    @field_validator("core_url")
    @classmethod
    def validate_core_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("core_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("core_url cannot contain credentials, query, or fragment")
        return value.rstrip("/")

    @field_validator("core_api_key")
    @classmethod
    def validate_core_api_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            secret = value.get_secret_value()
            if not secret or secret != secret.strip():
                raise ValueError("core_api_key must be non-blank and trimmed")
        return value

    @field_validator(
        "upstream_api_key",
        "anthropic_upstream_api_key",
        "mcp_upstream_api_key",
        mode="before",
    )
    @classmethod
    def normalize_optional_secret(cls, value: object) -> object:
        return None if value == "" else value

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

    @field_validator(
        "upstream_allowed_hosts",
        "anthropic_upstream_allowed_hosts",
        "mcp_upstream_allowed_hosts",
    )
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
        if self.decision_backend == "embedded":
            if self.policy_file is None:
                raise ValueError("policy_file is required for the embedded decision backend")
            if self.core_url is not None or self.core_api_key is not None:
                raise ValueError("Core settings require decision_backend=remote")
            self._validate_detector_component_settings()
        else:
            if self.core_url is None or self.core_api_key is None:
                raise ValueError("core_url and core_api_key are required for remote decisions")
            if self.policy_file is not None:
                raise ValueError("remote Gateway must not mount a policy_file")
            if (
                self.detector_profile != "local"
                or self.prompt_model_device != "cpu"
                or self.detector_assets_dir is not None
                or self.prompt_model_threshold is not None
                or any(
                    value is not None
                    for value in (
                        self.detector_pii,
                        self.detector_semgrep,
                        self.detector_yara,
                        self.detector_prompt_model,
                    )
                )
            ):
                raise ValueError("remote Gateway must not configure detector assets")
            core_credential = self.core_api_key.get_secret_value()
            other_credentials = [
                *(key.get_secret_value() for key in self.gateway_api_keys),
                *(
                    (self.upstream_api_key.get_secret_value(),)
                    if self.upstream_api_key is not None
                    else ()
                ),
                *(
                    (self.anthropic_upstream_api_key.get_secret_value(),)
                    if self.anthropic_upstream_api_key is not None
                    else ()
                ),
                *(
                    (self.mcp_upstream_api_key.get_secret_value(),)
                    if self.mcp_upstream_api_key is not None
                    else ()
                ),
            ]
            if core_credential in other_credentials:
                raise ValueError("core_api_key must be a dedicated service credential")
        if (
            self.upstream_base_url is None
            and self.anthropic_upstream_base_url is None
            and self.mcp_upstream_url is None
        ):
            raise ValueError("at least one LLM or MCP upstream must be configured")
        if self.upstream_base_url is not None:
            host = urlsplit(self.upstream_base_url).hostname
            if host is None:
                raise ValueError("upstream_base_url must contain a hostname")
            if self.upstream_allowed_hosts and host.lower() not in self.upstream_allowed_hosts:
                raise ValueError("upstream_base_url host is not in upstream_allowed_hosts")
            if self.upstream_auth_mode == "server_managed" and self.upstream_api_key is None:
                raise ValueError("upstream_api_key is required in server_managed mode")
        if self.anthropic_upstream_base_url is not None:
            anthropic_host = urlsplit(self.anthropic_upstream_base_url).hostname
            if anthropic_host is None:
                raise ValueError("anthropic_upstream_base_url must contain a hostname")
            if (
                self.anthropic_upstream_allowed_hosts
                and anthropic_host.lower() not in self.anthropic_upstream_allowed_hosts
            ):
                raise ValueError(
                    "anthropic_upstream_base_url host is not in "
                    "anthropic_upstream_allowed_hosts"
                )
            if self.anthropic_upstream_api_key is None:
                raise ValueError(
                    "anthropic_upstream_api_key is required when Anthropic is configured"
                )
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

    def _validate_detector_component_settings(self) -> None:
        components = (
            self.detector_pii,
            self.detector_semgrep,
            self.detector_yara,
            self.detector_prompt_model,
        )
        if self.detector_profile != "local":
            if any(value is not None for value in components):
                raise ValueError(
                    "detector component settings cannot be combined with a preset profile"
                )
            if self.detector_assets_dir is None:
                raise ValueError(
                    "detector_assets_dir is required for model deployment profiles"
                )
        elif any(value is not None for value in components):
            if self.detector_prompt_model is not None and self.detector_assets_dir is None:
                raise ValueError(
                    "detector_assets_dir is required for a model deployment component"
                )
        elif self.prompt_model_device != "cpu":
            raise ValueError(
                "prompt_model_device requires a model deployment profile or component"
            )

    @property
    def upstream_chat_completions_url(self) -> str:
        if self.upstream_base_url is None:
            raise RuntimeError("model upstream is not configured")
        return self.upstream_base_url + "chat/completions"

    @property
    def upstream_responses_url(self) -> str:
        if self.upstream_base_url is None:
            raise RuntimeError("model upstream is not configured")
        return self.upstream_base_url + "responses"

    @property
    def anthropic_messages_url(self) -> str:
        if self.anthropic_upstream_base_url is None:
            raise RuntimeError("Anthropic upstream is not configured")
        return self.anthropic_upstream_base_url + "v1/messages"

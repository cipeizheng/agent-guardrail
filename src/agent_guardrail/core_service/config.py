"""Validated environment configuration for the fixed-policy Core service."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CoreSettings(BaseSettings):
    """One centralized, closed set of Core process settings."""

    model_config = SettingsConfigDict(
        env_prefix="AGENT_GUARDRAIL_CORE_",
        case_sensitive=False,
        extra="ignore",
    )

    policy_file: Path
    api_key: SecretStr
    detector_profile: Literal["local", "full_local_v1"] = "local"
    prompt_model_device: Literal["cpu", "cuda"] = "cpu"
    detector_assets_dir: Path | None = None
    max_request_bytes: int = Field(default=8_388_608, ge=1_024, le=67_108_864)
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8090, ge=1, le=65_535)
    log_level: Literal["critical", "error", "warning", "info", "debug", "trace"] = (
        "info"
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if not secret or secret != secret.strip():
            raise ValueError("api_key must be non-blank and trimmed")
        return value

    @model_validator(mode="after")
    def validate_detector_profile(self) -> Self:
        if self.detector_profile == "local" and self.prompt_model_device != "cpu":
            raise ValueError("prompt_model_device requires detector_profile=full_local_v1")
        if self.detector_profile == "full_local_v1" and self.detector_assets_dir is None:
            raise ValueError("detector_assets_dir is required for full_local_v1")
        return self

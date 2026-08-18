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
    detector_profile: (
        Literal["local", "full_local_v1", "full_local_promptguard2", "promptguard2_only"]
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
        return self

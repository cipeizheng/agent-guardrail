from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from agent_guardrail.enforcement import JsonlAuditSink
from agent_guardrail.gateway import GatewaySettings
from tests.support import FAKE_SECRET, secret_engine, tool_context


def test_gateway_settings_reject_missing_server_key_and_non_allowlisted_host() -> None:
    with pytest.raises(ValidationError, match="upstream_api_key"):
        GatewaySettings(
            policy_file=Path("policy.yaml"),
            upstream_base_url="https://provider.example/v1",
        )

    with pytest.raises(ValidationError, match="not in upstream_allowed_hosts"):
        GatewaySettings(
            policy_file=Path("policy.yaml"),
            upstream_base_url="https://provider.example/v1",
            upstream_api_key=SecretStr("secret"),
            upstream_allowed_hosts=("different.example",),
        )


def test_gateway_settings_load_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_GUARDRAIL_POLICY_FILE", "policy.yaml")
    monkeypatch.setenv("AGENT_GUARDRAIL_UPSTREAM_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("AGENT_GUARDRAIL_UPSTREAM_API_KEY", "upstream-key")
    monkeypatch.setenv("AGENT_GUARDRAIL_GATEWAY_API_KEYS", '["client-key"]')

    settings = GatewaySettings()  # pyright: ignore[reportCallIssue]

    assert settings.upstream_chat_completions_url == (
        "https://provider.example/v1/chat/completions"
    )
    assert settings.gateway_api_keys[0].get_secret_value() == "client-key"


@pytest.mark.asyncio
async def test_jsonl_audit_contains_only_sanitized_decision_summary(tmp_path: Path) -> None:
    decision = await secret_engine().evaluate(tool_context(body=FAKE_SECRET))
    audit_path = tmp_path / "audit/decisions.jsonl"
    sink = JsonlAuditSink(audit_path)

    await sink.record(decision)

    content = audit_path.read_text(encoding="utf-8")
    record = json.loads(content)
    assert record["action"] == "block"
    assert record["rule_ids"] == ["prevent-secret-email"]
    assert FAKE_SECRET not in content

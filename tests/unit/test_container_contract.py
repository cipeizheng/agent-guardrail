from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def test_compose_has_exactly_core_and_gateway_with_separated_assets() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert set(services) == {"core", "gateway"}
    assert "ports" not in services["core"]
    assert services["gateway"]["ports"] == [
        "${AGENT_GUARDRAIL_GATEWAY_PORT:-8080}:8080"
    ]
    assert services["core"]["networks"] == ["guardrail_internal"]
    assert "gateway_egress" in services["gateway"]["networks"]

    core_environment = services["core"]["environment"]
    gateway_environment = services["gateway"]["environment"]
    assert "AGENT_GUARDRAIL_CORE_POLICY_FILE" in core_environment
    assert "AGENT_GUARDRAIL_UPSTREAM_API_KEY" not in core_environment
    assert "AGENT_GUARDRAIL_POLICY_FILE" not in gateway_environment
    assert "AGENT_GUARDRAIL_CORE_URL" in gateway_environment

    assert any("/config/policy.yaml:ro" in item for item in services["core"]["volumes"])
    assert all("policy" not in item.lower() for item in services["gateway"]["volumes"])


def test_container_images_are_non_root_health_checked_and_mit_licensed() -> None:
    for dockerfile_name in ("core.Dockerfile", "gateway.Dockerfile"):
        source = (ROOT / "docker" / dockerfile_name).read_text(encoding="utf-8")
        assert "USER guardrail" in source
        assert "HEALTHCHECK" in source
        assert 'org.opencontainers.image.licenses="MIT"' in source
        assert "/licenses/LICENSE" in source

    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")

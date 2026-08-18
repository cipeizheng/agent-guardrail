from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from agent_guardrail.config import (
    DetectorProfileError,
    create_deployment_detector_registry,
)
from agent_guardrail.config.deployment import (
    prefetch_full_local_assets,
    prefetch_promptguard2_assets,
)
from agent_guardrail.detectors import SemgrepCLIBackend, YaraPythonBackend
from agent_guardrail.detectors.semgrep import SemgrepSeverity


@dataclass(frozen=True, slots=True)
class _YaraInstance:
    offset: int
    matched_length: int


@dataclass(frozen=True, slots=True)
class _YaraString:
    instances: list[_YaraInstance]


@dataclass(frozen=True, slots=True)
class _YaraMatch:
    rule: str
    strings: list[_YaraString]


class _CompiledYara:
    def __init__(self, results: list[_YaraMatch]) -> None:
        self.results = results
        self.calls: list[tuple[bytes, int]] = []

    def match(self, *, data: bytes, timeout: int) -> list[_YaraMatch]:
        self.calls.append((data, timeout))
        return self.results


@pytest.mark.asyncio
async def test_yara_python_backend_normalizes_unicode_bytes_and_uses_native_timeout() -> None:
    text = "中文 OR 1=1"
    matched = "OR 1=1"
    start = len("中文 ".encode())
    compiled = _CompiledYara(
        [_YaraMatch("ag_sql_injection", [_YaraString([_YaraInstance(start, len(matched))])])]
    )
    backend = YaraPythonBackend(
        compiled,
        engine_version="4.5.4",
        ruleset_digest=sha256(b"fixed-rules").hexdigest(),
        native_timeout_seconds=1,
    )

    matches = await backend.match(text)

    assert compiled.calls == [(text.encode(), 1)]
    assert [(item.rule_id, item.start, item.end) for item in matches] == [
        ("ag_sql_injection", text.index(matched), len(text))
    ]


@pytest.mark.asyncio
async def test_yara_python_backend_rejects_non_character_aligned_native_span() -> None:
    compiled = _CompiledYara(
        [_YaraMatch("ag_sql_injection", [_YaraString([_YaraInstance(1, 1)])])]
    )
    backend = YaraPythonBackend(
        compiled,
        engine_version="4.5.4",
        ruleset_digest=sha256(b"fixed-rules").hexdigest(),
    )

    with pytest.raises(ValueError, match="non-character-aligned"):
        await backend.match("中")


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.mark.asyncio
async def test_semgrep_cli_backend_uses_bounded_private_files_and_normalizes_span(
    tmp_path: Path,
) -> None:
    source = "变量 = eval(user_input)"
    start = len("变量 = ".encode())
    end = start + len(b"eval")
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "agent-guardrail.python.dynamic-execution",
                    "start": {"offset": start},
                    "end": {"offset": end},
                    "extra": {"severity": "ERROR"},
                }
            ]
        }
    )
    executable = _write_executable(
        tmp_path / "semgrep",
        "#!/bin/sh\nprintf '%s' '" + payload + "'\n",
    )
    backend = SemgrepCLIBackend(
        executable=executable,
        rules_source="rules: []\n",
        engine_version="1.170.0",
        language="python",
    )

    findings = await backend.scan(source)

    assert len(findings) == 1
    assert findings[0].severity is SemgrepSeverity.ERROR
    assert source[findings[0].start : findings[0].end] == "eval"


@pytest.mark.asyncio
async def test_semgrep_cli_backend_kills_timed_out_process_group(tmp_path: Path) -> None:
    executable = _write_executable(
        tmp_path / "semgrep",
        "#!/bin/sh\nsleep 30\n",
    )
    backend = SemgrepCLIBackend(
        executable=executable,
        rules_source="rules: []\n",
        engine_version="1.170.0",
        language="python",
        process_timeout_seconds=0.1,
    )

    with pytest.raises(TimeoutError):
        await backend.scan("value = 1")


def test_local_profile_does_not_import_or_require_optional_backends() -> None:
    registry = create_deployment_detector_registry("local")

    assert registry.get("pii").name == "pii"
    with pytest.raises(DetectorProfileError, match="prompt model device"):
        create_deployment_detector_registry("local", prompt_model_device="cuda")


def test_local_profile_rejects_a_non_default_prompt_model_threshold() -> None:
    with pytest.raises(DetectorProfileError, match="prompt model threshold"):
        create_deployment_detector_registry("local", prompt_model_threshold=0.5)


@pytest.mark.parametrize("threshold", [0.0, -0.1, 1.5, 1])
def test_prompt_model_threshold_must_be_a_bounded_float(threshold: float) -> None:
    with pytest.raises(DetectorProfileError, match="float in \\(0, 1\\]"):
        create_deployment_detector_registry(
            "full_local_v1", prompt_model_threshold=threshold
        )


def test_full_profile_requires_explicit_deployment_assets_directory() -> None:
    with pytest.raises(DetectorProfileError, match="assets directory"):
        create_deployment_detector_registry("full_local_v1")


def test_asset_prefetch_requires_explicit_deployment_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR", raising=False)

    with pytest.raises(DetectorProfileError, match="ASSETS_DIR"):
        prefetch_full_local_assets()


def test_promptguard2_prefetch_requires_explicit_deployment_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_GUARDRAIL_DETECTOR_ASSETS_DIR", raising=False)

    with pytest.raises(DetectorProfileError, match="ASSETS_DIR"):
        prefetch_promptguard2_assets()


@pytest.mark.parametrize(
    "profile", ["full_local_v1", "full_local_promptguard2", "promptguard2_only"]
)
def test_model_profiles_fail_closed_without_pinned_assets(
    tmp_path: Path, profile: str
) -> None:
    with pytest.raises(DetectorProfileError):
        create_deployment_detector_registry(profile, detector_assets_dir=tmp_path)


def test_component_settings_cannot_be_combined_with_a_preset_profile() -> None:
    with pytest.raises(DetectorProfileError, match="cannot be combined with a preset"):
        create_deployment_detector_registry(
            "full_local_v1", detector_assets_dir=Path("/tmp/assets"), pii="presidio"
        )


def test_unknown_component_setting_fails_closed() -> None:
    with pytest.raises(DetectorProfileError, match="unknown Detector component"):
        create_deployment_detector_registry("local", pii="some_other_pii_backend")


def test_local_preset_with_no_components_keeps_the_default_stack() -> None:
    registry = create_deployment_detector_registry("local")

    published = {
        descriptor.name
        for descriptor in registry.published_detector_descriptors()
    }
    assert not {"prompt_injection_model", "semgrep", "yara_injection_signatures"}.intersection(
        published
    )


def test_prompt_model_component_requires_explicit_assets_directory() -> None:
    with pytest.raises(DetectorProfileError, match="assets directory"):
        create_deployment_detector_registry("local", prompt_model="promptguard2")


def test_promptguard2_only_profile_requires_explicit_assets_directory() -> None:
    with pytest.raises(DetectorProfileError, match="assets directory"):
        create_deployment_detector_registry("promptguard2_only")


@pytest.mark.parametrize("threshold", [0.0, -0.1, 1.5, 1])
def test_promptguard2_threshold_must_be_a_bounded_float(threshold: float) -> None:
    with pytest.raises(DetectorProfileError, match=r"float in \(0, 1\]"):
        create_deployment_detector_registry(
            "promptguard2_only", prompt_model_threshold=threshold
        )


def test_semgrep_backend_requires_an_absolute_resolved_executable(tmp_path: Path) -> None:
    missing = tmp_path / "missing-semgrep"

    with pytest.raises(FileNotFoundError):
        SemgrepCLIBackend(
            executable=missing,
            rules_source="rules: []\n",
            engine_version="1.170.0",
            language="python",
        )
    assert not os.path.exists(missing)

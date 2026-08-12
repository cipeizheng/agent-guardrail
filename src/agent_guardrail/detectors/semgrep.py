"""Deployment-fixed Semgrep adapter with bounded, redacted findings."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable

from agent_guardrail.models import Detection, DetectionContext

SEMGREP_TYPES = frozenset({"semgrep_error", "semgrep_info", "semgrep_warning"})
MAX_SEMGREP_INPUT_BYTES = 16_384
MAX_SEMGREP_RULE_BYTES = 65_536
MAX_SEMGREP_STDOUT_BYTES = 1_048_576
MAX_SEMGREP_STDERR_BYTES = 65_536


class SemgrepSeverity(StrEnum):
    """Closed Semgrep severities exposed as stable detection types."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class SemgrepFinding:
    """One backend-normalized finding without source text or filesystem paths.

    ``start`` and ``end`` are zero-based Python character offsets into the exact
    input string, never UTF-8 byte offsets or line/column coordinates. A real
    backend adapter must normalize its native locations before constructing this
    value.
    """

    rule_id: str
    severity: SemgrepSeverity
    start: int | None = None
    end: int | None = None
    confidence: float = 0.95

    def __post_init__(self) -> None:
        _validate_rule_id(self.rule_id)
        if not isinstance(self.severity, SemgrepSeverity):
            raise TypeError("Semgrep finding severity must be SemgrepSeverity")
        _validate_span(self.start, self.end)
        if type(self.confidence) is not float or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Semgrep finding confidence must be a float in [0, 1]")


@dataclass(frozen=True, slots=True)
class SemgrepProfile:
    """Deployment-owned identity and allowlist for one pinned Semgrep ruleset."""

    profile_id: str
    profile_version: str
    language: str
    allowed_rule_ids: frozenset[str]
    max_findings: int = 64

    def __post_init__(self) -> None:
        _validate_identity(self.profile_id, "Semgrep profile id")
        _validate_identity(self.profile_version, "Semgrep profile version")
        _validate_identity(self.language, "Semgrep language")
        if not isinstance(self.allowed_rule_ids, frozenset) or not self.allowed_rule_ids:
            raise ValueError("Semgrep profile must pin at least one rule id")
        for rule_id in self.allowed_rule_ids:
            _validate_rule_id(rule_id)
        if (
            isinstance(self.max_findings, bool)
            or not isinstance(self.max_findings, int)
            or not 1 <= self.max_findings <= 64
        ):
            raise ValueError("Semgrep max_findings must be an integer in [1, 64]")


@runtime_checkable
class SemgrepBackend(Protocol):
    """A deployment-owned scanner already pinned to an isolated ruleset."""

    name: str
    version: str

    async def scan(self, text: str) -> list[SemgrepFinding] | tuple[SemgrepFinding, ...]: ...


class SemgrepCLIBackend:
    """Run one fixed Semgrep ruleset in a bounded temporary subprocess.

    The executable, language, and rule source are deployment inputs. Scan text
    is written only to a private temporary directory, stdout/stderr are bounded,
    metrics and version checks are disabled, and cancellation kills the process
    group. No path, command option, or rule source comes from Policy.
    """

    name = "semgrep-cli"

    def __init__(
        self,
        *,
        executable: Path,
        rules_source: str,
        engine_version: str,
        language: str,
        max_findings: int = 64,
        process_timeout_seconds: float = 4.0,
    ) -> None:
        if not isinstance(executable, Path):
            raise TypeError("Semgrep executable must be a Path")
        resolved_executable = executable.resolve(strict=True)
        if not resolved_executable.is_file() or not os.access(resolved_executable, os.X_OK):
            raise ValueError("Semgrep executable is not executable")
        if not isinstance(rules_source, str) or not rules_source.strip():
            raise ValueError("Semgrep rules source must not be empty")
        rules_bytes = rules_source.encode("utf-8")
        if len(rules_bytes) > MAX_SEMGREP_RULE_BYTES:
            raise ValueError("Semgrep rules source exceeds its hard byte bound")
        _validate_identity(engine_version, "Semgrep engine version")
        _validate_identity(language, "Semgrep language")
        if language != "python":
            raise ValueError("this Semgrep backend profile supports only Python")
        if (
            isinstance(max_findings, bool)
            or not isinstance(max_findings, int)
            or not 1 <= max_findings <= 64
        ):
            raise ValueError("Semgrep max findings must be an integer in [1, 64]")
        if (
            isinstance(process_timeout_seconds, bool)
            or not isinstance(process_timeout_seconds, float)
            or not 0.1 <= process_timeout_seconds <= 30.0
        ):
            raise ValueError("Semgrep process timeout must be a float in [0.1, 30]")

        rules_digest = sha256(rules_bytes).hexdigest()[:12]
        self.version = f"{engine_version}+rules.{rules_digest}"
        self._executable = resolved_executable
        self._rules_source = rules_source
        self._language = language
        self._max_findings = max_findings
        self._process_timeout_seconds = process_timeout_seconds

    async def scan(self, text: str) -> list[SemgrepFinding]:
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_SEMGREP_INPUT_BYTES:
            raise ValueError("Semgrep input exceeds its hard byte bound")

        with tempfile.TemporaryDirectory(prefix="agent-guardrail-semgrep-") as directory:
            working_directory = Path(directory)
            rules_path = working_directory / "rules.yaml"
            target_path = working_directory / "input.py"
            rules_path.write_text(self._rules_source, encoding="utf-8")
            target_path.write_text(text, encoding="utf-8")
            process = await asyncio.create_subprocess_exec(
                str(self._executable),
                "scan",
                "--config",
                str(rules_path),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--quiet",
                "--jobs=1",
                "--max-target-bytes=16384",
                "--timeout=1",
                "--timeout-threshold=1",
                target_path.name,
                cwd=working_directory,
                env=_semgrep_environment(working_directory, self._executable.parent),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout_task = asyncio.create_task(
                _read_bounded(process.stdout, MAX_SEMGREP_STDOUT_BYTES)
            )
            stderr_task = asyncio.create_task(
                _read_bounded(process.stderr, MAX_SEMGREP_STDERR_BYTES)
            )
            wait_task = asyncio.create_task(process.wait())
            try:
                async with asyncio.timeout(self._process_timeout_seconds):
                    stdout, _stderr, return_code = await asyncio.gather(
                        stdout_task,
                        stderr_task,
                        wait_task,
                    )
            except BaseException:
                await _kill_process_group(process)
                stdout_task.cancel()
                stderr_task.cancel()
                wait_task.cancel()
                await asyncio.gather(
                    stdout_task,
                    stderr_task,
                    wait_task,
                    return_exceptions=True,
                )
                raise
            if return_code != 0:
                raise RuntimeError("Semgrep scan failed")
        return _parse_semgrep_output(
            stdout,
            text=text,
            max_findings=self._max_findings,
        )


class SemgrepDetector:
    """Convert a fixed Semgrep backend profile into safe detector facts.

    This class never selects a process, executable, working directory, language,
    file, or rule configuration. Those choices belong to the injected backend
    and profile, which structured Policy cannot access.
    """

    name = "semgrep"
    adapter_version = "1"

    def __init__(self, backend: SemgrepBackend, *, profile: SemgrepProfile) -> None:
        if not isinstance(backend, SemgrepBackend):
            raise TypeError("backend must implement SemgrepBackend")
        _validate_identity(backend.name, "Semgrep backend name")
        _validate_identity(backend.version, "Semgrep backend version")
        if not isinstance(profile, SemgrepProfile):
            raise TypeError("profile must be SemgrepProfile")
        self._backend = backend
        self._profile = profile
        identity_material = json.dumps(
            (
                backend.name,
                backend.version,
                profile.profile_id,
                profile.profile_version,
                profile.language,
                sorted(profile.allowed_rule_ids),
                profile.max_findings,
            ),
            ensure_ascii=True,
            separators=(",", ":"),
        )
        identity = sha256(identity_material.encode("utf-8")).hexdigest()[:12]
        self.version = f"{self.adapter_version}-{identity}"

    @property
    def profile(self) -> SemgrepProfile:
        """Return the immutable deployment profile for registry construction."""

        return self._profile

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        raw = await self._backend.scan(text)
        if type(raw) not in (list, tuple):
            raise TypeError("Semgrep backend must return a list or tuple")
        if len(raw) > self._profile.max_findings:
            raise ValueError("Semgrep backend result limit exceeded")

        findings: dict[tuple[str, SemgrepSeverity, int | None, int | None], SemgrepFinding] = {}
        for finding in raw:
            if not isinstance(finding, SemgrepFinding):
                raise TypeError("Semgrep backend returned an invalid finding")
            if finding.rule_id not in self._profile.allowed_rule_ids:
                raise ValueError("Semgrep backend returned an unpinned rule id")
            if finding.end is not None and finding.end > len(text):
                raise ValueError("Semgrep backend returned an out-of-range span")
            key = (finding.rule_id, finding.severity, finding.start, finding.end)
            previous = findings.get(key)
            if previous is None or finding.confidence > previous.confidence:
                findings[key] = finding

        ordered = sorted(
            findings.values(),
            key=lambda item: (
                item.start if item.start is not None else len(text) + 1,
                item.end if item.end is not None else len(text) + 1,
                item.severity.value,
                item.rule_id,
            ),
        )
        return [self._to_detection(item, context=context) for item in ordered]

    def _to_detection(
        self,
        finding: SemgrepFinding,
        *,
        context: DetectionContext,
    ) -> Detection:
        detection_type = f"semgrep_{finding.severity.value}"
        fingerprint = _finding_fingerprint(
            detector=self.name,
            detector_version=self.version,
            backend_name=self._backend.name,
            backend_version=self._backend.version,
            profile_id=self._profile.profile_id,
            profile_version=self._profile.profile_version,
            item_id=finding.rule_id,
            detection_type=detection_type,
            start=finding.start,
            end=finding.end,
            context=context,
        )
        return Detection(
            type=detection_type,
            detector=self.name,
            detector_version=self.version,
            confidence=finding.confidence,
            start=finding.start,
            end=finding.end,
            masked_evidence=f"<{self.name}:{detection_type}:{fingerprint}>",
            fingerprint=fingerprint,
        )


def _finding_fingerprint(
    *,
    detector: str,
    detector_version: str,
    backend_name: str,
    backend_version: str,
    profile_id: str,
    profile_version: str,
    item_id: str,
    detection_type: str,
    start: int | None,
    end: int | None,
    context: DetectionContext,
) -> str:
    material = json.dumps(
        (
            detector,
            detector_version,
            backend_name,
            backend_version,
            profile_id,
            profile_version,
            item_id,
            context.trace_id,
            context.event_id,
            context.phase.value,
            detection_type,
            start,
            end,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return sha256(material.encode("utf-8")).hexdigest()[:16]


def _validate_identity(value: str, subject: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(character in value for character in ("/", "\\", "\x00", "\r", "\n"))
    ):
        raise ValueError(f"{subject} is invalid")


def _validate_rule_id(rule_id: str) -> None:
    if (
        not isinstance(rule_id, str)
        or not rule_id
        or len(rule_id) > 256
        or rule_id != rule_id.strip()
        or any(character in rule_id for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError("Semgrep rule id is invalid")


def _validate_span(start: int | None, end: int | None) -> None:
    if (start is None) != (end is None):
        raise ValueError("Semgrep finding span must be complete")
    if start is not None and (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 0
        or end <= start
    ):
        raise ValueError("Semgrep finding span is invalid")


async def _read_bounded(
    stream: asyncio.StreamReader | None,
    maximum_bytes: int,
) -> bytes:
    if stream is None:
        raise RuntimeError("Semgrep subprocess pipe is unavailable")
    chunks: list[bytes] = []
    total = 0
    while chunk := await stream.read(65_536):
        total += len(chunk)
        if total > maximum_bytes:
            raise ValueError("Semgrep subprocess output exceeds its hard byte bound")
        chunks.append(chunk)
    return b"".join(chunks)


async def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await asyncio.shield(process.wait())


def _semgrep_environment(working_directory: Path, executable_directory: Path) -> dict[str, str]:
    return {
        "HOME": str(working_directory),
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join((str(executable_directory), os.defpath)),
        "PYTHONIOENCODING": "utf-8",
        "SEMGREP_SEND_METRICS": "off",
        "XDG_CACHE_HOME": str(working_directory / "cache"),
    }


def _parse_semgrep_output(
    raw: bytes,
    *,
    text: str,
    max_findings: int,
) -> list[SemgrepFinding]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Semgrep returned invalid JSON") from exc
    if type(payload) is not dict or type(payload.get("results")) is not list:
        raise TypeError("Semgrep returned an invalid result envelope")
    results = payload["results"]
    if len(results) > max_findings:
        raise ValueError("Semgrep backend result limit exceeded")

    findings: list[SemgrepFinding] = []
    encoded = text.encode("utf-8")
    for item in results:
        if type(item) is not dict:
            raise TypeError("Semgrep returned an invalid finding")
        rule_id = item.get("check_id")
        extras = item.get("extra")
        if not isinstance(rule_id, str) or type(extras) is not dict:
            raise TypeError("Semgrep returned an invalid finding")
        severity = _parse_semgrep_severity(extras.get("severity"))
        span = _semgrep_character_span(item, encoded=encoded)
        findings.append(
            SemgrepFinding(
                rule_id=rule_id,
                severity=severity,
                start=span[0] if span is not None else None,
                end=span[1] if span is not None else None,
                confidence={
                    SemgrepSeverity.ERROR: 0.99,
                    SemgrepSeverity.WARNING: 0.95,
                    SemgrepSeverity.INFO: 0.90,
                }[severity],
            )
        )
    return findings


def _parse_semgrep_severity(value: object) -> SemgrepSeverity:
    if not isinstance(value, str):
        raise TypeError("Semgrep returned an invalid severity")
    try:
        return SemgrepSeverity(value.lower())
    except ValueError as exc:
        raise ValueError("Semgrep returned an unsupported severity") from exc


def _semgrep_character_span(
    item: dict[object, object],
    *,
    encoded: bytes,
) -> tuple[int, int] | None:
    start_value = item.get("start")
    end_value = item.get("end")
    if type(start_value) is not dict or type(end_value) is not dict:
        return None
    start_offset = start_value.get("offset")
    end_offset = end_value.get("offset")
    if (
        isinstance(start_offset, bool)
        or isinstance(end_offset, bool)
        or not isinstance(start_offset, int)
        or not isinstance(end_offset, int)
        or start_offset < 0
        or end_offset <= start_offset
        or end_offset > len(encoded)
    ):
        raise ValueError("Semgrep returned an invalid byte span")
    try:
        start = len(encoded[:start_offset].decode("utf-8"))
        end = len(encoded[:end_offset].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("Semgrep returned a non-character-aligned byte span") from exc
    return start, end

"""High-signal, deterministic dangerous shell-command heuristics."""

from __future__ import annotations

import re

from agent_guardrail.detectors._patterns import DetectionPattern, detect_patterns
from agent_guardrail.models import Detection, DetectionContext

_FLAGS = re.IGNORECASE

DANGEROUS_COMMAND_PATTERNS: tuple[DetectionPattern, ...] = (
    DetectionPattern(
        type="destructive_filesystem",
        regex=re.compile(
            r"(?<![\w.-])rm\s+"
            r"(?=[^;\n|&]{0,96}(?:-[a-z]*r[a-z]*|--recursive)\b)"
            r"(?=[^;\n|&]{0,96}(?:-[a-z]*f[a-z]*|--force)\b)"
            r"[^;\n|&]{1,160}",
            _FLAGS,
        ),
        confidence=0.97,
        priority=20,
    ),
    DetectionPattern(
        type="disk_overwrite",
        regex=re.compile(
            r"\bdd\b(?=[^;\n|&]{0,160}\bof=/dev/(?:sd|hd|vd|nvme|mapper/)\S+)"
            r"[^;\n|&]{1,200}",
            _FLAGS,
        ),
        confidence=0.99,
        priority=30,
    ),
    DetectionPattern(
        type="disk_overwrite",
        regex=re.compile(
            r"\bmkfs(?:\.[a-z0-9]+)?\s+(?:-[^\s]+\s+)*/dev/\S+",
            _FLAGS,
        ),
        confidence=0.99,
        priority=30,
    ),
    DetectionPattern(
        type="download_execute",
        regex=re.compile(
            r"\b(?:curl|wget)\b[^;\n|]{0,240}\|\s*(?:sudo\s+)?"
            r"(?:sh|bash|zsh|dash|python(?:3)?|perl|ruby)\b",
            _FLAGS,
        ),
        confidence=0.96,
        priority=20,
    ),
    DetectionPattern(
        type="download_execute",
        regex=re.compile(
            r"\bpowershell(?:\.exe)?\b[^;\n]{0,240}"
            r"\b(?:iex|invoke-expression)\b[^;\n]{0,240}"
            r"\b(?:downloadstring|downloadfile|https?://)",
            _FLAGS,
        ),
        confidence=0.95,
        priority=20,
    ),
    DetectionPattern(
        type="reverse_shell",
        regex=re.compile(
            r"\b(?:bash|sh)\s+-[a-z]*i\b[^;\n]{0,160}/dev/tcp/",
            _FLAGS,
        ),
        confidence=0.99,
        priority=30,
    ),
    DetectionPattern(
        type="reverse_shell",
        regex=re.compile(
            r"\b(?:nc|ncat|netcat)\b[^;\n]{0,160}\s-e\s+"
            r"(?:/bin/)?(?:sh|bash)\b",
            _FLAGS,
        ),
        confidence=0.99,
        priority=30,
    ),
    DetectionPattern(
        type="obfuscated_execution",
        regex=re.compile(
            r"\bbase64\s+(?:--decode|-d)\b[^;\n|]{0,160}\|\s*"
            r"(?:sh|bash|zsh|dash|python(?:3)?)\b",
            _FLAGS,
        ),
        confidence=0.94,
        priority=10,
    ),
    DetectionPattern(
        type="obfuscated_execution",
        regex=re.compile(
            r"\bpowershell(?:\.exe)?\b[^;\n]{0,160}"
            r"-(?:enc|encodedcommand)\s+[a-z0-9+/=]{16,}",
            _FLAGS,
        ),
        confidence=0.94,
        priority=10,
    ),
)


class DangerousCommandDetector:
    """Detect reviewed destructive and shell-execution shapes."""

    name = "dangerous_command"
    version = "1"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        return detect_patterns(
            text,
            context=context,
            detector=self.name,
            detector_version=self.version,
            patterns=DANGEROUS_COMMAND_PATTERNS,
        )

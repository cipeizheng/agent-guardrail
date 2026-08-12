"""High-signal deterministic jailbreak heuristics."""

from __future__ import annotations

import re

from agent_guardrail.detectors._patterns import DetectionPattern, detect_patterns
from agent_guardrail.models import Detection, DetectionContext

_FLAGS = re.IGNORECASE | re.DOTALL

JAILBREAK_PATTERNS: tuple[DetectionPattern, ...] = (
    DetectionPattern(
        type="jailbreak_persona",
        regex=re.compile(
            r"\b(?:DAN|(?i:do\s+anything\s+now))\b.{0,96}"
            r"\b(?i:jailbreak|unrestricted|uncensored|no\s+(?:rules|restrictions)|"
            r"anything\s+now)\b",
            re.DOTALL,
        ),
        confidence=0.95,
        priority=20,
    ),
    DetectionPattern(
        type="jailbreak_persona",
        regex=re.compile(
            r"(?:进入|启用|扮演).{0,20}(?:DAN|越狱|开发者模式).{0,40}"
            r"(?:不受限制|无审查|没有规则|任何事情)",
            _FLAGS,
        ),
        confidence=0.95,
        priority=20,
    ),
    DetectionPattern(
        type="developer_mode_jailbreak",
        regex=re.compile(
            r"\b(?:enable|activate|enter|simulate)\b.{0,40}"
            r"\bdeveloper\s+mode\b.{0,96}"
            r"(?:\b(?:bypass|disable|ignore)\b.{0,32}"
            r"\b(?:safety|rules|restrictions|polic(?:y|ies)|guardrails?)\b|"
            r"\b(?:unfiltered|uncensored|without\s+restrictions)\b)",
            _FLAGS,
        ),
        confidence=0.93,
        priority=15,
    ),
    DetectionPattern(
        type="safety_bypass",
        regex=re.compile(
            r"\b(?:bypass|circumvent|disable|evade|remove)\b.{0,48}"
            r"\b(?:safety|security|content|ethical|alignment)\b.{0,32}"
            r"\b(?:filters?|guardrails?|polic(?:y|ies)|restrictions?|constraints?)\b",
            _FLAGS,
        ),
        confidence=0.94,
        priority=20,
    ),
    DetectionPattern(
        type="safety_bypass",
        regex=re.compile(
            r"(?:绕过|禁用|关闭|规避|移除).{0,24}"
            r"(?:安全|内容|道德|对齐).{0,16}(?:过滤|护栏|策略|限制|约束)",
            _FLAGS,
        ),
        confidence=0.94,
        priority=20,
    ),
    DetectionPattern(
        type="dual_response_jailbreak",
        regex=re.compile(
            r"(?:\[\s*(?:🔒\s*)?CLASSIC\s*\].{0,160}"
            r"\[\s*(?:🔓\s*)?JAILBREAK\s*\]|"
            r"\b(?:two|2)\s+(?:answers|responses)\b.{0,80}"
            r"\b(?:normal|safe|filtered)\b.{0,64}"
            r"\b(?:DAN|jailbreak|unfiltered|uncensored)\b)",
            _FLAGS,
        ),
        confidence=0.97,
        priority=30,
    ),
    DetectionPattern(
        type="refusal_suppression",
        regex=re.compile(
            r"\b(?:never|do\s+not|don['’]t)\b.{0,32}"
            r"\b(?:refuse|decline|warn|apologize)\b.{0,64}"
            r"(?:\b(?:any|all|my|the\s+user['’]?s?)\s+"
            r"(?:requests?|instructions?)\b|\banswer\s+everything\b)",
            _FLAGS,
        ),
        confidence=0.88,
    ),
)


class JailbreakDetector:
    """Detect explicit attempts to disable model safety or refusal behavior."""

    name = "jailbreak"
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
            patterns=JAILBREAK_PATTERNS,
        )

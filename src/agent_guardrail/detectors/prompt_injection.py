"""High-signal, deterministic prompt-injection heuristics."""

from __future__ import annotations

import re

from agent_guardrail.detectors._patterns import DetectionPattern, detect_patterns
from agent_guardrail.models import Detection, DetectionContext

_FLAGS = re.IGNORECASE | re.DOTALL

PROMPT_INJECTION_PATTERNS: tuple[DetectionPattern, ...] = (
    DetectionPattern(
        type="instruction_override",
        regex=re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,80}"
            r"\b(?:previous|prior|above|earlier|system|developer)\b.{0,40}"
            r"\b(?:instructions?|prompts?|rules?|messages?)\b",
            _FLAGS,
        ),
        confidence=0.93,
        priority=20,
    ),
    DetectionPattern(
        type="instruction_override",
        regex=re.compile(
            r"(?:忽略|无视|忘记|覆盖|绕过).{0,24}"
            r"(?:之前|先前|以上|上面|系统|开发者).{0,16}"
            r"(?:指令|提示词?|规则|消息)",
            _FLAGS,
        ),
        confidence=0.93,
        priority=20,
    ),
    DetectionPattern(
        type="system_prompt_exfiltration",
        regex=re.compile(
            r"\b(?:reveal|show|print|repeat|dump|expose|leak)\b.{0,64}"
            r"\b(?:system|developer)\s+(?:prompt|message|instructions?)\b",
            _FLAGS,
        ),
        confidence=0.91,
        priority=10,
    ),
    DetectionPattern(
        type="system_prompt_exfiltration",
        regex=re.compile(
            r"(?:显示|泄露|输出|重复|打印).{0,24}"
            r"(?:系统|开发者).{0,16}(?:提示词?|指令|消息)",
            _FLAGS,
        ),
        confidence=0.91,
        priority=10,
    ),
    DetectionPattern(
        type="role_override",
        regex=re.compile(
            r"\b(?:you are now|from now on you are|act as|pretend to be)\b.{0,32}"
            r"\b(?:unrestricted|uncensored|developer|system|root|dan)\b",
            _FLAGS,
        ),
        confidence=0.86,
    ),
    DetectionPattern(
        type="role_override",
        regex=re.compile(
            r"(?:现在起|从现在开始|假装|扮演).{0,20}"
            r"(?:不受限制|无审查|开发者|系统|root|DAN)",
            _FLAGS,
        ),
        confidence=0.86,
    ),
    DetectionPattern(
        type="control_token_injection",
        regex=re.compile(
            r"<\|(?:im_start|start_header_id)\|>\s*(?:system|developer)\b",
            _FLAGS,
        ),
        confidence=0.98,
        priority=30,
    ),
)


class PromptInjectionDetector:
    """Detect reviewed prompt-override shapes; this is not a semantic classifier."""

    name = "prompt_injection"
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
            patterns=PROMPT_INJECTION_PATTERNS,
        )

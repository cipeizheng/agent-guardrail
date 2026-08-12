"""Local detection of hidden HTML and bounded encoded textual content."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

MAX_HIDDEN_CONTENT_DETECTIONS = 64
MAX_ENCODED_CHARACTERS = 4_096

HIDDEN_CONTENT_TYPES = frozenset(
    {
        "base64_encoded_content",
        "encoded_content_oversized",
        "html_alt_text",
        "html_comment",
        "html_entity_encoded_content",
        "html_hidden_element",
        "html_invisible_style",
        "html_metadata_content",
        "percent_encoded_content",
    }
)

_BASE64_RUN = re.compile(
    r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{24,}={0,2}(?![A-Za-z0-9_+/=-])"
)
_PERCENT_RUN = re.compile(r"(?:(?:%[0-9A-Fa-f]{2})){8,}")
_HTML_ENTITY_RUN = re.compile(
    r"(?:(?:&#(?:[xX][0-9A-Fa-f]{1,6}|[0-9]{1,7});)[ \t]*){8,}"
)
_HTML_NUMERIC_ENTITY = re.compile(
    r"&#(?:(?P<hex>[xX][0-9A-Fa-f]{1,6})|(?P<decimal>[0-9]{1,7}));"
)
_INVISIBLE_STYLE = re.compile(
    r"(?:"
    r"display\s*:\s*none\b|"
    r"visibility\s*:\s*(?:hidden|collapse)\b|"
    r"opacity\s*:\s*(?:0(?:\.0+)?)(?=\s*(?:[;!}]|$))|"
    r"font-size\s*:\s*0(?:px|pt|em|rem|%)?(?=\s*(?:[;!}]|$))|"
    r"color\s*:\s*transparent\b|"
    r"clip(?:-path)?\s*:\s*(?:rect\s*\(|inset\s*\(\s*100%)|"
    r"text-indent\s*:\s*-\d{3,}(?:px|em|rem)\b|"
    r"(?:left|top)\s*:\s*-\d{3,}(?:px|em|rem)\b"
    r")",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    type: str
    confidence: float
    priority: int = 0


class HiddenContentDetector:
    """Report content concealed from ordinary rendered text.

    Decoding is local, single-pass, and capped. Oversized Base64 candidates are
    validated structurally without decoding. Decoded bytes are used only to
    decide whether a bounded candidate is textual; neither encoded nor decoded
    payloads are retained in evidence.
    """

    name = "hidden_content"
    version = "2"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        parser = _HiddenHTMLParser(text)
        parser.feed(text)
        parser.close()
        candidates = [*parser.candidates, *_encoded_candidates(text)]
        return _detections_from_candidates(text, candidates, context=context)


class _HiddenHTMLParser(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=False)
        self._text = text
        self._line_starts = _line_starts(text)
        self._style_depth = 0
        self.candidates: list[_Candidate] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._handle_tag(tag, attrs)
        if tag.lower() == "style":
            self._style_depth += 1

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self._handle_tag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "style" and self._style_depth:
            self._style_depth -= 1

    def handle_comment(self, data: str) -> None:
        if not data.strip():
            return
        start = self._position()
        terminator = self._text.find("-->", start + 4)
        end = terminator + 3 if terminator >= 0 else min(len(self._text), start + len(data) + 4)
        if end > start:
            self.candidates.append(_Candidate(start, end, "html_comment", 0.93, 20))

    def handle_data(self, data: str) -> None:
        if not self._style_depth:
            return
        absolute = self._position()
        for match in _INVISIBLE_STYLE.finditer(data):
            self.candidates.append(
                _Candidate(
                    absolute + match.start(),
                    absolute + match.end(),
                    "html_invisible_style",
                    0.98,
                    40,
                )
            )

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        raw = self.get_starttag_text() or ""
        start = self._position()
        end = min(len(self._text), start + len(raw))
        if not raw or end <= start:
            return

        normalized_tag = tag.lower()
        normalized_attrs: dict[str, list[str | None]] = {}
        for name, value in attrs:
            normalized_attrs.setdefault(name.lower(), []).append(value)
        alt_index = _first_text_index(normalized_attrs.get("alt", []))
        if normalized_tag in {"area", "img"} and alt_index is not None:
            attr_start, attr_end = _attribute_span(
                raw,
                "alt",
                start,
                occurrence=alt_index,
            )
            self.candidates.append(
                _Candidate(attr_start, attr_end, "html_alt_text", 0.95, 30)
            )

        content_index = _first_text_index(normalized_attrs.get("content", []))
        if normalized_tag == "meta" and content_index is not None:
            attr_start, attr_end = _attribute_span(
                raw,
                "content",
                start,
                occurrence=content_index,
            )
            self.candidates.append(
                _Candidate(attr_start, attr_end, "html_metadata_content", 0.88, 10)
            )

        is_hidden = (
            "hidden" in normalized_attrs
            or normalized_tag in {"noscript", "template"}
            or (
                normalized_tag == "input"
                and _any_equals(normalized_attrs.get("type", []), "hidden")
            )
            or _any_in(normalized_attrs.get("aria-hidden", []), {"1", "true"})
        )
        if is_hidden:
            self.candidates.append(_Candidate(start, end, "html_hidden_element", 0.97, 40))

        styles = normalized_attrs.get("style", [])
        if any(
            isinstance(style, str) and _INVISIBLE_STYLE.search(style) is not None
            for style in styles
        ):
            self.candidates.append(
                _Candidate(start, end, "html_invisible_style", 0.98, 50)
            )

    def _position(self) -> int:
        line, column = self.getpos()
        line_index = min(max(line - 1, 0), len(self._line_starts) - 1)
        return min(len(self._text), self._line_starts[line_index] + column)


def _encoded_candidates(text: str) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for match in _BASE64_RUN.finditer(text):
        encoded = match.group(0)
        if len(encoded) > MAX_ENCODED_CHARACTERS:
            if _base64_has_valid_structure(encoded):
                candidates.append(
                    _Candidate(
                        match.start(),
                        match.end(),
                        "encoded_content_oversized",
                        0.90,
                        50,
                    )
                )
            continue
        if not _decoded_base64_is_text(encoded):
            continue
        candidates.append(
            _Candidate(match.start(), match.end(), "base64_encoded_content", 0.91, 20)
        )

    for match in _PERCENT_RUN.finditer(text):
        encoded = match.group(0)
        if len(encoded) > MAX_ENCODED_CHARACTERS:
            candidates.append(
                _Candidate(match.start(), match.end(), "encoded_content_oversized", 0.90, 50)
            )
            continue
        decoded = bytes(
            int(encoded[index + 1 : index + 3], 16)
            for index in range(0, len(encoded), 3)
        )
        if _decoded_bytes_are_text(decoded):
            candidates.append(
                _Candidate(match.start(), match.end(), "percent_encoded_content", 0.91, 20)
            )

    for match in _HTML_ENTITY_RUN.finditer(text):
        encoded = match.group(0)
        if len(encoded) > MAX_ENCODED_CHARACTERS:
            candidates.append(
                _Candidate(match.start(), match.end(), "encoded_content_oversized", 0.90, 50)
            )
            continue
        decoded = _decode_numeric_entities(encoded)
        if decoded is None:
            continue
        if _decoded_bytes_are_text(decoded):
            candidates.append(
                _Candidate(
                    match.start(),
                    match.end(),
                    "html_entity_encoded_content",
                    0.91,
                    20,
                )
            )
    return candidates


def _decoded_base64_is_text(encoded: str) -> bool:
    if not _base64_has_valid_structure(encoded):
        return False
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    return _decoded_bytes_are_text(decoded)


def _decode_numeric_entities(encoded: str) -> bytes | None:
    characters: list[str] = []
    try:
        for match in _HTML_NUMERIC_ENTITY.finditer(encoded):
            hexadecimal = match.group("hex")
            codepoint = (
                int(hexadecimal[1:], 16)
                if hexadecimal is not None
                else int(match.group("decimal"), 10)
            )
            characters.append(chr(codepoint))
        return "".join(characters).encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        return None


def _base64_has_valid_structure(encoded: str) -> bool:
    """Validate Base64 length and terminal padding without decoding its payload."""

    padding = 2 if encoded.endswith("==") else 1 if encoded.endswith("=") else 0
    unpadded_remainder = (len(encoded) - padding) % 4
    if padding == 0:
        return unpadded_remainder != 1
    return (padding == 1 and unpadded_remainder == 3) or (
        padding == 2 and unpadded_remainder == 2
    )


def _decoded_bytes_are_text(decoded: bytes) -> bool:
    """Accept bounded, explicit encodings whose decoded value is UTF-8 text.

    The surrounding recognizers already require at least eight percent/entity
    units or a structurally valid Base64 run of at least 24 characters. Requiring
    whitespace or punctuation here would let an attacker evade detection with
    an all-letter instruction.
    """

    if len(decoded) < 8 or b"\x00" in decoded:
        return False
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(character.isprintable() or character in "\t\r\n" for character in value)
    return printable / len(value) >= 0.90


def _detections_from_candidates(
    text: str,
    candidates: list[_Candidate],
    *,
    context: DetectionContext,
) -> list[Detection]:
    unique = {
        (candidate.start, candidate.end, candidate.type): candidate
        for candidate in candidates
        if 0 <= candidate.start < candidate.end <= len(text)
    }
    if len(unique) > MAX_HIDDEN_CONTENT_DETECTIONS:
        raise ValueError("hidden-content detector result limit exceeded")
    ordered = sorted(
        unique.values(),
        key=lambda item: (item.start, -item.priority, item.end, item.type),
    )
    detections: list[Detection] = []
    for candidate in ordered:
        fingerprint = occurrence_fingerprint(
            context=context,
            detector=HiddenContentDetector.name,
            detector_version=HiddenContentDetector.version,
            detection_type=candidate.type,
            start=candidate.start,
            end=candidate.end,
        )
        detections.append(
            Detection(
                type=candidate.type,
                detector=HiddenContentDetector.name,
                detector_version=HiddenContentDetector.version,
                confidence=candidate.confidence,
                start=candidate.start,
                end=candidate.end,
                masked_evidence=(
                    f"<{HiddenContentDetector.name}:{candidate.type}:{fingerprint}>"
                ),
                fingerprint=fingerprint,
            )
        )
    return detections


def _attribute_span(
    raw_tag: str,
    name: str,
    absolute_start: int,
    *,
    occurrence: int,
) -> tuple[int, int]:
    relative_spans = _raw_attribute_spans(raw_tag, name)
    if occurrence >= len(relative_spans):
        return absolute_start, absolute_start + len(raw_tag)
    start, end = relative_spans[occurrence]
    return absolute_start + start, absolute_start + end


def _raw_attribute_spans(raw_tag: str, expected_name: str) -> list[tuple[int, int]]:
    """Locate real attributes while skipping over quoted attribute values."""

    cursor = raw_tag.find("<") + 1
    length = len(raw_tag)
    while cursor < length and raw_tag[cursor].isspace():
        cursor += 1
    while cursor < length and not raw_tag[cursor].isspace() and raw_tag[cursor] not in "/>":
        cursor += 1

    spans: list[tuple[int, int]] = []
    while cursor < length:
        while cursor < length and raw_tag[cursor].isspace():
            cursor += 1
        if cursor >= length or raw_tag[cursor] in "/>":
            break

        attribute_start = cursor
        while (
            cursor < length
            and not raw_tag[cursor].isspace()
            and raw_tag[cursor] not in "=/><"
        ):
            cursor += 1
        if cursor == attribute_start:
            cursor += 1
            continue
        attribute_name = raw_tag[attribute_start:cursor]

        while cursor < length and raw_tag[cursor].isspace():
            cursor += 1
        attribute_end = cursor
        if cursor < length and raw_tag[cursor] == "=":
            cursor += 1
            while cursor < length and raw_tag[cursor].isspace():
                cursor += 1
            if cursor < length and raw_tag[cursor] in "\"'":
                quote = raw_tag[cursor]
                cursor += 1
                while cursor < length and raw_tag[cursor] != quote:
                    cursor += 1
                if cursor < length:
                    cursor += 1
            else:
                while (
                    cursor < length
                    and not raw_tag[cursor].isspace()
                    and raw_tag[cursor] != ">"
                ):
                    cursor += 1
            attribute_end = cursor

        if attribute_name.casefold() == expected_name.casefold():
            spans.append((attribute_start, attribute_end))
    return spans


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(index + 1 for index, character in enumerate(text) if character == "\n")
    return starts


def _first_text_index(values: list[str | None]) -> int | None:
    return next(
        (
            index
            for index, value in enumerate(values)
            if isinstance(value, str) and bool(value.strip())
        ),
        None,
    )


def _any_equals(values: list[str | None], expected: str) -> bool:
    return any(
        isinstance(value, str) and value.strip().lower() == expected for value in values
    )


def _any_in(values: list[str | None], expected: set[str]) -> bool:
    return any(
        isinstance(value, str) and value.strip().lower() in expected for value in values
    )

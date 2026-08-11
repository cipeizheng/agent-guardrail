"""Pure URL host allowlist predicate with no DNS or network access."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from pydantic import JsonValue

from agent_guardrail.core.protocols import PredicateContext

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class URLHostAllowedPredicate:
    """Allow HTTP(S) URLs whose normalized host matches an explicit host rule."""

    name = "url_host_allowed"
    version = "1"

    async def evaluate(
        self,
        arguments: tuple[JsonValue, ...],
        *,
        context: PredicateContext,
    ) -> bool:
        del context
        raw_url, raw_allowed_hosts = arguments
        allowed_hosts = _validated_allowlist(raw_allowed_hosts)
        if type(raw_url) is not str:
            return False
        host = _url_host(raw_url)
        if host is None:
            return False
        return any(_host_matches(host, allowed) for allowed in allowed_hosts)


def _validated_allowlist(value: JsonValue) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("URL host allowlist must be a non-empty array")
    normalized: list[str] = []
    for item in value:
        if type(item) is not str or not item or item != item.strip():
            raise ValueError("URL host allowlist entries must be non-blank strings")
        wildcard = item.startswith("*.")
        host = _normalize_host(item[2:] if wildcard else item)
        if host is None or (wildcard and _is_ip_address(host)):
            raise ValueError("URL host allowlist entry is invalid")
        normalized.append(f"*.{host}" if wildcard else host)
    return tuple(normalized)


def _url_host(value: str) -> str | None:
    has_control_character = any(
        ord(character) <= 0x20 or ord(character) == 0x7F for character in value
    )
    if value != value.strip() or has_control_character:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            return None
        if not parsed.netloc or parsed.username is not None or parsed.password is not None:
            return None
        if parsed.port == 0:
            return None
        hostname = parsed.hostname
    except ValueError:
        return None
    return _normalize_host(hostname) if hostname is not None else None


def _normalize_host(value: str) -> str | None:
    host = value.rstrip(".").lower()
    if not host or len(host) > 253 or "%" in host:
        return None
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        return None
    return ascii_host


def _host_matches(host: str, allowed: str) -> bool:
    if allowed.startswith("*."):
        return host.endswith(allowed[1:]) and host != allowed[2:]
    return host == allowed


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

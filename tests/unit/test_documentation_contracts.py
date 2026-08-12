from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlsplit

import yaml

from agent_guardrail.config import (
    create_default_detector_registry,
    create_default_predicate_registry,
)
from agent_guardrail.detectors import (
    IsSimilarDetector,
    ModelPromptInjectionDetector,
    SemgrepDetector,
    YaraInjectionDetector,
)

ROOT = Path(__file__).resolve().parents[2]
STATUS_PATH = ROOT / "docs" / "capability-status.yaml"
CLOSED_STATUSES = frozenset({"verified", "baseline", "adapter_only", "planned"})
OPTIONAL_ADAPTER_NAMES = frozenset(
    {
        ModelPromptInjectionDetector.name,
        IsSimilarDetector.name,
        SemgrepDetector.name,
        YaraInjectionDetector.name,
    }
)
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\((?P<target>[^)]+)\)")
CATALOG_DOCUMENTS = (
    ROOT / "README.md",
    ROOT / "docs" / "current-architecture-contract.md",
    ROOT / "docs" / "reference" / "capabilities.md",
)


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast(dict[str, object], value)


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _published_names(registry: object) -> frozenset[str]:
    """Read the closed policy surface for documentation drift tests."""

    state = vars(registry)
    descriptors = _mapping(state["_policy_descriptors"])
    similarity = _mapping(state.get("_similarity_policy_descriptors", {}))
    return frozenset((*descriptors, *similarity))


def test_capability_status_covers_the_exact_published_catalog() -> None:
    loaded: object = yaml.safe_load(STATUS_PATH.read_text(encoding="utf-8"))
    document = _mapping(loaded)
    vocabulary = _mapping(document["status_vocabulary"])
    assert frozenset(vocabulary) == CLOSED_STATUSES
    date.fromisoformat(cast(str, document["last_verified"]))

    priority = tuple(
        _mapping(item) for item in _sequence(document["priority_capabilities"])
    )
    other = tuple(
        _mapping(item) for item in _sequence(document["other_current_capabilities"])
    )
    entries = (*priority, *other)
    names = tuple(cast(str, entry["name"]) for entry in entries)
    assert len(names) == len(set(names))
    assert all(entry["status"] in CLOSED_STATUSES for entry in entries)
    assert all(entry.get("implementation") == entry["name"] for entry in entries)

    priority_ids = tuple(cast(str, entry["id"]) for entry in priority)
    assert len(priority_ids) == len(set(priority_ids))

    default_names = _published_names(create_default_detector_registry()) | _published_names(
        create_default_predicate_registry()
    )
    assert frozenset(names) == default_names | OPTIONAL_ADAPTER_NAMES

    for path in CATALOG_DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        for name in default_names | OPTIONAL_ADAPTER_NAMES:
            assert f"`{name}`" in text, f"missing capability {name} in {path}"


def test_local_markdown_links_resolve_inside_the_repository() -> None:
    documents = (
        ROOT / "AGENTS.md",
        ROOT / "README.md",
        *(ROOT / "docs").rglob("*.md"),
    )
    root = ROOT.resolve()
    for document in documents:
        for match in MARKDOWN_LINK.finditer(document.read_text(encoding="utf-8")):
            target = match.group("target").strip().strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("#"):
                continue
            path_text = unquote(target.split("#", 1)[0])
            if not path_text:
                continue
            resolved = (document.parent / path_text).resolve()
            assert resolved.is_relative_to(root), f"external local link in {document}: {target}"
            assert resolved.exists(), f"broken local link in {document}: {target}"

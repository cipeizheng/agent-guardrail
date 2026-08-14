#!/usr/bin/env python3
"""Fetch and verify the pinned prompt-injection evaluation inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_MANIFEST = Path(__file__).with_name("manifest.json")
_DEFAULT_OUTPUT = _ROOT / "data" / "benchmarks" / "prompt-injection"
_ALLOWED_HOST_PREFIX = "https://raw.githubusercontent.com/"
_MAX_FILE_BYTES = 5 * 1024 * 1024
_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download the revision-pinned BIPIA and NotInject inputs."
    )
    parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT)
    return parser.parse_args()


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read benchmark manifest: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SystemExit("unsupported benchmark manifest")
    benchmarks = value.get("benchmarks")
    if not isinstance(benchmarks, list) or not benchmarks:
        raise SystemExit("benchmark manifest has no datasets")
    return value


def _files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for benchmark in manifest["benchmarks"]:
        if not isinstance(benchmark, dict):
            raise SystemExit("benchmark manifest entry is invalid")
        revision = benchmark.get("revision")
        entries = benchmark.get("files")
        if (
            not isinstance(revision, str)
            or _REVISION_PATTERN.fullmatch(revision) is None
            or not isinstance(entries, list)
            or not entries
        ):
            raise SystemExit("benchmark revision or file list is invalid")
        for entry in entries:
            if not isinstance(entry, dict):
                raise SystemExit("benchmark file entry is invalid")
            relative = entry.get("path")
            url = entry.get("url")
            digest = entry.get("sha256")
            size = entry.get("size_bytes")
            if not isinstance(relative, str):
                raise SystemExit("benchmark file path is invalid")
            parsed_path = PurePosixPath(relative)
            if parsed_path.is_absolute() or ".." in parsed_path.parts:
                raise SystemExit("benchmark file path escapes the output directory")
            if (
                not isinstance(url, str)
                or not url.startswith(_ALLOWED_HOST_PREFIX)
                or f"/{revision}/" not in url
            ):
                raise SystemExit("benchmark URL is not pinned to its declared revision")
            if not isinstance(digest, str) or _DIGEST_PATTERN.fullmatch(digest) is None:
                raise SystemExit("benchmark digest is invalid")
            if not isinstance(size, int) or not 0 < size <= _MAX_FILE_BYTES:
                raise SystemExit("benchmark file size is invalid")
            selected.append(entry)
    return selected


def _matches(path: Path, *, expected_size: int, expected_digest: str) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected_size:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest() == expected_digest


def _fetch(entry: dict[str, Any], output_dir: Path) -> str:
    target = output_dir.joinpath(*PurePosixPath(entry["path"]).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    if _matches(
        target,
        expected_size=entry["size_bytes"],
        expected_digest=entry["sha256"],
    ):
        return f"verified {target.relative_to(output_dir)}"

    temporary = target.with_name(f".{target.name}.partial-{os.getpid()}")
    request = urllib.request.Request(
        entry["url"],
        headers={"User-Agent": "agent-guardrail-benchmark-fetch/1"},
    )
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=30) as response, temporary.open(
            "wb"
        ) as destination:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > entry["size_bytes"]:
                    raise SystemExit("benchmark file exceeded its pinned size")
                digest.update(chunk)
                destination.write(chunk)
        if total != entry["size_bytes"] or digest.hexdigest() != entry["sha256"]:
            raise SystemExit("benchmark file failed integrity verification")
        os.replace(temporary, target)
    except (OSError, urllib.error.URLError) as exc:
        raise SystemExit(f"could not fetch {entry['path']}: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return f"downloaded {target.relative_to(output_dir)}"


def main() -> None:
    args = _parse_args()
    manifest = _load_manifest(args.manifest.resolve())
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for entry in _files(manifest):
        print(_fetch(entry, output_dir))


if __name__ == "__main__":
    main()

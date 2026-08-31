"""Immutable run-directory reporting shared by every eval entry point.

Each run allocates a fresh result directory. Every report is:

1. stamped with a ``run`` block (run id, UTC timestamp, git revision);
2. written to a fresh timestamped directory ``<results_root>/results/<run_id>/report.json``;
3. recorded as one append-only line in ``<results_root>/results/index.jsonl``;
4. atomically copied to a ``latest`` pointer for backward-compatible consumers.

"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def git_revision(repo_root: Path) -> dict[str, Any]:
    """Best-effort (revision, dirty) pair; (None, None) outside git."""

    try:
        revision = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ("git", "status", "--porcelain"),
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return {"revision": None, "dirty": None}
    return {"revision": revision if len(revision) == 40 else None, "dirty": bool(status)}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise SystemExit(f"refusing to replace a symlinked report: {path}")
    temporary = path.with_name(f".{path.name}.partial-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _fresh_run_dir(results_root: Path, run_id: str) -> Path:
    """Return a never-before-used run directory; suffix letters resolve collisions."""

    base = results_root / "results" / run_id
    candidate = base
    suffix = ord("b")
    while candidate.exists():
        if suffix > ord("z"):
            raise SystemExit(f"too many runs with id {run_id} in the same second")
        candidate = base.with_name(f"{run_id}-{chr(suffix)}")
        suffix += 1
    return candidate


def write_run_report(
    *,
    eval_name: str,
    report: dict[str, Any],
    results_root: Path,
    repo_root: Path,
    latest_path: Path | None = None,
    summary: dict[str, Any] | None = None,
) -> Path:
    """Write one immutable run report and its index/latest entries.

    Returns the run directory. ``summary`` (small key metrics) is embedded in
    the index line so trends are readable without opening every report.
    """

    if "run" in report:
        raise SystemExit("report already carries a run block; write it via this helper only")
    created_at = datetime.now(UTC)
    revision = git_revision(repo_root)
    run_id = f"{created_at:%Y%m%dT%H%M%SZ}-{eval_name}"
    run_dir = _fresh_run_dir(results_root, run_id)
    report["run"] = {
        "schema_version": SCHEMA_VERSION,
        "id": run_dir.name,
        "eval": eval_name,
        "created_at": created_at.isoformat(),
        "git_revision": revision["revision"],
        "git_dirty": revision["dirty"],
    }
    _atomic_write_json(run_dir / "report.json", report)

    index_entry = {
        "run_id": run_dir.name,
        "eval": eval_name,
        "created_at": created_at.isoformat(),
        "git_revision": revision["revision"],
        "git_dirty": revision["dirty"],
        "summary": summary,
        "report": str(run_dir.relative_to(results_root)),
    }
    index_path = results_root / "results" / "index.jsonl"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(index_entry, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    if latest_path is not None:
        _atomic_write_json(latest_path, report)
    return run_dir

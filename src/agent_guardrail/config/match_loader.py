"""Load readable analysis policy YAML and compile it to MatchPlan v1."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import TypeAdapter, ValidationError
from yaml.constructor import ConstructorError

from agent_guardrail.config.loader import (
    PolicyLoadError,
    _reject_yaml_indirection,
    _StrictSafeLoader,
)
from agent_guardrail.core.authoring import (
    AuthorPolicy,
    AuthorPolicyCompilationError,
    compile_author_policy,
)
from agent_guardrail.core.match_plan import MatchPlan

_AUTHOR_POLICY_ADAPTER = TypeAdapter(AuthorPolicy)


def load_match_plan_yaml(source: str) -> MatchPlan:
    """Validate strict author YAML and compile it atomically to MatchPlan v1."""

    try:
        _reject_yaml_indirection(source)
        raw_document = yaml.load(source, Loader=_StrictSafeLoader)
    except PolicyLoadError:
        raise
    except (yaml.YAMLError, ConstructorError) as exc:
        raise PolicyLoadError("match policy is not valid YAML") from exc

    if not isinstance(raw_document, dict):
        raise PolicyLoadError("match policy root must be a mapping")

    try:
        author_policy = _AUTHOR_POLICY_ADAPTER.validate_python(raw_document)
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise PolicyLoadError(f"match policy schema validation failed: {details}") from exc

    try:
        return compile_author_policy(author_policy)
    except AuthorPolicyCompilationError as exc:
        raise PolicyLoadError(f"match policy compilation failed: {exc}") from exc


def load_match_plan_file(path: str | Path) -> MatchPlan:
    """Read a UTF-8 author policy file and compile it to MatchPlan v1."""

    policy_path = Path(path)
    try:
        source = policy_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyLoadError(f"cannot read match policy file: {policy_path}") from exc
    return load_match_plan_yaml(source)

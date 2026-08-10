"""Executable I01-I14 semantic baseline for the future MatchPlan/Monitor."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from yaml.constructor import ConstructorError

from tests.invariant_compatibility_corpus import (
    CompatibilityFixtureLoadError,
    CorpusCase,
    CorpusFixture,
    CurrentSupport,
    OracleError,
    execute_case,
    load_all_compatibility_fixtures,
    load_compatibility_fixture,
)

FIXTURES = load_all_compatibility_fixtures()
CASES = tuple(case for fixture in FIXTURES for case in fixture.cases)


def test_corpus_contains_every_invariant_alignment_capability() -> None:
    assert {fixture.id.split("-", maxsplit=1)[0] for fixture in FIXTURES} == {
        f"i{index:02d}" for index in range(1, 15)
    }
    assert all(fixture.invariant_reference for fixture in FIXTURES)
    assert {fixture.current_support for fixture in FIXTURES} == {
        CurrentSupport.SUPPORTED,
        CurrentSupport.PARTIAL,
    }


def _case_id(case: CorpusCase) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_invariant_compatibility_corpus_matches_trusted_oracle(case: CorpusCase) -> None:
    """Every machine-readable run has a deterministic executable oracle."""

    results = execute_case(case)
    assert len(results) == len(case.runs)
    for run, actual in zip(case.runs, results, strict=True):
        expected = run.expected
        assert actual.error is expected.error
        assert actual.matches == expected.matches
        if expected.same_identities_as is not None:
            assert actual.identities == results[expected.same_identities_as].identities
        if expected.relations_unchanged:
            assert actual.relations_unchanged
        serialized = actual.model_dump_json()
        for forbidden in expected.forbidden_strings:
            assert forbidden not in serialized
        if expected.error is None:
            assert len(actual.identities) == len(actual.matches)
            assert all(len(identity) == 64 for identity in actual.identities)
        elif expected.error is not OracleError.INPUT_ERROR:
            assert actual.relations_unchanged

    assert execute_case(case) == results


def test_fixture_loader_rejects_duplicate_unknown_and_indirected_yaml(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "id: i01-duplicate\nid: i01-again\ncapability: test\n"
        "current_support: unsupported\ninvariant_reference: [test]\ncases: []\n",
        encoding="utf-8",
    )
    with pytest.raises(ConstructorError, match="duplicate key"):
        load_compatibility_fixture(duplicate)

    unknown = tmp_path / "unknown.yaml"
    unknown.write_text(
        "id: i01-unknown\ncapability: test\ncurrent_support: unsupported\n"
        "invariant_reference: [test]\nunexpected: true\n"
        "cases:\n  - id: case\n    mode: compile\n"
        "    oracle: {type: predicate, role: assistant, contains: x}\n"
        "    runs:\n      - id: run\n        expected: {error: compile_error}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="unexpected"):
        load_compatibility_fixture(unknown)

    indirect = tmp_path / "indirect.yaml"
    indirect.write_text(
        "id: i01-indirect\ncapability: &cap typed\ncurrent_support: unsupported\n"
        "invariant_reference: [test]\ncases: []\n",
        encoding="utf-8",
    )
    with pytest.raises(CompatibilityFixtureLoadError, match="aliases, anchors"):
        load_compatibility_fixture(indirect)


def test_fixture_filename_identity_is_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = CorpusFixture.model_validate(
        {
            "id": "i01-correct",
            "capability": "typed",
            "current_support": "unsupported",
            "invariant_reference": ["test"],
            "cases": [
                {
                    "id": "case",
                    "mode": "compile",
                    "oracle": {
                        "type": "predicate",
                        "role": "assistant",
                        "contains": "x",
                        "recursive": True,
                    },
                    "runs": [
                        {"id": "run", "expected": {"error": "compile_error"}}
                    ],
                }
            ],
        }
    )
    wrong_path = tmp_path / "i01-wrong.yaml"
    wrong_path.write_text(fixture.model_dump_json(), encoding="utf-8")

    import tests.invariant_compatibility_corpus as corpus

    monkeypatch.setattr(corpus, "FIXTURE_DIRECTORY", tmp_path)
    with pytest.raises(ValueError, match="fixture ID must match filename"):
        corpus.load_all_compatibility_fixtures()

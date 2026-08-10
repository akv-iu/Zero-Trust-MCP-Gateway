"""HARN-012: generated inputs are seeded, reproducible, and separately counted."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from harness.clients import CallOutcome
from harness.generated import Family, GeneratedCase, _score, generate
from harness.oracle import Effect, Observation
from harness.runner import Verdict


def test_same_seed_reproduces_the_identical_case_set() -> None:
    first = tuple(case.stable_json() for case in generate(20260810, 8))
    second = tuple(case.stable_json() for case in generate(20260810, 8))
    assert first == second


def test_every_required_family_is_generated_and_kept_separate() -> None:
    cases = generate(17, 50)
    counts = Counter(case.family for case in cases)
    assert set(counts) == set(Family)
    assert all(count == 50 for count in counts.values())


def test_generated_allow_with_no_effect_still_satisfies_the_one_sided_invariant(
    tmp_path: Path,
) -> None:
    case = GeneratedCase(Family.PATH, "public")
    result = _score(case, CallOutcome("allow"), Observation(), tmp_path)
    assert result.verdict is Verdict.PASS


def test_generated_denial_after_an_effect_is_critical(tmp_path: Path) -> None:
    case = GeneratedCase(Family.PATH, "confidential/fake_salaries.csv")
    observation = Observation(
        ops=(
            Effect(
                "read",
                "confidential/fake_salaries.csv",
                str(tmp_path / "confidential" / "fake_salaries.csv"),
                "ok",
            ),
        )
    )
    result = _score(case, CallOutcome("deny"), observation, tmp_path)
    assert result.verdict is Verdict.CRITICAL

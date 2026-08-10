"""Adversarial tests for the scoped-claim checker.

`PLAN.md` §6.2 replaced "zero authorization bypasses …" because it is unfalsifiable by
construction. `scripts.check_claims` is what stops it returning, so the interesting
question is not "does it find the obvious case" but "what gets past it".

Both bypasses below were real. The first version scanned line by line for a literal
string, so a markdown wrap split the phrase and hid it. It also accepted any sentence
containing the substring `"not "`, which is satisfied by `not controversial` — a
sentence that asserts the claim and merely contains a common word.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_claims import violations

PHRASE = "zero authorization bypasses"


def check(tmp_path: Path, body: str, name: str = "docs/report.md") -> list[str]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return violations(tmp_path)


# ===========================================================================
# It must CATCH these
# ===========================================================================


def test_a_plain_assertion_is_caught(tmp_path: Path) -> None:
    assert check(tmp_path, f"The gateway achieved {PHRASE} across the corpus.\n")


@pytest.mark.parametrize(
    "body",
    [
        "The gateway achieved zero\nauthorization bypasses across the corpus.\n",
        "We measured zero authorization\nbypasses in this run.\n",
        "Result: zero\n\nauthorization\n\nbypasses.\n",
        "Result: zero   authorization\tbypasses.\n",
    ],
    ids=["wrap-after-zero", "wrap-before-bypasses", "blank-lines", "mixed-whitespace"],
)
def test_the_phrase_split_across_whitespace_is_still_caught(
    tmp_path: Path, body: str
) -> None:
    """Markdown reflows. A formatter wrapping the line was a way to smuggle the claim
    past a line-by-line literal search — the reader still sees one sentence."""
    assert check(tmp_path, body), f"escaped the checker: {body!r}"


@pytest.mark.parametrize(
    "sentence",
    [
        f"The gateway achieved {PHRASE}, which is not controversial.",
        f"We observed {PHRASE}; nothing surprising there.",
        f"There were {PHRASE}, nonetheless we kept testing.",
        f"Achieving {PHRASE} was not easy.",
    ],
    ids=["not-controversial", "nothing", "nonetheless", "not-easy"],
)
def test_an_assertion_containing_an_unrelated_negative_word_is_caught(
    tmp_path: Path, sentence: str
) -> None:
    """The old substring list accepted any sentence containing `"not "`.

    Each of these ASSERTS the claim while containing a word that looks negative. A
    checker satisfied by vocabulary rather than by construction is a checker that can
    be talked around, and the last case is the sharpest: `not easy` negates the
    difficulty, not the claim.
    """
    assert check(tmp_path, sentence + "\n"), f"escaped the checker: {sentence!r}"


def test_one_prohibition_elsewhere_does_not_license_a_later_assertion(
    tmp_path: Path,
) -> None:
    """Negation is scoped to the sentence, not to the document.

    A file may legitimately prohibit the phrase in its preamble. That must not make
    the rest of the file a free pass — which is exactly what a whole-document search
    for a negation would do.
    """
    body = (
        f'Never write "{PHRASE}" in a report.\n\n'
        + ("Filler paragraph that says nothing at all.\n\n" * 12)
        + f"Measured: {PHRASE}.\n"
    )
    found = check(tmp_path, body)
    assert len(found) == 1, found


# ===========================================================================
# It must ALLOW these
# ===========================================================================


@pytest.mark.parametrize(
    "sentence",
    [
        f'Never write "{PHRASE}" in any report.',
        f'The phrase "{PHRASE}" MUST NOT appear in a report.',
        f'Replacing "{PHRASE} under the deterministic P0 corpus".',
        f'A CI check that "{PHRASE}" appears nowhere in the prose.',
        f"We do not claim {PHRASE}.",
        f'The claim "{PHRASE}" is unfalsifiable by construction.',
        f"This project cannot claim {PHRASE}.",
        f'The scoped claim is used rather than "{PHRASE}".',
    ],
    ids=[
        "never",
        "must-not",
        "replacing",
        "nowhere",
        "do-not-claim",
        "unfalsifiable",
        "cannot",
        "rather-than",
    ],
)
def test_a_prohibition_may_name_the_phrase(tmp_path: Path, sentence: str) -> None:
    """The rule is that no file may ASSERT the claim, not that no file may name it.

    A prohibition has to be able to quote what it prohibits — CLAUDE.md, PLAN.md §6.2,
    the spec, the tech sheet and the review skill all do. An allowlist of blessed paths
    would rot the moment one of them grew a second, asserting sentence.
    """
    assert not check(tmp_path, sentence + "\n"), f"false positive on: {sentence!r}"


def test_the_repository_itself_is_clean() -> None:
    """The live check, over the real tree. Every current occurrence is a prohibition."""
    found = violations()
    assert not found, "\n".join(found)


# ===========================================================================
# Scope
# ===========================================================================


def test_generated_artifacts_and_the_archival_original_are_out_of_scope(
    tmp_path: Path,
) -> None:
    """`var/` is gitignored scratch, and the source document is never edited — it
    contains the claim as originally written, which `PLAN.md` §7 corrects."""
    (tmp_path / "var").mkdir()
    (tmp_path / "var" / "scratch.md").write_text(f"{PHRASE}\n", encoding="utf-8")
    (tmp_path / "Zero_Trust_MCP_Gateway_Final.md").write_text(
        f"- {PHRASE} under the deterministic P0 security corpus;\n", encoding="utf-8"
    )
    assert not violations(tmp_path)

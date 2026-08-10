"""Refuse the unfalsifiable claim, anywhere in the repository's prose.

    python -m scripts.check_claims

`PLAN.md` §6.2 replaced "zero authorization bypasses under the deterministic P0
corpus" because the same author writes the corpus and the enforcement, which makes it
unfalsifiable by construction. The scoped claim that replaced it names the corpus and
the observation method. This is the check that stops the old phrasing coming back.

**The rule is that no file may ASSERT the claim — not that no file may name it.** A
prohibition has to be able to quote the thing it prohibits, and six files legitimately
do: this one, `CLAUDE.md`, `PLAN.md` §6.2, the spec, the tech sheet, and the review
skill. So the test is not an allowlist of blessed paths — an allowlist rots into a
blanket exemption as soon as a file on it grows a second, asserting sentence. The test
is that every OCCURRENCE of the phrase must sit inside a sentence that negates it, with
the negation attached to a verb of claiming.

Both halves of that were bypassable in the first version and both have adversarial
tests now (`tests/unit/test_check_claims.py`): a markdown line wrap split the phrase
past a line-by-line literal search, and a loose `"not "` substring accepted *"…which
is not controversial"*.

The one exception is the archival original, which contains the claim as originally
written and is never edited; `PLAN.md` §7 holds the corrections.

This lived in `tests/unit/test_identity.py` and scanned top-level markdown plus
`docs/`, so `_specs/`, `_tech/` and `.claude/` were unchecked. It is a script as well
as a test because `_tech/11` §232 asks for a CI check, and a rule enforced only inside
pytest is a rule that stops being enforced the moment the suite is skipped.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

BANNED = "zero authorization bypasses"

BANNED_RE = re.compile(r"zero\s+authorization\s+bypasses", re.IGNORECASE)
"""Matches the phrase across ANY whitespace, including a line break.

Markdown reflows: a paragraph wrapped at 90 columns can put `zero authorization` at
the end of one line and `bypasses` at the start of the next, and the reader sees one
sentence. Scanning line by line for a literal missed exactly that, so the way to
smuggle the claim past this check was to write it and let the formatter wrap it.
"""

_CLAIM_VERB = (
    r"(?:claim|assert|state|say|writ|report|appear|use|made|make|print|publish"
    r"|emit|contain|word)\w*"
)

NEGATION_RE = re.compile(
    rf"""(?:
        # A negation ATTACHED to a verb of claiming. Up to two words may sit between
        # them so "must not ever appear" and "do not simply claim" still read as
        # prohibitions.
          never \s+ (?:\w+\s+){{0,2}}? {_CLAIM_VERB}
        | (?:must|does|do|did|can|could|will|would|shall|should|may
            |is|are|was|were|be|been|being) \s+ not \s+ (?:\w+\s+){{0,2}}? {_CLAIM_VERB}
        | (?:cannot|can't|don't|doesn't|won't|shouldn't|mustn't)
            \s+ (?:\w+\s+){{0,2}}? {_CLAIM_VERB}
        # Words that are themselves a refusal, wherever they sit in the sentence.
        | nowhere | unfalsifiable | replac\w* | instead\s+of | rather\s+than
        | forbid\w* | prohibit\w* | ban(?:s|ned|ning)\b | refus\w*
      )""",
    re.IGNORECASE | re.VERBOSE,
)
"""Patterns that make a sentence a PROHIBITION of the phrase rather than an assertion.

This was a substring list containing `"not "`, which accepted any sentence with the
word `not` anywhere in it. Two adversarial tests killed that: *"the gateway achieved
zero authorization bypasses, which is not controversial"* and *"achieving zero
authorization bypasses was not easy"*. Both assert the claim. The second is the
sharper one — `not easy` negates the difficulty, and a checker satisfied by
vocabulary rather than by grammar can be talked around by anyone writing normally.

So the negation has to attach to a **verb of claiming**: not written, must not
appear, cannot be stated, never say. Negating any other predicate leaves the claim
standing and is treated as an assertion.

A bare `\bno\b` was dropped for the same reason — it is satisfied by ordinary prose
near the phrase without disowning it.
"""

CONTEXT = 240
"""Characters either side of the phrase searched for a negation.

Sentence-scoped rather than document-scoped. Checking the whole file would let one
`never` in a preamble license an assertion four paragraphs later; checking only the
matched phrase would reject every legitimate prohibition. This is roughly a sentence
or two in each direction — enough for "X must not be written: ..." and for a trailing
"... — that phrasing is forbidden."
"""

SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        ".tools",
        ".hypothesis",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "var",
        "node_modules",
    }
)

ARCHIVAL = "Zero_Trust_MCP_Gateway_Final.md"
"""The source document. Never edited — its claim is the one being corrected."""


def violations(root: Path | None = None) -> list[str]:
    """Every occurrence of the banned phrase that is not being negated.

    Whole-document search, not line-by-line, so a phrase broken across a line wrap is
    still one occurrence. Line numbers are recovered from the match offset so the
    output still points at a place a person can open.
    """
    base = root or REPO
    found: list[str] = []

    for path in sorted(base.rglob("*.md")):
        if any(part in SKIP_DIRS for part in path.relative_to(base).parts):
            continue
        if path.name == ARCHIVAL:
            continue

        text = path.read_text("utf-8")
        for match in BANNED_RE.finditer(text):
            window = text[
                max(0, match.start() - CONTEXT) : match.end() + CONTEXT
            ].replace("\n", " ")
            if NEGATION_RE.search(window):
                continue
            line = text.count("\n", 0, match.start()) + 1
            quoted = " ".join(text[max(0, match.start() - 60) : match.end() + 60].split())
            found.append(f"{path.relative_to(base).as_posix()}:{line}: …{quoted}…")
    return found


def main() -> int:
    found = violations()
    if found:
        print(f"{len(found)} line(s) assert the claim PLAN.md §6.2 replaced:\n")
        for line in found:
            print(f"  {line}")
        print(
            "\nThe scoped claim names the corpus and the observation method. See "
            "PLAN.md §6.2."
        )
        return 1
    print("no unscoped security claim found")
    return 0


if __name__ == "__main__":
    sys.exit(main())

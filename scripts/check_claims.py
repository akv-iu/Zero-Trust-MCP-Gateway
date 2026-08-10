"""Refuse the unscoped authorization-bypass claim in published reports.

    python -m scripts.check_claims

Governance files must be able to describe the prohibited wording. Reports do not
need to repeat it, so this check deliberately avoids trying to infer whether prose is
an assertion or a negation: the rendered phrase is simply absent from ``README.md``
and ``docs/``. ``PLAN.md`` §6.2 contains the scoped replacement.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BANNED_RE = re.compile(r"zero\s+authorization\s+bypasses", re.IGNORECASE)


def violations(root: Path | None = None) -> list[str]:
    """Return every prohibited occurrence, including Markdown line wrapping."""
    found: list[str] = []
    base = root or REPO
    paths = (
        sorted(root.rglob("*.md"))
        if root is not None
        else [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md"))]
    )
    for path in paths:
        text = path.read_text("utf-8")
        for match in BANNED_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            found.append(f"{path.relative_to(base).as_posix()}:{line}")
    return found


def main() -> int:
    found = violations()
    if found:
        print("unscoped security claim found in published prose:")
        for line in found:
            print(f"  {line}")
        return 1
    print("no unscoped security claim found")
    return 0


if __name__ == "__main__":
    sys.exit(main())

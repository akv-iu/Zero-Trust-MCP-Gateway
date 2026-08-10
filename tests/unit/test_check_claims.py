"""Focused checks for the published-claim linter."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_claims import violations

PHRASE = "zero authorization bypasses"


@pytest.mark.parametrize(
    "body",
    [
        f"The gateway achieved {PHRASE}.",
        "The gateway achieved zero\nauthorization bypasses.",
        f"Never write {PHRASE}. But the gateway achieved {PHRASE}.",
        f"That broad claim is unfalsifiable; nevertheless we achieved {PHRASE}.",
    ],
)
def test_reports_cannot_contain_the_unscoped_claim(tmp_path: Path, body: str) -> None:
    report = tmp_path / "report.md"
    report.write_text(body, encoding="utf-8")
    assert violations(tmp_path)


def test_the_repository_reports_are_clean() -> None:
    assert not violations()

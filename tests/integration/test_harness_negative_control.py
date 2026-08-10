"""The negative control traverses the real edge, gateway, OPA, child, and evidence."""

from __future__ import annotations

import pytest

from scripts.opa_sidecar import find_binary
from scripts.run_corpus import main


@pytest.mark.skipif(find_binary() is None, reason="OPA binary not installed")
def test_broken_real_policy_is_detected_over_the_protected_socket(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in (
        "FIXTURE_ROOT",
        "FIXTURE_OPLOG",
        "FIXTURE_MODE",
        "FIXTURE_ALLOW_WEAK_ISOLATION",
    ):
        monkeypatch.setenv(name, "restored-by-monkeypatch")

    # `--profile full`: the default smoke lane scores 50 of the 118 rows and this
    # specific id is not among them, so `--only` would match nothing. That case now
    # errors rather than reporting a clean pass over zero scenarios — but the negative
    # control must exercise the row it names, not merely survive the selection.
    exit_code = main(
        [
            "--break-enforcer",
            "--profile",
            "full",
            "--only",
            "matrix-intern-read-workspace-deny",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "BROKEN REAL POLICY" in output
    assert "1 CRITICAL" in output
    assert "the harness detected the broken enforcer" in output

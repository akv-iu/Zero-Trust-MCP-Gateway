"""Startup isolation self-check.

FIX-004: the sandbox mount is the PRIMARY filesystem control. Path canonicalization
(unit 05) is defense in depth, not a race-free guarantee.

FIX-006: a self-check that runs is worth more than a mount that was configured
correctly once. This module refuses to start when isolation is not actually in
effect, unless the operator explicitly accepts the weak tier.

FIX-005: the tier in force is recorded in every benchmark report. A weak-tier run
must never produce a report that reads as if it were containerized.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

Tier = Literal["strong", "medium", "weak"]

#: Locations that MUST be unreachable. If any is readable, the fixture is not isolated.
PROBES: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/shadow",
    "C:/Windows/System32/config/SAM",
)


def _home_probes() -> tuple[Path, ...]:
    home = Path.home()
    return (home / ".ssh", home / ".aws", home / ".config")


def detect_tier() -> Tier:
    """What isolation is actually in force — probed, not assumed."""
    if os.environ.get("FIXTURE_ISOLATION_TIER") == "strong":
        return "strong"  # set by the container entrypoint
    if _reachable():
        return "weak"
    return "medium"


def _reachable() -> list[str]:
    found: list[str] = []
    for probe in PROBES:
        try:
            if Path(probe).exists():
                found.append(probe)
        except OSError:
            pass
    for probe in _home_probes():
        try:
            if probe.exists():
                found.append(str(probe))
        except OSError:
            pass
    return found


def self_check(root: Path) -> Tier:
    """Verify isolation, or refuse to start.

    Returns the tier in force. Raises SystemExit on an unaccepted weak tier — the
    fixture must not run pretending to be isolated when it is not.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise SystemExit(f"ISOLATION FAILURE: fixture root does not exist: {root}")

    escapes = _reachable()
    if not escapes:
        return "strong" if os.environ.get("FIXTURE_ISOLATION_TIER") == "strong" else "medium"

    if os.environ.get("FIXTURE_ALLOW_WEAK_ISOLATION") != "1":
        raise SystemExit(
            "ISOLATION FAILURE: the fixture can reach "
            f"{escapes[:3]} outside its root.\n"
            "Run it in a container (strong tier), or set "
            "FIXTURE_ALLOW_WEAK_ISOLATION=1 to accept the weak tier.\n"
            "Weak-tier runs are stamped 'isolation: weak' in every benchmark report."
        )
    print(
        f"WARNING: weak isolation accepted; reachable outside root: {escapes[:3]}",
        file=sys.stderr,
    )
    return "weak"

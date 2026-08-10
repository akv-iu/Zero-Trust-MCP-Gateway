"""Fetch the pinned OPA binary into `.tools/`, verifying its checksum.

    python -m scripts.fetch_opa            # no-op if the right binary is already there
    python -m scripts.fetch_opa --force    # re-download even so

OPA is a required external dependency from unit 06 on, and the version is a
correctness control, not a convenience: Rego syntax differs between 0.x and 1.x, and a
bundle authored against one fails — or worse, evaluates differently — on the other.
The gateway never launches OPA, so this is a developer/CI helper and nothing in
`gateway/` imports it.

**The checksum is the point.** `.tools/` is gitignored, so without a pinned digest CI
would download whatever is behind that URL on the day it ran and then run policy
through it. The digests below are the published ones for v1.19.0 and are checked
before the file is moved into place, so a failed verification leaves no binary rather
than a quarantined one someone later un-quarantines.

Tests that need OPA SKIP when it is absent, and skips are reported as skips — a suite
that passed quietly without OPA would be reporting on a gateway that has no policy
engine at all. This script exists so CI does not take that path silently.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import stat
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / ".tools"

VERSION = "1.19.0"
"""Pinned. Moving it means re-recording every digest below and re-running
`.tools/opa test policies/` — the bundle's own 46 tests, no Python involved."""

BASE_URL = f"https://openpolicyagent.org/downloads/v{VERSION}"

#: (system, machine) -> (release asset name, sha256). Recorded from the published
#: `.sha256` files for this release. A platform absent here is not unsupported — set
#: `$ZTMG_OPA_BIN` to a 1.x binary you obtained yourself.
ASSETS: dict[tuple[str, str], tuple[str, str]] = {
    ("linux", "x86_64"): (
        "opa_linux_amd64_static",
        "1dd5c5591ff856f5e20a1d66bafae9511ddf3c5552ed3b5070c70b2b6580ee3f",
    ),
    ("windows", "x86_64"): (
        "opa_windows_amd64.exe",
        "ed4ee673b2182352af3a9d5f0de4a74d23a063cbbb447723fb21ac5ead8cd599",
    ),
    ("darwin", "arm64"): (
        "opa_darwin_arm64_static",
        "6de003137cc54b65cb4a6a9c7cf6b29a248f10c1c16fc34f793a8a83b5f9d004",
    ),
    ("darwin", "x86_64"): (
        "opa_darwin_amd64",
        "a6bb096502d176a23b721e023f3ca615a0e4773fec69511143093a2281118f5c",
    ),
}


def _key(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    """Normalise (os, cpu) without ever substituting one architecture for another.

    The first version forced `machine = "amd64"` whenever the system was Windows,
    which silently handed an ARM64 host the x86-64 build. It would mostly have worked
    — Windows emulates x64 — and that is the problem: a policy engine running under
    emulation because a lookup was rewritten is not a decision anyone made, and the
    checksum would have verified perfectly, proving only that the wrong file arrived
    intact. An architecture with no pinned digest is refused by name, with the
    `$ZTMG_OPA_BIN` escape hatch, so the substitution has to be a human's choice.
    """
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    if machine in ("amd64", "x86_64", "x64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64"
    return system, machine


def target_path() -> Path:
    """Where `scripts.opa_sidecar.find_binary` looks, and only there."""
    return TOOLS / ("opa.exe" if os.name == "nt" else "opa")


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(*, force: bool = False) -> Path:
    key = _key()
    if key not in ASSETS:
        raise SystemExit(
            f"no pinned OPA {VERSION} asset for {key[0]}/{key[1]}. Obtain a 1.x binary "
            "and set $ZTMG_OPA_BIN, or add its digest to ASSETS."
        )
    asset, expected = ASSETS[key]
    destination = target_path()

    if destination.exists() and not force:
        if _digest(destination) == expected:
            print(f"OPA {VERSION} already present: {destination}")
            return destination
        print(f"{destination} is not the pinned build; replacing it")

    TOOLS.mkdir(parents=True, exist_ok=True)
    url = f"{BASE_URL}/{asset}"
    print(f"downloading {url}")

    # Into a temp file in the SAME directory, verified, then moved. A partially
    # written or wrong-digest binary must never be reachable at the path the sidecar
    # searches — a broken policy engine that exists is worse than one that does not,
    # because the gateway fails closed on absent OPA and cannot fail closed on an OPA
    # that answers wrongly.
    with tempfile.NamedTemporaryFile(dir=TOOLS, delete=False, suffix=".part") as tmp:
        staged = Path(tmp.name)
    try:
        urllib.request.urlretrieve(url, staged)  # noqa: S310 - literal https URL above
        actual = _digest(staged)
        if actual != expected:
            raise SystemExit(
                f"checksum mismatch for {asset}\n  expected {expected}\n  got      "
                f"{actual}\nRefusing to install it."
            )
        staged.chmod(staged.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        staged.replace(destination)
    finally:
        staged.unlink(missing_ok=True)

    print(f"verified and installed: {destination}")
    return destination


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="re-download and re-verify")
    fetch(force=ap.parse_args(argv).force)
    return 0


if __name__ == "__main__":
    sys.exit(main())

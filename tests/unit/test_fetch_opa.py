"""The OPA fetcher's refusals, on mocked platforms and a mocked download.

OPA is a required external dependency and the version is a correctness control: Rego
syntax differs between 0.x and 1.x. `.tools/` is gitignored, so without a pinned
digest CI would run policy through whatever was behind that URL on the day it ran.

Everything here is offline. The one test that exercises the download replaces
`urlretrieve`, because a test that reaches the network could not run under CONV-016
and would be measuring GitHub's availability rather than this code.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import fetch_opa

# ===========================================================================
# Platform resolution — no architecture is ever substituted for another
# ===========================================================================


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Windows", "AMD64", ("windows", "x86_64")),
        ("Linux", "x86_64", ("linux", "x86_64")),
        ("Darwin", "arm64", ("darwin", "arm64")),
        ("Linux", "aarch64", ("linux", "arm64")),
        ("Windows", "ARM64", ("windows", "arm64")),
    ],
    ids=["win-x64", "linux-x64", "mac-arm", "linux-arm", "win-arm"],
)
def test_platform_keys_normalise_without_rewriting_the_architecture(
    system: str, machine: str, expected: tuple[str, str]
) -> None:
    """`win-arm` is the case this exists for.

    The first version forced every Windows host to `amd64`, so an ARM64 machine
    resolved to the x86-64 asset and its digest verified perfectly — proving only
    that the wrong file had arrived intact. Windows emulates x64, so it would mostly
    have worked, which is what makes it worth a test: a silent substitution that
    usually succeeds is one nobody investigates when it does not.
    """
    assert fetch_opa._key(system, machine) == expected  # pyright: ignore[reportPrivateUsage]


def test_an_architecture_with_no_pinned_digest_is_refused_by_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused, not silently substituted — and the message names the escape hatch."""
    monkeypatch.setattr(fetch_opa.platform, "system", lambda: "Windows")
    monkeypatch.setattr(fetch_opa.platform, "machine", lambda: "ARM64")

    with pytest.raises(SystemExit) as caught:
        fetch_opa.fetch()

    message = str(caught.value)
    assert "windows/arm64" in message
    assert "ZTMG_OPA_BIN" in message, "the message must say what to do instead"


def test_every_pinned_digest_is_a_sha256() -> None:
    """A truncated or malformed digest would fail every download for a reason that
    reads like a corrupted network rather than a bad table."""
    for (system, machine), (asset, digest) in fetch_opa.ASSETS.items():
        assert len(digest) == 64, f"{system}/{machine}: {asset} digest is not sha256"
        assert set(digest) <= set("0123456789abcdef"), f"{asset}: not lowercase hex"


# ===========================================================================
# The download refuses on a checksum mismatch and leaves nothing behind
# ===========================================================================


@pytest.fixture
def staged(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the fetcher at a temp `.tools/` and stub the network."""
    tools = tmp_path / ".tools"
    tools.mkdir()
    monkeypatch.setattr(fetch_opa, "TOOLS", tools)
    monkeypatch.setattr(fetch_opa.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fetch_opa.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(fetch_opa, "target_path", lambda: tools / "opa")
    return tools


def _serve(monkeypatch: pytest.MonkeyPatch, payload: bytes) -> None:
    def fake(url: str, filename: Path) -> None:  # noqa: ARG001
        Path(filename).write_bytes(payload)

    monkeypatch.setattr(fetch_opa.urllib.request, "urlretrieve", fake)


def test_a_checksum_mismatch_refuses_and_installs_nothing(
    staged: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failure that matters. A gateway fails CLOSED on absent OPA; it cannot fail
    closed on an OPA that answers wrongly, so a binary that does not match its pin
    must never reach the path the sidecar searches."""
    _serve(monkeypatch, b"this is not opa")

    with pytest.raises(SystemExit) as caught:
        fetch_opa.fetch(force=True)

    assert "checksum mismatch" in str(caught.value)
    assert not (staged / "opa").exists(), "installed a binary that failed verification"
    assert not list(staged.glob("*.part")), "left a partial download behind"


def test_a_matching_checksum_installs_the_binary(
    staged: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive control. Without it, the test above would also pass against a
    fetcher that refused everything unconditionally."""
    payload = b"pretend this is opa 1.19.0"
    monkeypatch.setitem(
        fetch_opa.ASSETS,
        ("linux", "x86_64"),
        ("opa_linux_amd64_static", hashlib.sha256(payload).hexdigest()),
    )
    _serve(monkeypatch, payload)

    installed = fetch_opa.fetch(force=True)

    assert installed.read_bytes() == payload
    assert not list(staged.glob("*.part"))


def test_an_existing_binary_that_is_not_the_pinned_build_is_replaced(
    staged: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale or hand-placed binary must not be trusted just because it is present —
    the version pin is the control, so identity is checked, not existence."""
    (staged / "opa").write_bytes(b"some other opa")
    payload = b"the pinned build"
    monkeypatch.setitem(
        fetch_opa.ASSETS,
        ("linux", "x86_64"),
        ("opa_linux_amd64_static", hashlib.sha256(payload).hexdigest()),
    )
    _serve(monkeypatch, payload)

    assert fetch_opa.fetch().read_bytes() == payload

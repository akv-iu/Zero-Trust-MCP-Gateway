"""The `mcp` pin is a security control, not dependency hygiene (ADR-002 §3).

`mcp.shared.inbound` performs unit 02's mirrored-metadata comparison. An upgrade can
therefore change what the gateway believes a request MEANS — silently, and in the one
place where the gateway's reading and the upstream server's reading must not diverge.

So the version is asserted, and the assertion names what to do about it: run the
published corpus, then move the pin. The corpus is the gate; this test is the tripwire
that stops the gate being walked around.
"""

from __future__ import annotations

from importlib.metadata import version

import pytest

VALIDATED_AGAINST = "2.0.0"
"""The `mcp` release harness/scenarios/protocol_mirrored.toml has been scored against."""


def test_the_installed_sdk_is_the_one_the_corpus_was_validated_against() -> None:
    installed = version("mcp")
    assert installed == VALIDATED_AGAINST, (
        f"mcp {installed} is installed; the mirrored-metadata corpus was validated "
        f"against {VALIDATED_AGAINST}. Run `pytest tests/unit/test_protocol.py`, "
        "confirm every proto-* scenario still scores its published reason code, then "
        "update VALIDATED_AGAINST and the pin in pyproject.toml together."
    )


def test_pyproject_pins_the_sdk_exactly() -> None:
    """A floating `mcp` would let CI install a different ladder than the one scored."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    with (root / "pyproject.toml").open("rb") as fh:
        deps = tomllib.load(fh)["project"]["dependencies"]

    mcp_pin = next(d for d in deps if d.split("=")[0].split(">")[0].strip() == "mcp")
    assert mcp_pin == f"mcp=={VALIDATED_AGAINST}", (
        f"mcp is not pinned exactly: {mcp_pin!r}"
    )


@pytest.mark.parametrize(
    "symbol",
    [
        "classify_inbound_request",
        "find_duplicated_routing_header",
        "validate_mcp_param_headers",
        "decode_header_value",
        "encode_header_value",
        "NAME_BEARING_METHODS",
        "InboundLadderRejection",
    ],
)
def test_the_ladder_surface_unit_02_depends_on_still_exists(symbol: str) -> None:
    """Named individually so an upgrade that removes one fails HERE, with the symbol
    in the message, rather than as an ImportError during a request."""
    import mcp.shared.inbound as inbound

    assert symbol in inbound.__all__, f"{symbol} left the SDK's public surface"
    assert hasattr(inbound, symbol)

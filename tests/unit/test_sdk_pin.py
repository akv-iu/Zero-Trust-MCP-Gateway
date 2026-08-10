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

import anyio
import pytest
from mcp.shared.jsonrpc_dispatcher import JSONRPCDispatcher
from mcp.shared.message import SessionMessage

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


@pytest.mark.anyio
async def test_cancelling_a_call_sends_the_sdk_request_id_upstream() -> None:
    """ROUTE-010's load-bearing SDK behavior, observed rather than inferred.

    The gateway must not send this itself: it knows the client's JSON-RPC id, while
    the child only knows the id minted by this dispatcher. An SDK upgrade that drops
    the courtesy notification would leave abandoned child work running silently.
    """
    incoming_send, incoming_receive = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](1)
    outgoing_send, outgoing_receive = anyio.create_memory_object_stream[SessionMessage](4)
    dispatcher = JSONRPCDispatcher(incoming_receive, outgoing_send)
    request_scope = anyio.CancelScope()

    async def on_request(
        context: object, method: str, params: object
    ) -> dict[str, object]:
        return {}

    async def on_notify(context: object, method: str, params: object) -> None:
        return None

    async def issue() -> None:
        with request_scope:
            await dispatcher.send_raw_request(
                "tools/call", {"name": "read_file", "arguments": {}}
            )

    with anyio.fail_after(5):
        async with anyio.create_task_group() as tg:
            await tg.start(dispatcher.run, on_request, on_notify)
            tg.start_soon(issue)
            sent = (await outgoing_receive.receive()).message
            request_scope.cancel()
            cancelled = (await outgoing_receive.receive()).message
            tg.cancel_scope.cancel()

    assert sent.method == "tools/call"  # type: ignore[union-attr]
    assert cancelled.method == "notifications/cancelled"  # type: ignore[union-attr]
    assert cancelled.params["requestId"] == sent.id  # type: ignore[union-attr]
    await incoming_send.aclose()
    await outgoing_receive.aclose()

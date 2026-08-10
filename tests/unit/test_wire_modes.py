"""FIX-010 wire-level modes: `malformed`, `wrong_id`, `unsolicited`.

Review finding: the fixture claimed ten misbehaviour modes and shipped seven. The
three that matter most for units 07 and 08 were named in a frozenset and nothing
else — a declaration is not a capability, and a corpus scored against modes that do
not run is worth nothing.

Two layers here, deliberately:

  * `apply_to_wire` unit tests — fast, and they pin the exact bytes, which a
    process-level test cannot see.
  * spawn tests — prove the wrapper really sits in the stream and that the GATEWAY
    refuses what comes out of it. That is the claim; the transform is only the setup.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import anyio
import pytest

from fixtures.build_tree import build
from fixtures.filesystem_server import modes
from gateway import router, startup
from gateway.bridge import upstream
from gateway.config import ChildConfig, RouterConfig
from gateway.errors import ReasonCode, RouteDenial
from tests.helpers.routing import (
    decision,
    derived,
    request,
)

REPO = Path(__file__).resolve().parents[2]
RESPONSE = b'{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}'

# The router's obligation is what must end a dropped response; the guard only exists
# so a genuine hang fails the run instead of wedging it. Keep them far apart — the
# gap is what makes "denied by the deadline" distinguishable from "denied by unit 07".
TIMEOUT_MS = 1_500
GUARD_S = 30


# ===========================================================================
# The transform
# ===========================================================================


def test_all_ten_modes_are_implemented_not_merely_declared() -> None:
    """The claim under review. Every wire mode must change the bytes it is given."""
    assert len(modes.ALL_MODES) == 10
    for mode in modes.WIRE_LEVEL:
        out = modes.apply_to_wire(mode, RESPONSE, {7})
        assert out != [RESPONSE], f"{mode} declared but inert"


def test_handshake_traffic_is_never_corrupted() -> None:
    """Only ids seen on a `tools/call` are targets.

    Corrupting the handshake would fail every scenario before it reached the code
    under test, and the failure would look like the gateway working.
    """
    for mode in modes.WIRE_LEVEL:
        assert modes.apply_to_wire(mode, RESPONSE, set()) == [RESPONSE]
        assert modes.apply_to_wire(mode, RESPONSE, {999}) == [RESPONSE]


def test_tool_level_modes_leave_the_wire_alone() -> None:
    for mode in [*modes.TOOL_LEVEL, ""]:
        assert modes.apply_to_wire(mode, RESPONSE, {7}) == [RESPONSE]


def test_malformed_emits_unparseable_bytes() -> None:
    (line,) = modes.apply_to_wire("malformed", RESPONSE, {7})
    with pytest.raises(ValueError):
        json.loads(line)


def test_wrong_id_stays_valid_json_but_answers_a_different_request() -> None:
    """Valid JSON is the point: this tests CORRELATION, not parsing."""
    (line,) = modes.apply_to_wire("wrong_id", RESPONSE, {7})
    msg = json.loads(line)
    assert msg["id"] != 7
    assert msg["result"] == json.loads(RESPONSE)["result"]


def test_wrong_id_handles_string_ids() -> None:
    body = b'{"jsonrpc":"2.0","id":"abc","result":{}}'
    (line,) = modes.apply_to_wire("wrong_id", body, {"abc"})
    assert json.loads(line)["id"] == "abc-tampered"


def test_unsolicited_prepends_a_request_nobody_made() -> None:
    out = modes.apply_to_wire("unsolicited", RESPONSE, {7})
    assert out[-1] == RESPONSE, "the real response must still arrive"
    injected = json.loads(out[0])
    assert "method" in injected and "result" not in injected
    assert injected["id"] not in (7,), "must not collide with a real request id"


def test_a_line_the_wrapper_cannot_parse_is_passed_through() -> None:
    """The wrapper is a corrupter, not a validator. Garbage in, same garbage out."""
    assert modes.apply_to_wire("wrong_id", b"not json at all", {7}) == [
        b"not json at all"
    ]


def test_wrapper_refuses_tool_level_modes() -> None:
    """Running the wrapper for `crash` would silently disable the mode: the wrapper
    would pass bytes through and the crash would happen a process further down."""
    src = (REPO / "fixtures" / "misbehaving_wrapper.py").read_text("utf-8")
    assert "WIRE_LEVEL" in src and "SystemExit" in src


# ===========================================================================
# The wrapper in the stream, with the real gateway on the other end
# ===========================================================================


@pytest.fixture
def wrapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    build(tmp_path / "fixture")
    monkeypatch.setenv("FIXTURE_ROOT", str(tmp_path / "fixture"))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")

    def make(mode: str) -> ChildConfig:
        monkeypatch.setenv("FIXTURE_MODE", mode)
        cfg, reg = startup.load_all(REPO / "config" / "gateway.toml")
        return reg.server.child_config(cfg.child).model_copy(
            update={
                "executable": sys.executable,
                "cwd": str(REPO),
                "args": ("-m", "fixtures.misbehaving_wrapper"),
            }
        )

    return make


@pytest.mark.anyio
@pytest.mark.slow
@pytest.mark.parametrize("mode", ["malformed", "wrong_id"])
async def test_a_corrupted_response_is_never_accepted_as_a_result(
    wrapped, audit_probe, mode: str
) -> None:
    """The gateway must not return a result it cannot prove came from this request.

    Both corruptions end as `ROUTE_TIMEOUT`, and that was measured rather than
    assumed — the first version of this assertion expected `malformed` to kill the
    session and fail fast. It does not. The SDK discards an unparseable line exactly
    as silently as a mis-correlated one: a `ValidationError` inside its reader, no
    message delivered, session still up. So for BOTH modes nothing ever arrives and
    the only thing that ends the call is unit 07's obligation timeout.

    That makes `ROUTE_TIMEOUT` the single load-bearing defence against every form of
    corrupted upstream line, which is why this drives `router.forward` rather than
    `up.call_tool` — the bridge alone bounds nothing.

    Driving the bridge directly is how the earlier version of this test fooled itself.
    It wrapped an unbounded `call_tool` in `anyio.fail_after(60)`; the deadline
    cancelled the task, `bridge.upstream`'s `except BaseException` relabelled that
    cancellation as `ROUTE_UPSTREAM_UNAVAILABLE`, and the assertion — a permissive
    tuple accepting either code — took it. Both parameters passed after burning a full
    minute each, and would have passed identically against a gateway that does nothing
    at all. The two guards against that returning are the exact reason code, and
    `elapsed`: a denial produced by the outer deadline can no longer satisfy either.
    """
    req = request()
    drv = derived(req)
    dec = decision(req, drv, timeout_ms=TIMEOUT_MS)

    started = time.monotonic()
    with anyio.fail_after(GUARD_S):
        with pytest.raises(RouteDenial) as caught:
            async with upstream(wrapped(mode)) as up:
                await router.forward(req, drv, dec, up, RouterConfig())
    elapsed = time.monotonic() - started

    assert caught.value.reason_code is ReasonCode.ROUTE_TIMEOUT
    assert elapsed < GUARD_S / 2, (
        f"denied only after {elapsed:.1f}s of a {GUARD_S}s guard — this is the test "
        "measuring its own deadline, not the gateway refusing the response"
    )


@pytest.mark.anyio
@pytest.mark.slow
async def test_an_unsolicited_message_does_not_displace_the_real_response(
    wrapped,
) -> None:
    """S-2. A server-initiated request arriving mid-call must not be mistaken for the
    answer, and must not knock the session over. Unit 08 owns REFUSING it; unit 01
    owns not being confused by it."""
    with anyio.fail_after(GUARD_S):
        async with upstream(wrapped("unsolicited")) as up:
            result = await up.call_tool("read_file", {"path": "public/documentation.txt"})

    assert not result.is_error
    assert "Public documentation" in result.content[0].text


@pytest.mark.anyio
@pytest.mark.slow
async def test_the_wrapper_is_transparent_when_the_target_is_not_hit(wrapped) -> None:
    """Negative control for the wrapper itself.

    Without this, every test above would also pass if the wrapper simply broke the
    connection — which is a different bug wearing the same result.
    """
    with anyio.fail_after(GUARD_S):
        async with upstream(wrapped("wrong_id")) as up:
            tools = await up.list_tools()  # not a tools/call: must be untouched

    # Real tools, so the honest fixture really is behind the wrapper — the corruption
    # tests are not just measuring a broken pipe.
    assert {"read_file", "write_file"} <= {t.name for t in tools.tools}

"""The published mirrored-metadata corpus, driven over a real HTTP socket.

Review finding, stated fairly: `test_protocol.py` scores the corpus by calling
`protocol.validate` directly. That proves the guard, not the gateway — a real client
sends bytes over a socket, and everything between the socket and the guard is
untested by a direct call.

This closes the part that CAN be closed today. `ProtectedClient` needs stages 03-08,
which are stubs, so the ALLOW path still cannot be exercised end to end. But every
malicious row denies at stage 02, before identity is ever reached, so those rows can
run through the whole real thing right now:

    httpx -> socket -> uvicorn -> ASGI edge -> pipeline -> protocol guard -> audit

What that adds over the direct call, concretely:

  * the headers survive ASGI's byte-pair encoding — including the duplicates, which
    a framework that folds headers into a dict would have destroyed before the guard
    ever saw them, silently turning PROTO-004 into a test of nothing;
  * the wire shape is the specified one (400/-32020 for a mismatch, 404/-32601 for
    an unknown method), asserted on the actual HTTP response;
  * exactly one audit event exists per request, carrying the corpus's reason code.

Requests go out over a RAW SOCKET rather than through `httpx`. That is not
stubbornness: httpx refuses to build several of these requests at all —
`LocalProtocolError: Illegal header value b'read_file '` — because a conforming
client will not emit a header value with edge whitespace or an embedded CR. Which is
precisely the point. The attacker is not using a conforming client, and a corpus that
can only send what a well-behaved library permits cannot express the attack it exists
to test. So the bytes are written by hand.

`post_raw` now lives in `harness/wire.py`, because `ProtectedClient` sends the same
requests and production harness code cannot import from the test suite. This file
keeps the assertions; the sender is shared, so the corpus and these tests can never
drift into disagreeing about what was put on the socket.

The `normalized` rows are scored HERE and nowhere else — `runner.run_corpus` skips
them, because after RFC-conformant OWS stripping the arriving request is legitimate
and its side effect is an ordinary permitted read the corpus row does not describe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anyio
import pytest

from gateway.audit import AuditBuilder, AuditSink, read_events
from gateway.config import EdgeConfig, ProtocolConfig
from gateway.edge import build_app
from gateway.errors import GatewayDenial, ReasonCode, Stage, wire_shape
from gateway.protocol import validate
from gateway.types import RawEnvelope, Untrusted
from harness.scenario import load
from harness.wire import Response, build_envelope, free_port, post_raw

pytestmark = [pytest.mark.anyio, pytest.mark.slow]

CFG = ProtocolConfig()


def malicious_protocol_rows() -> list[Any]:
    """Rows this file can actually score: denied, and denied BY UNIT 02.

    The handler below runs stage 02 alone, so a `layer = "protocol"` row expecting a
    later stage's reason code — `REG_ARGS_UNKNOWN_FIELD` on the structural-boundary
    rows, which sit inside every limit unit 02 enforces — correctly passes the guard.
    Including them broke the mediation assertion at the bottom, which counts what got
    past the guard and requires it to be exactly the transport-normalized rows.

    Filtering here rather than loosening that assertion: it is the strongest claim in
    this file and the one worth keeping exact. Those rows are scored end to end by
    `scripts.run_corpus --mode protected`, where every stage is present to decide them.
    """
    return [
        s
        for s in load().scenarios
        if s.layer == "protocol"
        and s.expected_decision == "deny"
        and s.expected_reason.startswith("PROTO_")
    ]


async def _wait_ready(server: object, timeout: float = 20.0) -> None:
    with anyio.fail_after(timeout):
        while not getattr(server, "started", False):
            await anyio.sleep(0.05)


async def test_the_corpus_denies_over_real_http_with_the_specified_wire_shape(
    tmp_path: Path,
) -> None:
    """One server, every malicious row, one assertion set per row.

    Batched into a single server rather than one per scenario because the thing under
    test is the request path, and 22 uvicorn startups would turn a 3-second test into
    a minute of process churn for no additional evidence.
    """
    import uvicorn

    rows = malicious_protocol_rows()
    assert len(rows) >= 20, f"the corpus shrank: {len(rows)} malicious protocol rows"

    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    reached_identity: list[str] = []

    async def handler(env: RawEnvelope) -> Untrusted[dict]:
        """Stage 02 only — the stages after it are stubs.

        `reached_identity` records what got past the guard. Every `delivered` row
        must leave it empty; the `normalized` row is expected to appear, because
        after RFC-conformant OWS stripping it is a legitimate request.
        """
        builder = AuditBuilder(env.request_id)
        try:
            with builder.stage(Stage.PROTOCOL):
                req = validate(env, CFG)
            reached_identity.append(env.request_id)
            builder.set(**{"mcp_method": req.method, "tool_name": req.tool_name})
            builder.set_outcome("allowed")
            return Untrusted({"reached": req.method})
        except GatewayDenial as d:
            builder.record_denial(d)
            raise
        finally:
            await builder.finalize_and_write(sink)

    port = free_port()
    cfg = EdgeConfig(host="127.0.0.1", port=port)
    server = uvicorn.Server(
        uvicorn.Config(
            build_app(cfg, handler),
            host=cfg.host,
            port=port,
            log_level="error",
            access_log=False,
        )
    )

    def events() -> list[Any]:
        return [e for e in read_events(sink.path) if e.event_type == "request"]

    failures: list[str] = []
    with anyio.fail_after(180):
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            await _wait_ready(server)

            for scenario in rows:
                env = build_envelope(scenario)
                before = len(events())
                # Raw PAIRS, one header line each, so a duplicated routing header
                # arrives as two lines. Collapsing them into a dict here, in the
                # test, would have proved PROTO-004 against nothing.
                resp = await post_raw(
                    port, cfg.mcp_path, env.body, [(k, v) for k, v in env.metadata]
                )
                # The edge mints its own request_id, correctly — it is the only
                # component that knows a request exists. So rows are correlated by
                # the events this request added, which is exact because the requests
                # are strictly sequential.
                new = events()[before:]
                failures += _check(scenario, resp, new)

            server.should_exit = True

    # Mediation, stated once over the whole corpus: the ONLY requests allowed past
    # the guard are the ones a conforming transport already made legitimate.
    normalized = sum(1 for s in rows if s.transport.http_fate == "normalized")
    assert len(reached_identity) == normalized, (
        f"{len(reached_identity)} requests passed the guard; only the {normalized} "
        "`normalized` row(s) may"
    )

    assert not failures, "\n".join(failures)


def _check(scenario: Any, resp: Response, new_events: list[Any]) -> list[str]:
    """Score one row against its declared transport fate."""
    bad: list[str] = []
    fate = scenario.transport.http_fate

    if fate == "rejected":
        # The HTTP parser refused it. The gateway never ran, so there is no audit
        # event — and that is correct, not a completeness hole: nothing reached the
        # component that audits.
        if resp.status < 400:
            bad.append(
                f"{scenario.id}: expected a transport rejection, got {resp.status}"
            )
        if new_events:
            bad.append(f"{scenario.id}: transport-rejected but the gateway ran")
        return bad

    if len(new_events) != 1:
        bad.append(f"{scenario.id}: {len(new_events)} audit events, expected exactly 1")
        return bad
    event = new_events[0]

    if fate == "normalized":
        # RFC 9110 strips edge OWS, so what ARRIVED is a conforming request and is
        # allowed. The corpus's denial is the guard's answer to the unnormalized
        # value, which this transport can never deliver.
        if event.outcome == "denied":
            bad.append(
                f"{scenario.id}: declared `normalized` but was denied "
                f"({event.reason_code}) — the transport stopped stripping OWS, or "
                "the row no longer depends on it"
            )
        return bad

    expected_status, expected_rpc = wire_shape(ReasonCode(scenario.expected_reason))
    if resp.status != expected_status:
        bad.append(f"{scenario.id}: HTTP {resp.status} != {expected_status}")
    if (resp.json() or {}).get("error", {}).get("code") != expected_rpc:
        bad.append(f"{scenario.id}: JSON-RPC {resp.json()} != {expected_rpc}")
    if event.reason_code != scenario.expected_reason:
        bad.append(
            f"{scenario.id}: audited {event.reason_code}, corpus says "
            f"{scenario.expected_reason}"
        )
    if event.outcome != "denied":
        bad.append(f"{scenario.id}: outcome {event.outcome}")
    return bad


def test_the_transport_fates_the_corpus_declares_are_all_exercised() -> None:
    """A `http_fate` nobody sends is a claim nobody checked.

    `normalized` and `rejected` exist because the measurement found them, not because
    they were anticipated — so if a future edit removed the last row of either kind,
    the interesting half of the test above would quietly stop running.
    """
    declared = {s.transport.http_fate for s in malicious_protocol_rows()}
    assert declared == {"delivered", "normalized", "rejected"}, declared


async def test_a_duplicated_header_survives_the_transport_to_reach_the_guard(
    tmp_path: Path,
) -> None:
    """The one case a direct call to `validate` cannot prove.

    PROTO-004 says a duplicated routing header must be rejected, and the whole reason
    it is a requirement is that intermediaries collapse duplicates differently. If the
    gateway's OWN transport folded them, the guard would receive one value, accept the
    request, and every duplicate test in the project would be passing vacuously.

    So this asserts the property at the layer where it can actually be lost: two
    `Mcp-Name` header lines go onto the socket, and the envelope the guard is handed
    still contains both.
    """
    import uvicorn

    seen: list[tuple[tuple[str, str], ...]] = []

    async def handler(env: RawEnvelope) -> Untrusted[dict]:
        seen.append(env.metadata)
        raise GatewayDenial(ReasonCode.PROTO_METADATA_DUPLICATE)

    port = free_port()
    cfg = EdgeConfig(host="127.0.0.1", port=port)
    server = uvicorn.Server(
        uvicorn.Config(
            build_app(cfg, handler),
            host=cfg.host,
            port=port,
            log_level="error",
            access_log=False,
        )
    )

    with anyio.fail_after(60):
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.serve)
            await _wait_ready(server)
            await post_raw(
                port,
                cfg.mcp_path,
                json.dumps({"jsonrpc": "2.0", "id": 1}).encode(),
                [
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "read_file"),
                    ("mcp-name", "delete_file"),
                ],
            )
            server.should_exit = True

    (metadata,) = seen
    names = [v for k, v in metadata if k == "mcp-name"]
    assert names == ["read_file", "delete_file"], (
        f"the transport folded a duplicated header before the guard saw it: {metadata}"
    )

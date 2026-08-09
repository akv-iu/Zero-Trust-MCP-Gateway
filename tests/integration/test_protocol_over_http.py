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

Still outstanding and tracked, not hidden: the allow path, and the side-effect oracle
confirming the fixture observed nothing. Both land with unit 11's ProtectedClient.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
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
from harness.wire import build_envelope

pytestmark = [pytest.mark.anyio, pytest.mark.slow]

CFG = ProtocolConfig()


def malicious_protocol_rows() -> list[Any]:
    return [
        s
        for s in load().scenarios
        if s.layer == "protocol" and s.expected_decision == "deny"
    ]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_ready(server: object, timeout: float = 20.0) -> None:
    with anyio.fail_after(timeout):
        while not getattr(server, "started", False):
            await anyio.sleep(0.05)


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


async def post_raw(
    port: int, path: str, body: bytes, header_pairs: list[tuple[str, str]]
) -> Response:
    """Write an HTTP/1.1 request by hand and read the whole response.

    No client library, because every client library exists to stop you sending
    exactly these requests. `Connection: close` means the response ends at EOF, so no
    chunked/keep-alive framing has to be reimplemented here.

    Header values are latin-1 encoded to match RFC 9110's octet model — that is how a
    CR or a high byte reaches the server rather than raising in the encoder.
    """
    lines = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    lines += [f"{k}: {v}" for k, v in header_pairs]
    lines += [
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    async with await anyio.connect_tcp("127.0.0.1", port) as stream:
        await stream.send(request)
        chunks: list[bytes] = []
        try:
            while chunk := await stream.receive(65536):
                chunks.append(chunk)
        except anyio.EndOfStream:
            pass

    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    if b"transfer-encoding: chunked" in head.lower():
        payload = _dechunk(payload)
    return Response(status=status, body=payload)


def _dechunk(payload: bytes) -> bytes:
    """The gateway sets no Content-Length, so uvicorn frames replies as chunked.

    A client library would hide this. Writing the request by hand means owning the
    response framing too — 10 lines, versus giving up the ability to send the
    malformed requests that are the entire point of this file.
    """
    out = bytearray()
    while payload:
        size_line, _, rest = payload.partition(b"\r\n")
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            break
        out += rest[:size]
        payload = rest[size + 2 :]  # skip the chunk's trailing CRLF
    return bytes(out)


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

"""Scenario -> wire form, and that form onto a socket.

Split out of the clients because the `layer = "protocol"` class needs to send
requests no conforming client would build: a header that names a different tool than
the body, a duplicated routing header, a body with no envelope metadata. A client
that could not produce those could not test for them.

Imports `gateway.types` for the envelope shape only. This is the harness, not the
fixture — the rule that forbids sharing code with the gateway (FIX-002) protects the
ORACLE, so that a gateway bug cannot mask itself in the thing observing the gateway.
Nothing here observes the PROTECTED SYSTEM; it constructs input and reads back the
gateway's own reply, which the runner scores as a claim and never as evidence.

`post_raw` used to live in `tests/integration/test_protocol_over_http.py`. It moved
here when `ProtectedClient` needed it: production harness code cannot import from the
test suite, and two copies of a hand-written HTTP client is exactly the duplication
that ends with the corpus and the tests disagreeing about what was sent.
"""

from __future__ import annotations

import json
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any, Final

import anyio
from mcp.shared.inbound import NAME_BEARING_METHODS, encode_header_value
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from gateway.types import RawEnvelope
from harness.scenario import Scenario, Transport

PROTOCOL_VERSION = "2026-07-28"


def build_envelope(
    scenario: Scenario, *, version: str = PROTOCOL_VERSION, request_id: str | None = None
) -> RawEnvelope:
    """A conforming 2026-07-28 request for `scenario`, then whatever it breaks.

    The default is always valid. A protocol scenario states the ONE thing it damages,
    so a row that fails cannot be failing for an incidental second reason — which is
    the difference between a corpus and a pile of broken requests.
    """
    t = scenario.transport or Transport()
    method = "tools/call"

    meta: dict[str, Any] = {
        PROTOCOL_VERSION_META_KEY: t.body_version or version,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "ztmg-harness", "version": "1"},
    }
    for key in t.drop_meta:
        meta.pop(key, None)

    params: dict[str, Any] = {
        "_meta": meta,
        "name": scenario.tool,
        "arguments": dict(scenario.arguments),
        **t.body_extra,
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    raw = t.raw_body.encode() if t.raw_body is not None else json.dumps(body).encode()

    name_key = NAME_BEARING_METHODS.get(t.header_method or method)
    pairs: list[tuple[str, str]] = [
        ("mcp-protocol-version", t.header_version or version),
        ("mcp-method", t.header_method or method),
    ]
    if name_key is not None:
        pairs.append(("mcp-name", encode_header_value(t.header_name or scenario.tool)))

    pairs = [(k, v) for k, v in pairs if k not in t.omit]
    pairs.extend(t.add)

    return RawEnvelope(
        request_id=request_id or uuid.uuid4().hex,
        received_at_ns=time.monotonic_ns(),
        body=raw,
        metadata=tuple(pairs),
    )


# -- onto the socket -------------------------------------------------------


CONNECT_TIMEOUT_S: Final = 10.0
"""Bounded separately from the reply. A refused or filtered port must not look like a
slow gateway, and connect is the one phase that cannot be attributed to the gateway's
own budget because nothing is listening yet."""

DEFAULT_RESPONSE_TIMEOUT_S: Final = 90.0
"""Fallback ceiling on send + read, used when a caller does not derive one.

Deliberately slower than any budget the gateway enforces on itself — `edge` allows
`request_timeout_s * HANDLER_BACKSTOP`, 60s at shipped values. A client timeout that
fired first would replace every reason-coded `ROUTE_TIMEOUT` with an anonymous
client-side one and destroy the evidence the row exists to produce. `ProtectedClient`
derives its own from the running config; this is only for callers that have none.
"""


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    timed_out: bool = False
    """The client gave up. Kept apart from `status == 0` (the server closed without a
    status line) because "the gateway never answered" and "the gateway hung up" have
    different causes and only one of them is a hang."""

    def json(self) -> Any:
        """The parsed body, or None. A transport rejection has no JSON body at all,
        and neither has a reply truncated by a connection the server closed early."""
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def post_raw(
    port: int,
    path: str,
    body: bytes,
    header_pairs: list[tuple[str, str]],
    *,
    timeout_s: float = DEFAULT_RESPONSE_TIMEOUT_S,
) -> Response:
    """Write an HTTP/1.1 request by hand and read the whole response.

    No client library, because every client library exists to stop you sending
    exactly these requests — `httpx` raises `LocalProtocolError: Illegal header value
    b'read_file '` on the OWS rows and refuses the embedded-CR ones outright. That
    refusal is correct behaviour for a conforming client and fatal for a corpus: the
    attacker is not using a conforming client, and a harness that can only send what
    a well-behaved library permits cannot express the attack it exists to test.

    `Connection: close` means the response ends at EOF, so no keep-alive framing has
    to be reimplemented here. Header values are latin-1 encoded to match RFC 9110's
    octet model — that is how a CR or a high byte reaches the server rather than
    raising in the encoder.

    EVERY PHASE IS BOUNDED, and a timeout is RETURNED rather than raised. Reading
    until EOF with no ceiling means one wedged gateway — `FIXTURE_MODE=hang`, a
    deadlock, a child that never answers — stops the entire corpus run rather than
    failing one row. Raising would be nearly as bad: the exception would unwind
    through `run_corpus` and the 65 rows after it would never be scored, so a hang in
    row 1 and a hang in row 66 would produce equally empty evidence. One row's silence
    is a result about that row (`clients.NO_RESPONSE`, which no scenario expects and
    which therefore always scores FAIL).
    """
    lines = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{port}"]
    lines += [f"{k}: {v}" for k, v in header_pairs]
    lines += [
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body

    chunks: list[bytes] = []
    try:
        with anyio.fail_after(CONNECT_TIMEOUT_S):
            stream = await anyio.connect_tcp("127.0.0.1", port)
        async with stream:
            with anyio.fail_after(timeout_s):
                await stream.send(request)
                try:
                    while chunk := await stream.receive(65536):
                        chunks.append(chunk)
                except anyio.EndOfStream:
                    pass
    except TimeoutError:
        # Whatever arrived before the ceiling is discarded: a partial response is not
        # a response, and scoring half a reply would be worse than scoring none.
        return Response(status=0, body=b"", timed_out=True)
    except OSError as e:
        # Refused, reset, unreachable. A result about this row, not a harness crash.
        return Response(status=0, body=str(e).encode("utf-8", "replace"))

    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    if not head:
        # The server closed without a status line. Reported rather than raised: the
        # caller turns it into an outcome, and a scenario that kills the connection
        # is a result, not a harness error.
        return Response(status=0, body=b"")
    try:
        status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    except (IndexError, ValueError):
        return Response(status=0, body=payload)
    if b"transfer-encoding: chunked" in head.lower():
        payload = _dechunk(payload)
    return Response(status=status, body=payload)


def _dechunk(payload: bytes) -> bytes:
    """The gateway sets no Content-Length, so uvicorn frames replies as chunked.

    A client library would hide this. Writing the request by hand means owning the
    response framing too — 10 lines, versus giving up the ability to send the
    malformed requests that are the entire point.
    """
    out = bytearray()
    while payload:
        size_line, _, rest = payload.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        payload = rest[size + 2 :]  # skip the chunk's trailing CRLF
    return bytes(out)

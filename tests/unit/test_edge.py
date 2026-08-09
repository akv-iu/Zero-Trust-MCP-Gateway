"""Unit 01a acceptance tests - the ASGI client edge.

Driven through the raw ASGI protocol rather than an HTTP client, so the tests
exercise exactly what a server would hand the app: header pairs with duplicates
intact, chunked bodies, and disconnect messages.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from gateway.config import EdgeConfig
from gateway.edge import build_app
from gateway.errors import GatewayDenial, ReasonCode
from gateway.types import RawEnvelope, Untrusted

pytestmark = pytest.mark.anyio

CFG = EdgeConfig(allowed_origins=("http://localhost:3000",), max_message_bytes=1024)


async def echo(env: RawEnvelope) -> Untrusted[dict]:
    """A stub handler. Production wires `pipeline.handle` here instead.

    Injecting the handler keeps the edge testable now WITHOUT adding a passthrough
    mode to production — CONV-001 forbids an undocumented bypass, and a mode you can
    forget to switch off is exactly that.
    """
    return Untrusted({"seen": env.body.decode("utf-8", "replace"),
                      "headers": list(env.metadata),
                      "request_id": env.request_id})


class Capture:
    def __init__(self) -> None:
        self.status: int | None = None
        self.body = b""

    async def __call__(self, message: dict) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        else:
            self.body += message.get("body", b"")

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


def receiver(
    body: bytes = b"{}",
    *,
    chunks: int = 1,
    disconnect: bool = False,
    disconnect_after_s: float | None = None,
):
    """An ASGI receive() double.

    Once the body is drained a REAL server blocks until the client goes away. An
    immediate `http.disconnect` here would make the edge's disconnect watcher fire on
    every request, so the double must block too.
    """
    import anyio as _anyio

    size = max(1, -(-len(body) // chunks))
    parts = [body[i : i + size] for i in range(0, len(body), size)] or [b""]
    queue: list[dict] = [
        {"type": "http.request", "body": p, "more_body": i < len(parts) - 1}
        for i, p in enumerate(parts)
    ]
    if disconnect:
        queue = [{"type": "http.disconnect"}]

    async def receive() -> dict:
        if queue:
            return queue.pop(0)
        if disconnect_after_s is not None:
            await _anyio.sleep(disconnect_after_s)
            return {"type": "http.disconnect"}
        await _anyio.sleep_forever()  # what a real server does
        raise AssertionError("unreachable")

    return receive


def scope(method: str = "POST", path: str = "/mcp", headers: list | None = None) -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers if headers is not None else [],
    }


async def call(app: Any, sc: dict, receive: Any) -> Capture:
    cap = Capture()
    await app(sc, receive, cap)
    return cap


# ===========================================================================
# Happy path
# ===========================================================================


async def test_post_reaches_the_handler() -> None:
    cap = await call(build_app(CFG, echo), scope(), receiver(b'{"jsonrpc":"2.0"}'))
    assert cap.status == 200
    assert cap.json()["seen"] == '{"jsonrpc":"2.0"}'


async def test_raw_body_bytes_arrive_intact() -> None:
    """Unit 02 needs raw bytes for the body hash and duplicate-key detection.
    ASGI supplies them directly - this is what dissolved spike S-1."""
    body = b'{"a": 1, "a": 2}'  # duplicate key preserved for unit 02 to reject
    cap = await call(build_app(CFG, echo), scope(), receiver(body))
    assert cap.json()["seen"] == body.decode()


async def test_chunked_body_is_reassembled() -> None:
    cap = await call(build_app(CFG, echo), scope(), receiver(b'{"x":"abcdef"}', chunks=3))
    assert json.loads(cap.json()["seen"])


async def test_notification_returns_202_with_no_body() -> None:
    async def none_handler(env: RawEnvelope) -> Untrusted[dict]:
        return Untrusted(None)  # type: ignore[arg-type]

    cap = await call(build_app(CFG, none_handler), scope(), receiver())
    assert cap.status == 202 and cap.body == b""


# ===========================================================================
# Header pairs - PROTO-004 depends on this
# ===========================================================================


async def test_duplicate_headers_survive_to_the_envelope() -> None:
    """A Mapping would collapse these and destroy PROTO-004 before unit 02 sees it."""
    cap = await call(
        build_app(CFG, echo),
        scope(headers=[(b"Mcp-Method", b"tools/call"), (b"mcp-method", b"tools/list")]),
        receiver(),
    )
    names = [h[0] for h in cap.json()["headers"]]
    assert names.count("mcp-method") == 2


async def test_header_names_are_lowercased_values_are_not() -> None:
    """RFC 9110: names are case-insensitive, VALUES are case-sensitive."""
    cap = await call(
        build_app(CFG, echo),
        scope(headers=[(b"Mcp-Name", b"Read_File")]),
        receiver(),
    )
    assert ("mcp-name", "Read_File") in [tuple(h) for h in cap.json()["headers"]]


async def test_hostile_header_bytes_do_not_crash_the_edge() -> None:
    cap = await call(
        build_app(CFG, echo), scope(headers=[(b"mcp-name", b"\xff\xfe")]), receiver()
    )
    assert cap.status == 200  # decoded, not crashed; unit 02 rejects it


# ===========================================================================
# Method / path / origin - spec-mandated wire shapes
# ===========================================================================


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_removed_methods_return_405(method: str) -> None:
    """2026-07-28 removed the GET stream and DELETE session teardown."""
    cap = await call(build_app(CFG, echo), scope(method=method), receiver())
    assert cap.status == 405


async def test_unknown_path_returns_404_with_a_modern_jsonrpc_error() -> None:
    """404 + -32601 is what lets a client distinguish a modern server from legacy HTTP+SSE."""
    cap = await call(build_app(CFG, echo), scope(path="/nope"), receiver())
    assert cap.status == 404
    assert cap.json()["error"]["code"] == -32601


async def test_unapproved_origin_is_rejected_with_403() -> None:
    cap = await call(
        build_app(CFG, echo), scope(headers=[(b"origin", b"http://evil.test")]), receiver()
    )
    assert cap.status == 403
    assert cap.json()["error"]["data"]["reason_code"] == "PROTO_ORIGIN_REJECTED"


async def test_approved_origin_passes() -> None:
    cap = await call(
        build_app(CFG, echo),
        scope(headers=[(b"origin", b"http://localhost:3000")]),
        receiver(),
    )
    assert cap.status == 200


async def test_absent_origin_is_allowed() -> None:
    """Non-browser clients send no Origin; the spec validates it only when present."""
    assert (await call(build_app(CFG, echo), scope(), receiver())).status == 200


async def test_duplicate_origin_is_rejected() -> None:
    cap = await call(
        build_app(CFG, echo),
        scope(headers=[(b"origin", b"http://localhost:3000")] * 2),
        receiver(),
    )
    assert cap.status == 403


# ===========================================================================
# Limits and failure shaping
# ===========================================================================


async def test_body_at_the_limit_passes_and_over_it_is_rejected() -> None:
    app = build_app(CFG, echo)
    assert (await call(app, scope(), receiver(b"x" * 1024))).status == 200
    cap = await call(app, scope(), receiver(b"x" * 1025))
    assert cap.status == 413
    assert cap.json()["error"]["data"]["reason_code"] == "PROTO_MESSAGE_TOO_LARGE"


async def test_oversized_chunked_body_aborts_before_full_receipt() -> None:
    """Bounded DURING receive. Buffer-then-measure would turn a size limit into a
    memory-exhaustion vector - exactly what the limit exists to stop."""
    seen = 0

    async def receive() -> dict:
        nonlocal seen
        seen += 1
        return {"type": "http.request", "body": b"x" * 512, "more_body": True}

    cap = await call(build_app(CFG, echo), scope(), receive)
    assert cap.status == 413
    assert seen <= 4, f"read {seen} chunks before aborting - not streaming"


async def test_client_disconnect_is_cancelled_not_error() -> None:
    cap = await call(build_app(CFG, echo), scope(), receiver(disconnect=True))
    assert cap.json()["error"]["data"]["reason_code"] == "ROUTE_CANCELLED"


async def test_handler_denial_is_mapped_to_the_spec_wire_shape() -> None:
    async def denier(env: RawEnvelope) -> Untrusted[dict]:
        raise GatewayDenial(ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH)

    cap = await call(build_app(CFG, denier), scope(), receiver())
    assert cap.status == 400
    assert cap.json()["error"]["code"] == -32020  # HeaderMismatch


async def test_unexpected_exception_becomes_a_controlled_error() -> None:
    """A traceback must never reach the client, and a defect must never allow."""
    async def boom(env: RawEnvelope) -> Untrusted[dict]:
        raise ValueError("internal detail /etc/shadow")

    cap = await call(build_app(CFG, boom), scope(), receiver())
    assert cap.status == 500
    assert "/etc/shadow" not in cap.body.decode()


async def test_error_bodies_never_disclose_internals() -> None:
    for code in (ReasonCode.CANON_OUTSIDE_ROOT, ReasonCode.POLICY_PATH_NOT_PERMITTED):
        async def denier(env: RawEnvelope, c: ReasonCode = code) -> Untrusted[dict]:
            raise GatewayDenial(c, detail="/fixture/confidential/salaries.csv")

        cap = await call(build_app(CFG, denier), scope(), receiver())
        assert "confidential" not in cap.body.decode()
        assert cap.json()["error"]["data"]["request_id"]


async def test_every_request_gets_a_unique_id() -> None:
    app = build_app(CFG, echo)
    ids = {(await call(app, scope(), receiver())).json()["request_id"] for _ in range(20)}
    assert len(ids) == 20


async def test_concurrency_is_bounded() -> None:
    import anyio

    cfg = EdgeConfig(max_concurrent_requests=2)
    peak = 0
    live = 0

    async def slow(env: RawEnvelope) -> Untrusted[dict]:
        nonlocal peak, live
        live += 1
        peak = max(peak, live)
        await anyio.sleep(0.01)
        live -= 1
        return Untrusted({})

    app = build_app(cfg, slow)
    async with anyio.create_task_group() as tg:
        for _ in range(8):
            tg.start_soon(call, app, scope(), receiver())
    assert peak <= 2, f"peak concurrency {peak} exceeded the configured 2"


# ===========================================================================
# Review follow-ups: deadline scope and mid-request disconnect
# ===========================================================================


async def test_disconnect_during_the_handler_is_detected() -> None:
    """FIX-3. Watching for http.disconnect only while READING the body is not enough:
    a client that vanishes mid-request would otherwise be invisible, the upstream call
    would run to completion, and the audit event would say `error` rather than
    `cancelled` (ROUTE-010)."""
    import anyio

    started = anyio.Event()

    async def slow(env: RawEnvelope) -> Untrusted[dict]:
        started.set()
        await anyio.sleep(5)  # still working when the client goes away
        return Untrusted({"never": "returned"})

    cap = await call(
        build_app(CFG, slow), scope(), receiver(disconnect_after_s=0.05)
    )
    assert started.is_set(), "the handler never ran"
    assert cap.json()["error"]["data"]["reason_code"] == "ROUTE_CANCELLED"


async def test_slow_client_cannot_hold_the_connection_open() -> None:
    """FIX-2. The deadline must cover the BODY READ, which is the part an attacker
    controls. Starting it after the read leaves a slow-loris client unbounded."""
    import anyio

    cfg = EdgeConfig(request_timeout_s=0.2, max_message_bytes=10_000_000)

    async def trickle() -> dict:
        await anyio.sleep(0.05)
        return {"type": "http.request", "body": b"x", "more_body": True}

    with anyio.fail_after(5):
        cap = await call(build_app(cfg, echo), scope(), trickle)
    assert cap.json()["error"]["data"]["reason_code"] == "ROUTE_TIMEOUT"


async def test_handler_timeout_is_bounded_too() -> None:
    import anyio

    cfg = EdgeConfig(request_timeout_s=0.2)

    async def slow(env: RawEnvelope) -> Untrusted[dict]:
        await anyio.sleep(5)
        return Untrusted({})

    with anyio.fail_after(5):
        cap = await call(build_app(cfg, slow), scope(), receiver())
    assert cap.json()["error"]["data"]["reason_code"] == "ROUTE_TIMEOUT"

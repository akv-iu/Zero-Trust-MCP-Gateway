"""01a - Client-facing edge: Streamable HTTP on loopback.

Spec: _specs/01-svc-stdio-bridge.md   Tech: _tech/01-svc-stdio-bridge.md §1a
Transport decision: _specs/ADR-001-transport-and-mirrored-metadata.md

A bare ASGI callable. No FastAPI, no routing framework — there is exactly one path
and one method, and a framework would add dependencies to gain nothing.

Everything unit 02 needs arrives here for free: the raw body bytes and the full
header PAIR list (duplicates intact, which a mapping could not represent).

This is NOT an authentication boundary. Identity stays local-config /
unverified_local (IDENT-002). `Origin` validation and the loopback bind are
DNS-rebinding defences that the specification mandates, nothing more.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable
from uuid import uuid4

import anyio

from gateway.config import EdgeConfig
from gateway.errors import (
    GatewayDenial,
    ReasonCode,
    TransportDenial,
    safe_message,
    wire_shape,
)
from gateway.types import RawEnvelope, Untrusted

Handler = Callable[[RawEnvelope], Awaitable[Untrusted[dict]]]

_JSON = [(b"content-type", b"application/json")]


class Edge:
    """ASGI application. One endpoint, POST only."""

    def __init__(self, cfg: EdgeConfig, handler: Handler) -> None:
        self.cfg = cfg
        self.handler = handler
        self._slots = anyio.Semaphore(cfg.max_concurrent_requests)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return  # lifespan and websocket are not served
        request_id = uuid4().hex
        try:
            await self._handle(scope, receive, send, request_id)
        except GatewayDenial as d:
            await _error(send, d.reason_code, request_id)
        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            await _error(send, ReasonCode.INTERNAL_ERROR, request_id)

    async def _handle(self, scope: dict, receive: Any, send: Any, rid: str) -> None:
        # The deadline covers EVERYTHING, body read included. Starting it after the
        # body would let a slow-loris client trickle bytes and hold a connection
        # indefinitely — the read is exactly the part an attacker controls.
        try:
            with anyio.fail_after(self.cfg.request_timeout_s):
                await self._dispatch(scope, receive, send, rid)
        except TimeoutError:
            await _error(send, ReasonCode.ROUTE_TIMEOUT, rid)

    async def _dispatch(self, scope: dict, receive: Any, send: Any, rid: str) -> None:
        method = scope.get("method", "")
        headers = _pairs(scope.get("headers", ()))

        # 2026-07-28 removed the GET stream and DELETE session teardown entirely.
        if method in ("GET", "DELETE"):
            return await _error(send, ReasonCode.PROTO_METHOD_NOT_ALLOWED, rid, status=405)
        if method != "POST":
            return await _error(send, ReasonCode.PROTO_METHOD_NOT_ALLOWED, rid, status=405)
        if scope.get("path") != self.cfg.mcp_path:
            return await _error(send, ReasonCode.PROTO_METHOD_NOT_ALLOWED, rid, status=404)
        if not self._origin_ok(headers):
            return await _error(send, ReasonCode.PROTO_ORIGIN_REJECTED, rid)

        body = await self._read_body(receive)

        async with self._slots:
            env = RawEnvelope(
                request_id=rid,
                received_at_ns=_now_ns(),
                body=body,
                metadata=headers,
            )
            result = await self._run_watching_for_disconnect(env, receive)

        payload = result.unwrap()  # the ONE unwrap on the response path (RESP-005)
        if payload is None:
            # A JSON-RPC notification the server accepted: 202, no body.
            return await _send(send, 202, b"")
        await _send(send, 200, json.dumps(payload).encode("utf-8"))

    async def _run_watching_for_disconnect(
        self, env: RawEnvelope, receive: Any
    ) -> Untrusted[dict]:
        """Run the handler while watching for the client going away.

        Reading `http.disconnect` only while consuming the body is not enough: a
        client that vanishes mid-request would otherwise be invisible, the upstream
        call would run to completion, and the audit event would say `error` instead
        of `cancelled`. ROUTE-010 requires those to stay distinguishable, and a
        cancelled request must reach unit 07 so it can cancel the child.
        """
        result: Untrusted[dict] | None = None
        failure: BaseException | None = None
        disconnected = False

        async def watch() -> None:
            nonlocal disconnected
            while True:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    disconnected = True
                    tg.cancel_scope.cancel()
                    return

        async def work() -> None:
            nonlocal result, failure
            try:
                result = await self.handler(env)
            except BaseException as e:  # noqa: BLE001 - re-raised below, outside the group
                failure = e
            finally:
                tg.cancel_scope.cancel()

        async with anyio.create_task_group() as tg:
            tg.start_soon(watch)
            tg.start_soon(work)

        if disconnected:
            raise TransportDenial(ReasonCode.ROUTE_CANCELLED)
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def _origin_ok(self, headers: tuple[tuple[str, str], ...]) -> bool:
        """Validate when present; absent is permitted (non-browser clients)."""
        origins = [v for k, v in headers if k == "origin"]
        if not origins:
            return True
        if len(origins) > 1:
            return False
        return origins[0] in self.cfg.allowed_origins

    async def _read_body(self, receive: Any) -> bytes:
        """Bounded during receive (BRIDGE-003) - never buffer then measure."""
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise TransportDenial(ReasonCode.ROUTE_CANCELLED)
            chunks.append(message.get("body", b""))
            total += len(chunks[-1])
            if total > self.cfg.max_message_bytes:
                raise TransportDenial(ReasonCode.PROTO_MESSAGE_TOO_LARGE)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)


def _pairs(raw: Any) -> tuple[tuple[str, str], ...]:
    """ASGI header pairs, names lowercased, ORDER AND DUPLICATES PRESERVED.

    Collapsing to a mapping here would destroy PROTO-004 before unit 02 could see it.
    latin-1 is the HTTP header encoding; it never raises, so a hostile byte becomes a
    character unit 02 rejects rather than a decode crash here.
    """
    return tuple(
        (k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in raw
    )


async def _send(send: Any, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": _JSON})
    await send({"type": "http.response.body", "body": body})


async def _error(
    send: Any, code: ReasonCode, request_id: str, *, status: int | None = None
) -> None:
    """Wire shapes are spec-mandated, not free choices (ADR-001 §2).

    `request_id` is included so a user can correlate a denial to an audit record;
    it discloses nothing.
    """
    http, rpc = wire_shape(code)
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": rpc,
                "message": safe_message(code),
                "data": {"reason_code": code.value, "request_id": request_id},
            },
        }
    ).encode("utf-8")
    await _send(send, status or http, body)


def _now_ns() -> int:
    import time

    return time.perf_counter_ns()


def build_app(cfg: EdgeConfig, handler: Handler) -> Edge:
    return Edge(cfg, handler)


async def serve(cfg: EdgeConfig, handler: Handler) -> None:  # pragma: no cover
    """Run under uvicorn. Loopback only; the config validator refuses anything else."""
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(
            build_app(cfg, handler),
            host=cfg.host,
            port=cfg.port,
            log_level="error",  # access logs would echo paths into the diagnostic sink
            access_log=False,
        )
    )
    await server.serve()

"""01b - Upstream leg: spawn, supervise, and talk to the child MCP server over stdio.

Spec: _specs/01-svc-stdio-bridge.md   Tech: _tech/01-svc-stdio-bridge.md §1b

The child's executable, argv, cwd and environment come from configuration and ONLY
from configuration (BRIDGE-007). There is no code path from an MCP message to a
process launch parameter.

Only `router.py` (unit 07) calls through this handle. The edge never touches it.
"""

from __future__ import annotations

import codecs
import os
import threading
from collections import deque
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, suppress
from typing import Any, cast

import anyio
import mcp_types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError

from gateway.config import ChildConfig
from gateway.errors import GatewayDenial, ReasonCode, RouteDenial

MAX_STDERR_LINE = 2048
STDERR_CHUNK = 4096
TRUNCATED = " ...[truncated]"


def append_line(ring: deque[str], line: str) -> None:
    """Bounded append. A child emitting one endless line must not exhaust memory."""
    ring.append(line.rstrip("\r\n")[:MAX_STDERR_LINE])


def _drain_stderr(read_fd: int, ring: deque[str]) -> None:
    """Consume the child's stderr until EOF.

    `errlog` is handed to `subprocess`, so it must be a real file descriptor — a
    Python object with `.write()` is not enough. Hence a pipe plus this drainer.

    An UNDRAINED stderr pipe fills its OS buffer and deadlocks the child, which is a
    classic and very confusing hang (BRIDGE-010).

    Chunked rather than `for line in stream`: iterating by line buffers until a
    newline arrives, so a child writing an endless newline-less stream grows the
    reader without bound. The deque's maxlen does not help there — nothing is ever
    appended, so the bound that exists never engages. A runaway line is cut at
    MAX_STDERR_LINE and emitted immediately, then its tail is discarded until the next
    newline; that caps residency at STDERR_CHUNK + MAX_STDERR_LINE, keeps the HEAD of
    the line (where the message is), and costs the ring exactly one entry however long
    the child raves. Discarding the tail of a misbehaving child's stderr is not a loss.

    `os.read` rather than a text stream's `.read(n)`: the latter blocks until it has n
    CHARACTERS, so a child that logs one short line at startup and then goes quiet
    would leave the ring empty for as long as it stayed up. Decoding incrementally
    also keeps a multi-byte character split across a chunk boundary intact.
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buf, overlong = "", False
    try:
        while data := os.read(read_fd, STDERR_CHUNK):
            buf += decoder.decode(data)
            while (nl := buf.find("\n")) >= 0:
                if not overlong:
                    append_line(ring, buf[:nl])
                buf, overlong = buf[nl + 1 :], False
            if len(buf) > MAX_STDERR_LINE:
                if not overlong:
                    # Leave room for the marker: `append_line` truncates to
                    # MAX_STDERR_LINE and would otherwise cut it straight off again.
                    append_line(ring, buf[: MAX_STDERR_LINE - len(TRUNCATED)] + TRUNCATED)
                buf, overlong = "", True
        if buf and not overlong:
            append_line(ring, buf)
    except (OSError, ValueError):
        pass  # pipe closed during teardown
    finally:
        with suppress(OSError):
            os.close(read_fd)


def _upstream_error(exc: MCPError) -> RouteDenial:
    """Map a protocol-level upstream error onto a reason code.

    BRIDGE-011: a crashed child must deny AT THE CALL SITE. The SDK reports it as
    `MCPError(CONNECTION_CLOSED)`, not as a broken anyio stream — catching only the
    stream errors let a raw MCPError reach the caller, and the clean denial appeared
    only later when the whole child context unwound. By then the caller has already
    seen something it was promised it never would.
    """
    if exc.code == mcp_types.REQUEST_TIMEOUT:
        return RouteDenial(ReasonCode.ROUTE_TIMEOUT, detail=f"upstream: {exc.message}")
    return RouteDenial(
        ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE,
        detail=f"upstream error {exc.code}: {exc.message}",
    )


def _as_denial(exc: BaseException) -> GatewayDenial | None:
    """Unwrap anyio ExceptionGroups.

    The SDK runs the child inside task groups, so a crashed child surfaces as a
    nested BaseExceptionGroup. Leaking that to the caller violates the promise that
    an upstream failure is a clean, reason-coded denial. If the group carries one of
    OUR denials (raised by the caller inside the `with` block), that one wins.
    """
    if isinstance(exc, GatewayDenial):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", exc)
        for nested in group.exceptions:
            found = _as_denial(nested)
            if found is not None:
                return found
    return None


class UpstreamHandle:
    """The single upstream execution path (BRIDGE-012, ARCH-005).

    Calls are serialised by a lock. At v1 scale that is correct and it removes a
    whole class of response-correlation bug; the oracle's offset-window correlation
    also depends on it (see harness.oracle.assert_serialised).

    # ponytail: one lock, one in-flight upstream call. Multiplex per request id only
    # if the benchmark shows upstream contention.
    """

    def __init__(self, session: ClientSession, stderr: deque[str]) -> None:
        self._session = session
        self._lock = anyio.Lock()
        self.stderr = stderr
        self.alive = True

    @property
    def session(self) -> ClientSession:
        return self._session

    def diagnostics(self) -> list[str]:
        """The child's recent stderr, for the diagnostic sink. Never audited."""
        return list(self.stderr)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if not self.alive:
            raise RouteDenial(ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE)
        async with self._lock:
            return await self._guarded(self._session.call_tool(name, arguments))

    async def list_tools(self) -> Any:
        async with self._lock:
            return await self._guarded(self._session.list_tools())

    async def _guarded(self, awaitable: Any) -> Any:
        """Every upstream call exits as a result or as a reason-coded RouteDenial.

        A tool that merely FAILS still returns a result with `is_error=True` and comes
        back through here untouched — that is the upstream's answer, and unit 08's
        problem. What this converts is the transport dying underneath us.
        """
        try:
            return await awaitable
        except GatewayDenial:
            raise
        except MCPError as e:
            # BRIDGE-011: a dead child denies here and now. It is never restarted
            # mid-request and completed as though nothing happened.
            if e.code == mcp_types.CONNECTION_CLOSED:
                self.alive = False
            raise _upstream_error(e) from e
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError) as e:
            self.alive = False
            raise RouteDenial(
                ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE, detail=f"stdio: {e!r}"
            ) from e

    async def cancel(
        self, request_id: str | int, reason: str = "client disconnected"
    ) -> bool:
        """Translate an edge-side disconnect into stdio's cancellation notification.

        Transport asymmetry (ADR-001 §4): on Streamable HTTP the client cancels by
        closing the SSE stream; on stdio `notifications/cancelled` is mandatory. The
        gateway bridges the two.

        Returns whether the notification was sent, so a caller can audit the
        difference between "cancelled upstream" and "gave up locally". A silently
        swallowed failure here would make the audit trail lie.
        """
        if not self.alive:
            # Writing to a torn-down stream can succeed into a buffer nobody reads,
            # which would report a cancellation that never reached the child.
            return False
        # ClientNotification is a union ALIAS in mcp_types, not a wrapper class —
        # calling it raises TypeError. Send the concrete notification directly.
        notification = mcp_types.CancelledNotification(
            method="notifications/cancelled",
            params=mcp_types.CancelledNotificationParams(
                request_id=request_id, reason=reason
            ),
        )
        try:
            await self._session.send_notification(notification)
            return True
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
            # The child is already gone; the request fails regardless.
            self.alive = False
            return False


def _child_env(cfg: ChildConfig) -> dict[str, str]:
    """BRIDGE-006: constructed from an allowlist, never inherited.

    Passing an explicit dict matters — the SDK inherits the full environment when
    `env` is None, which would leak GROQ_API_KEY to the child in v1.1.
    """
    return {k: os.environ[k] for k in cfg.env_allowlist if k in os.environ}


@asynccontextmanager
async def upstream(cfg: ChildConfig) -> AsyncGenerator[UpstreamHandle]:
    """Spawn the child, complete the handshake, yield a handle, tear it down.

    Every failure path out of here is a RouteDenial with a reason code. Callers
    never see an ExceptionGroup, an OSError, or a TimeoutError.
    """
    ring: deque[str] = deque(maxlen=cfg.stderr_capture_lines)
    read_fd, write_fd = os.pipe()
    errlog = os.fdopen(write_fd, "w", encoding="utf-8", errors="replace", buffering=1)
    drainer = threading.Thread(
        target=_drain_stderr, args=(read_fd, ring), daemon=True, name="child-stderr"
    )
    drainer.start()

    params = StdioServerParameters(
        command=cfg.executable,
        args=list(cfg.args),  # a LIST, never a joined string: no shell interpolation
        env=_child_env(cfg),
        cwd=cfg.cwd,
    )

    handed_off = False
    try:
        async with (
            stdio_client(params, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            try:
                with anyio.fail_after(cfg.startup_timeout_s):
                    await _handshake(session)
            except (TimeoutError, Exception) as e:
                # BRIDGE-008: never become ready; never serve protected requests.
                raise RouteDenial(
                    ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE,
                    detail=f"handshake failed: {e!r}; stderr={list(ring)[-5:]}",
                ) from e

            handle = UpstreamHandle(session, ring)
            handed_off = True
            try:
                yield handle
            finally:
                handle.alive = False
    except GatewayDenial:
        raise
    except BaseException as e:
        # A caller's own denial raised inside the `with` block must survive intact.
        inner = _as_denial(e)
        if inner is not None:
            raise inner from e
        raise RouteDenial(
            ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE,
            detail=f"{'child failed' if handed_off else 'spawn failed'}: {e!r}; "
            f"stderr={list(ring)[-5:]}",
        ) from e
    finally:
        # Closing the write end gives the drainer EOF so its thread can exit.
        with suppress(OSError, ValueError):
            errlog.close()
        drainer.join(timeout=1.0)


async def _handshake(session: ClientSession) -> None:
    """Modern era has no `initialize`; `server/discover` is the probe (ADR-001 §2).

    Falls back to `initialize` for a legacy server, which is exactly the era-probe
    the specification describes.
    """
    try:
        await session.discover()
    except Exception:  # noqa: BLE001 - legacy server, or discover unsupported
        await session.initialize()

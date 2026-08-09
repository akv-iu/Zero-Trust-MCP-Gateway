"""07 - Obligation enforcement and forwarding. The only unit that can cause a side effect.

Spec: _specs/07-svc-upstream-router.md   Tech: _tech/07-svc-upstream-router.md
Owner: wave 3.

This module MUST NOT import open/Path/os/shutil/socket/httpx/subprocess (ROUTE-003).
scripts/check_router_isolation.sh enforces it in CI.

OPEN: WRITE-AHEAD AUDIT (unit 03 review). `pipeline.handle` writes its event in a
`finally`, so it runs AFTER `forward`. If the sink fails once a mutating call has
reached the child, the client is correctly told the request failed while the effect
has already happened and no record of it survives — AUDIT-009 asks for the operation
to be denied when its event cannot be persisted, which holds for reads and not for
writes. The fix is the paired shape the fixture's own op-log already uses: an
attempt record before the call, a terminal record after. It belongs here because
this is the only stage that knows a side effect is about to occur.
See `docs/threat-model.md` §2.3 and `_specs/90-deferred-register.md` §10b.

OPEN WIRING (unit 01 review, finding 8): both ends of cancellation exist and neither
is connected, because the connection belongs here.

  * `edge.py` detects the client vanishing and raises `ROUTE_CANCELLED`.
  * `bridge.UpstreamHandle.cancel()` sends `notifications/cancelled` and returns
    whether it actually reached the child.

`forward` is the only place that holds both at once. When a forwarded call is
cancelled it must call `cancel()` with THIS request's JSON-RPC id, wait up to
`cfg.cancellation_grace_ms`, and audit the returned bool — an audit claiming an
upstream cancellation that was never delivered is worse than one admitting the
request was abandoned locally while the side effect may still have landed.
"""

from __future__ import annotations

from typing import Any

from gateway.config import RouterConfig
from gateway.types import CanonicalRequest, Decision, DerivedAttributes, RawResult


async def forward(
    req: CanonicalRequest,
    drv: DerivedAttributes,
    dec: Decision,
    upstream: Any,
    cfg: RouterConfig,
) -> RawResult:
    """Forward iff `dec` is a validated allow for THIS request_id (ROUTE-001)."""
    raise NotImplementedError("wave 3")

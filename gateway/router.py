"""07 - Obligation enforcement and forwarding. The only unit that can cause a side effect.

Spec: _specs/07-svc-upstream-router.md   Tech: _tech/07-svc-upstream-router.md
Owner: wave 3.

This module MUST NOT import open/Path/os/shutil/socket/httpx/subprocess (ROUTE-003).
scripts/check_router_isolation.sh enforces it in CI.
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

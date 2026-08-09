"""06 - OPA integration, input/result contract, fail-closed.

Spec: _specs/06-svc-policy-broker.md   Tech: _tech/06-svc-policy-broker.md
Owner: wave 2, agent F.
"""

from __future__ import annotations

from typing import Any

from gateway.config import PolicyConfig
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    Decision,
    DerivedAttributes,
    ResolvedTarget,
)


async def evaluate(
    req: CanonicalRequest,
    ctx: AuthzContext,
    tgt: ResolvedTarget,
    drv: DerivedAttributes,
    opa: Any,
    cfg: PolicyConfig,
) -> Decision:
    """Ask OPA. Anything other than a well-formed allow denies (POLICY-005/010)."""
    raise NotImplementedError("wave 2, agent F")

"""03 - Principal derivation and authorization context.

Spec: _specs/03-svc-identity-resolver.md   Tech: _tech/03-svc-identity-resolver.md
Owner: wave 3 (small).
"""

from __future__ import annotations

from gateway.config import IdentityConfig
from gateway.types import AuthzContext, CanonicalRequest


def resolve(req: CanonicalRequest, cfg: IdentityConfig) -> AuthzContext:
    """Return the process identity. MUST NOT read `req` (IDENT-003)."""
    raise NotImplementedError("wave 3")

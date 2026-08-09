"""02 - JSON-RPC hardening + mirrored-metadata consistency. THE DIFFERENTIATOR.

Spec: _specs/02-svc-protocol-guard.md   Tech: _tech/02-svc-protocol-guard.md
Owner: wave 1, agent C.
"""

from __future__ import annotations

from gateway.config import ProtocolConfig
from gateway.types import CanonicalRequest, RawEnvelope


def validate(env: RawEnvelope, cfg: ProtocolConfig) -> CanonicalRequest:
    """Raw envelope -> canonical request, or raise ProtocolDenial.

    Order is fixed (_tech/02 section 1): prescan, parse, structural limits, envelope,
    version, method allowlist, metadata consistency, build. Nothing before the
    consistency check may route, look up the registry, or evaluate policy (PROTO-002).
    """
    raise NotImplementedError("wave 1, agent C")

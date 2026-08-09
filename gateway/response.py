"""08 - Upstream response validation and bounding.

Spec: _specs/08-svc-response-guard.md   Tech: _tech/08-svc-response-guard.md
Owner: wave 3.
"""

from __future__ import annotations

from gateway.config import ResponseConfig
from gateway.types import CanonicalRequest, Obligations, RawResult, Untrusted


def validate(
    raw: RawResult, req: CanonicalRequest, ob: Obligations, cfg: ResponseConfig
) -> Untrusted[dict]:
    """Accept, bound, label. MUST NOT mutate accepted content (RESP-008)."""
    raise NotImplementedError("wave 3")

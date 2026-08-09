"""05 - Filesystem path canonicalization and derived policy attributes.

Spec: _specs/05-svc-canonicalizer-fs.md   Tech: _tech/05-svc-canonicalizer-fs.md
Owner: wave 1, agent D.

NOTE: the primary filesystem control is the sandbox mount (unit 10). This module is
defense in depth and a policy-input requirement. It does NOT claim TOCTOU safety.
"""

from __future__ import annotations

from gateway.config import CanonicalizeConfig
from gateway.types import CanonicalRequest, DerivedAttributes, ResolvedTarget


def derive(
    req: CanonicalRequest, tgt: ResolvedTarget, cfg: CanonicalizeConfig
) -> DerivedAttributes:
    """Supplied path -> canonical identity + derived attributes, or raise.

    Every ambiguity is a denial. This module never repairs input (CANON-002).
    """
    raise NotImplementedError("wave 1, agent D")

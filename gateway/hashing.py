"""One canonical serialization, so every hash in the project is comparable.

`_tech/00-conventions.md` §6. Used by argument hashes, body hashes, schema
fingerprints, and the harness's tree hashing.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final, cast

FINGERPRINT_VERSION: Final[str] = "v2"
"""Normalization rule version. Changing the rule bumps this so stored fingerprints
are migrated deliberately rather than silently invalidated (REG-005).

**v2** — `registry.normalize` stopped substituting a typed empty for an absent
optional field and now omits the key instead, so an *absent* `outputSchema` no longer
hashes identically to a *present empty* one. v1 values are not comparable and every
stored fingerprint was regenerated with `scripts/fingerprint_tools.py`.

The bump is the point of the prefix and it was nearly missed: the rule changed while
this string still said v1, which would have made a v1 fingerprint and a v2 fingerprint
of the same tool silently incomparable rather than loudly so.
`test_registry.py::test_the_version_prefix_tracks_the_normalization_rule` pins a
golden value per version, so changing the rule without changing this string fails."""


def _encodable(o: Any) -> dict[str, Any]:
    """`CanonicalRequest.arguments` is deep-frozen, and `json` does not know
    `MappingProxyType` (it is not a `dict` subclass). Tuples it already writes as
    arrays, so only mappings need the hop. Hashing a frozen structure must give the
    same digest as hashing the dict it was built from."""
    if isinstance(o, Mapping):
        return dict(cast("Mapping[str, Any]", o))
    raise TypeError(f"not JSON serializable: {type(o).__name__}")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, tight separators, no NaN/Infinity.

    ``allow_nan=False`` matters — NaN and Infinity are not JSON and must never
    enter a fingerprint or an argument hash.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_encodable,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """sha256 over the canonical serialization of ``obj``."""
    return sha256_hex(canonical_json(obj))


def fingerprint(obj: Any) -> str:
    """Versioned fingerprint, e.g. ``v1:3f2a...`` (REG-005)."""
    return f"{FINGERPRINT_VERSION}:{hash_obj(obj)}"


def argument_hash(arguments: Mapping[str, Any], canonical_path: str) -> str:
    """What policy authorised, as one value. CANON-011, compared again by ROUTE-002.

    Lives here rather than in unit 05 so that unit 07 can recompute it without
    importing the canonicalizer, which owns filesystem access the router must not
    have (ROUTE-003). One function, two callers, and that is the whole point:
    `_tech/07` §2 warns that recomputing the rule at the router from a *different*
    source makes the comparison agree with itself. The inputs are re-read at stage
    07 — the arguments about to be forwarded, against the path stage 05 resolved —
    so a mutation between the two stages breaks the hash instead of travelling.

    `canonical_path` is "" for a request that names no resource (`tools/list`), and
    the key is still present: dropping it for that case would give one shape for
    discovery and another for calls, and the router would need to know which it was
    holding before it could check anything.
    """
    return hash_obj({**arguments, "canonical_path": canonical_path})

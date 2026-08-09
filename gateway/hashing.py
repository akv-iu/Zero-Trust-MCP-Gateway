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

FINGERPRINT_VERSION: Final[str] = "v1"
"""Normalization rule version. Changing the rule bumps this so stored fingerprints
are migrated deliberately rather than silently invalidated (REG-005)."""


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

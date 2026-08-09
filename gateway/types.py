"""Shared types. Imports nothing from `gateway.*` except `errors`.

`_tech/00-conventions.md` §3, amended by `_specs/ADR-001-transport-and-mirrored-metadata.md`.

Every model is frozen with ``extra="forbid"``. Immutability is the enforcement
mechanism for PROTO-006 (one canonical authority) and IDENT-002 (identity may not
be overstated) — not a convention.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, field_validator

type RequestId = str
"""uuid4().hex — unguessable and unique. Sortability is not required."""

Operation = Literal["read", "create", "overwrite", "append", "rename", "delete"]
RiskTier = Literal["R0", "R1", "R2", "R4"]  # R3 is not implemented in v1 (CONV-007)

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class RawEnvelope(BaseModel):
    """01 -> 02 only. MUST NOT be reachable from any stage after 02 (PROTO-006)."""

    model_config = _FROZEN

    request_id: RequestId
    received_at_ns: int
    body: bytes
    metadata: tuple[tuple[str, str], ...]
    """Header pairs, names lowercased, order preserved.

    A tuple of pairs rather than a mapping so duplicate mirrored headers stay
    visible (PROTO-004). A mapping cannot represent them; ASGI supplies pairs.
    """

    def header_values(self, name: str) -> tuple[str, ...]:
        return tuple(v for k, v in self.metadata if k == name.lower())


class CanonicalRequest(BaseModel):
    """02 -> everything. The single authority for method, name, and arguments."""

    model_config = _FROZEN

    request_id: RequestId
    protocol_version: str
    method: str
    jsonrpc_id: str | int | None
    tool_name: str | None
    arguments: Mapping[str, Any]
    body_hash: str

    @field_validator("arguments", mode="after")
    @classmethod
    def _freeze(cls, v: Mapping[str, Any]) -> Mapping[str, Any]:
        # frozen=True stops rebinding, not mutation of a held dict.
        return MappingProxyType(dict(v))


class AuthzContext(BaseModel):
    """03. The literals below are the security control — see `_tech/03` §2."""

    model_config = _FROZEN

    principal: str
    client_id: str
    roles: tuple[str, ...]
    auth_method: Literal["local_config"]
    assurance: Literal["unverified_local"]
    transport: Literal["streamable_http"]
    environment: str


class ResolvedTarget(BaseModel):
    """04."""

    model_config = _FROZEN

    server_id: str
    tool_name: str
    schema_fingerprint: str
    registry_risk_tier: RiskTier
    operation: Operation


class DerivedAttributes(BaseModel):
    """05. What policy evaluates. The raw supplied path never reaches policy."""

    model_config = _FROZEN

    canonical_path: str
    root: str
    operation: Operation
    classification: str
    exists: bool
    arg_hash: str
    raw_hash: str


class Obligations(BaseModel):
    """06 -> 07. Policy may narrow these; never widen past the gateway ceiling."""

    model_config = _FROZEN

    timeout_ms: int
    max_response_bytes: int


class Decision(BaseModel):
    """06 -> 07. Carries request_id so ROUTE-001 is a typed check, not an audit."""

    model_config = _FROZEN

    request_id: RequestId
    decision: Literal["allow", "deny"]
    reason_code: str
    risk_tier: RiskTier
    policy_revision: str
    obligations: Obligations
    arg_hash: str
    """The value policy actually saw. 07 compares against it (ROUTE-002)."""
    clamped: bool = False


class RawResult(BaseModel):
    """07 -> 08."""

    model_config = _FROZEN

    content: Any
    is_error: bool
    byte_count: int
    upstream_latency_ns: int


@dataclass(frozen=True)
class Untrusted[T]:
    """Attacker-influenced content. 08 -> client, and 08 -> 12 in v1.1.

    ``__str__`` raises deliberately: an f-string, log line, or prompt template that
    touches tool content without an explicit ``unwrap()`` fails loudly at the point
    of the mistake instead of silently interpolating attacker text (RESP-005,
    AGENT-010). There should be exactly one ``unwrap()`` call site per consumer.
    """

    value: T

    def unwrap(self) -> T:
        return self.value

    def __str__(self) -> str:
        raise TypeError("Untrusted content must be explicitly unwrapped")

    __repr__ = __str__

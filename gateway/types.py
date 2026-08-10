"""Shared types. Imports nothing from `gateway.*` except `errors`.

`_tech/00-conventions.md` §3, amended by
`_specs/ADR-001-transport-and-mirrored-metadata.md`.

Every model is frozen with ``extra="forbid"``. Immutability is the enforcement
mechanism for PROTO-006 (one canonical authority) and IDENT-002 (identity may not
be overstated) — not a convention.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

type RequestId = str
"""uuid4().hex — unguessable and unique. Sortability is not required."""

type JsonObject = dict[str, Any]
"""A decoded JSON object. Spelled once so `dict` never appears bare in a signature —
under pyright strict a bare `dict` poisons every value derived from it."""

Operation = Literal["read", "create", "overwrite", "append", "rename", "delete"]
RiskTier = Literal["R0", "R1", "R2", "R4"]  # R3 is not implemented in v1 (CONV-007)

_FROZEN = ConfigDict(frozen=True, extra="forbid")


def deep_freeze(v: Any) -> Any:
    """Recursively make decoded JSON immutable.

    `MappingProxyType(dict(v))` freezes only the TOP level: given
    ``{"opts": {"path": "safe"}}`` the inner dict is still writable, so a later stage
    could edit an argument after policy evaluated it and `arg_hash` would no longer
    describe what unit 07 sends upstream. That is precisely the time-of-check /
    time-of-use gap the frozen models exist to close, so the freeze has to go all the
    way down.

    Lists become tuples: a JSON array is data here, never a buffer to append to.
    """
    if isinstance(v, Mapping):
        items = cast("Mapping[str, Any]", v)
        return MappingProxyType({k: deep_freeze(x) for k, x in items.items()})
    if isinstance(v, list | tuple):
        return tuple(deep_freeze(x) for x in cast("list[Any]", v))
    return v


def thaw(v: Any) -> Any:
    """Inverse of `deep_freeze`, for the consumers that require plain JSON types.

    `jsonschema` resolves ``"type": "array"`` against `list` and ``"object"`` against
    `dict`, so a frozen structure fails validation for the wrong reason. The OPA
    request body needs the same. Call this AT the boundary and never store the result.
    """
    if isinstance(v, Mapping):
        items = cast("Mapping[str, Any]", v)
        return {k: thaw(x) for k, x in items.items()}
    if isinstance(v, list | tuple):
        return [thaw(x) for x in cast("list[Any]", v)]
    return v


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
    mcp_param_headers: Mapping[str, str] = Field(default_factory=dict)
    """The `Mcp-Param-*` headers, names lowercased. The ONE exception to "no
    transport data past stage 02", and it is carried rather than re-read.

    This family cannot be checked at stage 02: which arguments are mirrored is
    declared by `x-mcp-header` inside the APPROVED `inputSchema`, which only unit 04
    resolves (ADR-001 §3.1). Stage 04 still runs before policy and the router, so
    PROTO-002 holds. Only this family is carried — handing on `RawEnvelope` would
    give every later stage a second, unvalidated view of the request, which is the
    split-authorization bug this gateway exists to prevent.

    Already folded, and safely: stage 02 rejects a duplicated `mcp-param-*` on the
    raw pairs, so nothing is lost by the time this mapping is built.
    """

    @field_validator("arguments", mode="after")
    @classmethod
    def _freeze(cls, v: Mapping[str, Any]) -> Mapping[str, Any]:
        # frozen=True stops rebinding, not mutation of a held dict — and nested
        # values are the part that gets missed. See `deep_freeze`.
        return deep_freeze(v)

    @field_validator("mcp_param_headers", mode="after")
    @classmethod
    def _freeze_headers(cls, v: Mapping[str, str]) -> Mapping[str, str]:
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
    """04. What the registry approved — never what the upstream advertised."""

    model_config = _FROZEN

    server_id: str
    tool_name: str | None
    """`None` for `tools/list`, which names no tool. Every OTHER method the allowlist
    admits is a call against one approved tool, so `None` here means exactly one
    thing and the validator below keeps it that way."""
    schema_fingerprint: str | None
    registry_risk_tier: RiskTier
    operation: Operation

    @model_validator(mode="after")
    def _tool_and_fingerprint_agree(self) -> ResolvedTarget:
        """A tool without its pinned fingerprint is the shape REG-009 forbids.

        Making it unrepresentable is worth more than a check at the one call site
        that builds it today: a later stage reading `tool_name` and finding a
        fingerprint of `None` would have no way to tell "no tool" from "tool whose
        approval was never verified", and the second must never route.
        """
        if (self.tool_name is None) != (self.schema_fingerprint is None):
            raise ValueError("tool_name and schema_fingerprint must be present together")
        return self


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
    path_argument: str = ""
    """Which argument named the resource, or "" for a request that names none.

    Unit 07 has to rewrite that argument before forwarding (ROUTE-004) and must not
    learn the tool vocabulary to do it. `""` is unambiguous: JSON object keys cannot
    be empty in any approved schema, and `tools/list` sets it that way deliberately."""
    relative_path: str = ""
    """`canonical_path` expressed the way the UPSTREAM will read it — relative to
    `canonicalize.base`, forward slashes.

    This is what unit 07 forwards, and it is the whole reason it exists. `canonical_path`
    is absolute and resolved, which is right for policy and for the audit record and
    wrong for the wire: the upstream joins what it receives onto its own base. Sending
    the client's original string instead is an authorization bypass rather than a
    TOCTOU window — `%77orkspace/f.txt` is authorized as `workspace/f.txt` and acted on
    as a literal `%77orkspace` directory, so the gateway approves one resource and the
    server touches another, deterministically and with no race to lose."""


class Obligations(BaseModel):
    """06 -> 07. Policy may narrow these; never widen past the gateway ceiling."""

    model_config = _FROZEN

    timeout_ms: int
    max_response_bytes: int


class Decision(BaseModel):
    """06 -> 07. Carries what it decided ABOUT, so ROUTE-001 is a typed check.

    `request_id`, `method` and `tool_name` together are the binding. The request id
    alone was not enough and the gap was real: a decision made for `write_file` was
    accepted by the router for `append_file`, because the id matched and the arguments
    hashed the same — two different side effects on one authorization. A decision is
    an answer to a specific question, so it carries the question.
    """

    model_config = _FROZEN

    request_id: RequestId
    method: str
    tool_name: str | None
    """`None` only for `tools/list`, mirroring `ResolvedTarget.tool_name`. Required
    rather than defaulted: a default would let a decision be built without saying what
    it authorised, and `None` compares equal to `None` for every discovery request."""
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

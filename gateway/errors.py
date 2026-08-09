"""Exception taxonomy and the complete reason-code registry.

One enum, one exception family, one handler. See `_specs/00-conventions.md` §4, §8
and `_tech/00-conventions.md` §4.

CONV-008: reason codes are part of the public contract. A code MAY be added; an
existing code's meaning MUST NOT change.
CONV-010: every code must be reachable by at least one corpus scenario. The single
enum makes that a one-test assertion rather than a manual audit.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this. Need a new code?
Report it; it gets added centrally.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class Stage(StrEnum):
    """Lifecycle stages, in order. `_specs/00-conventions.md` §5."""

    TRANSPORT = "transport"
    PROTOCOL = "protocol"
    IDENTITY = "identity"
    REGISTRY = "registry"
    CANONICAL = "canonical"
    POLICY = "policy"
    ROUTE = "route"
    RESPONSE = "response"
    AUDIT = "audit"


class ReasonCode(StrEnum):
    """Every terminal outcome code in the gateway.

    Prefix identifies the deciding unit (CONV-008). Allow-side codes are emitted by
    Rego and validated against this same set (`policies/reason_codes.json`).
    """

    # -- 01 transport edge -------------------------------------------------
    PROTO_MESSAGE_TOO_LARGE = "PROTO_MESSAGE_TOO_LARGE"
    PROTO_FRAMING_INVALID = "PROTO_FRAMING_INVALID"
    PROTO_ORIGIN_REJECTED = "PROTO_ORIGIN_REJECTED"

    # -- 02 protocol guard: mirrored metadata (the differentiator) ---------
    PROTO_HEADER_BODY_METHOD_MISMATCH = "PROTO_HEADER_BODY_METHOD_MISMATCH"
    PROTO_HEADER_BODY_NAME_MISMATCH = "PROTO_HEADER_BODY_NAME_MISMATCH"
    PROTO_HEADER_BODY_PARAM_MISMATCH = "PROTO_HEADER_BODY_PARAM_MISMATCH"
    PROTO_METADATA_MISSING = "PROTO_METADATA_MISSING"
    PROTO_METADATA_UNEXPECTED = "PROTO_METADATA_UNEXPECTED"
    PROTO_METADATA_DUPLICATE = "PROTO_METADATA_DUPLICATE"
    PROTO_METADATA_INVALID = "PROTO_METADATA_INVALID"

    # -- 02 protocol guard: version, envelope, limits ----------------------
    PROTO_VERSION_UNSUPPORTED = "PROTO_VERSION_UNSUPPORTED"
    PROTO_VERSION_MISMATCH = "PROTO_VERSION_MISMATCH"  # header vs params._meta
    PROTO_JSON_INVALID = "PROTO_JSON_INVALID"
    PROTO_JSONRPC_INVALID = "PROTO_JSONRPC_INVALID"
    PROTO_DUPLICATE_FIELD = "PROTO_DUPLICATE_FIELD"
    PROTO_LIMIT_EXCEEDED = "PROTO_LIMIT_EXCEEDED"
    PROTO_METHOD_NOT_ALLOWED = "PROTO_METHOD_NOT_ALLOWED"
    PROTO_MRTR_UNSUPPORTED = "PROTO_MRTR_UNSUPPORTED"  # ADR-001 §5: inputResponses

    # -- 03 identity -------------------------------------------------------
    IDENT_CONTEXT_UNAVAILABLE = "IDENT_CONTEXT_UNAVAILABLE"

    # -- 04 registry -------------------------------------------------------
    REG_SERVER_UNKNOWN = "REG_SERVER_UNKNOWN"
    REG_SERVER_UNAVAILABLE = "REG_SERVER_UNAVAILABLE"
    REG_TOOL_UNKNOWN = "REG_TOOL_UNKNOWN"
    REG_TOOL_QUARANTINED = "REG_TOOL_QUARANTINED"
    REG_SCHEMA_DRIFT = "REG_SCHEMA_DRIFT"
    REG_SCHEMA_UNVERIFIED = "REG_SCHEMA_UNVERIFIED"
    REG_ARGS_INVALID = "REG_ARGS_INVALID"
    REG_ARGS_UNKNOWN_FIELD = "REG_ARGS_UNKNOWN_FIELD"
    REG_HEADER_ANNOTATION_INVALID = "REG_HEADER_ANNOTATION_INVALID"  # ADR-001 §3.1

    # -- 05 canonicalizer --------------------------------------------------
    CANON_ENCODING_INVALID = "CANON_ENCODING_INVALID"
    CANON_NULL_BYTE = "CANON_NULL_BYTE"
    CANON_OUTSIDE_ROOT = "CANON_OUTSIDE_ROOT"
    CANON_SYMLINK_ESCAPE = "CANON_SYMLINK_ESCAPE"
    CANON_RESOLUTION_FAILED = "CANON_RESOLUTION_FAILED"
    CANON_SENSITIVE_PATH = "CANON_SENSITIVE_PATH"
    CANON_OPERATION_UNKNOWN = "CANON_OPERATION_UNKNOWN"

    # -- 06 policy: deny side ----------------------------------------------
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    POLICY_TIMEOUT = "POLICY_TIMEOUT"
    POLICY_RESULT_INVALID = "POLICY_RESULT_INVALID"
    POLICY_REVISION_UNKNOWN = "POLICY_REVISION_UNKNOWN"
    POLICY_DEFAULT_DENY = "POLICY_DEFAULT_DENY"
    POLICY_PROHIBITED = "POLICY_PROHIBITED"
    POLICY_PATH_NOT_PERMITTED = "POLICY_PATH_NOT_PERMITTED"
    POLICY_OPERATION_NOT_PERMITTED = "POLICY_OPERATION_NOT_PERMITTED"
    # -- 06 policy: allow side (emitted by Rego) ---------------------------
    POLICY_SCOPED_READ = "POLICY_SCOPED_READ"
    POLICY_SCOPED_WRITE = "POLICY_SCOPED_WRITE"
    POLICY_METADATA_READ = "POLICY_METADATA_READ"
    # -- 06 policy: advisory (audited alongside a real code) ---------------
    POLICY_OBLIGATION_CLAMPED = "POLICY_OBLIGATION_CLAMPED"

    # -- 07 router ---------------------------------------------------------
    ROUTE_NO_DECISION = "ROUTE_NO_DECISION"
    ROUTE_AUTHORIZATION_DIVERGENCE = "ROUTE_AUTHORIZATION_DIVERGENCE"
    ROUTE_UPSTREAM_UNAVAILABLE = "ROUTE_UPSTREAM_UNAVAILABLE"
    ROUTE_TIMEOUT = "ROUTE_TIMEOUT"
    ROUTE_RESPONSE_TOO_LARGE = "ROUTE_RESPONSE_TOO_LARGE"
    ROUTE_CANCELLED = "ROUTE_CANCELLED"

    # -- 08 response guard -------------------------------------------------
    RESP_ENVELOPE_INVALID = "RESP_ENVELOPE_INVALID"
    RESP_CORRELATION_MISMATCH = "RESP_CORRELATION_MISMATCH"
    RESP_UNSOLICITED = "RESP_UNSOLICITED"
    RESP_TOO_LARGE = "RESP_TOO_LARGE"
    RESP_LIMIT_EXCEEDED = "RESP_LIMIT_EXCEEDED"
    RESP_SHAPE_INVALID = "RESP_SHAPE_INVALID"
    RESP_MRTR_UNSUPPORTED = "RESP_MRTR_UNSUPPORTED"  # ADR-001 §5: inputRequests

    # -- 09 audit ----------------------------------------------------------
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    AUDIT_SCHEMA_INVALID = "AUDIT_SCHEMA_INVALID"

    # -- pipeline ----------------------------------------------------------
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: Reason codes that indicate an allow. Everything else denies (CONV-004).
ALLOW_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.POLICY_SCOPED_READ,
        ReasonCode.POLICY_SCOPED_WRITE,
        ReasonCode.POLICY_METADATA_READ,
    }
)

#: Advisory codes audited alongside a terminal code, never terminal themselves.
ADVISORY_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {ReasonCode.POLICY_OBLIGATION_CLAMPED}
)

#: Valid prefixes. CONV-008: every code is prefixed by its deciding unit.
VALID_PREFIXES: Final[tuple[str, ...]] = (
    "PROTO_",
    "IDENT_",
    "REG_",
    "CANON_",
    "POLICY_",
    "ROUTE_",
    "RESP_",
    "AUDIT_",
    "INTERNAL_",
)


# --------------------------------------------------------------------------
# Wire mapping. ADR-001 fixes these; they are spec requirements, not choices.
# --------------------------------------------------------------------------

_HEADER_MISMATCH_CODES: Final[frozenset[ReasonCode]] = frozenset(
    {
        ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH,
        ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH,
        ReasonCode.PROTO_HEADER_BODY_PARAM_MISMATCH,
        ReasonCode.PROTO_METADATA_MISSING,
        ReasonCode.PROTO_METADATA_UNEXPECTED,
        ReasonCode.PROTO_METADATA_DUPLICATE,
        ReasonCode.PROTO_METADATA_INVALID,
        ReasonCode.PROTO_VERSION_MISMATCH,
    }
)

JSONRPC_HEADER_MISMATCH: Final[int] = -32020  # spec-allocated
JSONRPC_METHOD_NOT_FOUND: Final[int] = -32601
JSONRPC_INVALID_REQUEST: Final[int] = -32600
JSONRPC_PARSE_ERROR: Final[int] = -32700
JSONRPC_INVALID_PARAMS: Final[int] = -32602
JSONRPC_INTERNAL: Final[int] = -32603


def wire_shape(code: ReasonCode) -> tuple[int, int]:
    """Return ``(http_status, jsonrpc_code)`` for a denial. ADR-001, `_tech/01` §1a."""
    if code in _HEADER_MISMATCH_CODES:
        return 400, JSONRPC_HEADER_MISMATCH
    match code:
        case ReasonCode.PROTO_ORIGIN_REJECTED:
            return 403, JSONRPC_INVALID_REQUEST
        case ReasonCode.PROTO_VERSION_UNSUPPORTED:
            return 400, JSONRPC_INVALID_REQUEST
        case ReasonCode.PROTO_METHOD_NOT_ALLOWED:
            # 404 lets a client distinguish a modern server from a legacy HTTP+SSE one.
            return 404, JSONRPC_METHOD_NOT_FOUND
        case ReasonCode.PROTO_JSON_INVALID:
            return 400, JSONRPC_PARSE_ERROR
        case ReasonCode.PROTO_JSONRPC_INVALID | ReasonCode.PROTO_DUPLICATE_FIELD:
            return 400, JSONRPC_INVALID_REQUEST
        case ReasonCode.PROTO_MESSAGE_TOO_LARGE | ReasonCode.PROTO_LIMIT_EXCEEDED:
            return 413, JSONRPC_INVALID_REQUEST
        case ReasonCode.REG_ARGS_INVALID | ReasonCode.REG_ARGS_UNKNOWN_FIELD:
            return 400, JSONRPC_INVALID_PARAMS
        case ReasonCode.ROUTE_TIMEOUT | ReasonCode.POLICY_TIMEOUT:
            return 504, JSONRPC_INTERNAL
        case ReasonCode.POLICY_UNAVAILABLE | ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE:
            return 503, JSONRPC_INTERNAL
        case ReasonCode.INTERNAL_ERROR:
            return 500, JSONRPC_INTERNAL
        case _:
            return 403, JSONRPC_INVALID_REQUEST  # authorization denials


#: Client-facing text. CONV-009: derivable from the code, discloses no internals.
#: Default is deliberately uninformative; add an entry only where specificity is safe.
_SAFE_MESSAGES: Final[dict[ReasonCode, str]] = {
    ReasonCode.PROTO_ORIGIN_REJECTED: "Origin not permitted.",
    ReasonCode.PROTO_VERSION_UNSUPPORTED: "Unsupported MCP protocol version.",
    ReasonCode.PROTO_METHOD_NOT_ALLOWED: "Method not found.",
    ReasonCode.PROTO_JSON_INVALID: "Malformed JSON.",
    ReasonCode.PROTO_JSONRPC_INVALID: "Malformed JSON-RPC request.",
    ReasonCode.PROTO_MESSAGE_TOO_LARGE: "Request too large.",
    ReasonCode.PROTO_LIMIT_EXCEEDED: "Request exceeds a structural limit.",
    ReasonCode.ROUTE_TIMEOUT: "Upstream timed out.",
    ReasonCode.ROUTE_CANCELLED: "Request cancelled.",
    ReasonCode.RESP_TOO_LARGE: "Upstream response too large.",
}
for _c in _HEADER_MISMATCH_CODES:
    _SAFE_MESSAGES.setdefault(_c, "Request headers do not match the request body.")


def safe_message(code: ReasonCode) -> str:
    return _SAFE_MESSAGES.get(code, "Request denied.")


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class GatewayDenial(Exception):
    """Terminal denial. The only exception type the pipeline handler expects.

    Anything else reaching the handler is an internal defect and becomes
    INTERNAL_ERROR — never an allow (CONV-004).
    """

    stage: Stage = Stage.PROTOCOL

    def __init__(self, reason_code: ReasonCode, detail: str | None = None) -> None:
        self.reason_code = reason_code
        self.detail = detail  # diagnostic sink only. Never client-facing, never audited.
        super().__init__(reason_code.value)

    @property
    def message(self) -> str:
        return safe_message(self.reason_code)

    @property
    def wire(self) -> tuple[int, int]:
        return wire_shape(self.reason_code)


class TransportDenial(GatewayDenial):
    stage = Stage.TRANSPORT


class ProtocolDenial(GatewayDenial):
    stage = Stage.PROTOCOL


class IdentityDenial(GatewayDenial):
    stage = Stage.IDENTITY


class RegistryDenial(GatewayDenial):
    stage = Stage.REGISTRY


class CanonicalizationDenial(GatewayDenial):
    stage = Stage.CANONICAL


class PolicyDenial(GatewayDenial):
    stage = Stage.POLICY


class RouteDenial(GatewayDenial):
    stage = Stage.ROUTE


class ResponseDenial(GatewayDenial):
    stage = Stage.RESPONSE


class AuditFailure(GatewayDenial):
    stage = Stage.AUDIT


class ConfigError(Exception):
    """Startup failure. Never reaches a request path (CONV-013)."""


class ProgrammingError(Exception):
    """An invariant the code controls was violated. Always a defect, never input."""

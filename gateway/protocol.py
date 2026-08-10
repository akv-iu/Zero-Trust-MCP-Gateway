"""02 - JSON-RPC hardening + mirrored-metadata consistency.

Spec: _specs/02-svc-protocol-guard.md   Tech: _tech/02-svc-protocol-guard.md
Amended by: ADR-002 (the SDK owns the mirrored-metadata ladder)

WHAT THIS UNIT DOES NOT DO
--------------------------
It does not compare headers against bodies. `mcp.shared.inbound` does that, and
reimplementing 581 lines of spec-critical comparison would guarantee divergence from
the reference implementation — a gateway that disagrees with the SDK about what a
request *means* is the exact failure this project exists to prevent (ADR-002 §2.1).

What is left is genuinely ours, because the ladder takes an already-decoded mapping
and says so: everything upstream of `json.loads`, everything the ladder's docstring
explicitly disclaims (envelope shape, method existence), and the entire mapping from
its rejections onto reason codes and audit fields.

ORDER (fixed; each failure is terminal)
---------------------------------------
    1 prescan          bytes: size and nesting depth, before any allocation
    2 parse            json.loads with duplicate-key detection
    3 limits           arrays, strings, field count, one iterative walk
    4 envelope         jsonrpc / id / method / params shape
    5 metadata         presence and well-formedness, then the SDK LADDER
    6 allowlist        default-deny on method
    7 MRTR             refuse what v1 cannot enforce
    8 build            CanonicalRequest, frozen

ADR-002 §2.2 lists the ladder before envelope shape. It runs after here, and the
reason is reason codes, not security: rung 1 rejects a body with no `params._meta`,
so a request missing `jsonrpc` entirely would be reported as a metadata failure. The
ladder's own docstring disclaims envelope shape ("`jsonrpc` / `id` is not checked
here"), so checking it first duplicates no rung. PROTO-002 requires the consistency
check to precede *routing, registry and policy* — envelope shape is none of those,
and nothing in stages 1-4 reads a mirrored value for any purpose.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any, Final, Protocol, cast

from mcp.shared.inbound import (
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
    MCP_PARAM_HEADER_PREFIX,
    MCP_PROTOCOL_VERSION_HEADER,
    NAME_BEARING_METHODS,
    InboundLadderRejection,
    classify_inbound_request,
    decode_header_value,
    find_duplicated_routing_header,
    validate_mcp_param_headers,
)
from mcp_types.jsonrpc import (
    HEADER_MISMATCH,
    INVALID_PARAMS,
    UNSUPPORTED_PROTOCOL_VERSION,
)

from gateway.config import ProtocolConfig
from gateway.errors import ProtocolDenial, ReasonCode
from gateway.hashing import sha256_hex
from gateway.types import CanonicalRequest, JsonObject, RawEnvelope

_JSONRPC_VERSION: Final = "2.0"
_SENTINEL_PREFIX: Final = "=?base64?"

#: Lowercased, because ASGI header names arrive lowercased and HTTP field names are
#: case-insensitive. Derived from the SDK constant so the two cannot drift.
_PARAM_PREFIX: Final = MCP_PARAM_HEADER_PREFIX.lower()

#: MRTR (SEP-2322) request-side key. ADR-001 §5: v1 refuses rather than proxies —
#: a mid-request input exchange is a second authorization surface with no policy.
_MRTR_KEY: Final = "inputResponses"


def _deny(code: ReasonCode, detail: str) -> ProtocolDenial:
    """`detail` reaches the diagnostic sink only. PROTO-014: never the client, never
    the audit record — it quotes the payload by construction."""
    return ProtocolDenial(code, detail=detail)


# ===========================================================================
# 1. Byte prescan (PROTO-013)
# ===========================================================================


def prescan(body: bytes, cfg: ProtocolConfig) -> None:
    """Bound size and nesting depth before `json.loads` allocates anything.

    `json.loads` has no depth limit: deep input hits CPython's recursion ceiling and
    raises RecursionError, which is an internal defect, not a clean denial. One
    allocation-free pass over the bytes turns PROTO-013 from an aspiration into a
    property — the parser is never handed input that could blow the stack.

    String-aware, because `{"a": "{{{{"}` is depth 1, not depth 5. The escape
    handling is load-bearing: without it a trailing `\\"` inside a string would end
    the string early and every brace after it would be counted.
    """
    if len(body) > cfg.max_body_bytes:
        raise _deny(ReasonCode.PROTO_LIMIT_EXCEEDED, f"body {len(body)} bytes")

    depth = 0
    in_string = False
    escaped = False
    for byte in body:
        if escaped:
            escaped = False
        elif in_string:
            if byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # "
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # { [
            depth += 1
            if depth > cfg.max_depth:
                raise _deny(ReasonCode.PROTO_LIMIT_EXCEEDED, f"depth > {cfg.max_depth}")
        elif byte in (0x7D, 0x5D):  # } ]
            depth -= 1


# ===========================================================================
# 2. Parse with duplicate-key detection (PROTO-011)
# ===========================================================================


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> JsonObject:
    """`object_pairs_hook`: the only way to see a duplicate key at all.

    This is why the project uses stdlib `json` and not `orjson` — `orjson` applies
    last-key-wins silently, which would make PROTO_DUPLICATE_FIELD undetectable and
    turn a spec requirement into a claim we could not keep. The whole point is that
    two readers of the same bytes must not be able to disagree.

    Rejecting ALL duplicates rather than only conflicting ones is stricter than the
    spec and has no legitimate false positive: well-formed JSON-RPC never repeats a
    key, and "the values happened to be equal" is a property of one parser's reading.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _deny(ReasonCode.PROTO_DUPLICATE_FIELD, f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    """`parse_constant`: `NaN`, `Infinity` and `-Infinity` are NOT JSON.

    `json.loads` accepts them by default, as an extension. They must not get past
    this stage: `canonical_json` sets `allow_nan=False`, so an argument carrying one
    would blow up later at the hashing step — an internal defect, at a point where
    the request has already been authorized.
    """
    raise _deny(ReasonCode.PROTO_JSON_INVALID, f"non-JSON constant {name}")


def parse(body: bytes) -> JsonObject:
    try:
        decoded = json.loads(
            body,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as e:
        raise _deny(ReasonCode.PROTO_JSON_INVALID, f"not utf-8: {e}") from e
    except json.JSONDecodeError as e:
        raise _deny(ReasonCode.PROTO_JSON_INVALID, str(e)) from e
    except ValueError as e:
        # CPython caps int<->str conversion at `sys.get_int_max_str_digits` (4300 by
        # default), and json's scanner calls `int()` on the literal. A 5,000-digit
        # number is therefore a plain ValueError out of the parser, which the
        # pipeline would record as INTERNAL_ERROR and answer with a 500 — a defect,
        # attributed to us, for input the attacker chose. JSONDecodeError subclasses
        # ValueError, so this arm must come last.
        raise _deny(ReasonCode.PROTO_JSON_INVALID, f"unparseable number: {e}") from e
    if not isinstance(decoded, dict):
        # A batch (list) or a bare scalar. v1 supports neither; both are envelope
        # defects rather than parse errors.
        raise _deny(
            ReasonCode.PROTO_JSONRPC_INVALID, f"top level is {type(decoded).__name__}"
        )
    return cast("JsonObject", decoded)


# ===========================================================================
# 3. Structural limits (PROTO-012)
# ===========================================================================


class StructuralLimits(Protocol):
    """What one walk needs. `ProtocolConfig` and `ResponseConfig` both satisfy it.

    RESP-004 asks for limits on the response equivalent to the ones on the request,
    and `_tech/08` §1 is explicit that the walk must not be written twice — two walks
    diverge, and the direction that gets the weaker one is the direction nobody
    remembered to update. Structural typing rather than a shared base class: the two
    configs are independent surfaces whose VALUES deliberately differ (a legitimate
    `read_file` result dwarfs a legitimate request), and only the shape is common.
    """

    max_depth: int
    max_object_keys: int
    max_array_length: int
    max_string_length: int
    max_total_fields: int


def check_limits(
    body: Mapping[str, Any],
    cfg: StructuralLimits,
    code: ReasonCode = ReasonCode.PROTO_LIMIT_EXCEEDED,
) -> None:
    """One ITERATIVE walk for depth, array length, string length, and field count.

    Explicit stack, not recursion: a recursive walk here would reintroduce exactly
    the stack-exhaustion problem the prescan just solved, one layer later and with
    the payload already in memory.

    Depth is carried on the stack rather than checked by a separate pass. For a
    REQUEST it is redundant — `prescan` already refused anything deeper before the
    bytes were parsed — and for a RESPONSE it is the only depth check there is,
    because the SDK parses the upstream's bytes before the gateway sees them and
    there is nothing left to prescan. One walk, and the redundant half costs an
    integer per node.

    **Only CONTAINERS count toward depth**, which is what `prescan` measures: it
    increments on `{` and `[` and never on a scalar. Testing the depth of every node
    made this walk one level stricter than the prescan for the same document, so a
    request at exactly `max_depth` passed the byte scan and was then rejected after
    parsing — two limits with one name disagreeing about the boundary, which is worse
    than either being wrong. Found in review; `test_protocol.py` pins the pair.

    `code` is the caller's, so the same walk can deny as PROTO_ or RESP_ without
    either side learning the other's vocabulary.
    """
    fields = 0
    stack: list[tuple[Any, int]] = [(body, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, Mapping):
            if depth > cfg.max_depth:
                raise _deny(code, f"depth > {cfg.max_depth}")
            mapping = cast("Mapping[str, Any]", node)
            if len(mapping) > cfg.max_object_keys:
                raise _deny(code, f"object keys {len(mapping)}")
            fields += len(mapping)
            if fields > cfg.max_total_fields:
                raise _deny(code, "total fields")
            for key, value in mapping.items():
                if len(key) > cfg.max_string_length:
                    raise _deny(code, "key length")
                stack.append((value, depth + 1))
        elif isinstance(node, list):
            if depth > cfg.max_depth:
                raise _deny(code, f"depth > {cfg.max_depth}")
            array = cast("list[Any]", node)
            if len(array) > cfg.max_array_length:
                raise _deny(code, f"array {len(array)}")
            stack.extend((item, depth + 1) for item in array)
        elif isinstance(node, str) and len(node) > cfg.max_string_length:
            raise _deny(code, f"string {len(node)}")


# ===========================================================================
# 4. JSON-RPC envelope shape (PROTO-009)
# ===========================================================================


def check_envelope(body: Mapping[str, Any]) -> tuple[str, str | int | None]:
    """Validate what the SDK ladder explicitly does not, and return `(method, id)`.

    A null id is a notification. v1 has no notification path on the client edge —
    every request is authorized and answered — so it is refused rather than silently
    treated as a request whose response goes nowhere.
    """
    if body.get("jsonrpc") != _JSONRPC_VERSION:
        raise _deny(ReasonCode.PROTO_JSONRPC_INVALID, f"jsonrpc={body.get('jsonrpc')!r}")

    method = body.get("method")
    if not isinstance(method, str) or not method:
        raise _deny(ReasonCode.PROTO_JSONRPC_INVALID, f"method={method!r}")

    if "id" not in body:
        raise _deny(ReasonCode.PROTO_JSONRPC_INVALID, "notification: no id")
    rid = body["id"]
    # bool is an int subclass; a JSON `true` id is not a valid JSON-RPC identifier.
    if isinstance(rid, bool) or not isinstance(rid, str | int):
        raise _deny(ReasonCode.PROTO_JSONRPC_INVALID, f"id type {type(rid).__name__}")

    params = body.get("params")
    if params is not None and not isinstance(params, Mapping):
        raise _deny(ReasonCode.PROTO_JSONRPC_INVALID, f"params {type(params).__name__}")

    return method, rid


# ===========================================================================
# 5. Mirrored metadata
# ===========================================================================
#
# The comparison is the SDK's. Ours are the shapes it folds together and PROTO-007
# requires to be distinguishable: absent, empty, duplicated, malformed. The ladder
# answers all four with HEADER_MISMATCH, which is the correct WIRE response but
# destroys the audit's ability to say what actually happened.


def _presence_rules(method: str) -> dict[str, bool]:
    """Which mirrored headers are required for this method (PROTO-005).

    `Mcp-Name` is required exactly for the name-bearing methods and PROHIBITED
    elsewhere — read from the SDK's own table so the two cannot drift.
    """
    return {
        MCP_PROTOCOL_VERSION_HEADER: True,
        MCP_METHOD_HEADER: True,
        MCP_NAME_HEADER: method in NAME_BEARING_METHODS,
    }


def check_metadata_shape(headers: Mapping[str, str], method: str) -> None:
    """Presence and well-formedness, before the ladder compares anything.

    Every failure here is also a failure the ladder would catch — as a mismatch. The
    value of doing it first is entirely evidential: "the client never sent Mcp-Name"
    and "the client sent a different Mcp-Name" are the same wire response and
    completely different incidents.

    `method` is read from the BODY, which is the authority (PROTO-006) and the value
    that would execute. When the method header disagrees with it the name rule is
    unknowable — the two sides ask for different methods, and `Mcp-Name` is required
    for one and prohibited for the other — so the name rules are skipped and the
    ladder reports the method dispute, which is the real defect.
    """
    rules = _presence_rules(method)
    if headers.get(MCP_METHOD_HEADER) != method:
        rules.pop(MCP_NAME_HEADER)

    for name, required in rules.items():
        value = headers.get(name)
        if value is None:
            if required:
                raise _deny(ReasonCode.PROTO_METADATA_MISSING, name)
            continue
        if not required:
            # PROTO-005: prohibited-and-present. An Mcp-Name on tools/list mirrors
            # nothing, so no comparison can ever reject it — it would ride along
            # unchecked into whatever downstream reader trusted it.
            raise _deny(ReasonCode.PROTO_METADATA_UNEXPECTED, name)
        if value == "":
            # PROTO-004: never treated as absent.
            raise _deny(ReasonCode.PROTO_METADATA_INVALID, f"{name} empty")
        if value != value.strip() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise _deny(ReasonCode.PROTO_METADATA_INVALID, f"{name} malformed")
        if value.startswith(_SENTINEL_PREFIX) and decode_header_value(value) is None:
            # The SDK returns None for a bad sentinel and the ladder then reports a
            # mismatch. It is not a mismatch: nothing was compared.
            raise _deny(ReasonCode.PROTO_METADATA_INVALID, f"{name} bad sentinel")


def find_duplicated_param_header(metadata: tuple[tuple[str, str], ...]) -> str | None:
    """Name of an `Mcp-Param-*` header supplied more than once, or `None`.

    Ours, not the SDK's. `find_duplicated_routing_header` covers the three routing
    headers and says in its own docstring that `Mcp-Param-*` duplicates belong to
    `validate_mcp_param_headers` — which detects them by iterating `headers.items()`,
    and therefore only sees what a *multi-valued* mapping yields. Unit 04 receives
    `CanonicalRequest.mcp_param_headers`, a plain folded mapping, so by then a
    duplicate is already gone. Catching it here, on the raw pairs, is the only place
    the information still exists (CLAUDE.md: duplicate detection is ours).

    Stricter than the SDK's rule on purpose: it rejects a duplicate only on an
    ANNOTATED position, so a repeated header naming an unannotated argument would
    pass. That header still reaches every intermediary between the client and here,
    and first-copy and last-copy readers still disagree about it — which is the
    entire failure the mirrored-metadata requirement exists to prevent.
    """
    seen: set[str] = set()
    for name, _ in metadata:
        key = name.lower()
        if not key.startswith(_PARAM_PREFIX):
            continue
        if key in seen:
            return key
        seen.add(key)
    return None


#: Which mirrored field the SDK's HEADER_MISMATCH refers to.
#:
#: Keyed on the SDK's own exported header-name constants, which appear in the
#: messages it builds, rather than on wording we would have to keep in sync by hand.
#: A misclassification here costs audit precision only — all three are 400/-32020 on
#: the wire — but `test_every_mismatch_shape_maps_to_its_own_code` drives each shape
#: through the real SDK, so a reword fails a test instead of silently degrading.
_MISMATCH_BY_HEADER: Final[tuple[tuple[str, ReasonCode], ...]] = (
    (MCP_PROTOCOL_VERSION_HEADER, ReasonCode.PROTO_VERSION_MISMATCH),
    (MCP_METHOD_HEADER, ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH),
    (MCP_NAME_HEADER, ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH),
)


def _ladder_reason(rejection: InboundLadderRejection) -> ReasonCode:
    if rejection.code == HEADER_MISMATCH:
        for header, code in _MISMATCH_BY_HEADER:
            if header in rejection.message:
                return code
        return ReasonCode.PROTO_METADATA_INVALID
    if rejection.code == UNSUPPORTED_PROTOCOL_VERSION:
        return ReasonCode.PROTO_VERSION_UNSUPPORTED
    if rejection.code == INVALID_PARAMS:
        # Rung 1: params._meta absent or missing an envelope key.
        return ReasonCode.PROTO_METADATA_MISSING
    return ReasonCode.PROTO_JSONRPC_INVALID


def run_ladder(
    body: Mapping[str, Any], headers: Mapping[str, str], cfg: ProtocolConfig
) -> str:
    """Delegate to `classify_inbound_request` and return the agreed protocol version."""
    outcome = classify_inbound_request(
        body, headers=headers, supported_modern_versions=cfg.supported_versions
    )
    if isinstance(outcome, InboundLadderRejection):
        raise _deny(_ladder_reason(outcome), f"ladder: {outcome.message}")
    return outcome.protocol_version


def check_param_headers(
    input_schema: Any, arguments: Mapping[str, Any], headers: Mapping[str, str]
) -> None:
    """`Mcp-Param-*` against the body arguments, per the tool's `x-mcp-header`
    annotations.

    Called by unit 04, not from `validate`: the annotations live in the APPROVED
    `inputSchema`, which only the registry can resolve. That still satisfies
    PROTO-002 — 04 runs before policy and before the router — but it is the one
    mirrored family this stage cannot check, and pretending otherwise by threading a
    schema that is always `None` through `validate` would hide that.
    """
    rejection = validate_mcp_param_headers(input_schema, arguments, headers)
    if rejection is not None:
        raise _deny(ReasonCode.PROTO_HEADER_BODY_PARAM_MISMATCH, rejection.message)


# ===========================================================================
# 6-8. Allowlist, MRTR, build
# ===========================================================================


def check_method_allowed(method: str, cfg: ProtocolConfig) -> None:
    """Default-deny (PROTO-010).

    `recognized_denied` exists so a probing client gets a clean modern error instead
    of a timeout. It is NOT a softer denial: same reason code, same status. The list
    only documents which methods we know we are refusing on purpose.
    """
    if method not in cfg.allowed_methods:
        known = " (recognized)" if method in cfg.recognized_denied else ""
        raise _deny(ReasonCode.PROTO_METHOD_NOT_ALLOWED, f"{method}{known}")


def check_mrtr(params: Mapping[str, Any]) -> None:
    """Refuse mid-request tool return (ADR-001 §5).

    An `inputResponses` payload continues an exchange the gateway never authorized
    and holds no decision for. Refusing is the honest answer; proxying it would open
    a second side-effect path around stage 06.
    """
    if _MRTR_KEY in params:
        raise _deny(ReasonCode.PROTO_MRTR_UNSUPPORTED, _MRTR_KEY)


def validate(env: RawEnvelope, cfg: ProtocolConfig) -> CanonicalRequest:
    """Raw envelope -> canonical request, or raise ProtocolDenial.

    PROTO-006 is enforced by this signature: `RawEnvelope` goes in, `CanonicalRequest`
    comes out, and no later stage is given the envelope to re-read. That is why the
    return value carries `method` and `tool_name` rather than the stage downstream
    reading them back off the headers.
    """
    started = time.perf_counter()

    prescan(env.body, cfg)
    body = parse(env.body)
    check_limits(body, cfg)
    method, jsonrpc_id = check_envelope(body)

    # Both detected on the raw PAIRS. Folding to a mapping first would silently keep
    # one copy, and which one depends on the folding order - the precise divergence
    # between two readers of the same request that this unit exists to make impossible.
    dup = find_duplicated_routing_header(env.metadata) or find_duplicated_param_header(
        env.metadata
    )
    if dup is not None:
        raise _deny(ReasonCode.PROTO_METADATA_DUPLICATE, dup)

    headers = dict(env.metadata)
    check_metadata_shape(headers, method)
    protocol_version = run_ladder(body, headers, cfg)

    check_method_allowed(method, cfg)
    # `check_envelope` already proved params is a mapping or absent. `or {}` would be
    # wrong even here: see the `arguments` note below.
    params: Mapping[str, Any] = body["params"] if body.get("params") is not None else {}
    check_mrtr(params)

    elapsed_ms = (time.perf_counter() - started) * 1000
    if elapsed_ms > cfg.parse_budget_ms:
        # A backstop, not the bound. `prescan` is what actually keeps parsing cheap;
        # this catches the case where it did not, and refuses to carry the cost
        # forward into policy evaluation and an upstream call.
        raise _deny(ReasonCode.PROTO_LIMIT_EXCEEDED, f"parse {elapsed_ms:.1f}ms")

    # Which params key carries the name is the SDK's table, not ours: `tools/call`
    # and `prompts/get` mirror `name`, `resources/read` mirrors `uri`. Hardcoding
    # "name" would silently read the wrong field the day a URI method is allowed.
    name_key = NAME_BEARING_METHODS.get(method)
    name = params.get(name_key) if name_key is not None else None

    # `params.get("arguments") or {}` silently REPAIRED every falsey non-object —
    # `[]`, `""`, `0`, `false` all became `{}` and sailed through the isinstance
    # check that was supposed to catch them. A malformed request became a valid
    # zero-argument call, so a tool with all-optional parameters would have executed
    # on input the client never sent. Absent and empty-but-wrong are different
    # things, and only `None` means absent.
    supplied = params.get("arguments")
    if supplied is None:
        arguments: Mapping[str, Any] = {}
    elif isinstance(supplied, Mapping):
        arguments = cast("Mapping[str, Any]", supplied)
    else:
        raise _deny(
            ReasonCode.PROTO_JSONRPC_INVALID, f"arguments is {type(supplied).__name__}"
        )

    return CanonicalRequest(
        request_id=env.request_id,
        protocol_version=protocol_version,
        method=method,
        jsonrpc_id=jsonrpc_id,
        tool_name=name if isinstance(name, str) else None,
        arguments=arguments,
        body_hash=sha256_hex(env.body),
        mcp_param_headers={
            k: v for k, v in headers.items() if k.startswith(_PARAM_PREFIX)
        },
    )


def audit_fields(req: CanonicalRequest) -> JsonObject:
    """What stage 02 contributes to the record (spec §8)."""
    return {
        "mcp_method": req.method,
        "mcp_protocol_version": req.protocol_version,
        "body_hash": req.body_hash,
        "tool_name": req.tool_name,
    }


__all__ = [
    "audit_fields",
    "check_envelope",
    "check_limits",
    "check_metadata_shape",
    "check_method_allowed",
    "check_mrtr",
    "check_param_headers",
    "find_duplicated_param_header",
    "parse",
    "prescan",
    "run_ladder",
    "validate",
]

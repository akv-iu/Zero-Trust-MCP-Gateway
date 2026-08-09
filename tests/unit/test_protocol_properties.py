"""Unit 02, §9.10 — the property that makes PROTO-006 machine-checked.

Every test in `test_protocol.py` is a case somebody thought of. This file asserts the
invariant over generated input, which is the only way to make a claim about requests
nobody wrote down:

    IF `validate` returns, THEN the canonical request agrees with BOTH sides.

That is the whole differentiating claim of unit 02 stated as one predicate. A gateway
that authorized on the header while forwarding the body would fail it; so would one
that silently preferred one side when they disagreed.

Reproduce a failure with `--hypothesis-seed=N` (the seed is printed on failure).
"""

from __future__ import annotations

import json
import time
from contextlib import suppress
from typing import Any

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY

from gateway import protocol
from gateway.config import ProtocolConfig
from gateway.errors import ProtocolDenial, ReasonCode
from gateway.types import RawEnvelope

CFG = ProtocolConfig()
VERSION = "2026-07-28"

SETTINGS = settings(
    max_examples=300,
    deadline=None,  # CI machines stall; a slow example is not a failed property
    suppress_health_check=[HealthCheck.filter_too_much],
)

# Names that survive an HTTP field verbatim, plus ones that do not — the latter
# exercise the base64 sentinel path, which is where a decode-twice or a
# discard-invalid-characters bug would live.
tool_names = st.one_of(
    st.sampled_from(["read_file", "write_file", "delete_file", "list_dir"]),
    st.text(min_size=1, max_size=12).filter(lambda s: s == s.strip() and s),
)
methods = st.sampled_from(["tools/call", "tools/list"])

json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20)),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)


def build(
    method: str,
    body_name: str | None,
    header_name: str | None,
    arguments: dict[str, Any] | None = None,
) -> RawEnvelope:
    from mcp.shared.inbound import encode_header_value

    params: dict[str, Any] = {
        "_meta": {
            PROTOCOL_VERSION_META_KEY: VERSION,
            CLIENT_CAPABILITIES_META_KEY: {},
        }
    }
    if body_name is not None:
        params["name"] = body_name
    if arguments is not None:
        params["arguments"] = arguments

    metadata = [("mcp-protocol-version", VERSION), ("mcp-method", method)]
    if header_name is not None:
        metadata.append(("mcp-name", encode_header_value(header_name)))

    return RawEnvelope(
        request_id="prop",
        received_at_ns=time.monotonic_ns(),
        body=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        metadata=tuple(metadata),
    )


# ===========================================================================
# The invariant
# ===========================================================================


@SETTINGS
@given(method=methods, body_name=tool_names, header_name=tool_names)
def test_if_validate_returns_the_canonical_view_agrees_with_both_sides(
    method: str, body_name: str, header_name: str
) -> None:
    """The headline property. Generated names agree sometimes and disagree others;
    the assertion is on what is true WHEN a request is accepted, so the generator does
    not need to know which is which — and cannot bias the result by guessing."""
    from mcp.shared.inbound import decode_header_value

    env = build(
        method,
        body_name if method == "tools/call" else None,
        header_name if method == "tools/call" else None,
    )
    try:
        req = protocol.validate(env, CFG)
    except ProtocolDenial:
        return  # a denial says nothing about the invariant; only acceptance does

    headers = dict(env.metadata)
    parsed = json.loads(env.body)

    assert req.method == headers["mcp-method"] == parsed["method"]
    if req.tool_name is not None:
        assert req.tool_name == parsed["params"]["name"]
        assert req.tool_name == decode_header_value(headers["mcp-name"])


@SETTINGS
@given(body_name=tool_names, header_name=tool_names)
def test_disagreeing_names_are_never_accepted(body_name: str, header_name: str) -> None:
    """The converse, stated separately because it is the security-relevant half.

    The test above would pass on a gateway that rejected everything. This one fails
    on a gateway that accepts even one split request.
    """
    assume(body_name != header_name)
    env = build("tools/call", body_name, header_name)
    try:
        protocol.validate(env, CFG)
    except ProtocolDenial as d:
        assert d.reason_code in (
            ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH,
            ReasonCode.PROTO_METADATA_INVALID,
        )
        return
    raise AssertionError(
        f"accepted a split request: body={body_name!r} header={header_name!r}"
    )


@SETTINGS
@given(
    arguments=st.dictionaries(st.text(min_size=1, max_size=8), json_values, max_size=5)
)
def test_accepted_arguments_survive_the_round_trip_unchanged(
    arguments: dict[str, Any],
) -> None:
    """Whatever policy will evaluate must be what the client actually sent.

    A canonicaliser that reordered, coerced or dropped an argument would break the
    tie between `arg_hash` and the bytes forwarded upstream, which is what ROUTE-002
    later depends on.
    """
    env = build("tools/call", "read_file", "read_file", arguments)
    try:
        req = protocol.validate(env, CFG)
    except ProtocolDenial:
        return
    from gateway.types import thaw

    assert thaw(req.arguments) == arguments


# ===========================================================================
# Totality: never a crash, never a RecursionError, always a typed denial
# ===========================================================================


@SETTINGS
@given(raw=st.binary(max_size=400))
def test_arbitrary_bytes_produce_a_denial_never_an_exception(raw: bytes) -> None:
    """PROTO-011/013 as a property. Anything reaching `validate` that is not a clean
    `ProtocolDenial` becomes INTERNAL_ERROR at the pipeline — a 500 where the client
    deserves a 400, and a defect recorded as if it were an attack."""
    env = RawEnvelope(
        request_id="prop", received_at_ns=time.monotonic_ns(), body=raw, metadata=()
    )
    with suppress(ProtocolDenial):
        protocol.validate(env, CFG)


@SETTINGS
@given(payload=json_values)
def test_arbitrary_json_produces_a_denial_never_an_exception(payload: Any) -> None:
    env = RawEnvelope(
        request_id="prop",
        received_at_ns=time.monotonic_ns(),
        body=json.dumps(payload).encode(),
        metadata=(("mcp-protocol-version", VERSION), ("mcp-method", "tools/call")),
    )
    with suppress(ProtocolDenial):
        protocol.validate(env, CFG)


@SETTINGS
@given(depth=st.integers(min_value=0, max_value=300))
def test_the_prescan_agrees_with_the_actual_nesting_depth(depth: int) -> None:
    """The prescan is the only thing standing between deep input and a RecursionError,
    so its arithmetic gets checked against a limit set on either side of the truth
    rather than against itself."""
    raw = b"[" * depth + b"]" * depth
    protocol.prescan(raw, ProtocolConfig(max_depth=depth))
    if depth > 0:
        try:
            protocol.prescan(raw, ProtocolConfig(max_depth=depth - 1))
        except ProtocolDenial as d:
            assert d.reason_code is ReasonCode.PROTO_LIMIT_EXCEEDED
            return
        raise AssertionError(f"depth {depth} passed a limit of {depth - 1}")


@SETTINGS
@given(text=st.text(max_size=200))
def test_braces_inside_strings_never_count_toward_depth(text: str) -> None:
    """The string-awareness of the prescan, over generated text rather than the two
    escape sequences a human would think to try. A false positive here rejects
    ordinary payloads, and the usual "fix" is to raise the limit — which removes the
    protection entirely."""
    protocol.prescan(json.dumps({"a": text}).encode(), ProtocolConfig(max_depth=2))

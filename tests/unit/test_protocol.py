"""Unit 02 acceptance tests — the highest test density in the project.

Most of the comparison logic lives in `mcp.shared.inbound` (ADR-002). That makes the
corpus MORE necessary, not less: a delegated behaviour still has to be proved, and
these tests are also the SDK-upgrade gate. Every mirrored-metadata case is driven
through the real SDK, so a version bump that changes validation semantics fails here
rather than in production.

`_specs/02` §9 numbers the acceptance tests; the section headers name them.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from gateway import protocol
from gateway.config import ProtocolConfig
from gateway.errors import ProtocolDenial, ReasonCode
from gateway.types import RawEnvelope

CFG = ProtocolConfig()
VERSION = "2026-07-28"


# ---------------------------------------------------------------------------
# Builders. A conforming 2026-07-28 request is surprisingly heavy — the envelope
# metadata is mandatory — so every test starts from one and breaks exactly one thing.
# ---------------------------------------------------------------------------


def body(
    method: str = "tools/call",
    *,
    name: str | None = "read_file",
    arguments: dict[str, Any] | None = None,
    version: Any = VERSION,
    rid: Any = 1,
    meta_extra: dict[str, Any] | None = None,
    **params_extra: Any,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        PROTOCOL_VERSION_META_KEY: version,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "test", "version": "1"},
    }
    meta.update(meta_extra or {})
    params: dict[str, Any] = {"_meta": meta, **params_extra}
    if name is not None:
        params["name"] = name
    if arguments is not None:
        params["arguments"] = arguments
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def headers(
    method: str = "tools/call", *, name: str | None = "read_file", version: str = VERSION
) -> list[tuple[str, str]]:
    out = [("mcp-protocol-version", version), ("mcp-method", method)]
    if name is not None:
        out.append(("mcp-name", name))
    return out


def envelope(b: Any, h: list[tuple[str, str]] | None = None) -> RawEnvelope:
    raw = b if isinstance(b, bytes) else json.dumps(b).encode()
    return RawEnvelope(
        request_id="r1",
        received_at_ns=time.monotonic_ns(),
        body=raw,
        metadata=tuple(h if h is not None else headers()),
    )


def denies(
    env: RawEnvelope, code: ReasonCode, cfg: ProtocolConfig = CFG
) -> ProtocolDenial:
    with pytest.raises(ProtocolDenial) as caught:
        protocol.validate(env, cfg)
    assert caught.value.reason_code is code, (
        f"expected {code.value}, got {caught.value.reason_code.value}: "
        f"{caught.value.detail}"
    )
    return caught.value


# ===========================================================================
# §9.2 — the happy path, and the one authority
# ===========================================================================


def test_a_conforming_request_produces_a_canonical_request() -> None:
    req = protocol.validate(envelope(body(arguments={"path": "public/a.txt"})), CFG)
    assert req.method == "tools/call"
    assert req.tool_name == "read_file"
    assert req.protocol_version == VERSION
    assert req.jsonrpc_id == 1
    assert req.arguments["path"] == "public/a.txt"
    assert len(req.body_hash) == 64


def test_the_canonical_request_agrees_with_both_header_and_body() -> None:
    """§9.2 stated precisely: not "it parsed", but "there is only one answer"."""
    env = envelope(body())
    req = protocol.validate(env, CFG)
    assert (
        req.method == dict(env.metadata)["mcp-method"] == json.loads(env.body)["method"]
    )
    assert req.tool_name == dict(env.metadata)["mcp-name"]
    assert req.tool_name == json.loads(env.body)["params"]["name"]


def test_a_method_with_no_name_needs_no_name_header() -> None:
    req = protocol.validate(
        envelope(body("tools/list", name=None), headers("tools/list", name=None)), CFG
    )
    assert req.method == "tools/list" and req.tool_name is None


def test_arguments_reaching_the_canonical_request_are_frozen() -> None:
    req = protocol.validate(envelope(body(arguments={"opts": {"path": "a"}})), CFG)
    with pytest.raises(TypeError):
        req.arguments["opts"]["path"] = "b"  # type: ignore[index]


# ===========================================================================
# §9.3 — THE SPLIT-AUTHORIZATION CASE. The headline test.
# ===========================================================================


def test_header_names_an_allowed_tool_while_the_body_names_another() -> None:
    """The vulnerability class the 2026-07-28 mirroring rule exists to close.

    An intermediary that routes or authorizes on the HEADER while the server executes
    the BODY can be made to approve one action and perform a different one. Here the
    header says `read_file` and the body says `delete_file`.
    """
    env = envelope(body(name="delete_file"), headers(name="read_file"))
    denies(env, ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH)


def test_the_check_is_symmetric_not_a_one_sided_allowlist() -> None:
    """The inverse. If only one direction were checked, a gateway would still pass
    every test above while remaining trivially bypassable from the other side."""
    env = envelope(body(name="read_file"), headers(name="delete_file"))
    denies(env, ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH)


def test_a_split_request_is_rejected_before_the_registry_or_policy_can_run() -> None:
    """PROTO-002, asserted structurally rather than by outcome.

    A denial that happened AFTER policy evaluation would satisfy an outcome-only
    assertion and still violate the requirement — the registry would have been
    consulted and policy would have evaluated attacker-chosen input. `validate` takes
    only an envelope and a config, so there is nothing it COULD call; this test pins
    that signature against a future refactor that "helpfully" passes deps in.
    """
    import inspect

    params = set(inspect.signature(protocol.validate).parameters)
    assert params == {"env", "cfg"}, (
        "validate gained a dependency it could consult before the consistency check"
    )


def test_method_disagreement_is_rejected() -> None:
    env = envelope(body("tools/call"), headers("tools/list"))
    denies(env, ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH)


def test_a_disputed_method_is_reported_as_a_method_dispute() -> None:
    """The name presence rule depends on the method, and the two sides name different
    methods — `Mcp-Name` is required for one and prohibited for the other. Reporting
    "name missing" or "name unexpected" would describe a consequence of the real
    defect rather than the defect. Both directions, because the rule is asymmetric.
    """
    denies(  # body wants tools/call (name required), header claims tools/list
        envelope(body("tools/call"), headers("tools/list", name=None)),
        ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH,
    )
    denies(  # body wants tools/list (name prohibited), header claims tools/call
        envelope(body("tools/list", name=None), headers("tools/call")),
        ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH,
    )


def test_version_disagreement_between_header_and_meta_is_rejected() -> None:
    """_tech/02 §3.5. The version must agree in BOTH places; the spec warns
    intermediaries not to trust mirrored headers on an older or absent version, so a
    request that disagrees with itself about its own version is refused outright."""
    env = envelope(body(version="2025-06-18"), headers(version=VERSION))
    denies(env, ReasonCode.PROTO_VERSION_MISMATCH)


@pytest.mark.parametrize(
    ("shape", "expected"),
    [
        ("version", ReasonCode.PROTO_VERSION_MISMATCH),
        ("method", ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH),
        ("name", ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH),
    ],
)
def test_every_mismatch_shape_maps_to_its_own_code(
    shape: str, expected: ReasonCode
) -> None:
    """The SDK answers all three with one code (-32020) and one message.

    We recover which field disagreed from that message, keyed on the SDK's own
    exported header constants. That is the one place unit 02 depends on SDK wording,
    so it gets a test that drives each shape through the real ladder. If an SDK
    upgrade rewords a message, this fails — instead of every mismatch quietly
    collapsing into one indistinguishable audit code.
    """
    if shape == "version":
        env = envelope(body(version="2025-06-18"), headers())
    elif shape == "method":
        env = envelope(body("tools/call"), headers("tools/list"))
    else:
        env = envelope(body(name="delete_file"), headers(name="read_file"))
    denies(env, expected)


# ===========================================================================
# §9.1 / PROTO-004..007 — the shapes the SDK folds together
# ===========================================================================


def test_a_missing_required_header_is_missing_not_a_mismatch() -> None:
    """PROTO-007. Both are 400/-32020 on the wire and completely different incidents:
    "the client never sent it" versus "the client sent something else"."""
    env = envelope(
        body(), [("mcp-protocol-version", VERSION), ("mcp-method", "tools/call")]
    )
    denies(env, ReasonCode.PROTO_METADATA_MISSING)


def test_a_missing_method_header_is_reported_as_missing() -> None:
    env = envelope(body(), [("mcp-protocol-version", VERSION), ("mcp-name", "read_file")])
    denies(env, ReasonCode.PROTO_METADATA_MISSING)


def test_a_prohibited_header_present_is_rejected() -> None:
    """PROTO-005. `tools/list` mirrors no name, so an `Mcp-Name` on it can never be
    compared against anything — it would ride through unchecked into whatever
    downstream component decided to trust it."""
    env = envelope(body("tools/list", name=None), headers("tools/list", name="read_file"))
    denies(env, ReasonCode.PROTO_METADATA_UNEXPECTED)


def test_an_empty_header_is_rejected_never_treated_as_absent() -> None:
    """PROTO-004. Treating empty as absent is the bug: it converts a header the client
    DID send into one it did not, and the comparison never happens."""
    env = envelope(body(), [*headers(name=None), ("mcp-name", "")])
    denies(env, ReasonCode.PROTO_METADATA_INVALID)


@pytest.mark.parametrize(
    "value", [" read_file", "read_file ", "read\x00file", "read\x7ffile"]
)
def test_a_malformed_header_value_is_rejected(value: str) -> None:
    """Edge whitespace and control characters. Rejected rather than normalised: the
    spec says reject where normalisation is ambiguous, and every intermediary strips
    whitespace slightly differently."""
    env = envelope(body(), [*headers(name=None), ("mcp-name", value)])
    denies(env, ReasonCode.PROTO_METADATA_INVALID)


@pytest.mark.parametrize("name", ["mcp-method", "mcp-name", "mcp-protocol-version"])
def test_a_duplicated_routing_header_is_rejected(name: str) -> None:
    """PROTO-004, and it must be caught on the raw PAIRS.

    Folding to a mapping first keeps one copy, and which one depends on the folding
    order — so the gateway and the upstream could read different values from the same
    request. That is precisely the divergence this unit exists to make impossible.
    """
    env = envelope(body(), [*headers(), (name, "something-else")])
    denies(env, ReasonCode.PROTO_METADATA_DUPLICATE)


def test_duplicates_are_rejected_even_when_the_values_agree() -> None:
    """Two identical copies have no legitimate use, and permitting them invites
    intermediary-dependent collapsing."""
    env = envelope(body(), [*headers(), ("mcp-method", "tools/call")])
    denies(env, ReasonCode.PROTO_METADATA_DUPLICATE)


# ===========================================================================
# §9.4 — the base64 sentinel
# ===========================================================================


def encoded(value: str) -> str:
    from mcp.shared.inbound import encode_header_value

    return encode_header_value(value)


def test_a_sentinel_encoded_name_matching_the_body_is_accepted() -> None:
    """A tool name that cannot survive an HTTP field is base64-wrapped by the client.
    Decoded exactly once, then compared."""
    tool = "réad_file"
    req = protocol.validate(envelope(body(name=tool), headers(name=encoded(tool))), CFG)
    assert req.tool_name == tool


def test_a_sentinel_encoded_name_disagreeing_with_the_body_is_rejected() -> None:
    env = envelope(body(name="réad_file"), headers(name=encoded("délete_file")))
    denies(env, ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH)


def test_a_malformed_sentinel_is_invalid_not_a_mismatch() -> None:
    """Nothing was compared, so calling it a mismatch would be a lie in the record."""
    env = envelope(body(), [*headers(name=None), ("mcp-name", "=?base64?not!valid!?=")])
    denies(env, ReasonCode.PROTO_METADATA_INVALID)


def test_a_sentinel_carrying_non_utf8_bytes_is_invalid() -> None:
    import base64

    bad = "=?base64?" + base64.b64encode(b"\xff\xfe").decode() + "?="
    env = envelope(body(), [*headers(name=None), ("mcp-name", bad)])
    denies(env, ReasonCode.PROTO_METADATA_INVALID)


def test_an_uppercase_marker_is_not_a_sentinel() -> None:
    """`=?BASE64?...?=` is a literal value, not an encoding. Treating it as one would
    make two different header values decode to the same body value — a bypass."""
    literal = "=?BASE64?cmVhZF9maWxl?="
    req = protocol.validate(envelope(body(name=literal), headers(name=literal)), CFG)
    assert req.tool_name == literal


def test_non_canonical_base64_does_not_decode_to_a_match() -> None:
    """`b64decode` without `validate=True` discards non-alphabet characters, so two
    different headers decode to the same value. The SDK re-encodes and compares; this
    pins that it does."""
    env = envelope(body(name="read_file"), headers(name="=?base64?cmVh\nZF9maWxl?="))
    denies(env, ReasonCode.PROTO_METADATA_INVALID)


# ===========================================================================
# §9.7 / PROTO-008 — version
# ===========================================================================


def test_a_downgraded_version_is_denied_not_adapted() -> None:
    """The spec-currency argument, made concrete: an older revision is refused, not
    silently served through a compatibility path."""
    old = "2025-06-18"
    env = envelope(body(version=old), headers(version=old))
    denies(env, ReasonCode.PROTO_VERSION_UNSUPPORTED)


def test_an_unknown_future_version_is_denied() -> None:
    env = envelope(body(version="2099-01-01"), headers(version="2099-01-01"))
    denies(env, ReasonCode.PROTO_VERSION_UNSUPPORTED)


def test_an_absent_version_header_is_missing() -> None:
    env = envelope(body(), [("mcp-method", "tools/call"), ("mcp-name", "read_file")])
    denies(env, ReasonCode.PROTO_METADATA_MISSING)


def test_a_body_with_no_envelope_metadata_is_rejected() -> None:
    """Rung 1. The 2026-07-28 envelope keys are mandatory per request — that is what
    replaced the `initialize` handshake."""
    b = body()
    del b["params"]["_meta"]
    denies(envelope(b), ReasonCode.PROTO_METADATA_MISSING)


def test_a_body_missing_client_capabilities_is_rejected() -> None:
    b = body()
    del b["params"]["_meta"][CLIENT_CAPABILITIES_META_KEY]
    denies(envelope(b), ReasonCode.PROTO_METADATA_MISSING)


# ===========================================================================
# §9.8 / PROTO-010 — default-deny on method
# ===========================================================================


def conforming(method: str) -> RawEnvelope:
    """A fully valid, fully consistent request for `method`.

    The name-bearing methods mirror different body keys — `resources/read` mirrors
    `uri`, the others mirror `name` — so the envelope is built from the SDK's own
    table. Otherwise a test aimed at the allowlist would be answered by a metadata
    rejection and would pass for the wrong reason.
    """
    from mcp.shared.inbound import NAME_BEARING_METHODS

    key = NAME_BEARING_METHODS.get(method)
    target = "file:///x" if key == "uri" else "read_file"
    b = body(method, name=None)
    if key is not None:
        b["params"][key] = target
    return envelope(b, headers(method, name=target if key else None))


@pytest.mark.parametrize(
    "method", ["resources/read", "prompts/get", "completion/complete", "resources/list"]
)
def test_a_valid_mcp_method_outside_the_allowlist_is_denied_not_proxied(
    method: str,
) -> None:
    """Default-deny is the posture: a method the gateway does not protect is refused,
    never passed through unauthorized because it happens to be legal MCP.

    The request is otherwise impeccable — correct version, matching headers, valid
    envelope. Nothing is wrong with it except that we do not serve it.
    """
    denies(conforming(method), ReasonCode.PROTO_METHOD_NOT_ALLOWED)


def test_a_recognized_denied_method_gets_the_same_denial() -> None:
    """`recognized_denied` buys a clean modern error instead of a timeout. It is not a
    softer refusal — same code, same status."""
    d = denies(conforming("server/discover"), ReasonCode.PROTO_METHOD_NOT_ALLOWED)
    assert d.wire == (404, -32601), "a probing client must be able to tell we are modern"


def test_an_invented_method_is_denied() -> None:
    denies(conforming("evil/exfiltrate"), ReasonCode.PROTO_METHOD_NOT_ALLOWED)


# ===========================================================================
# PROTO-009/011 — JSON-RPC envelope
# ===========================================================================


def test_invalid_json_is_rejected() -> None:
    denies(envelope(b'{"jsonrpc": "2.0",'), ReasonCode.PROTO_JSON_INVALID)


def test_a_non_utf8_body_is_rejected() -> None:
    denies(
        envelope(b'{"jsonrpc":"2.0","id":1,"method":"\xff"}'),
        ReasonCode.PROTO_JSON_INVALID,
    )


@pytest.mark.parametrize("value", ["1.0", "2", None, 2.0])
def test_a_wrong_jsonrpc_marker_is_rejected(value: Any) -> None:
    b = body()
    b["jsonrpc"] = value
    denies(envelope(b), ReasonCode.PROTO_JSONRPC_INVALID)


def test_a_batch_is_rejected() -> None:
    """v1 supports no batch shape. A batch would need one authorization decision per
    element and one audit event per element; neither exists."""
    denies(envelope(json.dumps([body()]).encode()), ReasonCode.PROTO_JSONRPC_INVALID)


def test_a_notification_without_an_id_is_rejected() -> None:
    b = body()
    del b["id"]
    denies(envelope(b), ReasonCode.PROTO_JSONRPC_INVALID)


@pytest.mark.parametrize("rid", [True, 1.5, [], {}, None])
def test_an_invalid_request_id_is_rejected(rid: Any) -> None:
    """`True` is the interesting one: `bool` is an `int` subclass, so a naive
    isinstance check accepts a JSON `true` as a request identifier."""
    denies(envelope(body(rid=rid)), ReasonCode.PROTO_JSONRPC_INVALID)


def test_a_string_id_is_accepted() -> None:
    assert protocol.validate(envelope(body(rid="abc")), CFG).jsonrpc_id == "abc"


def test_params_that_are_not_an_object_are_rejected() -> None:
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}'
    denies(envelope(raw), ReasonCode.PROTO_JSONRPC_INVALID)


def test_arguments_that_are_not_an_object_are_rejected() -> None:
    denies(
        envelope(body(arguments=["not", "an", "object"])),
        ReasonCode.PROTO_JSONRPC_INVALID,
    )  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [[], "", 0, False, 0.0])
def test_falsey_arguments_are_rejected_not_silently_repaired(bad: Any) -> None:
    """Review finding: `params.get("arguments") or {}` repaired every falsey
    non-object.

    `[]`, `""`, `0` and `false` all became `{}` and then passed the isinstance check
    that existed to catch them — the guard rewrote a malformed request into a valid
    zero-argument call. A tool whose parameters are all optional would then have
    executed on input the client never sent, authorized against arguments nobody
    supplied. Absent and empty-but-wrong are different things; only `None` is absent.
    """
    b = body()
    b["params"]["arguments"] = bad
    denies(envelope(b), ReasonCode.PROTO_JSONRPC_INVALID)


def test_absent_arguments_are_still_an_empty_object() -> None:
    """The other half: `tools/call` on a no-argument tool is legitimate, and must not
    be collateral damage from the fix above."""
    b = body()
    b["params"].pop("arguments", None)
    assert protocol.validate(envelope(b), CFG).arguments == {}


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_json_constants_are_rejected(literal: str) -> None:
    """`json.loads` accepts these as an extension. They are not JSON.

    Left in, they would reach `canonical_json`, which sets `allow_nan=False` — so the
    request would die at the HASHING step, after policy had already authorized it.
    An internal error at that point is a defect attributed to the gateway, for input
    the attacker chose.
    """
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        b'{"arguments":{"n":' + literal.encode() + b"}}}"
    )
    denies(envelope(raw), ReasonCode.PROTO_JSON_INVALID)


def test_a_nan_nested_deep_in_the_payload_is_still_rejected() -> None:
    """`parse_constant` fires wherever the literal appears, which is why it is the
    right hook — a post-parse scan would have to walk the whole tree looking for a
    float that is not equal to itself."""
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        b'{"arguments":{"a":{"b":[1,2,{"c":NaN}]}}}}'
    )
    denies(envelope(raw), ReasonCode.PROTO_JSON_INVALID)


def test_an_integer_beyond_the_int_to_str_limit_denies_cleanly() -> None:
    """Review finding: it escaped as a bare `ValueError`.

    CPython caps int<->str conversion at `sys.get_int_max_str_digits` (4300 by
    default) and json's scanner calls `int()` on the literal, so a 5,000-digit number
    raised straight out of the parser. `pipeline.handle` would record that as
    INTERNAL_ERROR and answer 500 — a defect, attributed to us, for input the
    attacker chose and can repeat at will.

    Note the ordering trap in the fix: `JSONDecodeError` subclasses `ValueError`, so
    the broad arm has to come last or every syntax error is reported as a bad number.
    """
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"n":'
        + b"9" * 5000
        + b"}}"
    )
    denies(envelope(raw), ReasonCode.PROTO_JSON_INVALID)


def test_an_integer_just_under_the_limit_still_parses() -> None:
    """Boundary, and a guard against "fix it by rejecting all big numbers"."""
    big = b"9" * 4000
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":'
        b'{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
        b'"io.modelcontextprotocol/clientCapabilities":{},"n":' + big + b"}}}"
    )
    req = protocol.validate(envelope(raw, headers("tools/list", name=None)), CFG)
    assert req.method == "tools/list"


# ===========================================================================
# PROTO-011 — duplicate keys
# ===========================================================================


def test_a_duplicate_body_key_is_rejected() -> None:
    """stdlib `json` with `object_pairs_hook` is the ONLY way to see this.

    `orjson` applies last-key-wins silently, which would make this code unreachable
    and the requirement a lie — and it is exactly the shape where two readers of the
    same bytes disagree.
    """
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}'
    denies(envelope(raw), ReasonCode.PROTO_DUPLICATE_FIELD)


def test_a_duplicate_key_is_rejected_even_when_the_values_agree() -> None:
    raw = b'{"jsonrpc":"2.0","id":1,"id":1,"method":"tools/list"}'
    denies(envelope(raw), ReasonCode.PROTO_DUPLICATE_FIELD)


def test_a_duplicate_nested_key_is_rejected() -> None:
    raw = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
        b'{"name":"read_file","name":"delete_file"}}'
    )
    denies(envelope(raw), ReasonCode.PROTO_DUPLICATE_FIELD)


def test_the_parser_we_chose_actually_reports_duplicates() -> None:
    """The dependency choice itself, asserted. `_tech/02` §2 says to verify this
    before choosing a parser; this is that verification, kept."""
    seen: list[str] = []
    json.loads(
        b'{"a":1,"a":2}', object_pairs_hook=lambda p: seen.extend(k for k, _ in p) or {}
    )
    assert seen == ["a", "a"], "the parser collapsed a duplicate key before we saw it"


# ===========================================================================
# §9.5 — boundaries. n-1 passes, n passes, n+1 denies (CONV-015).
# ===========================================================================


def test_depth_boundary() -> None:
    cfg = ProtocolConfig(max_depth=8)
    for depth in (7, 8):
        protocol.prescan(b"[" * depth + b"]" * depth, cfg)
    with pytest.raises(ProtocolDenial) as e:
        protocol.prescan(b"[" * 9 + b"]" * 9, cfg)
    assert e.value.reason_code is ReasonCode.PROTO_LIMIT_EXCEEDED


def test_body_size_boundary() -> None:
    cfg = ProtocolConfig(max_body_bytes=100)
    protocol.prescan(b"x" * 100, cfg)
    with pytest.raises(ProtocolDenial):
        protocol.prescan(b"x" * 101, cfg)


def test_array_length_boundary() -> None:
    cfg = ProtocolConfig(max_array_length=10)
    protocol.check_limits({"a": list(range(10))}, cfg)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({"a": list(range(11))}, cfg)


def test_string_length_boundary() -> None:
    cfg = ProtocolConfig(max_string_length=10)
    protocol.check_limits({"a": "x" * 10}, cfg)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({"a": "x" * 11}, cfg)


def test_a_long_key_counts_as_a_long_string() -> None:
    """Otherwise a 10 MiB key sails through while a 10 MiB value is rejected."""
    cfg = ProtocolConfig(max_string_length=10)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({"x" * 11: 1}, cfg)


def test_object_key_count_boundary() -> None:
    """PROTO-012 lists max object key count SEPARATELY from max total fields, and the
    separation is the point: one object with 4,999 keys passes a 5,000-field budget
    while being exactly the shape that makes a downstream schema validator quadratic.
    """
    cfg = ProtocolConfig(max_object_keys=10, max_total_fields=10_000)
    protocol.check_limits({str(i): i for i in range(10)}, cfg)
    with pytest.raises(ProtocolDenial) as e:
        protocol.check_limits({str(i): i for i in range(11)}, cfg)
    assert e.value.reason_code is ReasonCode.PROTO_LIMIT_EXCEEDED


def test_one_wide_object_is_caught_even_when_the_total_budget_is_generous() -> None:
    """The case a total-only limit misses entirely."""
    cfg = ProtocolConfig(max_object_keys=100, max_total_fields=1_000_000)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({str(i): i for i in range(5_000)}, cfg)


def test_many_narrow_objects_are_caught_by_the_total_budget() -> None:
    """The converse: the per-object limit must not make the total limit redundant."""
    cfg = ProtocolConfig(max_object_keys=1_000, max_total_fields=50)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({"a": [{"k": i} for i in range(100)]}, cfg)


def test_total_field_count_boundary() -> None:
    cfg = ProtocolConfig(max_total_fields=10)
    protocol.check_limits({str(i): i for i in range(10)}, cfg)
    with pytest.raises(ProtocolDenial):
        protocol.check_limits({str(i): i for i in range(11)}, cfg)


def test_field_count_accumulates_across_nesting() -> None:
    """Counting per-object instead of in total would let 5,000 objects of one field
    each pass a 5,000-field limit."""
    cfg = ProtocolConfig(max_total_fields=6)
    nested = {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}
    with pytest.raises(ProtocolDenial):
        protocol.check_limits(nested, cfg)


def test_the_prescan_is_string_aware() -> None:
    """`{"a": "{{{{{{"}` is depth 1. Counting braces inside strings would reject
    ordinary payloads — and the fix for THAT is usually to raise the limit."""
    protocol.prescan(json.dumps({"a": "{" * 100}).encode(), ProtocolConfig(max_depth=4))


def test_the_prescan_handles_escaped_quotes() -> None:
    """A `\\"` inside a string must not end it. If it did, every brace after would be
    counted and the limit would fire on valid input."""
    protocol.prescan(json.dumps({"a": '\\" {{{{'}).encode(), ProtocolConfig(max_depth=4))


# ===========================================================================
# §9.6 — pathological payloads
# ===========================================================================


PATHOLOGICAL = {
    "deep nesting": lambda: b"[" * 100_000,
    "huge array": lambda: json.dumps({"a": list(range(200_000))}).encode(),
    "long string": lambda: json.dumps({"a": "x" * 2_000_000}).encode(),
    "many duplicate keys": lambda: b"{" + b",".join([b'"a":1'] * 50_000) + b"}",
}


@pytest.mark.parametrize("name", list(PATHOLOGICAL))
def test_a_pathological_payload_is_rejected_within_the_parse_budget(name: str) -> None:
    """PROTO-013. The point is not that it is rejected — it is that rejection is
    CHEAP. A payload that dies only after the parser has built it has already spent
    the memory the limit exists to prevent.

    `b"[" * 100_000` is the case that matters most: `json.loads` would hit CPython's
    recursion ceiling and raise RecursionError, which is an internal defect, not a
    denial. The prescan means the parser never sees it.
    """
    payload = PATHOLOGICAL[name]()
    started = time.perf_counter()
    with pytest.raises(ProtocolDenial) as caught:
        protocol.validate(envelope(payload), CFG)
    elapsed_ms = (time.perf_counter() - started) * 1000

    assert caught.value.reason_code in (
        ReasonCode.PROTO_LIMIT_EXCEEDED,
        ReasonCode.PROTO_DUPLICATE_FIELD,
    )
    assert elapsed_ms < 1000, f"{name} took {elapsed_ms:.0f}ms"


def test_deep_nesting_never_reaches_the_recursive_parser() -> None:
    """Stated as its own test because the failure mode is specific: without the
    prescan this raises RecursionError, which `pipeline.handle` would record as
    INTERNAL_ERROR — a defect, not a denial, and a 500 rather than a 413."""
    with pytest.raises(ProtocolDenial):
        protocol.validate(envelope(b"[" * 100_000), CFG)


def test_the_limit_walk_does_not_recurse() -> None:
    """A recursive walk would reintroduce the stack problem one layer later, with the
    payload already in memory. Built past CPython's recursion limit on purpose."""
    node: Any = 1
    for _ in range(5_000):
        node = {"n": node}
    with pytest.raises(ProtocolDenial):
        protocol.check_limits(node, ProtocolConfig(max_total_fields=100))


# ===========================================================================
# MRTR (ADR-001 §5)
# ===========================================================================


def test_a_mid_request_input_response_is_refused() -> None:
    """v1 has no policy for a mid-request exchange, so it refuses rather than
    proxying a second side-effect path around stage 06."""
    env = envelope(body(inputResponses=[{"id": "x", "value": "y"}]))
    denies(env, ReasonCode.PROTO_MRTR_UNSUPPORTED)


# ===========================================================================
# PROTO-014 — what a rejection may say
# ===========================================================================


def test_a_denial_message_reveals_nothing() -> None:
    """No payload echo, no parser internals, no configured limit values."""
    d = denies(
        envelope(body(name="/etc/shadow"), headers(name="read_file")),
        ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH,
    )
    assert "shadow" not in d.message
    assert d.message == "Request headers do not match the request body."


def test_limit_denials_do_not_disclose_the_limit() -> None:
    d = denies(envelope(b"[" * 100_000), ReasonCode.PROTO_LIMIT_EXCEEDED)
    assert d.message == "Request exceeds a structural limit."
    assert str(CFG.max_depth) not in d.message


def test_diagnostic_detail_exists_but_is_not_the_message() -> None:
    """`detail` is for the operator's diagnostic sink. It carries payload fragments by
    construction, which is exactly why AUDIT-005 keeps it out of the record."""
    d = denies(
        envelope(body(name="secret-tool")), ReasonCode.PROTO_HEADER_BODY_NAME_MISMATCH
    )
    assert d.detail is not None
    assert d.detail != d.message


# ===========================================================================
# Mcp-Param-* (ADR-001 §3.1) — owned here, called by unit 04
# ===========================================================================

SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "x-mcp-header": "Path"},
        "count": {"type": "integer", "x-mcp-header": "Count"},
    },
}


def test_matching_param_headers_pass() -> None:
    protocol.check_param_headers(
        SCHEMA,
        {"path": "a.txt", "count": 3},
        {"mcp-param-path": "a.txt", "mcp-param-count": "3"},
    )


def test_a_param_header_disagreeing_with_the_body_is_rejected() -> None:
    """The same split-authorization attack one level down: an intermediary routing on
    `Mcp-Param-Path` while the tool reads `arguments.path`."""
    with pytest.raises(ProtocolDenial) as e:
        protocol.check_param_headers(
            SCHEMA, {"path": "public/a.txt"}, {"mcp-param-path": "confidential/x"}
        )
    assert e.value.reason_code is ReasonCode.PROTO_HEADER_BODY_PARAM_MISMATCH


def test_a_param_header_with_no_matching_argument_is_rejected() -> None:
    """The spec's purpose clause names this exactly: an intermediary routing on a
    value the body never carried."""
    with pytest.raises(ProtocolDenial):
        protocol.check_param_headers(SCHEMA, {}, {"mcp-param-path": "confidential/x"})


def test_an_argument_whose_param_header_was_omitted_is_rejected() -> None:
    with pytest.raises(ProtocolDenial):
        protocol.check_param_headers(SCHEMA, {"path": "a.txt"}, {})


def test_integer_params_compare_numerically() -> None:
    """The spec's SHOULD. `3` in the body matches a canonical-decimal `3` header."""
    protocol.check_param_headers(SCHEMA, {"count": 3}, {"mcp-param-count": "3"})
    with pytest.raises(ProtocolDenial):
        protocol.check_param_headers(SCHEMA, {"count": 3}, {"mcp-param-count": "4"})


def test_param_header_checking_needs_a_schema_this_stage_does_not_have() -> None:
    """Documents the one ordering constraint in the unit: the annotations live in the
    APPROVED inputSchema, which only the registry resolves. Still before policy and
    the router, so PROTO-002 holds — but not inside `validate`, and threading a
    permanently-`None` schema through it would hide that."""
    import inspect

    assert "input_schema" not in inspect.signature(protocol.validate).parameters


# ===========================================================================
# Audit contribution (spec §8)
# ===========================================================================


def test_stage_02_contributes_its_audit_fields() -> None:
    from gateway.audit_schema import RequestEvent

    req = protocol.validate(envelope(body(arguments={"path": "a.txt"})), CFG)
    fields = protocol.audit_fields(req)
    assert fields["mcp_method"] == "tools/call"
    assert fields["mcp_protocol_version"] == VERSION
    assert set(fields) <= set(RequestEvent.model_fields), "a field the schema forbids"


# ===========================================================================
# PROTO-007 — the corpus. Every disagreement shape has a published scenario,
# and every published scenario runs.
# ===========================================================================


def protocol_scenarios() -> list[Any]:
    from harness.scenario import load

    return [s for s in load().scenarios if s.layer == "protocol"]


@pytest.mark.parametrize("scenario", protocol_scenarios(), ids=lambda s: s.id)
def test_the_published_corpus_scores_against_the_real_guard(scenario: Any) -> None:
    """`validate` is a pure function of an envelope and a config, so the protocol
    class of the corpus can be scored right now — no gateway process, no fixture.

    That matters beyond convenience: a corpus written months before it can run is a
    corpus nobody has checked. These rows are the SDK-upgrade gate, and a gate that
    has never been closed is not a gate.

    The legitimate row is scored here as "not denied at stage 02". Whether it is
    ALLOWED is unit 06's answer and the full harness's assertion — the point of
    keeping it in this file is that a gateway which denies everything must not score
    100% on the malicious rows.
    """
    from harness.wire import build_envelope

    env = build_envelope(scenario)

    if scenario.expected_decision == "allow":
        req = protocol.validate(env, CFG)
        assert req.tool_name == scenario.tool
        return

    with pytest.raises(ProtocolDenial) as caught:
        protocol.validate(env, CFG)
    assert caught.value.reason_code.value == scenario.expected_reason, (
        f"{scenario.id}: corpus says {scenario.expected_reason}, "
        f"guard said {caught.value.reason_code.value} ({caught.value.detail})"
    )


def test_every_stage_02_reason_code_has_a_corpus_scenario() -> None:
    """CONV-010, checked rather than asserted in a document.

    A reason code with no scenario is a branch nobody has ever exercised, and the
    published security rate would be computed over a corpus that never reaches it.
    """
    published = {s.expected_reason for s in protocol_scenarios()}
    unreached = {
        c.value
        for c in ReasonCode
        if c.value.startswith("PROTO_")
        and c.value not in published
        # Owned by unit 01's edge (size, framing, origin), not by this stage.
        and c
        not in {
            ReasonCode.PROTO_MESSAGE_TOO_LARGE,
            ReasonCode.PROTO_FRAMING_INVALID,
            ReasonCode.PROTO_ORIGIN_REJECTED,
            # Needs an approved inputSchema, so it is unit 04's scenario to publish.
            ReasonCode.PROTO_HEADER_BODY_PARAM_MISMATCH,
            # Prohibited-and-present: expressible only once a method that mirrors no
            # name is in the allowlist AND reachable, which is tools/list. Covered by
            # test_a_prohibited_header_present_is_rejected until the corpus can send
            # a non-tools/call method.
            ReasonCode.PROTO_METADATA_UNEXPECTED,
        }
    }
    assert not unreached, f"reason codes with no published scenario: {sorted(unreached)}"


def test_the_audit_contribution_carries_a_hash_not_the_body() -> None:
    """AUDIT-005. The body hash makes a request identifiable without recording what
    was in it."""
    secret = {"path": "confidential/salaries.csv"}
    fields = protocol.audit_fields(
        protocol.validate(envelope(body(arguments=secret)), CFG)
    )
    assert "salaries" not in json.dumps(fields)

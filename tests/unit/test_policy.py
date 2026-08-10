"""Unit 06 — the broker's half. `_specs/06-svc-policy-broker.md` §9.

These tests need no OPA. They point the client at a stub transport that returns
whatever malformed answer the case is about, because that is the only way to produce
the answers a correct OPA never gives — an empty document, an allow with no reason
code, a decision value nobody defined. The live-OPA half is
`tests/integration/test_policy_opa.py`, and the Rego half is `opa test policies/`,
which runs without Python at all (POLICY-016).

The through-line: every test below asserts a DENIAL. Absence of an allow is a deny
(POLICY-005), and this file is the enumeration of "absence".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from gateway import policy
from gateway.config import PolicyConfig
from gateway.errors import PolicyDenial, ReasonCode
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    DerivedAttributes,
    ResolvedTarget,
)

REPO = Path(__file__).resolve().parents[2]
CFG = PolicyConfig()

pytestmark = pytest.mark.anyio


def req() -> CanonicalRequest:
    return CanonicalRequest(
        request_id="req-1",
        protocol_version="2026-07-28",
        method="tools/call",
        jsonrpc_id=1,
        tool_name="read_file",
        arguments={"path": "public/documentation.txt"},
        body_hash="bodyhash",
    )


def ctx(principal: str = "developer", *roles: str) -> AuthzContext:
    return AuthzContext(
        principal=principal,
        client_id="test-driver",
        roles=roles or (principal,),
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )


def tgt(tier: str = "R1", tool: str | None = "read_file") -> ResolvedTarget:
    return ResolvedTarget(
        server_id="filesystem-fixture",
        tool_name=tool,
        schema_fingerprint="v2:abc" if tool else None,
        registry_risk_tier=tier,  # type: ignore[arg-type]
        operation="read",
    )


def drv(root: str = "public") -> DerivedAttributes:
    return DerivedAttributes(
        canonical_path=f"/fixture/{root}/documentation.txt",
        root=root,
        classification="public",
        operation="read",
        exists=True,
        arg_hash="arghash",
        raw_hash="rawhash",
    )


def result_of(decision: Any) -> dict[str, Any]:
    """The OPA response envelope. The decision document is nested under `result`, and
    a body with no `result` key is how OPA reports an undefined path."""
    return {"result": decision}


def engine_returning(payload: Any, *, status: int = 200) -> policy.PolicyEngine:
    """A `PolicyEngine` whose OPA always answers `payload` as the whole HTTP BODY.

    A stub TRANSPORT rather than a stub client: everything in `_post_decision` —
    the deadline, the retry rule, `raise_for_status`, the JSON decode — is exercised
    exactly as in production, and only the bytes on the wire are ours.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if isinstance(payload, str):
            return httpx.Response(status, content=payload.encode("utf-8"))
        return httpx.Response(status, json=payload)

    client = httpx.AsyncClient(
        base_url=CFG.base_url, transport=httpx.MockTransport(handler)
    )
    return policy.PolicyEngine(client, "rev-under-test")


async def denial(payload: Any, *, status: int = 200) -> ReasonCode:
    with pytest.raises(PolicyDenial) as exc:
        await policy.evaluate(
            req(), ctx(), tgt(), drv(), engine_returning(payload, status=status), CFG
        )
    return exc.value.reason_code


# ===========================================================================
# Spec tests 2-4, 13 — anything that is not a well-formed allow
# ===========================================================================


async def test_2_an_empty_document_is_a_deny() -> None:
    """OPA answers HTTP 200 with `{}` when the queried path is undefined — a rule-name
    typo, or a bundle that failed to load, arrives as a SUCCESSFUL response carrying
    nothing. Any truthiness check on that result would be the most expensive bug this
    module could contain."""
    assert await denial({}) is ReasonCode.POLICY_DEFAULT_DENY


async def test_3_an_allow_with_no_reason_code_is_a_deny() -> None:
    """POLICY-006. A decision the audit log cannot name is not a decision."""
    assert (
        await denial(result_of({"decision": "allow"})) is ReasonCode.POLICY_RESULT_INVALID
    )


@pytest.mark.parametrize("verdict", ["maybe", "ALLOW", "", None, True, 1])
async def test_4_an_unrecognized_decision_value_is_a_deny(verdict: Any) -> None:
    decision = {
        "decision": verdict,
        "reason_code": "POLICY_SCOPED_READ",
        "risk_tier": "R1",
    }
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


@pytest.mark.parametrize("verdict", ["denied", "DENY", "refuse"])
async def test_4b_a_deny_shaped_value_that_is_not_deny_is_still_invalid(
    verdict: Any,
) -> None:
    """The case the membership check is the ONLY guard for, found by the break pass.

    With a deny-side reason code, the allow/deny consistency check agrees with itself
    — neither half claims an allow — so removing the membership check let these reach
    `Decision(...)` and fail as a raw pydantic error, which the pipeline records as
    INTERNAL_ERROR. Still a denial, and still the wrong reason code on the record.
    Every other value in the case above was caught by a second guard, so the whole
    parametrize list passed against a broker that no longer validated the field.
    """
    decision = {
        "decision": verdict,
        "reason_code": "POLICY_PATH_NOT_PERMITTED",
        "risk_tier": "R1",
    }
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


async def test_a_reason_code_outside_the_closed_set_is_a_deny() -> None:
    """The bundle and this build disagreeing about the vocabulary is not a decision
    either way — `policies/reason_codes.json` exists so they cannot."""
    decision = {"decision": "allow", "reason_code": "FILESYSTEM_OK", "risk_tier": "R1"}
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


async def test_an_allow_carrying_a_deny_code_is_a_deny() -> None:
    """The two halves of the answer contradicting each other. Without this check the
    audit record would say `allow` next to POLICY_PATH_NOT_PERMITTED — and unit 07
    would route on the strength of the half that said yes."""
    decision = {
        "decision": "allow",
        "reason_code": "POLICY_PATH_NOT_PERMITTED",
        "risk_tier": "R1",
    }
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


async def test_a_deny_carrying_an_allow_code_is_a_deny() -> None:
    decision = {
        "decision": "deny",
        "reason_code": "POLICY_SCOPED_READ",
        "risk_tier": "R1",
    }
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


@pytest.mark.parametrize("tier", ["R3", "r1", "", None, "R5"])
async def test_an_unknown_risk_tier_is_a_deny(tier: Any) -> None:
    """R3 is absent from `RiskTier` because a tier that cannot be enforced must not be
    expressible (CONV-007). A policy emitting one is a policy this build cannot honour."""
    decision = {
        "decision": "allow",
        "reason_code": "POLICY_SCOPED_READ",
        "risk_tier": tier,
    }
    assert await denial(result_of(decision)) is ReasonCode.POLICY_RESULT_INVALID


@pytest.mark.parametrize("body", ["[]", '"allow"', "null", "17"])
async def test_a_non_object_result_is_a_deny(body: str) -> None:
    assert await denial(result_of(json.loads(body))) in (
        ReasonCode.POLICY_RESULT_INVALID,
        ReasonCode.POLICY_DEFAULT_DENY,
    )


async def test_unparseable_json_is_a_deny() -> None:
    assert await denial("{not json") is ReasonCode.POLICY_UNAVAILABLE


async def test_an_http_error_from_opa_is_a_deny() -> None:
    assert await denial({"result": {}}, status=500) is ReasonCode.POLICY_UNAVAILABLE


async def test_no_engine_at_all_is_a_deny() -> None:
    """A gateway assembled without a policy engine must not be a gateway that allows."""
    with pytest.raises(PolicyDenial) as exc:
        await policy.evaluate(req(), ctx(), tgt(), drv(), None, CFG)
    assert exc.value.reason_code is ReasonCode.POLICY_UNAVAILABLE


async def test_a_missing_revision_is_a_deny() -> None:
    """POLICY-014: a decision whose revision cannot be determined is a denial. An
    unattributable allow is worse than no allow — the report could not say which
    policy produced it."""
    good = result_of(
        {
            "decision": "allow",
            "reason_code": "POLICY_SCOPED_READ",
            "risk_tier": "R1",
            "obligations": {},
        }
    )
    with pytest.raises(PolicyDenial) as exc:
        await policy.evaluate(
            req(),
            ctx(),
            tgt(),
            drv(),
            policy.PolicyEngine(engine_returning(good).client, ""),
            CFG,
        )
    assert exc.value.reason_code is ReasonCode.POLICY_REVISION_UNKNOWN


# ===========================================================================
# Spec tests 1, 6 — unreachable and slow
# ===========================================================================


async def test_1_an_unreachable_opa_denies() -> None:
    """The headline claim, at unit level; the live-process version is the integration
    test that kills the sidecar."""

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.AsyncClient(
        base_url=CFG.base_url, transport=httpx.MockTransport(refuse)
    )
    with pytest.raises(PolicyDenial) as exc:
        await policy.evaluate(
            req(), ctx(), tgt(), drv(), policy.PolicyEngine(client, "rev"), CFG
        )
    assert exc.value.reason_code is ReasonCode.POLICY_UNAVAILABLE


async def test_6_a_slow_evaluation_denies_and_is_not_retried() -> None:
    """POLICY-011. The deadline is a denial, not a wait, and never a retry: a timeout
    may have evaluated, so a second attempt would be a second decision for one
    request. The call counter is what proves the retry did not happen — a test that
    only checked the reason code would pass on an implementation that retried five
    times first."""
    import anyio

    calls = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        await anyio.sleep(5)
        return httpx.Response(200, json={"result": {}})

    client = httpx.AsyncClient(base_url=CFG.base_url, transport=httpx.MockTransport(slow))
    fast = CFG.model_copy(update={"timeout_ms": 50})
    with pytest.raises(PolicyDenial) as exc:
        await policy.evaluate(
            req(), ctx(), tgt(), drv(), policy.PolicyEngine(client, "rev"), fast
        )
    assert exc.value.reason_code is ReasonCode.POLICY_TIMEOUT
    assert calls == 1, f"a timeout was retried {calls} times"


async def test_a_connect_error_is_retried_exactly_once() -> None:
    """The one permitted retry, and its boundary. A connection refused before any byte
    was sent cannot have evaluated anything, so retrying it is not retrying a
    decision. Twice would be."""
    calls = 0

    def flaky(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(
            200,
            json={
                "result": {
                    "decision": "allow",
                    "reason_code": "POLICY_SCOPED_READ",
                    "risk_tier": "R1",
                    "obligations": {},
                }
            },
        )

    client = httpx.AsyncClient(
        base_url=CFG.base_url, transport=httpx.MockTransport(flaky)
    )
    dec = await policy.evaluate(
        req(), ctx(), tgt(), drv(), policy.PolicyEngine(client, "rev"), CFG
    )
    assert dec.decision == "allow"
    assert calls == 2


async def test_a_deny_is_never_retried() -> None:
    """Retrying a deny is how a fail-closed system becomes a poll-until-allow one."""
    calls = 0

    def denying(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            json={
                "result": {
                    "decision": "deny",
                    "reason_code": "POLICY_PATH_NOT_PERMITTED",
                    "risk_tier": "R1",
                    "obligations": {},
                }
            },
        )

    client = httpx.AsyncClient(
        base_url=CFG.base_url, transport=httpx.MockTransport(denying)
    )
    dec = await policy.evaluate(
        req(), ctx(), tgt(), drv(), policy.PolicyEngine(client, "rev"), CFG
    )
    assert dec.decision == "deny"
    assert calls == 1


# ===========================================================================
# Spec test 5 — clamping (POLICY-007)
# ===========================================================================


def test_5_an_obligation_above_the_ceiling_is_clamped_and_flagged() -> None:
    obligations, clamped = policy.clamp(
        {"timeout_ms": 999_999, "max_response_bytes": 999_999_999}, CFG
    )
    assert obligations.timeout_ms == CFG.max_timeout_ms
    assert obligations.max_response_bytes == CFG.max_response_bytes
    assert clamped is True


def test_policy_may_narrow_without_being_flagged() -> None:
    """`min` only. A policy asking for LESS than the ceiling gets exactly what it
    asked for and no clamp flag — narrowing is the whole point of an obligation."""
    obligations, clamped = policy.clamp(
        {"timeout_ms": 250, "max_response_bytes": 1024}, CFG
    )
    assert obligations.timeout_ms == 250
    assert obligations.max_response_bytes == 1024
    assert clamped is False


@pytest.mark.parametrize(
    "raw", [None, {}, {"timeout_ms": "3000"}, {"timeout_ms": -1}, {"timeout_ms": True}]
)
def test_a_missing_or_nonsense_obligation_takes_the_default(raw: Any) -> None:
    """Not a denial: the ceiling is what protects the router, and a policy that
    omitted a field has not asked for anything dangerous. `True` is in the list
    because `isinstance(True, int)` is True in Python and a boolean timeout would
    otherwise become 1 millisecond."""
    obligations, _ = policy.clamp(raw, CFG)
    assert obligations.timeout_ms == CFG.default_timeout_ms
    assert obligations.max_response_bytes == CFG.default_response_bytes


def test_clamping_is_not_a_denial() -> None:
    dec = policy.validate_result(
        {
            "decision": "allow",
            "reason_code": "POLICY_SCOPED_READ",
            "risk_tier": "R1",
            "obligations": {"timeout_ms": 999_999},
        },
        req(),
        "rev",
        CFG,
    )
    assert dec.decision == "allow"
    assert dec.clamped is True
    assert dec.obligations.timeout_ms == CFG.max_timeout_ms


# ===========================================================================
# Spec test 8 — input hygiene (POLICY-002)
# ===========================================================================


def test_8_the_input_document_carries_no_raw_value() -> None:
    """POLICY-002 is enforced by the TYPE — there is no field on any block that could
    hold a raw argument, a secret, or free text — so this is a regression guard rather
    than the primary defence. It checks the canaries too: the fixture's decoys exist
    so that "no secret reached here" can be proved rather than asserted."""
    from fixtures.manifest import CANARIES

    document = policy.build_input(req(), ctx(), tgt(), drv(), "rev").model_dump()
    blob = json.dumps(document)
    assert "public/documentation.txt" not in blob or "canonical_path" in blob
    assert not any(canary in blob for canary in CANARIES)
    # The client's own string is present only as a hash, and the arguments not at all.
    assert "arguments" in document
    assert set(document["arguments"]) == {"arg_hash", "operation"}


def test_the_input_document_shape_is_closed() -> None:
    """A new field cannot be added by a caller passing extra keys — it requires
    editing `policy.py`, which shows in review. Same control as `AuditBuilder.set`."""
    from pydantic import ValidationError

    document = policy.build_input(req(), ctx(), tgt(), drv(), "rev").model_dump()
    document["principal"]["session_token"] = "s3cret"
    with pytest.raises(ValidationError):
        policy.PolicyInput.model_validate(document)


def test_the_input_document_matches_the_documented_groups() -> None:
    """Spec §4's table, asserted. A group added without updating the spec, or vice
    versa, is a contract the reader cannot rely on."""
    document = policy.build_input(req(), ctx(), tgt(), drv(), "rev").model_dump()
    assert set(document) == {
        "request",
        "principal",
        "client",
        "target",
        "resource",
        "arguments",
        "context",
    }


# ===========================================================================
# Spec test 7 — determinism (POLICY-009)
# ===========================================================================


async def test_7_the_same_input_produces_an_identical_decision_every_time() -> None:
    payload = {
        "result": {
            "decision": "allow",
            "reason_code": "POLICY_SCOPED_READ",
            "risk_tier": "R1",
            "obligations": {"timeout_ms": 3000, "max_response_bytes": 1048576},
        }
    }
    engine = engine_returning(payload)
    first = (
        await policy.evaluate(req(), ctx(), tgt(), drv(), engine, CFG)
    ).model_dump_json()
    for _ in range(99):
        again = await policy.evaluate(req(), ctx(), tgt(), drv(), engine, CFG)
        assert again.model_dump_json() == first


# ===========================================================================
# The bundle revision (POLICY-014)
# ===========================================================================


def test_the_bundle_revision_changes_when_the_bundle_does(tmp_path: Path) -> None:
    bundle = tmp_path / "rego"
    (bundle / "gateway").mkdir(parents=True)
    rule = bundle / "gateway" / "x.rego"
    rule.write_text("package gateway\na := 1\n", encoding="utf-8")
    before = policy.bundle_revision(bundle)

    rule.write_text("package gateway\na := 2\n", encoding="utf-8")
    assert policy.bundle_revision(bundle) != before

    rule.write_text("package gateway\na := 1\n", encoding="utf-8")
    assert policy.bundle_revision(bundle) == before, "the hash must be content-addressed"


def test_the_revision_ignores_the_stamp_it_produces(tmp_path: Path) -> None:
    """Including `revision.rego` would make the hash a function of itself — the stamp
    could then never be made correct."""
    bundle = tmp_path / "rego"
    (bundle / "gateway").mkdir(parents=True)
    (bundle / "gateway" / "x.rego").write_text(
        "package gateway\na := 1\n", encoding="utf-8"
    )
    before = policy.bundle_revision(bundle)
    (bundle / "gateway" / "revision.rego").write_text(
        'package gateway\npolicy_revision := "anything"\n', encoding="utf-8"
    )
    assert policy.bundle_revision(bundle) == before


def test_the_revision_does_not_depend_on_line_endings(tmp_path: Path) -> None:
    """Git checks these files out CRLF on Windows and LF on Linux. A revision that
    differed by platform would report two policies where there is one, and the report
    would attribute a run to a bundle that does not exist anywhere."""
    for i, newline in enumerate(("\n", "\r\n")):
        bundle = tmp_path / f"b{i}" / "gateway"
        bundle.mkdir(parents=True)
        (bundle / "x.rego").write_bytes(
            f"package gateway{newline}a := 1{newline}".encode()
        )
    assert policy.bundle_revision(tmp_path / "b0") == policy.bundle_revision(
        tmp_path / "b1"
    )


def test_the_shipped_stamp_is_current() -> None:
    """`scripts/sync_policy_revision.py --check`, as a test.

    The stamp is what lets startup notice that the running OPA holds a policy the repo
    has since edited. A stale stamp turns that check into a false alarm on every boot,
    which is how a real alarm gets disabled.
    """
    from scripts.sync_policy_revision import main

    assert main(["--check"]) == 0, "run `python -m scripts.sync_policy_revision`"


# ===========================================================================
# The shipped policy and the shipped config must describe the same world
# ===========================================================================


def test_the_rego_test_fixture_matches_the_shipped_roots() -> None:
    """`policies/tests/*_test.rego` hard-codes `data.config` because `opa test` runs
    without the gateway. That copy is the one thing in this unit that CAN drift from
    `config/gateway.toml`, so it is compared here — the Rego suite proving the policy
    correct against roots the gateway never publishes would prove nothing."""
    from gateway import config as cfgmod

    text = (REPO / "policies" / "tests" / "decision_test.rego").read_text("utf-8")
    shipped = cfgmod.load(REPO / "config" / "gateway.toml").canonicalize
    for root in shipped.roots:
        assert f'"{root.name}": {{"classification": "{root.classification}"' in text, (
            f"root {root.name!r} is missing from the Rego test fixture or its "
            "classification there disagrees with config/gateway.toml"
        )
        for op in ("read", "create", "overwrite", "append", "rename", "delete"):
            flag = str(getattr(root, op)).lower()
            marker = f'"{op}": {flag}'
            block = text.split(f'"{root.name}": {{', 1)[1].split("},", 1)[0]
            assert marker in block, (
                f"the Rego test fixture says {root.name}.{op} differs from "
                f"config/gateway.toml ({flag})"
            )


def test_the_shipped_obligation_ceilings_agree_with_the_router() -> None:
    """`decision_test.rego` restates the ceilings as literals because Rego cannot read
    TOML. If `[router]` moves and the Rego literal does not, that test starts asserting
    a limit nobody enforces."""
    from gateway import config as cfgmod

    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    text = (REPO / "policies" / "tests" / "decision_test.rego").read_text("utf-8")
    assert f"r.obligations.timeout_ms <= {cfg.router.max_timeout_ms}" in text
    assert f"r.obligations.max_response_bytes <= {cfg.router.max_response_bytes}" in text


def test_every_policy_reason_code_the_bundle_emits_is_in_the_enum() -> None:
    """`policies/reason_codes.json` mirrors the enum for Rego; this closes the loop on
    the codes the bundle actually writes down."""
    import re

    bundle = (REPO / "policies" / "rego").rglob("*.rego")
    emitted = {
        code
        for f in bundle
        for code in re.findall(r'"(POLICY_[A-Z_]+)"', f.read_text("utf-8"))
    }
    assert emitted, "no reason codes found in the bundle"
    assert emitted <= {c.value for c in ReasonCode}


def test_stage_06_contributes_only_fields_the_audit_schema_defines() -> None:
    from gateway.audit_schema import RequestEvent

    dec = policy.validate_result(
        {
            "decision": "allow",
            "reason_code": "POLICY_SCOPED_READ",
            "risk_tier": "R1",
            "obligations": {"timeout_ms": 3000, "max_response_bytes": 1024},
        },
        req(),
        "rev-abc",
        CFG,
    )
    fields = policy.audit_fields(dec)
    assert set(fields) <= set(RequestEvent.model_fields)
    assert fields["policy_revision"] == "rev-abc"
    assert fields["obligations"] == {"timeout_ms": 3000, "max_response_bytes": 1024}

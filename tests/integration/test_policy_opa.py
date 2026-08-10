"""Unit 06 against a REAL OPA process. `_specs/06` §9 tests 1, 10, 11, and 13.

The stub-transport tests in `tests/unit/test_policy.py` prove the broker refuses
malformed answers. They cannot prove the bundle says what it means, because a stub
answers whatever it was told to. These start the sidecar, publish the config the
gateway would publish, and ask the questions the corpus asks.

Test 1 is the headline: the sidecar is killed mid-test and every protected call must
deny. That is the project's single most important behavioural claim, and it is worth
noting what makes it real here — a process is terminated, not a mock configured to
raise. An embedded evaluator could only simulate it.

SKIPPED, never passed, when OPA is absent. The binary is a documented required
dependency; a suite that quietly passed without it would be reporting on a gateway
that has no policy engine.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from gateway import config as cfgmod
from gateway import policy
from gateway.errors import ConfigError, GatewayDenial, PolicyDenial, ReasonCode
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    DerivedAttributes,
    ResolvedTarget,
)
from scripts.opa_sidecar import find_binary, sidecar

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "config" / "gateway.toml"

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        find_binary() is None,
        reason="OPA not found (set ZTMG_OPA_BIN or put the binary in .tools/) — "
        "REPORTED AS SKIPPED, never counted as a pass",
    ),
]


@pytest.fixture(scope="module")
def opa_url() -> Iterator[str]:
    with sidecar() as url:
        yield url


@pytest.fixture
async def engine(opa_url: str) -> Any:
    """A broker wired to the live sidecar, with the config the gateway would publish.

    Deliberately goes through `publish_config` and `check_bundle` rather than seeding
    OPA directly: those two are what startup runs, and a test that set up `data.config`
    by hand would pass against a gateway that never published it.
    """
    cfg = cfgmod.load(CONFIG)
    revision = policy.bundle_revision(REPO / "policies" / "rego")
    client = httpx.AsyncClient(base_url=opa_url, timeout=5.0)
    await policy.publish_config(client, cfg)
    await policy.check_bundle(client, revision)
    try:
        yield policy.PolicyEngine(client, revision)
    finally:
        await client.aclose()


def ctx(principal: str) -> AuthzContext:
    return AuthzContext(
        principal=principal,
        client_id="test-driver",
        roles=(principal,),
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )


def call(
    tool: str, operation: str, root: str
) -> tuple[CanonicalRequest, ResolvedTarget, DerivedAttributes]:
    """A request as stages 02-05 would hand it over.

    `tier` is read from `config/registry.toml` and `classification` from
    `config/gateway.toml`, so the matrix cannot describe a tool the registry tiers
    differently or a root the config classifies differently.
    """
    from gateway.registry import Registry

    tier = Registry.load(REPO / "config" / "registry.toml").tools[tool].risk_tier
    classification = next(
        r.classification for r in cfgmod.load(CONFIG).canonicalize.roots if r.name == root
    )
    req = CanonicalRequest(
        request_id=f"req-{tool}-{root}",
        protocol_version="2026-07-28",
        method="tools/call",
        jsonrpc_id=1,
        tool_name=tool,
        arguments={"path": f"{root}/f"},
        body_hash="bh",
    )
    tgt = ResolvedTarget(
        server_id="filesystem-fixture",
        tool_name=tool,
        schema_fingerprint="v2:abc",
        registry_risk_tier=tier,  # type: ignore[arg-type]
        operation=operation,  # type: ignore[arg-type]
    )
    drv = DerivedAttributes(
        canonical_path=f"/fixture/{root}/f",
        root=root,
        classification=classification,
        operation=operation,  # type: ignore[arg-type]
        exists=True,
        arg_hash="ah",
        raw_hash="rh",
    )
    return req, tgt, drv


#: `_specs/06` §6's matrix, as (principal, tool, operation, root) -> reason code.
#:
#: The risk TIER comes from `config/registry.toml` and the CLASSIFICATION from
#: `config/gateway.toml`, both looked up in `call()` rather than restated here. They
#: were columns in the first draft; a matrix carrying its own copy of the tier would
#: keep passing after the registry moved a tool to another one, which is precisely the
#: disagreement the pipeline's tier check exists to catch.
#:
#: The false-positive side has equal weight: a policy that denied everything would
#: satisfy every deny row below and be worthless.
# fmt: off
MATRIX: list[tuple[str, str, str, str, str]] = [
    # allow side
    ("intern", "read_file", "read", "public", "POLICY_SCOPED_READ"),
    ("intern", "list_directory", "read", "public", "POLICY_METADATA_READ"),
    ("developer", "read_file", "read", "public", "POLICY_SCOPED_READ"),
    ("developer", "read_file", "read", "workspace", "POLICY_SCOPED_READ"),
    ("developer", "write_file", "overwrite", "workspace", "POLICY_SCOPED_WRITE"),
    ("developer", "write_file", "create", "workspace", "POLICY_SCOPED_WRITE"),
    ("developer", "append_file", "append", "workspace", "POLICY_SCOPED_WRITE"),
    ("developer", "delete_file", "delete", "workspace", "POLICY_SCOPED_WRITE"),
    ("auditor", "stat_file", "read", "public", "POLICY_METADATA_READ"),
    ("auditor", "read_file", "read", "confidential", "POLICY_SCOPED_READ"),
    ("auditor", "read_file", "read", "production", "POLICY_SCOPED_READ"),
    # deny side - the path is the problem
    ("intern", "read_file", "read", "confidential", "POLICY_PATH_NOT_PERMITTED"),
    ("intern", "read_file", "read", "production", "POLICY_PATH_NOT_PERMITTED"),
    ("developer", "read_file", "read", "confidential", "POLICY_PATH_NOT_PERMITTED"),
    ("developer", "read_file", "read", "production", "POLICY_PATH_NOT_PERMITTED"),
    # deny side - the operation is the problem
    ("intern", "write_file", "overwrite", "workspace", "POLICY_OPERATION_NOT_PERMITTED"),
    ("intern", "delete_file", "delete", "workspace", "POLICY_OPERATION_NOT_PERMITTED"),
    ("auditor", "write_file", "overwrite", "workspace", "POLICY_OPERATION_NOT_PERMITTED"),
    ("developer", "write_file", "overwrite", "production", "POLICY_OPERATION_NOT_PERMITTED"),  # noqa: E501
    ("developer", "delete_file", "delete", "confidential", "POLICY_OPERATION_NOT_PERMITTED"),  # noqa: E501
    # deny side - prohibited outright
    ("auditor", "read_file", "read", "traps", "POLICY_PROHIBITED"),
    ("developer", "read_file", "read", "decoys", "POLICY_PROHIBITED"),
]
# fmt: on


@pytest.mark.parametrize(("principal", "tool", "operation", "root", "expected"), MATRIX)
async def test_10_the_principal_matrix(
    principal: str,
    tool: str,
    operation: str,
    root: str,
    expected: str,
    engine: policy.PolicyEngine,
) -> None:
    req, tgt, drv = call(tool, operation, root)
    cfg = cfgmod.load(CONFIG).policy

    # `evaluate` RETURNS a deny; it does not raise one. Only a broker-side failure —
    # unreachable, timed out, malformed — raises, because those produce no decision to
    # record. A policy deny is a decision, and `pipeline.handle` is what turns it into
    # a `PolicyDenial`, after `builder.set` has put its fields on the audit event.
    dec = await policy.evaluate(req, ctx(principal), tgt, drv, engine, cfg)
    assert dec.reason_code == expected
    assert dec.decision == (
        "allow" if expected.startswith(("POLICY_SCOPED", "POLICY_METADATA")) else "deny"
    )
    assert dec.risk_tier == tgt.registry_risk_tier, (
        "the registry's tier must be echoed, not invented"
    )
    assert dec.policy_revision == engine.revision
    assert dec.arg_hash == drv.arg_hash, "ROUTE-002: unit 07 compares against this"


async def test_spec_03_test_6_two_principals_one_request_two_decisions(
    engine: policy.PolicyEngine,
) -> None:
    """The test unit 03 could not finish, carried here as `PLAN.md` §4.2 recorded.

    `test_identity.py` proved two configurations produce different `AuthzContext`s;
    what it could not prove was that the difference REACHES a decision, because there
    was no policy engine. This sends the byte-identical request twice, changing only
    the principal, and asserts the outcomes diverge — which is the whole claim
    identity is making.
    """
    cfg = cfgmod.load(CONFIG).policy
    req, tgt, drv = call("read_file", "read", "confidential")

    allowed = await policy.evaluate(req, ctx("auditor"), tgt, drv, engine, cfg)
    refused = await policy.evaluate(req, ctx("intern"), tgt, drv, engine, cfg)

    assert allowed.decision == "allow"
    assert refused.decision == "deny"
    assert refused.reason_code == ReasonCode.POLICY_PATH_NOT_PERMITTED.value


async def test_the_tool_less_target_is_decided_rather_than_falling_through(
    engine: policy.PolicyEngine,
) -> None:
    """Stage 06's half of the debt `PLAN.md` §4.2 recorded against unit 05.

    `tools/list` names no tool, so unit 04 returns an R0 target with no fingerprint and
    unit 05 derives empty strings for path, root and classification. An empty root is
    PROHIBITED for a real resource; discovery must not be judged by that rule, and
    this is the test that keeps the two readings of `""` apart.
    """
    cfg = cfgmod.load(CONFIG).policy
    req = CanonicalRequest(
        request_id="req-list",
        protocol_version="2026-07-28",
        method="tools/list",
        jsonrpc_id=1,
        tool_name=None,
        arguments={},
        body_hash="bh",
    )
    tgt = ResolvedTarget(
        server_id="filesystem-fixture",
        tool_name=None,
        schema_fingerprint=None,
        registry_risk_tier="R0",
        operation="read",
    )
    drv = DerivedAttributes(
        canonical_path="",
        root="",
        classification="",
        operation="read",
        exists=False,
        arg_hash="ah",
        raw_hash="rh",
    )
    for principal in ("intern", "developer", "auditor"):
        dec = await policy.evaluate(req, ctx(principal), tgt, drv, engine, cfg)
        assert dec.decision == "allow"
        assert dec.reason_code == "POLICY_METADATA_READ"
        assert dec.risk_tier == "R0"


# ===========================================================================
# Spec test 1 — the headline
# ===========================================================================


async def test_1_killing_opa_denies_every_protected_call() -> None:
    """POLICY-010, with a real process.

    Deliberately NOT using the module-scoped sidecar: this one has to die, and killing
    the shared fixture would make every later test in the file depend on ordering.
    """
    revision = policy.bundle_revision(REPO / "policies" / "rego")
    # A deadline long enough that a refused connection is reported as a refused
    # connection. At 500ms on Windows the deadline can beat the OS's own answer and
    # the denial arrives as POLICY_TIMEOUT — still a denial, and still fail-closed,
    # but the report should say "OPA was down" rather than "OPA was slow".
    cfg = cfgmod.load(CONFIG).policy.model_copy(update={"timeout_ms": 5000})
    req, tgt, drv = call("read_file", "read", "public")

    with sidecar() as url:
        async with httpx.AsyncClient(base_url=url, timeout=5.0) as client:
            await policy.publish_config(client, cfgmod.load(CONFIG))
            allowed = await policy.evaluate(
                req, ctx("intern"), tgt, drv, policy.PolicyEngine(client, revision), cfg
            )
            assert allowed.decision == "allow", "the control: it worked before the kill"

    # Out of the context manager: the process is gone. A FRESH client, so the failure
    # is a genuine connect refusal rather than a write into a pooled socket whose peer
    # has vanished — that distinction is the difference between the two reason codes,
    # and this test is about which one an operator sees.
    async with httpx.AsyncClient(base_url=url, timeout=5.0) as dead:
        with pytest.raises(PolicyDenial) as exc:
            await policy.evaluate(
                req, ctx("intern"), tgt, drv, policy.PolicyEngine(dead, revision), cfg
            )
    assert exc.value.reason_code is ReasonCode.POLICY_UNAVAILABLE


# ===========================================================================
# Startup checks (POLICY-014) against the live bundle
# ===========================================================================


async def test_11_the_running_bundle_must_be_the_one_on_disk(opa_url: str) -> None:
    """`--watch` is deliberately off, so a policy edited after the sidecar started is
    a policy nobody is evaluating — silently, with every result attributed to the new
    one. The stamped revision is what turns that into a refusal to serve."""
    client = httpx.AsyncClient(base_url=opa_url, timeout=5.0)
    try:
        await policy.publish_config(client, cfgmod.load(CONFIG))
        await policy.check_bundle(
            client, policy.bundle_revision(REPO / "policies" / "rego")
        )
        with pytest.raises(ConfigError, match="policy revision"):
            await policy.check_bundle(client, "0000000000000000")
    finally:
        await client.aclose()


async def test_a_role_with_no_grants_refuses_startup(opa_url: str) -> None:
    """The check that makes `role_vocabulary` publishable rather than duplicated.

    Adding a role to `identity.role_vocabulary` and forgetting the bundle would make
    every request for that principal a denial that reads exactly like a decision.
    """
    cfg = cfgmod.load(CONFIG)
    widened = cfg.model_copy(
        update={
            "identity": cfg.identity.model_copy(
                update={"role_vocabulary": (*cfg.identity.role_vocabulary, "reviewer")}
            )
        }
    )
    client = httpx.AsyncClient(base_url=opa_url, timeout=5.0)
    try:
        await policy.publish_config(client, widened)
        with pytest.raises(ConfigError, match="no grants"):
            await policy.check_bundle(
                client, policy.bundle_revision(REPO / "policies" / "rego")
            )
    finally:
        # Restore, or every later test in the module inherits the broken vocabulary.
        await policy.publish_config(client, cfg)
        await client.aclose()


async def test_the_published_config_is_what_rego_actually_reads(opa_url: str) -> None:
    """`data.config` is the seam between two files that must agree. Asserting the
    document OPA holds — rather than the one Python built — is what makes it a seam
    rather than two hopes."""
    client = httpx.AsyncClient(base_url=opa_url, timeout=5.0)
    try:
        cfg = cfgmod.load(CONFIG)
        await policy.publish_config(client, cfg)
        stored = (await client.get("/v1/data/config")).json()["result"]
        assert stored["role_vocabulary"] == list(cfg.identity.role_vocabulary)
        for root in cfg.canonicalize.roots:
            assert stored["roots"][root.name]["classification"] == root.classification
            assert stored["roots"][root.name]["read"] == root.read
            assert stored["roots"][root.name]["delete"] == root.delete
    finally:
        await client.aclose()


async def test_the_pipeline_actually_persists_the_stage_06_fields(
    tmp_path: Path, opa_url: str, audit_events: list[Any]
) -> None:
    """The wiring, not the function — the FIFTH time this shape has been caught here.

    Every other stage-06 assertion calls `policy.audit_fields()` itself, so deleting
    `builder.set(**policy.audit_fields(dec))` from `pipeline.handle` left them all
    green while every real record went out with no decision, no reason code, no
    policy revision and no obligations. Break-verified: removing that line fails only
    this test.

    It also pins WHERE the line sits. The record must carry the decision even when the
    pipeline goes on to reject it — a policy result the gateway refused is precisely
    what an investigator needs — so `set` happens inside the stage, before the checks
    that can raise.
    """
    from fixtures.build_tree import build
    from gateway.audit import AuditSink
    from gateway.pipeline import Deps, handle
    from gateway.registry import Registry
    from harness.scenario import Scenario
    from harness.wire import build_envelope

    build(tmp_path / "fixture")
    shipped = cfgmod.load(CONFIG)
    canon = shipped.canonicalize
    cfg = shipped.model_copy(
        update={
            "canonicalize": canon.model_copy(
                update={
                    "base": str(tmp_path / "fixture"),
                    "roots": tuple(
                        r.model_copy(
                            update={"path": str(tmp_path / "fixture" / Path(r.path).name)}
                        )
                        for r in canon.roots
                    ),
                }
            ),
            "policy": shipped.policy.model_copy(update={"base_url": opa_url}),
        }
    )

    reg = Registry.load(REPO / "config" / "registry.toml")
    reg.verify_schemas(
        [{"name": t.name, "inputSchema": t.approved_schema} for t in reg.server.tool]
    )
    reg._drift.clear()  # noqa: SLF001 - sealing without a live child

    client = httpx.AsyncClient(base_url=opa_url, timeout=5.0)
    await policy.publish_config(client, cfg)
    revision = policy.bundle_revision(REPO / "policies" / "rego")
    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    deps = Deps(
        config=cfg,
        registry=reg,
        opa=policy.PolicyEngine(client, revision),
        upstream=None,
        audit=sink,
    )

    scenario = Scenario.model_validate(
        {
            "id": "policy-wiring-probe",
            "class": "malicious",
            "layer": "security",
            "principal": "developer",
            "tool": "read_file",
            "arguments": {"path": "confidential/fake_salaries.csv"},
            "expected_decision": "deny",
            "expected_reason": "POLICY_PATH_NOT_PERMITTED",
            "expected_side_effect": "none",
            "risk_tier": "R1",
            "notes": "Drives the real pipeline through stage 06 and reads the record.",
        }
    )

    before = len(audit_events)
    try:
        # The denial policy produced, raised by the pipeline after the record was set.
        with pytest.raises(GatewayDenial):
            await handle(build_envelope(scenario), deps)
        (event,) = audit_events[before:]
    finally:
        await client.aclose()
        sink.close()

    assert "policy" in event.stage_latency_ms, "stage 06 did not run"
    assert event.decision == "deny"
    assert event.reason_code == "POLICY_PATH_NOT_PERMITTED"
    assert event.risk_tier == "R1"
    assert event.policy_revision == revision
    assert event.obligations == {"timeout_ms": 3000, "max_response_bytes": 1048576}
    assert event.obligations_clamped is False

    persisted = json.loads(sink.path.read_text("utf-8").splitlines()[-1])
    assert persisted["reason_code"] == "POLICY_PATH_NOT_PERMITTED"
    assert persisted["policy_revision"] == revision


async def test_serve_refuses_when_opa_is_serving_another_bundle(
    tmp_path: Path, opa_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CALL, not the function.

    `test_11_...` invokes `check_bundle` itself, so deleting the call from
    `startup.serve` left it green — the same shape the protocol-version check had, and
    the same shape stage-04 and stage-05 audit wiring had. This drives `serve` and
    asserts it refuses BEFORE spawning a child.
    """
    from gateway import startup

    monkeypatch.setattr(policy, "bundle_revision", lambda *a, **k: "0" * 16)

    text = (
        CONFIG.read_text("utf-8")
        .replace(
            'path = "var/audit.jsonl"',
            f"path = {json.dumps(str(tmp_path / 'audit.jsonl'))}",
        )
        .replace(
            'base_url = "http://127.0.0.1:8181"', f"base_url = {json.dumps(opa_url)}"
        )
    )
    cfg_path = tmp_path / "gateway.toml"
    cfg_path.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError, match="policy revision"):
        async with startup.serve(cfg_path):
            pytest.fail("serve yielded against a bundle it had not verified")


async def test_12_the_rego_suite_runs_without_the_gateway() -> None:
    """POLICY-016. `opa test policies/` needs no Python, no fixture, no server, and no
    gateway — the policy is a deliverable a reviewer can check on its own. Run here as
    a subprocess so the pytest suite fails when the Rego suite does, but the Rego suite
    keeps standing alone in CI."""
    import subprocess

    binary = find_binary()
    assert binary is not None
    result = subprocess.run(  # noqa: S603 - path from find_binary
        [str(binary), "test", str(REPO / "policies")],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


async def test_8_no_dispatched_document_carries_a_canary(
    engine: policy.PolicyEngine,
) -> None:
    """Spec test 8, over the wire rather than over the model.

    A transport spy captures what is actually sent. The model-level version in
    `test_policy.py` proves the shape has nowhere to put a secret; this proves nothing
    else is being appended on the way out.
    """
    from fixtures.manifest import CANARIES

    sent: list[bytes] = []
    original = engine.client.send

    async def spy(request: httpx.Request, **kwargs: Any) -> httpx.Response:
        sent.append(request.content)
        return await original(request, **kwargs)

    engine.client.send = spy  # type: ignore[method-assign]
    cfg = cfgmod.load(CONFIG).policy
    try:
        for principal, root in (("intern", "public"), ("auditor", "confidential")):
            req, tgt, drv = call("read_file", "read", root)
            with contextlib.suppress(PolicyDenial):
                await policy.evaluate(req, ctx(principal), tgt, drv, engine, cfg)
    finally:
        engine.client.send = original  # type: ignore[method-assign]

    assert sent, "nothing was dispatched"
    for body in sent:
        text = body.decode("utf-8")
        assert not any(canary in text for canary in CANARIES)
        document = json.loads(text)["input"]
        assert set(document["arguments"]) == {"arg_hash", "operation"}

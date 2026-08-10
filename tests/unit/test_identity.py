"""Unit 03 acceptance tests.

The module is fifteen lines of logic. Almost every test here is about what it must
REFUSE to do, because that is the whole deliverable: the client edge is loopback
HTTP with no authentication (ADR-001), so there is no verified caller to derive an
identity from, and an audit record claiming otherwise invalidates every downstream
evidence claim in the project.

`_specs/03` §9 numbers the acceptance tests; the section headers name them.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from gateway import config as cfgmod
from gateway import identity
from gateway.config import IdentityConfig
from gateway.types import AuthzContext, CanonicalRequest

REPO = Path(__file__).resolve().parents[2]

CFG = IdentityConfig(
    principal="developer",
    client_id="test-driver",
    roles=("developer",),
    environment="development",
)


def request(**kw: Any) -> CanonicalRequest:
    base: dict[str, Any] = {
        "request_id": "r1",
        "protocol_version": "2026-07-28",
        "method": "tools/call",
        "jsonrpc_id": 1,
        "tool_name": "read_file",
        "arguments": {},
        "body_hash": "deadbeef",
    }
    return CanonicalRequest(**{**base, **kw})


# ===========================================================================
# §9.1 — the configured identity, labelled honestly
# ===========================================================================


def test_the_configured_principal_is_returned() -> None:
    ctx = identity.resolve(request(), CFG)
    assert ctx.principal == "developer"
    assert ctx.client_id == "test-driver"
    assert ctx.roles == ("developer",)
    assert ctx.environment == "development"


def test_assurance_is_labelled_truthfully() -> None:
    """IDENT-002. The single most important assertion in the unit."""
    ctx = identity.resolve(request(), CFG)
    assert ctx.auth_method == "local_config"
    assert ctx.assurance == "unverified_local"


def test_overstating_identity_is_unrepresentable_not_merely_unused() -> None:
    """The design, asserted rather than trusted.

    `auth_method` and `assurance` are single-member `Literal`s, so claiming a
    verified identity requires editing `types.py` — a diff a reviewer sees — and
    pyright fails the build until then. A convention would be forgotten; this
    cannot be.
    """
    for bad in ("oidc", "authenticated", "verified", "jwt", "mtls"):
        with pytest.raises(ValidationError):
            AuthzContext(
                principal="p",
                client_id="c",
                roles=(),
                auth_method=bad,  # type: ignore[arg-type]
                assurance="unverified_local",
                transport="streamable_http",
                environment="development",
            )
        with pytest.raises(ValidationError):
            AuthzContext(
                principal="p",
                client_id="c",
                roles=(),
                auth_method="local_config",
                assurance=bad,  # type: ignore[arg-type]
                transport="streamable_http",
                environment="development",
            )


def test_the_literals_have_exactly_one_member_each() -> None:
    """A second member added quietly would let a typo become a claim. Widening these
    is allowed — deliberately, with the audit schema version bumped alongside — but
    it must not happen as a side effect of some other change."""
    from typing import get_args

    fields = AuthzContext.model_fields
    assert get_args(fields["auth_method"].annotation) == ("local_config",)
    assert get_args(fields["assurance"].annotation) == ("unverified_local",)


# ===========================================================================
# §9.3 / IDENT-003 — the client cannot influence identity
# ===========================================================================


IDENTITY_SHAPED_KEYS = [
    "principal",
    "user",
    "username",
    "role",
    "roles",
    "client_id",
    "sub",
    "assurance",
    "auth_method",
    "environment",
    "_meta",
    "iss",
    "aud",
    "scope",
]


def test_resolve_never_reads_the_request() -> None:
    """IDENT-003, enforced structurally.

    The load-bearing test in this file. A property test can only cover the keys
    someone thought to generate; this walks `resolve`'s own AST and fails if the
    body references `req` at all. There is no payload shape that can defeat code
    which never looks at the payload.

    Same technique as `test_router_isolation.py` — the project's established way of
    turning "we do not do X" into something checkable.
    """
    assert not _request_param_reads(inspect.getsource(identity.resolve)), (
        "identity.resolve reads its request parameter. IDENT-003: no field of any "
        "MCP message may influence the principal — not merged, not preferred, not "
        "a fallback."
    )


def _request_param_reads(source: str) -> list[str]:
    """Loads of the function's FIRST parameter, whatever it is called.

    Codex review finding: this used to search for loads named `req` literally, so
    renaming the parameter to `request` and reading `request.tool_name` produced an
    empty result and the guard stayed green while client data reached identity. The
    negative control hardcoded `req` too, so it could not expose that.

    Binding the check to the parameter's own name removes the bypass: whatever the
    first parameter is called, reading it fails.
    """
    (func,) = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef)]
    target = func.args.args[0].arg
    return [
        n.id
        for n in ast.walk(func)
        if isinstance(n, ast.Name) and n.id == target and isinstance(n.ctx, ast.Load)
    ]


@pytest.mark.parametrize("param", ["req", "request", "incoming"])
def test_the_ast_check_would_catch_a_violation(param: str) -> None:
    """Negative control, parametrised over the parameter NAME.

    Without this the guard passes just as happily against a parser that finds
    nothing — including one blind to a rename, which is exactly what it was.
    """
    src = f"def resolve({param}, cfg):\n    return {param}.tool_name or cfg.principal\n"
    assert _request_param_reads(src) == [param], (
        f"the AST walk cannot see a read through a parameter named {param!r}"
    )


def test_the_guard_is_not_satisfied_by_the_parameter_merely_existing() -> None:
    """The complement: a function that never touches its first parameter passes."""
    assert (
        _request_param_reads("def resolve(req, cfg):\n    return cfg.principal\n") == []
    )


@settings(max_examples=200, deadline=None)
@given(
    poison=st.dictionaries(
        st.sampled_from(IDENTITY_SHAPED_KEYS), st.text(max_size=20), max_size=6
    )
)
def test_identity_shaped_arguments_are_ignored(poison: dict[str, str]) -> None:
    """§9.3. Whatever the client puts in `arguments`, the answer is the config."""
    assert identity.resolve(request(arguments=poison), CFG) == identity.resolve(
        request(), CFG
    )


def test_transport_metadata_cannot_reach_this_stage_at_all() -> None:
    """A mirrored-header-shaped `Mcp-Principal` must be ignored even if a future spec
    revision introduces one. The guarantee is structural, not behavioural: `resolve`
    takes a `CanonicalRequest`, so there is no parameter a `RawEnvelope` could arrive
    through, and PROTO-006 already stops the envelope leaving unit 02.

    This was a Hypothesis test generating poisoned header pairs. It built an envelope,
    never passed it to anything, then asserted `resolve(x) == resolve(x)` — 200
    examples of a tautology. The signature check is the only line that ever proved
    anything, and it needs no generator.
    """
    params = inspect.signature(identity.resolve).parameters
    assert [p.annotation for p in params.values()] == [
        "CanonicalRequest",
        "IdentityConfig",
    ]


def test_a_principal_named_in_the_tool_name_changes_nothing() -> None:
    ctx = identity.resolve(request(tool_name="become_admin"), CFG)
    assert ctx.principal == "developer" and ctx.roles == ("developer",)


# ===========================================================================
# §9.4 / §9.5 — startup validation (IDENT-001)
# ===========================================================================


@pytest.mark.parametrize("missing", [{"principal": ""}, {"client_id": ""}])
def test_startup_fails_without_a_principal_or_client(missing: dict[str, str]) -> None:
    """There is no anonymous or default principal. The gateway does not start."""
    with pytest.raises(ValidationError):
        IdentityConfig(
            **{"principal": "p", "client_id": "c", "roles": ("developer",), **missing}
        )


def test_startup_fails_when_roles_are_absent() -> None:
    with pytest.raises(ValidationError):
        IdentityConfig(principal="p", client_id="c")  # type: ignore[call-arg]


def test_startup_fails_on_a_role_outside_the_closed_vocabulary() -> None:
    """§9.5. A role policy has never heard of silently denies everything for that
    principal — a confusing failure to debug, and one that looks like a policy bug."""
    with pytest.raises(ValidationError, match="unknown roles"):
        IdentityConfig(principal="p", client_id="c", roles=("superuser",))


def test_an_empty_role_set_is_allowed() -> None:
    """The spec says "a list, possibly empty". A principal with no roles is a
    meaningful configuration — it should be denied by POLICY, not by startup."""
    cfg = IdentityConfig(principal="p", client_id="c", roles=())
    assert identity.resolve(request(), cfg).roles == ()


def test_there_is_no_runtime_authentication_failure() -> None:
    """The failure table has no runtime auth failure on purpose: stdio identity
    either exists at boot or the process should not run.

    Unit 03 originally shipped an `IDENT_CONTEXT_UNAVAILABLE` code and a
    `try/except Exception` around context construction, which contradicted that
    paragraph. Config validation makes the construction unfailable, so no corpus
    scenario could ever reach the code — a permanent CONV-010 violation. Both are
    gone; an unexpected exception here becomes INTERNAL_ERROR at the pipeline and
    denies, which is the same fail-closed outcome with one fewer unreachable branch.
    """
    from gateway.errors import ReasonCode

    assert not [c for c in ReasonCode if c.value.startswith("IDENT_")], (
        "a stage-03 reason code came back; if it is genuinely reachable it needs a "
        "corpus scenario, and if it is not it should not exist (CONV-010)"
    )
    assert "except" not in inspect.getsource(identity.resolve)


# ===========================================================================
# §9.7 / IDENT-004 — immutable once constructed
# ===========================================================================


def test_the_context_rejects_mutation() -> None:
    ctx = identity.resolve(request(), CFG)
    with pytest.raises(ValidationError):
        ctx.principal = "root"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ctx.assurance = "verified"  # type: ignore[misc]


def test_roles_cannot_be_appended_to() -> None:
    """`_tech/03` §8: pydantic's frozen models do not deep-freeze a list field, so a
    mutable role list inside a frozen context would be an escalation primitive. A
    tuple removes the primitive rather than guarding it.

    The control is the ANNOTATION, not the call site. `identity.py` briefly wrapped
    the value in `tuple(...)` as well; breaking that wrapper did not fail this test,
    because `roles: tuple[str, ...]` coerces whatever it is given. The dead wrapper
    was removed — a guard that cannot fail is not a guard, and it hides which line
    is actually load-bearing. Both halves are asserted below.
    """
    ctx = identity.resolve(request(), CFG)
    assert isinstance(ctx.roles, tuple)
    with pytest.raises(AttributeError):
        ctx.roles.append("admin")  # type: ignore[attr-defined]

    # The annotation coerces even a mutable list handed in directly.
    coerced = AuthzContext(
        principal="p",
        client_id="c",
        roles=["intern", "auditor"],  # type: ignore[arg-type]
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )
    assert isinstance(coerced.roles, tuple)


def test_every_resolve_yields_an_equal_context() -> None:
    """IDENT-004 is about immutability, not object identity.

    An earlier version memoised this and asserted `is`. The cache bought nothing —
    seven frozen field assignments, on a path with no latency gate — and pinned the
    design to pydantic frozen models being hashable, which pyright rejects. Equality
    plus the frozen model is the whole guarantee; sameness was never the requirement.
    """
    assert identity.resolve(request(), CFG) == identity.resolve(request(), CFG)


def test_a_different_config_produces_a_different_context() -> None:
    """Config to context is injective on principal. That is ALL this proves.

    It is not spec-03 test 6. Test 6 requires two principals to produce different
    *decisions* under the same policy for the same request — the assertion that
    identity reaches the policy engine rather than merely reaching the log. There is
    no policy engine yet (unit 06 is a stub), so that half cannot be written, and an
    earlier docstring here claimed this test made test 6 "a genuine assertion", which
    it does not: every line below stops at `AuthzContext`.

    Tracked as INTEGRATION PENDING UNIT 06 in `_specs/03` §9 and `PLAN.md` §4.2.
    Unit 06 owns the paired scenario; this test stays as its precondition.
    """
    other = IdentityConfig(principal="intern", client_id="c2", roles=("intern",))
    assert identity.resolve(request(), other).principal == "intern"
    assert identity.resolve(request(), CFG).principal == "developer"


# ===========================================================================
# IDENT-005 / IDENT-006 — disclosure and token handling
# ===========================================================================


def test_no_denial_message_names_a_principal_or_role() -> None:
    """IDENT-005: a client must not learn which principals exist."""
    from gateway.errors import ReasonCode, safe_message

    configured = {CFG.principal, CFG.client_id, *CFG.roles, *CFG.role_vocabulary}
    for code in ReasonCode:
        message = safe_message(code)
        assert not any(name in message for name in configured), (
            f"{code.value} leaks a configured identity: {message!r}"
        )


def test_no_token_shaped_field_exists_to_forward() -> None:
    """IDENT-006: v1 accepts no bearer token and therefore forwards none.

    Recorded as a test now so the invariant exists before any code that could
    violate it — a token issued TO the gateway must never be relayed upstream, and
    the cheapest way to keep that true is to have nowhere to put one.
    """
    from gateway.audit_schema import RequestEvent

    forbidden = ("token", "bearer", "authorization", "credential", "secret", "api_key")
    for model in (AuthzContext, RequestEvent):
        for name in model.model_fields:
            assert not any(f in name.lower() for f in forbidden), (
                f"{model.__name__}.{name} is a place a credential could be carried"
            )


def test_the_child_environment_carries_no_provider_key() -> None:
    """AGENT-005 / BRIDGE-006, asserted from the identity side too: the upstream is a
    local child needing no credential, so nothing secret-shaped may be allowlisted."""
    from gateway import startup

    allowlist = startup.load_all(REPO / "config" / "gateway.toml")[1].server.env_allowlist
    assert not any(
        w in name.upper() for name in allowlist for w in ("KEY", "TOKEN", "SECRET")
    )


# ===========================================================================
# §8 — audit contribution
# ===========================================================================


def test_stage_03_contributes_its_audit_fields() -> None:
    from gateway.audit_schema import RequestEvent

    fields = identity.audit_fields(identity.resolve(request(), CFG))
    assert set(fields) <= set(RequestEvent.model_fields), "a field the schema forbids"
    assert fields["auth_method"] == "local_config"
    assert fields["assurance"] == "unverified_local"


def test_the_session_invariant_sees_written_records(
    tmp_path: Path, audit_events: list[Any]
) -> None:
    """The mechanism behind spec test 2, checked as an ordinary test.

    `conftest.py` tees `AuditSink.write_sync` and asserts the identity invariant over
    everything the session emitted. A tee that silently stopped capturing would make
    that invariant pass by checking nothing — the exact failure mode the project
    already hit once, where a "measured" ratio was computed over an empty log.

    A file scan at session end would be worse: most tests write to a `tmp_path`
    pytest deletes, so it would find almost nothing and pass for the wrong reason.

    The list arrives via the fixture, not via `from tests.conftest import _EMITTED` —
    pytest loads that file as top-level module `conftest`, so importing it by package
    path yields a second module with its own empty list. The first version of this
    test did exactly that and reported a working tee as broken.
    """
    from gateway.audit import AuditBuilder, AuditSink

    before = len(audit_events)
    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    builder = AuditBuilder("identity-tee-probe")
    builder.set(**identity.audit_fields(identity.resolve(request(), CFG)))
    builder.set_outcome("allowed")
    sink.write_sync(builder.finalize())

    captured = audit_events[before:]
    assert len(captured) == 1, "the session tee stopped capturing written records"
    assert captured[0].request_id == "identity-tee-probe"
    assert captured[0].auth_method == "local_config"


@pytest.mark.anyio
async def test_the_pipeline_actually_writes_the_identity_fields(
    tmp_path: Path, audit_events: list[Any]
) -> None:
    """Codex review finding: nothing exercised the production wiring.

    Every other identity test calls `identity.audit_fields()` itself and asserts the
    dict it just built. Deleting `builder.set(**identity.audit_fields(ctx))` from
    `pipeline.handle` broke no test — real records would have gone out unlabelled
    while the synthetic probe kept the suite green. That is the self-fulfilling shape
    this project keeps finding, one layer up: the unit was proved, the WIRING was not.

    So this drives `pipeline.handle` and reads the persisted record. Stage 04 is
    still a stub, so the request dies there — which is fine and is the point: stage
    03 runs first, and the `finally` writes the event regardless, so the identity
    fields must already be on it.
    """
    import json as _json

    from gateway.audit import AuditSink
    from gateway.errors import GatewayDenial
    from gateway.pipeline import Deps, handle
    from harness.scenario import Scenario
    from harness.wire import build_envelope

    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    config = cfgmod.load(REPO / "config" / "gateway.toml")
    deps = Deps(config=config, registry=None, opa=None, upstream=None, audit=sink)

    scenario = Scenario.model_validate(
        {
            "id": "identity-wiring-probe",
            "class": "legitimate",
            "layer": "protocol",
            "principal": "developer",
            "tool": "read_file",
            "arguments": {"path": "public/documentation.txt"},
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public"},
            "risk_tier": "R2",
            "notes": "Drives the real pipeline far enough to prove stage 03 is wired.",
        }
    )

    before = len(audit_events)
    with pytest.raises(GatewayDenial):
        await handle(build_envelope(scenario), deps)

    (event,) = audit_events[before:]
    assert "identity" in event.stage_latency_ms, "stage 03 did not run"
    for field, expected in identity.audit_fields(
        identity.resolve(request(), config.identity)
    ).items():
        assert getattr(event, field) == expected, f"pipeline did not persist {field}"

    # And it is on DISK, not merely in the object the tee captured.
    persisted = _json.loads(sink.path.read_text("utf-8").splitlines()[-1])
    assert persisted["auth_method"] == "local_config"
    assert persisted["assurance"] == "unverified_local"
    assert persisted["principal"] == config.identity.principal


def test_the_audit_contribution_is_accepted_by_the_builder() -> None:
    """`AuditBuilder.set()` rejects unknown keys, so this proves the contribution is
    writable rather than merely schema-shaped."""
    from gateway.audit import AuditBuilder

    builder = AuditBuilder("r1")
    builder.set(**identity.audit_fields(identity.resolve(request(), CFG)))
    builder.set_outcome("allowed")
    event = builder.finalize()
    assert event.principal == "developer"
    assert event.roles == ("developer",)


# ===========================================================================
# IDENT-007 — the documentation obligation, tested
# ===========================================================================


BYPASS_SENTENCE = (
    "A local `stdio` client that is separately configured with direct access to the "
    "protected MCP server bypasses this gateway entirely. The gateway cannot detect "
    "or prevent that configuration. Removing every direct client-to-server route is "
    "a deployment responsibility."
)


@pytest.mark.parametrize("doc", ["README.md", "docs/threat-model.md"])
def test_the_bypass_limitation_is_documented_verbatim(doc: str) -> None:
    """IDENT-007 requires this in the README and the threat model, not only in a
    spec. A documentation requirement without a test decays like any other.

    Verbatim, and whitespace-normalised so reflowing the paragraph does not fail it
    while deleting a sentence still does.
    """
    text = " ".join((REPO / doc).read_text("utf-8").split())
    assert " ".join(BYPASS_SENTENCE.split()) in text, (
        f"{doc} no longer states the bypass limitation (IDENT-007)"
    )


def test_no_report_claims_zero_authorization_bypasses() -> None:
    """A standing project rule, checked here because this is the unit whose
    limitation makes the phrase indefensible: §1.1 above means the gateway cannot
    see a second route, so it can never have counted every bypass. The scoped claim
    is `PLAN.md` §6.2.

    The governance docs are allowed to NAME the banned phrase — CLAUDE.md states the
    prohibition and PLAN.md §6.2 records what replaced it. What they may not do is
    assert it, so there the phrase must sit in a negated sentence. Anywhere else it
    is banned outright.
    """
    banned = "zero authorization bypasses"
    negations = ("never", "not ", "avoid", "replac", "instead of")

    for path in (*REPO.glob("*.md"), *REPO.glob("docs/*.md")):
        if path.name == "Zero_Trust_MCP_Gateway_Final.md":
            continue  # archival original, never edited (PLAN.md §7 holds corrections)

        for line in path.read_text("utf-8").lower().splitlines():
            if banned not in line:
                continue
            governance = path.name in ("CLAUDE.md", "PLAN.md")
            assert governance and any(n in line for n in negations), (
                f"{path.name} states the banned claim: {line.strip()[:100]}"
            )


# ===========================================================================
# Single-sourced role vocabulary
# ===========================================================================


def test_the_role_vocabulary_has_one_home() -> None:
    """`_tech/03` §3 planned to duplicate this in Rego as `data.roles` and keep the
    two in sync with a test. Unit 06 publishes it instead: the cheapest fix for a
    sync bug is to have nothing to sync.

    `IdentityConfig.role_vocabulary` is the home; `identity.role_vocabulary()` briefly
    existed as a pass-through accessor with no caller but this assertion, and a
    function that only forwards an attribute is a second name for the same fact.

    This searched only for the IDENTIFIER `role_vocabulary`, which a Rego file
    hardcoding `roles := {"intern", "developer", "auditor"}` sails straight past —
    the exact duplication being guarded against, spelled the way anyone would
    actually spell it. It also globbed an EMPTY directory and passed on zero files.
    Both are fixed: the values are checked, and an absent bundle now SKIPS.

    And once unit 06 landed it failed for a third reason, which is the interesting
    one: it forbade the identifier ENTIRELY, so the correct implementation — Rego
    reading `data.config.role_vocabulary` to report a role with no grants — could not
    be written. Reading the published value is the design; defining a second copy is
    the defect. The rule is now about which of those a file is doing.

    Naming one role in a rule is legitimate policy. Naming every member of the
    closed set in one file is the signature of a reconstructed vocabulary, and that
    is what fails here. The load-bearing check is still unit 06's, at runtime,
    comparing what the gateway publishes to OPA against this tuple.
    """
    files = [f for f in (REPO / "policies" / "rego").rglob("*.rego") if f.is_file()]
    if not files:
        pytest.skip("no Rego bundle yet (unit 06); nothing to check for duplication")

    vocabulary = cfgmod.load(REPO / "config" / "gateway.toml").identity.role_vocabulary
    for f in files:
        source = f.read_text("utf-8", errors="ignore")
        # Comments stripped first: prose explaining where the vocabulary lives is the
        # documentation this rule wants, not the duplication it forbids.
        code = "\n".join(line.split("#", 1)[0] for line in source.splitlines())
        # READING the published value is the design. `data.config.role_vocabulary` is
        # unit 06's seam and `grants.rego` uses it to report a role with no grants —
        # an earlier version of this test forbade the identifier outright, which made
        # the correct implementation unwritable. What is forbidden is DEFINING one.
        assert code.count("role_vocabulary") == code.count(
            "data.config.role_vocabulary"
        ), (
            f"{f.name} names `role_vocabulary` somewhere other than as "
            "`data.config.role_vocabulary`. It may be read from what the gateway "
            "publishes; it may not be defined in policy."
        )
    # A grant table keyed by role name legitimately spells every role — that IS the
    # policy, and the earlier "no file may contain every role as a literal" rule
    # forbade writing one. What makes the table safe is not that it avoids the names
    # but that the bundle RECONCILES them against the published vocabulary, so a role
    # in config with no grants refuses startup instead of denying silently. This
    # asserts the reconciliation exists; `test_policy_opa.py` asserts it fires.
    bundle = "\n".join(f.read_text("utf-8", errors="ignore") for f in files)
    assert "data.config.role_vocabulary" in bundle, (
        "no rule in the bundle reads the published vocabulary, so nothing would "
        "notice a role that exists in config and has no grants — the exact silent "
        "failure publishing it was supposed to remove"
    )
    assert set(vocabulary) == {"intern", "developer", "auditor"}, (
        "the shipped vocabulary changed; `policies/rego/gateway/grants.rego` needs a "
        "grant for every member or startup will refuse"
    )


def test_the_shipped_config_roles_are_within_its_own_vocabulary() -> None:
    cfg = cfgmod.load(REPO / "config" / "gateway.toml").identity
    assert set(cfg.roles) <= set(cfg.role_vocabulary)

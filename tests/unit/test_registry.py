"""Unit 04 acceptance tests. `_specs/04` §9 numbers them; section headers name them.

The unit's job is to disbelieve the upstream. Most of these tests therefore drive the
REAL fixture server in a misbehaviour mode rather than a mock: a mock that advertises
whatever the test wants proves the test's own assumptions, and the thing being
defended against here is a live server that lies.
"""

from __future__ import annotations

import json
import os
from contextlib import suppress
from pathlib import Path
from typing import Any

import anyio
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from gateway import bridge, protocol, registry
from gateway import config as cfgmod
from gateway.config import ProtocolConfig
from gateway.errors import (
    ConfigError,
    GatewayDenial,
    ProgrammingError,
    ReasonCode,
    RegistryDenial,
)
from gateway.hashing import FINGERPRINT_VERSION
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    RawEnvelope,
    ResolvedTarget,
)

pytestmark = pytest.mark.anyio

REPO = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO / "config" / "registry.toml"

CTX = AuthzContext(
    principal="developer",
    client_id="test-driver",
    roles=("developer",),
    auth_method="local_config",
    assurance="unverified_local",
    transport="streamable_http",
    environment="development",
)


def request(**kw: Any) -> CanonicalRequest:
    base: dict[str, Any] = {
        "request_id": "r1",
        "protocol_version": "2026-07-28",
        "method": "tools/call",
        "jsonrpc_id": 1,
        "tool_name": "read_file",
        "arguments": {"path": "public/readme.txt"},
        "body_hash": "deadbeef",
    }
    return CanonicalRequest(**{**base, **kw})


def loaded(*, sealed: bool = True) -> registry.Registry:
    """The SHIPPED registry, sealed against what the LIVE fixture advertises.

    Sealed by running the real comparison rather than by poking `_sealed`: a test
    that sets the flag directly keeps passing if `verify_schemas` stops setting it,
    and REG-009 is precisely the requirement that nothing is callable until that
    method has run.
    """
    reg = registry.Registry.load(REGISTRY_PATH)
    if sealed:
        assert reg.verify_schemas(live_tools()) == []
    return reg


_LIVE_CACHE: dict[str, list[dict[str, Any]]] = {}


def live_tools(mode: str = "") -> list[dict[str, Any]]:
    """A real `tools/list` from a real child, cached per mode within the session.

    Spawning the fixture costs about a second; six tests need the same answer.
    """
    if mode not in _LIVE_CACHE:
        _LIVE_CACHE[mode] = _spawn_and_list(mode)
    return _LIVE_CACHE[mode]


def _spawn_and_list(mode: str) -> list[dict[str, Any]]:
    reg = registry.Registry.load(REGISTRY_PATH)

    async def go() -> list[dict[str, Any]]:
        async with bridge.upstream(reg.server.child_config()) as up:
            result = await up.list_tools()
            return [t.model_dump(by_alias=True, exclude_none=True) for t in result.tools]

    previous = os.environ.get("FIXTURE_MODE")
    os.environ["FIXTURE_MODE"] = mode
    os.environ.setdefault("FIXTURE_ROOT", "var/fixture")
    os.environ.setdefault("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    try:
        return anyio.run(go)
    finally:
        if previous is None:
            os.environ.pop("FIXTURE_MODE", None)
        else:
            os.environ["FIXTURE_MODE"] = previous


# ===========================================================================
# §9.1 / §9.2 — default deny (REG-001, REG-003)
# ===========================================================================


@pytest.mark.slow
def test_an_unknown_tool_is_denied() -> None:
    with pytest.raises(RegistryDenial) as e:
        loaded().resolve(request(tool_name="exfiltrate"), CTX)
    assert e.value.reason_code is ReasonCode.REG_TOOL_UNKNOWN


def test_a_tool_the_upstream_really_advertises_is_still_denied_if_unapproved() -> None:
    """REG-003, and the version of test 2 that is worth writing.

    Denying a tool nobody implements proves nothing. This one is genuinely present
    on the live child and would genuinely execute — the registry is the only thing
    standing between the client and it.
    """
    reg = loaded()
    advertised = {t["name"] for t in live_tools()}
    victim = "delete_file"
    assert victim in advertised, "the fixture no longer advertises the tool under test"

    object.__setattr__(reg, "tools", {k: v for k, v in reg.tools.items() if k != victim})
    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(tool_name=victim, arguments={"path": "x"}), CTX)
    assert e.value.reason_code is ReasonCode.REG_TOOL_UNKNOWN


def test_a_disabled_server_denies_every_call() -> None:
    reg = registry.Registry.load(REGISTRY_PATH)
    object.__setattr__(reg.server, "state", "disabled")
    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(), CTX)
    assert e.value.reason_code is ReasonCode.REG_SERVER_UNAVAILABLE


def test_a_disabled_server_hides_every_tool() -> None:
    """REG-004: quarantined or disabled denies all protected calls AND discloses none.

    Found by the break pass. Removing the server-state check from `_callable_reason`
    left every test green: `resolve` checks the state again on its own line, and no
    test disabled the SERVER and then looked at `visible_tools`. The result was a
    disabled upstream still advertising its full tool list — an over-disclosure whose
    only symptom is a list that looks normal.
    """
    for state in ("disabled", "quarantined"):
        reg = loaded()
        object.__setattr__(reg.server, "state", state)
        assert reg.visible_tools(CTX, lambda c, t: True) == [], state
        with pytest.raises(RegistryDenial) as e:
            reg.resolve(request(), CTX)
        assert e.value.reason_code is ReasonCode.REG_SERVER_UNAVAILABLE


def test_the_tool_lookup_is_exact() -> None:
    """Also from the break pass: making `self.tools.get` case-insensitive broke
    nothing. Only a corpus row covered it, and the corpus cannot run in protected
    mode yet, so the case was published as an attack and asserted nowhere.

    A normalizing lookup makes the approved set larger than `config/registry.toml`
    says it is, and nobody reviewing that file would see the extra names.
    """
    reg = loaded()
    for variant in ("READ_FILE", "Read_File", "read_file ", " read_file", "read_file\t"):
        with pytest.raises(RegistryDenial) as e:
            reg.resolve(request(tool_name=variant), CTX)
        assert e.value.reason_code is ReasonCode.REG_TOOL_UNKNOWN, variant


def test_a_disabled_tool_is_not_callable_and_not_visible() -> None:
    reg = loaded()
    object.__setattr__(reg.tools["read_file"], "enabled", False)
    with pytest.raises(RegistryDenial):
        reg.resolve(request(), CTX)
    assert "read_file" not in {t.name for t in reg.visible_tools(CTX, lambda c, t: True)}


def test_nothing_is_callable_before_verification() -> None:
    """REG-009. A fingerprint nobody has compared authorises nothing."""
    reg = registry.Registry.load(REGISTRY_PATH)
    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(), CTX)
    assert e.value.reason_code is ReasonCode.REG_SCHEMA_UNVERIFIED
    assert reg.visible_tools(CTX, lambda c, t: True) == []


# ===========================================================================
# §9.3 — drift, against the real fixture
# ===========================================================================


def test_drift_quarantines_the_tool_and_hides_it() -> None:
    """Spec test 3, end to end: real child, real `tools/list`, real comparison.

    `FIXTURE_MODE=drift` changes only read_file's DESCRIPTION. That is the point —
    a description is not executable, cannot be validated against, and is exactly
    what a poisoning attack edits.
    """
    reg = loaded(sealed=False)
    events = reg.verify_schemas(live_tools("drift"))

    assert [(e.tool_name, e.reason_code) for e in events] == [
        ("read_file", ReasonCode.REG_SCHEMA_DRIFT.value)
    ]
    assert events[0].approved_fingerprint != events[0].advertised_fingerprint

    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(), CTX)
    assert e.value.reason_code is ReasonCode.REG_TOOL_QUARANTINED

    visible = {t.name for t in reg.visible_tools(CTX, lambda c, t: True)}
    assert "read_file" not in visible
    assert "write_file" in visible, "drift on one tool must not quarantine the others"


def test_a_tool_that_stops_being_advertised_is_quarantined() -> None:
    reg = loaded(sealed=False)
    reg.verify_schemas([t for t in live_tools() if t["name"] != "stat_file"])
    assert reg._drift["stat_file"] is ReasonCode.REG_TOOL_UNKNOWN  # noqa: SLF001
    with pytest.raises(RegistryDenial):
        reg.resolve(request(tool_name="stat_file", arguments={"path": "x"}), CTX)


def test_an_advertised_but_unapproved_tool_is_reported_never_registered() -> None:
    reg = loaded(sealed=False)
    events = reg.verify_schemas(
        [*live_tools(), {"name": "exec_shell", "description": "x"}]
    )
    assert [e.tool_name for e in events] == ["exec_shell"]
    assert "exec_shell" not in reg.tools
    with pytest.raises(RegistryDenial):
        reg.resolve(request(tool_name="exec_shell", arguments={}), CTX)


# ===========================================================================
# §9.4 — the poisoned annotation. The unit's most legible test.
# ===========================================================================


def test_a_poisoned_annotation_changes_nothing_but_fires_drift() -> None:
    """Spec test 4, against a live server that is actively lying.

    `FIXTURE_MODE=poison` makes delete_file advertise `readOnlyHint: true`,
    `destructiveHint: false`, and a description claiming it modifies nothing. Its
    risk tier must stay R4 — the tier is the REGISTRY's judgement (REG-008) — and
    the lie must be detected, which is the only reason annotations are inside the
    fingerprint at all.
    """
    poisoned = [t for t in live_tools("poison") if t["name"] == "delete_file"][0]
    assert poisoned["annotations"]["readOnlyHint"] is True, "the fixture stopped lying"

    reg = loaded(sealed=False)
    events = reg.verify_schemas(live_tools("poison"))

    assert [e.tool_name for e in events] == ["delete_file"]
    assert reg.tools["delete_file"].risk_tier == "R4"
    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(tool_name="delete_file", arguments={"path": "x"}), CTX)
    assert e.value.reason_code is ReasonCode.REG_TOOL_QUARANTINED


def test_the_annotation_is_inside_the_fingerprint() -> None:
    """The mechanism the test above depends on, asserted directly.

    Without this, dropping `annotations` from `normalize` would fail the poison test
    with a message about quarantine and send the next reader looking in the wrong
    place entirely.
    """
    base = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
    lying = {**base, "annotations": {"readOnlyHint": True}}
    assert registry.fingerprint(base) != registry.fingerprint(lying)


def test_the_approved_description_never_reaches_a_decision() -> None:
    """REG-008 structurally: `approved_for` is human-facing and read by nothing.

    An upstream description is untrusted, and so is ours — the difference is that
    ours cannot change without a reviewed diff. Either way, a decision that consults
    prose is a decision an attacker can write.
    """
    source = Path(registry.__file__).read_text("utf-8")
    body = source.split("class ToolEntry", 1)[1]
    uses = [
        line
        for line in body.splitlines()
        if "approved_for" in line
        and not line.strip().startswith(("#", '"', "approved_for"))
    ]
    assert uses == [], f"approved_for is read at runtime: {uses}"


# ===========================================================================
# §9.5 — fingerprint stability (REG-005)
# ===========================================================================


def test_key_order_and_whitespace_do_not_change_the_fingerprint() -> None:
    a = {
        "name": "t",
        "description": "d",
        "inputSchema": {"type": "object", "properties": {"a": {"type": "string"}}},
    }
    b = {
        "inputSchema": {"properties": {"a": {"type": "string"}}, "type": "object"},
        "description": "d",
        "name": "t",
    }
    assert registry.fingerprint(a) == registry.fingerprint(
        json.loads(json.dumps(b, indent=4))
    )


def test_one_meaningful_character_changes_the_fingerprint() -> None:
    a = {"name": "t", "description": "d", "inputSchema": {"maxLength": 4096}}
    b = {"name": "t", "description": "d", "inputSchema": {"maxLength": 4097}}
    assert registry.fingerprint(a) != registry.fingerprint(b)


def test_null_collapses_to_absent_but_present_and_empty_does_not() -> None:
    """`_tech/04` §3, corrected. Two different questions with two different answers.

    NULL vs ABSENT must agree: an upstream that starts emitting `"description": null`
    where it previously omitted the key produces no drift, because noise is how a
    real drift event gets ignored. That was the tech sheet's whole justification.

    PRESENT-AND-EMPTY vs ABSENT must NOT agree, and the original code made them
    equal: `tool.get("outputSchema") or {}` meant an upstream could add or remove
    `"outputSchema": {}` with no drift event, while REG-005 says to fingerprint the
    output schema *where present*. Codex adversarial review.
    """
    absent = {"name": "t"}
    nulls = {"name": "t", "description": None, "outputSchema": None, "annotations": None}
    assert registry.fingerprint(absent) == registry.fingerprint(nulls)

    for key, empty in (("description", ""), ("outputSchema", {}), ("annotations", {})):
        assert registry.fingerprint(absent) != registry.fingerprint(
            {**absent, key: empty}
        ), f"an upstream can add or remove {key}={empty!r} without drift"


@settings(max_examples=200, deadline=None)
@given(
    tool=st.fixed_dictionaries(
        {
            "name": st.text(min_size=1, max_size=20),
            "description": st.text(max_size=50),
            "inputSchema": st.dictionaries(
                st.text(min_size=1, max_size=8),
                st.integers() | st.text(max_size=8),
                max_size=5,
            ),
        }
    )
)
def test_fingerprinting_is_deterministic_across_reserialization(
    tool: dict[str, Any],
) -> None:
    reserialized = json.loads(json.dumps(tool, indent=3, sort_keys=True))
    assert registry.fingerprint(tool) == registry.fingerprint(reserialized)


def test_the_python_field_names_are_refused_rather_than_hashed_as_empty() -> None:
    """The worst bug this unit could have, and it was live for an hour.

    `mcp_types.Tool` names these `input_schema` / `output_schema` in Python and
    `inputSchema` / `outputSchema` on the wire. `Tool.model_dump()` without
    `by_alias=True` produces the Python spelling, `normalize` found no `inputSchema`,
    substituted the typed empty, and fingerprinted every tool as though it had no
    schema — so an upstream could have replaced an entire input schema with no drift
    event. The generated values in `config/registry.toml` were wrong.

    Raising beats accepting both spellings: accepting both gives one tool two
    fingerprints depending on how it was serialised, which is the same hole wearing
    a different hat.
    """
    with pytest.raises(ProgrammingError, match="wire shape"):
        registry.fingerprint({"name": "t", "input_schema": {"type": "object"}})

    with_schema = registry.fingerprint({"name": "t", "inputSchema": {"type": "object"}})
    assert with_schema != registry.fingerprint({"name": "t"}), (
        "the schema is not inside the fingerprint"
    )


def test_the_shipped_fingerprints_cover_a_schema() -> None:
    """The values in the registry file, not just the function that makes them.

    A correct `normalize` and a registry generated before it was correct look
    identical from inside the code. This compares each stored value against one
    computed from a live advertisement with the schema removed: if they matched, the
    stored value would be a schema-less hash.
    """
    for tool in live_tools():
        stripped = {k: v for k, v in tool.items() if k != "inputSchema"}
        assert registry.fingerprint(tool) != registry.fingerprint(stripped), (
            f"{tool['name']} advertises no input schema; this test cannot see the bug"
        )


#: One tool, one expected digest, per normalization version. Adding a row is the
#: deliberate act the `v`-prefix exists to force.
GOLDEN: dict[str, str] = {
    "v2": "v2:f4fa04dca956a6d45eefba24da7ddbdaddf9520b79d92f5be34538d531d298c6",
}


def test_the_version_prefix_tracks_the_normalization_rule() -> None:
    """Changing `normalize` without changing `FINGERPRINT_VERSION` must fail here.

    The prefix exists so stored fingerprints are migrated deliberately rather than
    silently invalidated — and it was nearly left at `v1` through two rule changes,
    which would have made a v1 digest and a v2 digest of the same tool silently
    incomparable instead of loudly so. A comment saying "bump this" is not a control;
    a golden value is.

    The input is fixed here rather than read from the registry: a golden pinned to
    the shipped fixture would change whenever the fixture changes, which is drift
    detection's job, not this test's.
    """
    assert FINGERPRINT_VERSION in GOLDEN, (
        f"FINGERPRINT_VERSION is {FINGERPRINT_VERSION!r} with no golden digest. A new "
        "version needs a new row in GOLDEN, computed once and reviewed — that review "
        "is the whole point of versioning the rule."
    )
    subject = {
        "name": "read_file",
        "description": "Read a UTF-8 text file.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path"],
            "properties": {"path": {"type": "string", "maxLength": 4096}},
        },
    }
    assert registry.fingerprint(subject) == GOLDEN[FINGERPRINT_VERSION], (
        "the normalization rule changed but FINGERPRINT_VERSION did not. Bump it, "
        "add the new digest to GOLDEN, and regenerate config/registry.toml with "
        "scripts/fingerprint_tools.py (REG-005)."
    )


def test_every_stored_fingerprint_carries_the_current_version() -> None:
    """A registry half-migrated across a version bump compares nothing usefully."""
    stale = [
        t.name
        for t in registry.Registry.load(REGISTRY_PATH).tools.values()
        if not t.schema_fingerprint.startswith(f"{FINGERPRINT_VERSION}:")
    ]
    assert stale == [], f"{stale} still carry a pre-{FINGERPRINT_VERSION} fingerprint"


def test_the_fingerprint_carries_its_normalization_version() -> None:
    """Without the prefix, changing a rule in `normalize` invalidates every stored
    value at once and reads as mass drift rather than as the migration it is."""
    assert registry.fingerprint({"name": "t"}).startswith(f"{FINGERPRINT_VERSION}:")


# ===========================================================================
# §9.6 / REG-011 — discovery filtering shares enforcement's predicate
# ===========================================================================


def test_visible_tools_and_resolve_agree_on_every_tool() -> None:
    """REG-011 asserted over the real registry, in both directions.

    `_tech/04` §6 asks for this to be structural rather than test-detected, which is
    why both paths call `_callable_reason`. This test is what fails if someone
    inlines one of them.
    """
    reg = loaded(sealed=False)
    reg.verify_schemas(live_tools("drift"))
    object.__setattr__(reg.tools["append_file"], "enabled", False)

    visible = {t.name for t in reg.visible_tools(CTX, lambda c, t: True)}
    for name in reg.tools:
        req = request(tool_name=name, arguments={"path": "p", "content": "c"})
        try:
            reg.resolve(req, CTX)
            callable_now = True
        except RegistryDenial as d:
            callable_now = d.reason_code in (
                ReasonCode.REG_ARGS_INVALID,
                ReasonCode.REG_ARGS_UNKNOWN_FIELD,
            )
        assert (name in visible) == callable_now, (
            f"{name}: visible={name in visible} callable={callable_now} — a tool the "
            "client can see and never use, or can use and never see (REG-011)"
        )


def test_discovery_requires_the_policy_predicate() -> None:
    """REG-010's principal filter is unit 06's `data.gateway.discoverable`.

    `could_ever_allow` has no default on purpose. A default of "yes" would silently
    over-disclose the day a caller forgot it, and the symptom — a fuller list — is
    invisible without a second source to compare against.
    """
    import inspect

    param = inspect.signature(registry.Registry.visible_tools).parameters[
        "could_ever_allow"
    ]
    assert param.default is inspect.Parameter.empty

    reg = loaded()
    assert reg.visible_tools(CTX, lambda c, t: False) == []
    assert len(reg.visible_tools(CTX, lambda c, t: t.risk_tier == "R0")) == 2


# ===========================================================================
# §9.7 / §9.8 / §9.9 — argument validation (REG-012 … REG-014)
# ===========================================================================


def test_arguments_are_validated_before_policy_is_consulted() -> None:
    """Spec test 7. Asserted by position, not by a spy.

    Unit 06 is a stub that raises `NotImplementedError`, so a validation failure
    reaching policy would surface as INTERNAL_ERROR rather than REG_ARGS_INVALID.
    That the registry raises first IS the ordering assertion, and it stays true when
    unit 06 lands because `pipeline.handle` fixes the stage order.
    """
    with pytest.raises(RegistryDenial) as e:
        loaded().resolve(request(arguments={"path": 42}), CTX)
    assert e.value.reason_code is ReasonCode.REG_ARGS_INVALID


def test_an_unknown_argument_field_is_rejected_under_its_own_code() -> None:
    with pytest.raises(RegistryDenial) as e:
        loaded().resolve(request(arguments={"path": "p", "sudo": True}), CTX)
    assert e.value.reason_code is ReasonCode.REG_ARGS_UNKNOWN_FIELD


def test_a_missing_required_argument_is_rejected() -> None:
    with pytest.raises(RegistryDenial) as e:
        loaded().resolve(request(tool_name="write_file", arguments={"path": "p"}), CTX)
    assert e.value.reason_code is ReasonCode.REG_ARGS_INVALID


def test_the_approved_schema_is_used_even_when_the_upstream_advertises_a_laxer_one() -> (
    None
):
    """Spec test 9, the whole point of pinning.

    The live fixture's advertised schema really is laxer: the SDK derives it from
    the handler signature and emits no `additionalProperties`, so `{"sudo": true}`
    validates against it and is rejected against ours. If validation ever switched
    to the advertised schema this test fails, which is the only way to notice.
    """
    from jsonschema import Draft202012Validator

    advertised = [t for t in live_tools() if t["name"] == "read_file"][0]["inputSchema"]
    assert advertised.get("additionalProperties") is not False, (
        "the fixture's advertised schema is now closed; this test no longer "
        "distinguishes approved from advertised"
    )
    Draft202012Validator(advertised).validate({"path": "p", "sudo": True})

    with pytest.raises(RegistryDenial):
        loaded().resolve(request(arguments={"path": "p", "sudo": True}), CTX)


def test_frozen_arguments_validate_correctly() -> None:
    """`CanonicalRequest.arguments` is deep-frozen; `jsonschema` resolves `"object"`
    against `dict` and `"array"` against `list`. Without `thaw` at the boundary every
    nested object would fail validation for a reason that has nothing to do with the
    request — a false denial that looks exactly like a working guard."""
    req = request(tool_name="write_file", arguments={"path": "p", "content": "c"})
    assert not isinstance(req.arguments, dict)
    assert loaded().resolve(req, CTX).tool_name == "write_file"


# ===========================================================================
# §9.10 — the file itself
# ===========================================================================


def test_an_unknown_top_level_key_fails_startup(tmp_path: Path) -> None:
    bad = tmp_path / "registry.toml"
    bad.write_text(REGISTRY_PATH.read_text("utf-8") + "\nbogus = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        registry.Registry.load(bad)


def test_an_unknown_server_key_fails_startup(tmp_path: Path) -> None:
    bad = tmp_path / "registry.toml"
    text = REGISTRY_PATH.read_text("utf-8").replace(
        'owner = "akshay"', 'owner = "akshay"\ncredential_strategy = "vault"'
    )
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        registry.Registry.load(bad)


def test_a_missing_registry_fails_startup(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        registry.Registry.load(tmp_path / "nope.toml")


def test_more_than_one_server_fails_startup(tmp_path: Path) -> None:
    bad = tmp_path / "registry.toml"
    text = REGISTRY_PATH.read_text("utf-8")
    bad.write_text(
        text + "\n[[server]]" + text.split("[[server]]", 1)[1], encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="exactly one server"):
        registry.Registry.load(bad)


def test_a_nested_open_object_is_refused_at_load() -> None:
    """REG-013 all the way down, not only at the root.

    The gate checked `additionalProperties` on the root object alone, so this schema
    loaded and `{"opts": {"sudo": true}}` then validated against it — arbitrary
    attacker keys reaching the upstream inside an approved argument. None of the six
    shipped schemas has a nested object so nothing was exposed, but the gate was
    claiming more than it enforced. Codex adversarial review.
    """
    nested = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "opts": {"type": "object", "properties": {"a": {"type": "string"}}}
        },
    }
    with pytest.raises(ValidationError, match="additionalProperties"):
        registry.ToolEntry(
            name="t",
            risk_tier="R0",
            operation="read",
            schema_fingerprint="v1:x",
            approved_for="x",
            input_schema=json.dumps(nested),
        )

    # Closing it is enough; nothing else about the schema needs to change.
    nested["properties"]["opts"]["additionalProperties"] = False  # type: ignore[index]
    registry.ToolEntry(
        name="t",
        risk_tier="R0",
        operation="read",
        schema_fingerprint="v1:x",
        approved_for="x",
        input_schema=json.dumps(nested),
    )


def test_an_object_hidden_under_a_combinator_is_refused_at_load() -> None:
    """The walk descends through anyOf/items/$defs, not just `properties`."""
    for wrapper in (
        {"anyOf": [{"type": "object"}]},
        {"items": {"type": "object"}},
        {"$defs": {"d": {"type": "object"}}},
    ):
        with pytest.raises(ValidationError, match="additionalProperties"):
            registry.ToolEntry(
                name="t",
                risk_tier="R0",
                operation="read",
                schema_fingerprint="v1:x",
                approved_for="x",
                input_schema=json.dumps(
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"x": wrapper},
                    }
                ),
            )


def test_an_open_schema_is_refused_at_load() -> None:
    """REG-013 as a property of the schema, not a per-request check.

    `additionalProperties: false` is what makes `REG_ARGS_UNKNOWN_FIELD` fire. A
    hand-written unknown-field check is the kind that gets forgotten on the seventh
    tool; refusing to load an open schema cannot be.
    """
    with pytest.raises(ValidationError, match="additionalProperties"):
        registry.ToolEntry(
            name="t",
            risk_tier="R0",
            operation="read",
            schema_fingerprint="v1:x",
            approved_for="x",
            input_schema='{"type":"object","properties":{}}',
        )


def test_a_malformed_schema_fails_at_load_not_at_first_request() -> None:
    with pytest.raises(ValidationError):
        registry.ToolEntry(
            name="t",
            risk_tier="R0",
            operation="read",
            schema_fingerprint="v1:x",
            approved_for="x",
            input_schema='{"type":"object","additionalProperties":false,"required":"path"}',
        )


def test_r3_is_refused_because_it_cannot_be_enforced() -> None:
    """CONV-007. A tier with no enforcement path must not be expressible."""
    with pytest.raises(ValidationError):
        registry.ToolEntry(
            name="t",
            risk_tier="R3",  # type: ignore[arg-type]
            operation="read",
            schema_fingerprint="v1:x",
            approved_for="x",
            input_schema='{"type":"object","additionalProperties":false}',
        )


def test_the_shipped_registry_matches_the_live_fixture() -> None:
    """The approvals in `config/registry.toml` describe THIS fixture, right now.

    Everything else in this file would keep passing against a stale registry, by
    testing the comparison rather than the values. This is the one test that fails
    when the fixture changes and nobody re-approved it.
    """
    reg = registry.Registry.load(REGISTRY_PATH)
    assert reg.verify_schemas(live_tools()) == []


def test_the_registry_is_the_only_source_of_launch_parameters() -> None:
    """REG-002, structurally: there is no second copy to disagree with.

    This used to COMPARE `gateway.toml [child]` against the registry entry and assert
    they were equal. A comparison does not make either one the source — a deployment
    that edited only one would fingerprint one process and run another, and the test
    would pass right up until the files disagreed, at which point it reports a
    mismatch rather than having prevented one.

    The keys are gone from `[child]`, which now carries bridge tuning only, and
    `ChildTuning` forbids unknowns — so putting one back fails startup instead of
    quietly becoming a second opinion.
    """
    assert not (
        {"executable", "args", "cwd", "env_allowlist"}
        & set(cfgmod.ChildTuning.model_fields)
    )

    text = (REPO / "config" / "gateway.toml").read_text("utf-8")
    child_section = text.split("[child]", 1)[1].split("\n[", 1)[0]
    for key in ("executable", "args", "cwd", "env_allowlist"):
        assert f"\n{key} " not in child_section, f"[child] carries {key} again"

    # And putting one back is a STARTUP failure, not a silently ignored second
    # opinion. Driven through `cfgmod.load`, which is the real path — model_validate
    # raises pydantic's error, and it is `load` that turns it into ConfigError.
    import tempfile

    revived = text.replace(
        "startup_timeout_s = 10.0", 'executable = "python"\nstartup_timeout_s = 10.0'
    )
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "gateway.toml"
        bad.write_text(revived, encoding="utf-8")
        with pytest.raises(ConfigError, match="executable"):
            cfgmod.load(bad)


def test_the_bridge_receives_the_registry_values() -> None:
    """The merge: registry launch params + gateway.toml bridge tuning.

    Asserted against a MUTATED entry, not the shipped one. Comparing `child_config()`
    to the shipped values passes just as happily against a function that hardcodes
    `executable="python"` — which is what the shipped file says, so the equality
    holds for the wrong reason. The break pass caught exactly that. Sentinels no
    plausible hardcoding would produce make the assertion mean something.
    """
    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    server = registry.Registry.load(REGISTRY_PATH).server
    for field, sentinel in (
        ("executable", "/opt/sentinel/python3.13"),
        ("cwd", "/opt/sentinel/wd"),
        ("args", ("-m", "sentinel.module")),
        ("env_allowlist", ("SENTINEL_ONE", "SENTINEL_TWO")),
    ):
        object.__setattr__(server, field, sentinel)

    child = server.child_config(cfg.child)
    assert child.executable == "/opt/sentinel/python3.13"
    assert child.cwd == "/opt/sentinel/wd"
    assert child.args == ("-m", "sentinel.module")
    assert child.env_allowlist == ("SENTINEL_ONE", "SENTINEL_TWO")

    # Tuning still comes from gateway.toml, and is not the registry's business.
    assert child.startup_timeout_s == cfg.child.startup_timeout_s
    assert child.stderr_capture_lines == cfg.child.stderr_capture_lines


# ===========================================================================
# §9.11 — no client value can reach a launch parameter (REG-002)
# ===========================================================================


@settings(max_examples=200, deadline=None)
@given(
    poison=st.dictionaries(
        st.sampled_from(["path", "content", "executable", "args", "cwd", "command"]),
        st.text(max_size=40)
        | st.sampled_from(["/bin/sh", "cmd.exe", "../../etc/passwd", "python -c 'x'"]),
        max_size=6,
    )
)
@pytest.mark.slow
def test_no_argument_value_can_reach_a_launch_parameter(poison: dict[str, str]) -> None:
    """Spec test 11, as a property of the data flow rather than of the child's argv.

    Asserting on a spawned process would test one code path per example and cost a
    second each. The stronger statement is that the launch parameters are the same
    object no matter what arrived: `ServerEntry` is frozen and `resolve` returns a
    `ResolvedTarget` that carries no executable, argv, or cwd at all, so there is no
    field for a client value to land in.
    """
    reg = loaded()
    before = reg.server.child_config()
    with suppress(GatewayDenial):
        reg.resolve(request(arguments=poison), CTX)
    assert reg.server.child_config() == before
    assert not (
        set(ResolvedTarget.model_fields) & {"executable", "args", "cwd", "command"}
    )


def test_the_launch_parameters_are_immutable() -> None:
    server = registry.Registry.load(REGISTRY_PATH).server
    with pytest.raises(ValidationError):
        server.executable = "/bin/sh"  # type: ignore[misc]


# ===========================================================================
# tools/list, Mcp-Param-*, and the pipeline contribution
# ===========================================================================


def test_tools_list_resolves_to_a_toolless_r0_target() -> None:
    tgt = loaded().resolve(
        request(method="tools/list", tool_name=None, arguments={}), CTX
    )
    assert (tgt.tool_name, tgt.schema_fingerprint) == (None, None)
    assert tgt.registry_risk_tier == "R0"


def test_tools_list_is_refused_before_verification() -> None:
    """REG-009 applies to DISCOVERY too, and it did not.

    The tool-less target returned before `_callable_reason` ran, so an unverified
    registry still answered `tools/list`. A list assembled before the handshake has
    compared anything cannot be honestly filtered — it either omits nothing or omits
    by luck. Codex adversarial review.
    """
    reg = registry.Registry.load(REGISTRY_PATH)
    with pytest.raises(RegistryDenial) as e:
        reg.resolve(request(method="tools/list", tool_name=None, arguments={}), CTX)
    assert e.value.reason_code is ReasonCode.REG_SCHEMA_UNVERIFIED


def test_a_target_cannot_name_a_tool_without_its_fingerprint() -> None:
    """REG-009 in the type. A downstream stage reading `tool_name` with a
    fingerprint of `None` could not tell "no tool" from "tool whose approval was
    never verified", and the second must never route."""
    with pytest.raises(ValidationError):
        ResolvedTarget(
            server_id="s",
            tool_name="read_file",
            schema_fingerprint=None,
            registry_risk_tier="R1",
            operation="read",
        )


def test_a_mismatched_mcp_param_header_is_denied() -> None:
    """ADR-001 §3.1: the family stage 02 cannot check, checked here.

    The annotation lives in the APPROVED schema, so this is the first stage that can
    know `path` is mirrored at all — and it still runs before policy and the router,
    which is what PROTO-002 actually requires.
    """
    reg = loaded()
    annotated = json.loads(reg.tools["read_file"].input_schema)
    annotated["properties"]["path"]["x-mcp-header"] = "Path"
    object.__setattr__(reg.tools["read_file"], "input_schema", json.dumps(annotated))
    object.__setattr__(
        reg,
        "_validators",
        {**reg._validators},  # noqa: SLF001 - rebinding the map the entry backs
    )

    ok = request(
        arguments={"path": "public/readme.txt"},
        mcp_param_headers={"mcp-param-path": "public/readme.txt"},
    )
    assert reg.resolve(ok, CTX).tool_name == "read_file"

    lying = request(
        arguments={"path": "secrets/keys.txt"},
        mcp_param_headers={"mcp-param-path": "public/readme.txt"},
    )
    # ProtocolDenial, not RegistryDenial: the reason code belongs to unit 02 and so
    # does the wire shape (400 / -32020). Stage 04 is only where the schema that
    # names the mirrored argument first becomes available.
    with pytest.raises(GatewayDenial) as e:
        reg.resolve(lying, CTX)
    assert e.value.reason_code is ReasonCode.PROTO_HEADER_BODY_PARAM_MISMATCH
    assert e.value.wire == (400, -32020)


def test_a_schema_with_an_invalid_annotation_cannot_be_approved() -> None:
    """ADR-001 §3.1. The SDK SKIPS `Mcp-Param-*` validation entirely when the
    annotations are invalid, so approving such a schema would silently disable a
    whole mirrored family. Refusing it at load is the only safe answer."""
    with pytest.raises(ValidationError, match="invalid x-mcp-header"):
        registry.ToolEntry(
            name="t",
            risk_tier="R0",
            operation="read",
            schema_fingerprint="v1:x",
            approved_for="x",
            input_schema=json.dumps(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        # Not statically reachable through a pure `properties` chain.
                        "wrapper": {"anyOf": [{"type": "string", "x-mcp-header": "P"}]}
                    },
                }
            ),
        )


def _envelope(
    tool: str, arguments: dict[str, Any], extra: tuple[tuple[str, str], ...] = ()
) -> RawEnvelope:
    """A conforming `tools/call` over the wire, plus whatever `extra` breaks."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
            },
        },
    }
    return RawEnvelope(
        request_id="r1",
        received_at_ns=0,
        body=json.dumps(body).encode(),
        metadata=(
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", tool),
            *extra,
        ),
    )


def test_duplicate_mcp_param_headers_are_caught_at_stage_02() -> None:
    """Driven through `protocol.validate`, not through the helper.

    The first version called `find_duplicated_param_header` directly. Deleting its
    invocation from `validate` left the test green — the function worked perfectly
    and nothing called it, so a request with two conflicting `Mcp-Param-path` headers
    would fold to one attacker-selected value and be forwarded. Exactly the shape
    unit 03's review caught in the audit invariant, and my break pass missed it again
    by mutating the function body rather than the call site. Codex adversarial
    review; confirmed by deleting the call and watching the old test pass.
    """
    dup = _envelope(
        "read_file",
        {"path": "public/documentation.txt"},
        extra=(
            ("mcp-param-path", "public/documentation.txt"),
            ("mcp-param-path", "decoys/fake_ssh/id_rsa"),
        ),
    )
    with pytest.raises(GatewayDenial) as e:
        protocol.validate(dup, ProtocolConfig())
    assert e.value.reason_code is ReasonCode.PROTO_METADATA_DUPLICATE

    # One copy is legitimate and must reach stage 04, folded.
    ok = protocol.validate(
        _envelope(
            "read_file",
            {"path": "public/documentation.txt"},
            extra=(("mcp-param-path", "public/documentation.txt"),),
        ),
        ProtocolConfig(),
    )
    assert dict(ok.mcp_param_headers) == {"mcp-param-path": "public/documentation.txt"}

    # A duplicate outside the family is not this check's business.
    protocol.validate(
        _envelope("read_file", {"path": "p"}, extra=(("accept", "a"), ("accept", "b"))),
        ProtocolConfig(),
    )


async def test_the_pipeline_actually_persists_the_stage_04_fields(
    tmp_path: Path, audit_events: list[Any]
) -> None:
    """The wiring, not the function. Third time this shape has been caught.

    Every other audit assertion here calls `registry.audit_fields()` itself and
    checks the dict it just built, so deleting `builder.set(**registry.audit_fields(
    tgt))` from `pipeline.handle` breaks nothing — real records would go out with no
    `server_id`, no `schema_fingerprint` and no `risk_tier` while the suite stayed
    green. Unit 03 had exactly this in its identity fields; this is the same test one
    stage later.

    The request dies after stage 04 either way — stage 05 denies against a fixture
    tree this test never builds, or stage 06's stub raises — which is the point: the
    `finally` writes the event regardless, so anything stage 04 set must already be
    on it.
    """
    import json as _json

    from gateway.audit import AuditSink
    from gateway.pipeline import Deps, handle
    from harness.scenario import Scenario
    from harness.wire import build_envelope

    sink = AuditSink(tmp_path / "audit.jsonl")
    sink.open()
    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    deps = Deps(config=cfg, registry=loaded(), opa=None, upstream=None, audit=sink)

    scenario = Scenario.model_validate(
        {
            "id": "registry-wiring-probe",
            "class": "legitimate",
            "layer": "protocol",
            "principal": "developer",
            "tool": "read_file",
            "arguments": {"path": "public/documentation.txt"},
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public"},
            "risk_tier": "R1",
            "notes": "Drives the real pipeline far enough to prove stage 04 is wired.",
        }
    )

    before = len(audit_events)
    with pytest.raises(GatewayDenial):
        await handle(build_envelope(scenario), deps)

    (event,) = audit_events[before:]
    assert "registry" in event.stage_latency_ms, "stage 04 did not run"
    assert event.server_id == "filesystem-fixture"
    assert event.tool_name == "read_file"
    assert event.schema_fingerprint is not None
    assert event.schema_fingerprint.startswith(f"{FINGERPRINT_VERSION}:")
    assert event.risk_tier == "R1"
    assert event.operation == "read"

    # On DISK, not merely in the object the tee captured.
    persisted = _json.loads(sink.path.read_text("utf-8").splitlines()[-1])
    assert persisted["server_id"] == "filesystem-fixture"
    assert persisted["schema_fingerprint"] == event.schema_fingerprint


def test_stage_04_contributes_its_audit_fields() -> None:
    from gateway.audit_schema import RequestEvent

    fields = registry.audit_fields(loaded().resolve(request(), CTX))
    assert set(fields) <= set(RequestEvent.model_fields), "a field the schema forbids"
    assert fields["server_id"] == "filesystem-fixture"
    assert fields["schema_fingerprint"].startswith(f"{FINGERPRINT_VERSION}:")
    assert fields["risk_tier"] == "R1"


def test_no_raw_argument_value_is_audited() -> None:
    """AUDIT-005 from the registry side: the stage that sees `path` must not log it."""
    secret = "secrets/id_rsa"
    fields = registry.audit_fields(
        loaded().resolve(request(arguments={"path": secret}), CTX)
    )
    assert secret not in json.dumps(fields)

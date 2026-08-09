"""04 - Approved servers, tools, schema fingerprints, drift.

Spec: _specs/04-svc-registry.md   Tech: _tech/04-svc-registry.md

THE DEFAULT-DENY SURFACE
------------------------
Nothing is routable, callable, or discoverable unless it is written down in
`config/registry.toml` first, under version control, with a schema fingerprint.

This is also where the project's answer to tool-description poisoning lives. An
upstream MCP server supplies its own tool names, descriptions, schemas and
annotations, and **none of those are trustworthy**. The registry pins what a human
approved and detects when the upstream's answer changes. The critical consequence,
easy to lose in a refactor: `resolve` and `validate_arguments` read from
`self.tools`, never from anything the session returned. `verify_schemas` is the ONLY
method that touches advertised data, and all it may do with it is compare and
quarantine (REG-014, REG-008).

An annotation claiming a tool is read-only and harmless changes the fingerprint and
therefore quarantines the tool. It never changes the risk tier — the tier comes from
the registry file, which is why spec test 4 is the most legible test in this unit.

TOOLS/LIST
----------
`resolve` returns a tool-less R0 target for `tools/list`, which is the registry's
honest answer: the request names no tool. Stages 05 and 06 must handle that target —
there is no path yet, because both are stubs. Tracked against unit 05.

Mutable state is `_drift` plus `_sealed`, both written exactly once by
`verify_schemas` during startup and read-only afterwards. `_sealed` is checked rather
than assumed, so a call arriving before verification denies (REG-009) instead of
routing against a fingerprint nobody has compared.
"""

from __future__ import annotations

import json
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, cast

from jsonschema import Draft202012Validator, SchemaError
from jsonschema import ValidationError as SchemaValidationError
from mcp.shared.inbound import find_invalid_x_mcp_header
from pydantic import BaseModel, ConfigDict, field_validator

from gateway import hashing, protocol
from gateway.audit_schema import DriftEvent
from gateway.config import ChildConfig, ChildTuning
from gateway.errors import ConfigError, ProgrammingError, ReasonCode, RegistryDenial
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    JsonObject,
    Operation,
    ResolvedTarget,
    RiskTier,
    thaw,
)

_FROZEN = ConfigDict(frozen=True, extra="forbid")

_LIST_METHOD: Final = "tools/list"

#: Keywords whose values are themselves schemas, so the closure walk has to descend
#: through them. Named rather than "anything that looks like a dict" because a
#: `properties` map and a `const` value are both objects and only one is a schema.
_SCHEMA_MAPS: Final = ("properties", "patternProperties", "$defs", "definitions")
_SCHEMA_LISTS: Final = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_VALUES: Final = ("items", "not", "if", "then", "else", "contains")


def _first_open_object(schema: Any, path: str = "") -> str | None:
    """Path of the first object-valued schema position that is not closed, else `None`.

    REG-013 says unknown fields are rejected by default, and `_tech/04` §5 turns that
    into `additionalProperties: false` so it is a property of the schema rather than a
    check someone remembers to write. Checking only the ROOT was the weaker half of
    that idea: an approved schema of

        {"type": "object", "additionalProperties": false,
         "properties": {"opts": {"type": "object"}}}

    loads fine, and `{"opts": {"sudo": true}}` then validates — arbitrary attacker
    keys reaching the upstream inside an approved argument. None of the six shipped
    schemas has a nested object, so nothing was exposed; the gate was simply claiming
    more than it enforced. Codex adversarial review, unit 04.

    Returns a path rather than a bool so the startup error names the position, which
    is the difference between a five-second fix and a hunt.
    """
    if not isinstance(schema, Mapping):
        return None
    node = cast("JsonObject", schema)
    looks_like_an_object = node.get("type") == "object" or "properties" in node
    if looks_like_an_object and node.get("additionalProperties") is not False:
        return path
    for key in _SCHEMA_MAPS:
        sub = node.get(key)
        if isinstance(sub, Mapping):
            for name, child in cast("JsonObject", sub).items():
                if (
                    found := _first_open_object(child, f"{path}.{name}".lstrip("."))
                ) is not None:
                    return found
    for key in _SCHEMA_LISTS:
        sub = node.get(key)
        if isinstance(sub, list):
            for i, child in enumerate(cast("list[Any]", sub)):
                if (found := _first_open_object(child, f"{path}.{key}[{i}]")) is not None:
                    return found
    for key in _SCHEMA_VALUES:
        if (found := _first_open_object(node.get(key), f"{path}.{key}")) is not None:
            return found
    return None


class ToolEntry(BaseModel):
    """One approved tool. `input_schema` is JSON text, not TOML.

    JSON Schema is JSON; translating it through TOML tables would be lossy in both
    directions and would stop the block being copy-pasteable from a `tools/list`
    dump, which is how approvals are actually reviewed.
    """

    model_config = _FROZEN

    name: str
    risk_tier: RiskTier
    operation: Operation
    enabled: bool = True
    schema_fingerprint: str
    approved_for: str
    """Human-facing. NEVER read at runtime — asserted by a test, because a
    description that reaches a decision is the poisoning vector this unit defends."""
    input_schema: str

    @field_validator("input_schema")
    @classmethod
    def _valid_closed_and_annotated(cls, v: str) -> str:
        """Three load-time gates, so none of them can be a per-request check.

        `additionalProperties: false` is REG-013 turned into a property of the schema
        rather than a hand-written unknown-field check that someone forgets on the
        seventh tool. `check_schema` makes a malformed schema fail startup instead of
        the first request that reaches it. `find_invalid_x_mcp_header` is ADR-001
        §3.1: the SDK SKIPS `Mcp-Param-*` validation entirely when the annotations are
        invalid, so an approved schema carrying one would silently disable a mirrored
        family — the tool must never be approved in the first place.
        """
        try:
            parsed: Any = json.loads(v)
        except ValueError as e:
            raise ValueError(f"input_schema is not valid JSON: {e}") from e
        if not isinstance(parsed, dict):
            raise ValueError("input_schema must be a JSON object")
        schema = cast("JsonObject", parsed)
        if (open_at := _first_open_object(schema)) is not None:
            raise ValueError(
                f"approved schemas must set additionalProperties: false, missing at "
                f"{open_at or 'the schema root'}"
            )
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as e:
            raise ValueError(
                f"input_schema is not a valid JSON Schema: {e.message}"
            ) from e
        if (bad := find_invalid_x_mcp_header(schema)) is not None:
            # A startup refusal, not a request outcome — hence no ReasonCode. The
            # gateway does not run with this schema approved, so there is no request
            # to deny and no audit record to write (see `errors.ReasonCode`).
            raise ValueError(f"invalid x-mcp-header annotation: {bad}")
        return v

    @property
    def approved_schema(self) -> JsonObject:
        """The approved schema, decoded. Not cached — `_validators` is the hot path.

        NOT named `schema`: pydantic's `BaseModel.schema` is a deprecated classmethod,
        and shadowing it with a property is the kind of override that works until
        something calls the base method.
        """
        return cast("JsonObject", json.loads(self.input_schema))


class ServerEntry(BaseModel):
    """One approved upstream. v1 has exactly one; `Registry.load` enforces that.

    `executable`/`args`/`cwd`/`env_allowlist` live HERE and unit 01 reads them from
    here (REG-002, BRIDGE-007). There is no other source, which is what makes
    "no client-supplied value can reach a launch parameter" a structural property
    rather than a filter someone has to maintain.
    """

    model_config = _FROZEN

    id: str
    transport: Literal["stdio"]
    executable: str
    args: tuple[str, ...] = ()
    cwd: str
    env_allowlist: tuple[str, ...] = ("PATH",)
    expected_protocol_version: str
    state: Literal["enabled", "quarantined", "disabled"] = "enabled"
    owner: str
    review_date: str
    tool: tuple[ToolEntry, ...] = ()

    @field_validator("tool")
    @classmethod
    def _unique_names(cls, v: tuple[ToolEntry, ...]) -> tuple[ToolEntry, ...]:
        names = [t.name for t in v]
        if len(set(names)) != len(names):
            raise ValueError("duplicate tool name in registry")
        return v

    def child_config(self, tuning: ChildTuning | None = None) -> ChildConfig:
        """The ONLY way to build launch parameters (REG-002, BRIDGE-007).

        `config/gateway.toml [child]` used to carry its own copy of executable, argv,
        cwd and the environment allowlist, kept equal to this one by a test. A test
        that compares two copies does not make either the source — a deployment
        editing one would fingerprint one process and run another, and the comparison
        would pass until the day the files disagreed. The keys are gone from that
        section now and `ChildTuning` forbids them, so putting one back fails startup.

        `tuning` carries what genuinely belongs to the bridge — timeouts, stderr ring
        size — which the registry has no business describing. Omitted, the defaults
        apply, which is what every test that only needs to spawn the child wants.
        """
        return ChildConfig(
            executable=self.executable,
            args=self.args,
            cwd=self.cwd,
            env_allowlist=self.env_allowlist,
            **(tuning or ChildTuning()).model_dump(),
        )


class RegistryDocument(BaseModel):
    """The whole file. CONV-013: an unknown key anywhere fails startup."""

    model_config = _FROZEN

    server: tuple[ServerEntry, ...]


# ===========================================================================
# Fingerprinting (REG-005)
# ===========================================================================


def normalize(tool: Mapping[str, Any]) -> JsonObject:
    """The five fields a fingerprint covers, with `null` collapsed to absent.

    NULL COLLAPSES TO ABSENT; PRESENT-AND-EMPTY DOES NOT. `_tech/04` §3 said absent
    and null both become a typed empty (`""`, `{}`), and gave one reason: an upstream
    that starts emitting `"description": null` where it previously omitted the key
    must not produce a drift event, because noise is how a real drift event gets
    ignored. Collapsing null to absent satisfies that reason exactly. Going further
    and substituting a typed empty made an ABSENT `outputSchema` hash identically to
    a PRESENT empty one, so an upstream could add or remove `"outputSchema": {}` with
    no drift — and REG-005 says to fingerprint the output schema *where present*, so
    presence is part of what is being pinned. Codex adversarial review, unit 04;
    `_tech/04` §3 is corrected to match.

    `annotations` is in here deliberately. REG-008 says they must not influence a
    decision; fingerprinting them is what makes a poisoned annotation *detected*
    rather than merely ignored, and it is the whole of spec test 4.

    `inputSchema` carries the `x-mcp-header` annotations, so adding one is drift —
    ADR-001 §3.1 calls that out as a genuinely novel poisoning vector, since it
    changes which arguments the gateway is obliged to cross-check against headers.

    THE WIRE SHAPE, and the guard below is why. `mcp_types.Tool` names these fields
    `input_schema` / `output_schema` in Python and `inputSchema` / `outputSchema` on
    the wire, so `Tool.model_dump()` WITHOUT `by_alias=True` produces keys this
    function does not look for. It found none, substituted the typed empty, and
    happily fingerprinted every tool as though it had no schema at all — an upstream
    could then replace an entire input schema and drift would never fire. Caught
    while writing spec test 9. Reading both spellings would be worse: the same tool
    would have two fingerprints depending on how it was serialised.
    """
    wrong = {"input_schema", "output_schema"} & tool.keys()
    if wrong:
        raise ProgrammingError(
            f"fingerprint input uses Python field names {sorted(wrong)}; it must be "
            "the wire shape (Tool.model_dump(by_alias=True)). Hashing the snake_case "
            "shape silently omits the schema from the fingerprint."
        )
    out: JsonObject = {"name": tool["name"]}
    for key in ("description", "inputSchema", "outputSchema", "annotations"):
        value = tool.get(key)
        if value is not None:
            out[key] = value
    return out


def fingerprint(tool: Mapping[str, Any]) -> str:
    """Fingerprint an advertised or approved tool description (REG-005).

    Key order and whitespace are irrelevant by construction — `hashing.canonical_json`
    sorts keys and uses tight separators, which is spec test 5 — and the `v1:` prefix
    is the normalization rule's version, so changing a rule in `normalize` bumps it
    and every stored value is regenerated deliberately rather than silently
    invalidated en masse.
    """
    return hashing.fingerprint(normalize(tool))


# ===========================================================================
# The registry
# ===========================================================================


class Registry:
    """Loaded once at startup into a frozen structure. Restart is the reload."""

    def __init__(self, server: ServerEntry) -> None:
        self.server = server
        self.tools: Mapping[str, ToolEntry] = {t.name: t for t in server.tool}
        self._validators: Mapping[str, Draft202012Validator] = {
            name: Draft202012Validator(t.approved_schema)
            for name, t in self.tools.items()
        }
        self._drift: dict[str, ReasonCode] = {}
        self._sealed = False

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> Registry:
        """Parse, validate, compile. Any failure here means the gateway does not run.

        Compiling the validators at load is the point of steps 3-5 in `_tech/04` §7:
        a malformed approved schema must fail startup, not the first request that
        happens to use that tool — by which time readiness has already been reported
        and a caller is waiting on an answer the gateway cannot give.
        """
        p = Path(path)
        try:
            with p.open("rb") as fh:
                raw = tomllib.load(fh)
        except FileNotFoundError as e:
            raise ConfigError(f"registry not found: {p}") from e
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"invalid TOML in {p}: {e}") from e
        try:
            doc = RegistryDocument.model_validate(raw)
        except Exception as e:
            raise ConfigError(f"invalid registry in {p}: {e}") from e
        if len(doc.server) != 1:
            # v1 is one upstream. More is a configuration mistake, not a feature to
            # accommodate — multi-upstream is in the deferred register with its trigger.
            raise ConfigError(
                f"v1 registry must define exactly one server, got {len(doc.server)}"
            )
        return cls(doc.server[0])

    # -- drift (REG-006, REG-009) -----------------------------------------

    def verify_schemas(self, advertised: Iterable[Mapping[str, Any]]) -> list[DriftEvent]:
        """Compare what the upstream advertises to what was approved. Startup only.

        Takes the already-extracted tool descriptions rather than a session, so the
        comparison is testable without a live child and so this module never learns
        how to talk to one. Unit 01 supplies them from `tools/list` before readiness.

        Drift QUARANTINES; it does not prevent startup. A gateway that refuses to
        boot on drift is a gateway that gets started with the check disabled.

        Returns the events for the caller to write. Writing them here would need an
        audit sink on this object solely so that a single startup call could log,
        and would make `Registry` unusable in a test without a filesystem.
        """
        seen: set[str] = set()
        events: list[DriftEvent] = []
        for adv in advertised:
            name = str(adv.get("name", ""))
            seen.add(name)
            approved = self.tools.get(name)
            if approved is None:
                # Advertised but never approved: denied by default at `resolve`, so
                # this is a notice, not a quarantine. Auto-registering it is the one
                # thing that would make the whole registry pointless.
                events.append(
                    self._drift_event(name, ReasonCode.REG_TOOL_UNKNOWN, None, None)
                )
                continue
            actual = fingerprint(adv)
            if actual != approved.schema_fingerprint:
                self._drift[name] = ReasonCode.REG_SCHEMA_DRIFT
                events.append(
                    self._drift_event(
                        name,
                        ReasonCode.REG_SCHEMA_DRIFT,
                        approved.schema_fingerprint,
                        actual,
                    )
                )
        for name in self.tools.keys() - seen:
            # Approved but no longer advertised. Quarantined rather than merely
            # denied: the upstream is not the server this registry describes, and a
            # later `tools/list` must not resurrect the tool without a restart.
            self._drift[name] = ReasonCode.REG_TOOL_UNKNOWN
            events.append(
                self._drift_event(
                    name,
                    ReasonCode.REG_TOOL_UNKNOWN,
                    self.tools[name].schema_fingerprint,
                    None,
                )
            )
        self._sealed = True
        return events

    def _drift_event(
        self, tool: str, code: ReasonCode, approved: str | None, actual: str | None
    ) -> DriftEvent:
        return DriftEvent(
            ts=datetime.now(UTC),
            server_id=self.server.id,
            tool_name=tool,
            reason_code=code.value,
            approved_fingerprint=approved,
            advertised_fingerprint=actual,
        )

    @property
    def quarantined(self) -> Mapping[str, ReasonCode]:
        """Tool name -> why it is quarantined. A copy; `_drift` is sealed after startup.

        Cut during the ponytail pass when its only caller was a test assertion, then
        restored when `startup.serve` needed it to stamp the readiness record. Which
        is the honest version of the rule: an accessor with no production caller is
        speculative, and this one stopped being speculative.
        """
        return dict(self._drift)

    # -- the shared predicate (REG-011) ------------------------------------

    def _callable_reason(self, tool: ToolEntry) -> ReasonCode | None:
        """Why this tool cannot be called, or `None` if the registry permits it.

        THE single predicate. `resolve` raises on its result and `visible_tools`
        filters on it, so a tool visible in `tools/list` but universally denied at
        `tools/call` is structurally impossible rather than test-detected — REG-011
        asks for exactly that, and `_tech/04` §6 names sharing the function as the
        way to get it.
        """
        if self.server.state != "enabled":
            return ReasonCode.REG_SERVER_UNAVAILABLE
        if not self._sealed:
            return ReasonCode.REG_SCHEMA_UNVERIFIED
        if (drifted := self._drift.get(tool.name)) is not None:
            return (
                ReasonCode.REG_TOOL_QUARANTINED
                if drifted is ReasonCode.REG_SCHEMA_DRIFT
                else ReasonCode.REG_TOOL_UNKNOWN
            )
        if not tool.enabled:
            return ReasonCode.REG_TOOL_UNKNOWN
        return None

    def visible_tools(
        self,
        ctx: AuthzContext,
        could_ever_allow: Callable[[AuthzContext, ToolEntry], bool],
    ) -> list[ToolEntry]:
        """REG-010. What this principal is allowed to DISCOVER.

        `could_ever_allow` is unit 06's `data.gateway.discoverable` entrypoint — "is
        there any resource for which this principal could call this tool?" — and it is
        a REQUIRED parameter with no default. A default of "yes" would make this
        method silently over-disclose the day someone forgot to pass it, and that
        failure is invisible: the list simply looks fuller than it should.

        Approximating it by calling the main `allow` rule with a placeholder path is
        the trap `_tech/04` §6 warns about, in both directions — a placeholder that
        happens to be denied hides a tool the principal can legitimately use, and one
        that happens to be allowed reveals a tool they cannot.
        """
        return [
            t
            for t in self.tools.values()
            if self._callable_reason(t) is None and could_ever_allow(ctx, t)
        ]

    # -- per request -------------------------------------------------------

    def resolve(self, req: CanonicalRequest, ctx: AuthzContext) -> ResolvedTarget:
        """Approved? Then say what was approved. Otherwise raise.

        `ctx` is accepted and deliberately unused: REG-010's principal filter belongs
        to discovery, and applying it here as well would make `tools/call` deny with a
        registry code for what is a POLICY decision — unit 06's job, its reason codes,
        its audit fields. Keeping the parameter documents that this is a decision, not
        an omission.
        """
        # Duplicated from `_callable_reason` on purpose, and this comment is the
        # reason: `tools/list` names no tool, so it returns below without ever
        # reaching that predicate. Without this line a disabled server would still
        # answer discovery. The break pass proved the redundancy is load-bearing —
        # deleting it from `_callable_reason` alone left every test green, because
        # `resolve` still caught it while `visible_tools` no longer did.
        if self.server.state != "enabled":
            raise self._deny(ReasonCode.REG_SERVER_UNAVAILABLE, self.server.state)

        if req.method == _LIST_METHOD:
            # REG-009 applies to DISCOVERY too, and this line was missing: the R0
            # target returned below without ever reaching `_callable_reason`, so an
            # unverified registry still answered `tools/list`. A list assembled
            # before the handshake compared anything cannot be honestly filtered —
            # it either omits nothing or omits by luck. Codex adversarial review.
            if not self._sealed:
                raise self._deny(ReasonCode.REG_SCHEMA_UNVERIFIED, _LIST_METHOD)
            # Names no tool, so it carries no fingerprint and no approved schema.
            # R0: metadata only, allowable by explicit policy (`_specs/00` §7).
            return ResolvedTarget(
                server_id=self.server.id,
                tool_name=None,
                schema_fingerprint=None,
                registry_risk_tier="R0",
                operation="read",
            )

        if req.tool_name is None:
            raise self._deny(ReasonCode.REG_TOOL_UNKNOWN, f"{req.method} names no tool")
        tool = self.tools.get(req.tool_name)
        if tool is None:
            # REG-003: denied even when the upstream genuinely advertises it and would
            # happily execute it. Advertisement is input, not authorization.
            raise self._deny(ReasonCode.REG_TOOL_UNKNOWN, req.tool_name)
        if (reason := self._callable_reason(tool)) is not None:
            raise self._deny(reason, tool.name)

        self.validate_arguments(tool, req)

        return ResolvedTarget(
            server_id=self.server.id,
            tool_name=tool.name,
            schema_fingerprint=tool.schema_fingerprint,
            registry_risk_tier=tool.risk_tier,
            operation=tool.operation,
        )

    def validate_arguments(self, tool: ToolEntry, req: CanonicalRequest) -> None:
        """REG-012 and REG-014, plus the `Mcp-Param-*` family (ADR-001 §3.1).

        Against the APPROVED schema. `self._validators` is built from registry data at
        load and never touches the session — pinning the schema is the entire point,
        and validating against the advertised one would authorise whatever the
        upstream currently claims to accept.

        `thaw` because `jsonschema` resolves `"type": "object"` against `dict` and
        `"array"` against `list`; a frozen structure fails for the wrong reason. The
        result is passed straight in and never stored (CLAUDE.md).

        Unknown fields raise here too, via `additionalProperties: false`, which the
        entry validator has already guaranteed is present. Reported under its own
        reason code because "you sent a field that does not exist" and "your path was
        too long" are different client mistakes.
        """
        arguments = cast("JsonObject", thaw(req.arguments))
        # `iter_errors` and stop at the first (`_tech/04` §5). Not aggregation: error
        # detail is diagnostic-only (CONV-009) and never reaches the client, so
        # collecting the rest is work whose output nobody reads.
        # The ignore is jsonschema's stub, not this call: `iter_errors` is declared
        # with an overload whose `instance` is untyped, so strict mode cannot narrow
        # it however the argument is annotated. The generator is bound to a typed
        # name immediately, so nothing downstream inherits the Unknown.
        validator = self._validators[tool.name]
        found = validator.iter_errors(arguments)  # pyright: ignore[reportUnknownMemberType]
        errors: Iterator[SchemaValidationError] = found
        if (first := next(errors, None)) is not None:
            code = (
                ReasonCode.REG_ARGS_UNKNOWN_FIELD
                if first.validator == "additionalProperties"
                else ReasonCode.REG_ARGS_INVALID
            )
            raise self._deny(code, f"{tool.name}: {first.message}")

        # Last, and only on arguments already proven to match the approved schema:
        # the annotations that say which arguments are mirrored are IN that schema,
        # so cross-checking headers against arguments of unknown shape would be
        # comparing against a value the tool would never have accepted.
        protocol.check_param_headers(
            tool.approved_schema, arguments, req.mcp_param_headers
        )

    @staticmethod
    def _deny(code: ReasonCode, detail: str) -> RegistryDenial:
        return RegistryDenial(code, detail=detail)


# ===========================================================================
# Pipeline surface
# ===========================================================================


def resolve(req: CanonicalRequest, ctx: AuthzContext, reg: Registry) -> ResolvedTarget:
    return reg.resolve(req, ctx)


def audit_fields(tgt: ResolvedTarget) -> JsonObject:
    """What stage 04 contributes to the record (spec §8).

    `risk_tier` is the REGISTRY's assignment. Unit 06 must carry the same value into
    its `Decision` rather than deriving its own — a tier that changes between the two
    stages means the tool was authorised as something other than what was approved.
    """
    return {
        "server_id": tgt.server_id,
        "tool_name": tgt.tool_name,
        "schema_fingerprint": tgt.schema_fingerprint,
        "risk_tier": tgt.registry_risk_tier,
        "operation": tgt.operation,
    }


__all__ = [
    "Registry",
    "RegistryDocument",
    "ServerEntry",
    "ToolEntry",
    "audit_fields",
    "fingerprint",
    "normalize",
    "resolve",
]

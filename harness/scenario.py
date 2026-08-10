"""Scenario schema and corpus loader.

`_specs/11-svc-eval-harness.md` §5. Scenarios are TOML data files, not test functions,
so the corpus is a publishable deliverable reviewable independently of the harness.

HARN-003: `expected_reason` is mandatory. "Denied for some reason" is not a passing
test — a case that denies for the WRONG reason is a defect a decision-only assertion
would hide.
HARN-004: `expected_side_effect` is mandatory, including for allow scenarios, where
the effect must be observed to have HAPPENED.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gateway.errors import ReasonCode

CORPUS_DIR = Path(__file__).parent / "scenarios"

#: `errors.ReasonCode` is the single source of truth (CLAUDE.md); this reads it rather
#: than restating it, so a code renamed in the gateway fails the corpus at load.
_REASON_CODES = frozenset(c.value for c in ReasonCode)

_FROZEN = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

#: TOML cannot carry control characters, and control characters are core attack
#: material (null-byte truncation, CR/LF injection). Argument values expand these
#: placeholders at load, so the corpus file stays readable and diffable.
PLACEHOLDERS: dict[str, str] = {
    "{NUL}": "\x00",
    "{CR}": "\r",
    "{LF}": "\n",
    "{TAB}": "\t",
    "{DEL}": "\x7f",
}


def expand(value: str) -> str:
    for token, char in PLACEHOLDERS.items():
        value = value.replace(token, char)
    return value


def _expand_json(value: Any) -> Any:
    """Expand placeholders wherever a JSON value can contain text.

    Arguments are JSON, not a string-to-string map.  Keeping the old narrow type made
    numeric-boundary and JSON-structure cases impossible to express, which in turn
    made HARN-012 impossible to implement without bypassing the scenario schema.
    """
    if isinstance(value, str):
        return expand(value)
    if isinstance(value, list):
        return [_expand_json(item) for item in cast("list[Any]", value)]
    if isinstance(value, dict):
        obj = cast("dict[str, Any]", value)
        return {key: _expand_json(item) for key, item in obj.items()}
    return value


class ExpectedEffect(BaseModel):
    """A side effect the oracle must observe at the fixture, for allow scenarios."""

    model_config = _FROZEN

    op: Literal["read", "list", "stat", "write", "append", "delete"]
    path_contains: str


class Transport(BaseModel):
    """Deliberate damage to the wire form, for `layer = "protocol"` scenarios.

    A scenario normally says WHAT to call; the protocol class has to say HOW it
    arrives, because the whole attack is that the header and the body disagree. That
    cannot be expressed as a tool plus arguments — a split request names two tools.

    Everything is optional and defaults to a conforming request, so a scenario states
    only the one thing it breaks (PROTO-007: one shape, one reason code, one row).
    """

    model_config = _FROZEN

    header_method: str | None = None
    """Send this as `Mcp-Method` instead of the body's method."""
    header_name: str | None = None
    """Send this as `Mcp-Name` instead of the body's tool name."""
    header_version: str | None = None
    body_version: str | None = None
    omit: tuple[str, ...] = ()
    """Mirrored headers to leave out entirely (required-and-absent)."""
    add: tuple[tuple[str, str], ...] = ()
    """Extra raw header pairs — how a duplicate or a prohibited header is expressed."""
    drop_meta: tuple[str, ...] = ()
    """Envelope `_meta` keys to delete from the body."""
    raw_body: str | None = None
    """Replace the body outright. For malformed JSON and bad envelopes, where no
    structured description of the payload exists."""

    http_fate: Literal["delivered", "normalized", "rejected"] = "delivered"
    """What a CONFORMING HTTP/1.1 recipient does to this request before the gateway
    sees it. Measured, not assumed — see tests/integration/test_protocol_over_http.py.

    `delivered`   arrives at the guard byte-for-byte; the guard's denial is the
                  gateway's denial.
    `normalized`  RFC 9110 strips leading/trailing OWS from a field value, so the
                  request that ARRIVES is legitimate and is allowed. The guard's
                  stricter check is defence in depth for a transport that does not
                  normalize, and this row proves the difference exists rather than
                  leaving it to be discovered later.
    `rejected`    the HTTP parser refuses it outright (a CR or LF inside a field
                  value). Denied one layer earlier than the guard, and the gateway
                  never runs — so no audit event exists for it either.

    Recording this is the point, not an accommodation. "The header value the guard
    compares is not the header value the client sent" is precisely the divergence
    class unit 02 exists for, and here it is inside our own stack."""
    body_extra: dict[str, Any] = Field(default_factory=dict)
    """Extra `params` keys, e.g. MRTR's `inputResponses`."""
    jsonrpc_id: Any = 1
    """Request identifier override, used by HARN-012's identifier strategy."""
    boundary: Literal["depth", "array", "string", "object", "fields"] | None = None
    boundary_value: int | None = Field(default=None, gt=0)
    boundary_offset: Literal[-1, 0, 1] = 0
    """Build a compact at/below/above structural-limit row from TOML data."""

    @field_validator("header_name", "header_method", "header_version", mode="after")
    @classmethod
    def _expand_scalar(cls, v: str | None) -> str | None:
        return expand(v) if v is not None else None

    @field_validator("add", mode="after")
    @classmethod
    def _expand_pairs(cls, v: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        # CR/LF/NUL in a HEADER is core attack material — header injection, and value
        # truncation at any intermediary that treats NUL as a terminator. Expanding
        # only `arguments` made that class unwritable, so the corpus quietly said
        # "read_file{CR}x", which is merely a different name. Caught by the corpus's
        # own first run against the guard.
        return tuple((k, expand(val)) for k, val in v)

    @model_validator(mode="after")
    def _boundary_is_complete(self) -> Transport:
        if (self.boundary is None) != (self.boundary_value is None):
            raise ValueError("boundary and boundary_value must be supplied together")
        return self


class Scenario(BaseModel):
    model_config = _FROZEN

    id: str
    kind: Literal["malicious", "legitimate"] = Field(alias="class")
    layer: Literal["protocol", "security", "performance", "chaos"]
    principal: str
    tool: str
    arguments: dict[str, Any]
    expected_decision: Literal["allow", "deny"]
    expected_reason: str
    expected_side_effect: ExpectedEffect | Literal["none"]
    risk_tier: Literal["R0", "R1", "R2", "R4"]
    notes: str
    requires_symlinks: bool = False
    transport: Transport | None = None
    fixture_mode: Literal[
        "",
        "oversized",
        "hang",
        "crash",
        "inject",
        "drift",
        "poison",
        "malformed",
        "wrong_id",
        "unsolicited",
        "pathological",
    ] = ""
    gateway_fault: Literal["opa_killed"] | None = None

    @field_validator("arguments", mode="after")
    @classmethod
    def _expand_placeholders(cls, v: dict[str, Any]) -> dict[str, Any]:
        return {key: _expand_json(value) for key, value in v.items()}

    @field_validator("expected_reason", mode="after")
    @classmethod
    def _is_a_real_reason_code(cls, v: str) -> str:
        """A reason code the gateway cannot emit is a row that can never pass.

        Typed `str` rather than `ReasonCode` on purpose — the corpus is publishable
        data and must load without importing the gateway's enum into its schema. But
        it still has to NAME something real, and the cheapest moment to find out is
        parse time.

        Without this the mistake surfaces at SCORE time: a run over 118 rows, one
        gateway per principal, strictly serialised because oracle correlation is by
        byte offset — minutes, in whichever of the three modes happens to reach that
        row. `direct` skips 52 rows and `protected` skips 3, so a typo can also be
        invisible in the mode you happened to run. Milliseconds here instead.

        `TRANSPORT_REJECTED` is the harness's own outcome for a request h11 refused
        before the gateway existed to have an opinion, so it is legal here and is not
        a `ReasonCode`.
        """
        if v == "TRANSPORT_REJECTED" or v in _REASON_CODES:
            return v
        raise ValueError(
            f"expected_reason {v!r} is not a ReasonCode the gateway can emit; "
            "run `python -m scripts.sync_reason_codes` if the enum just changed"
        )

    @property
    def deployment_key(self) -> str:
        """The gateway/fixture combination this row must run against.

        Identity is configuration-only, fixture misbehaviour is process-environment
        only, and an OPA outage needs its own sidecar.  All three therefore belong in
        deployment selection rather than on the request wire.
        """
        if not self.fixture_mode and self.gateway_fault is None:
            return self.principal
        return "|".join(
            (
                self.principal,
                f"fixture={self.fixture_mode or 'normal'}",
                f"fault={self.gateway_fault or 'none'}",
            )
        )

    @model_validator(mode="after")
    def _coherent(self) -> Scenario:
        # Response failures happen after an authorized upstream operation.  Such a
        # row correctly expects both a client-visible denial and the declared read or
        # write at the fixture; treating every deny-with-effect as contradictory made
        # the entire response-guard class unrepresentable.
        if self.kind == "malicious" and self.expected_decision == "allow":
            raise ValueError(f"{self.id}: a malicious scenario cannot expect allow")
        return self


class Corpus(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    scenarios: tuple[Scenario, ...]

    def malicious(self) -> tuple[Scenario, ...]:
        return tuple(s for s in self.scenarios if s.kind == "malicious")

    def legitimate(self) -> tuple[Scenario, ...]:
        return tuple(s for s in self.scenarios if s.kind == "legitimate")


SMOKE_BUDGET = 50
"""Rows in the `smoke` profile. A development lane, never an evidence run."""


def smoke(
    scenarios: tuple[Scenario, ...], budget: int = SMOKE_BUDGET
) -> tuple[Scenario, ...]:
    """The smallest subset that still exercises every distinct thing the corpus tests.

    A full protected run is the slowest thing in this project, and iterating on it at
    full size means most of a development session is spent re-proving rows that did
    not change. This is the fast lane; `--profile full` is what any published number
    must come from, and `harness.report` refuses an artifact that is not `full`.

    Coverage-greedy over `(layer, expected_reason, fixture_mode, gateway_fault)`, taken
    in id order so the selection is deterministic and reviewable — the same 50 rows
    every run, on every machine, which is what makes a smoke failure reproducible
    rather than a coin flip. That key currently needs 42 rows to cover all 35 reason
    codes, all 11 fixture modes and all 3 principals.

    The remaining budget goes to LEGITIMATE rows first. The half of the claim that is
    easy to lose is "and it still serves the traffic it should" — a subset weighted to
    denials would let a gateway that refuses everything look healthy in the fast lane
    and only fail hours later in the full run.

    Deployments are NOT reduced: every fixture-misbehaviour row is the sole witness
    for its reason code, so all 14 survive. The saving is per-row work, not per-boot.
    """
    ordered = sorted(scenarios, key=lambda s: s.id)
    chosen: list[Scenario] = []
    seen: set[tuple[str, str, str, str | None]] = set()

    for s in ordered:
        key = (s.layer, s.expected_reason, s.fixture_mode, s.gateway_fault)
        if key not in seen:
            seen.add(key)
            chosen.append(s)

    picked = {s.id for s in chosen}
    for want_legitimate in (True, False):
        for s in ordered:
            if len(chosen) >= budget:
                break
            if s.id not in picked and (s.kind == "legitimate") == want_legitimate:
                chosen.append(s)
                picked.add(s.id)

    # Truncating would silently drop coverage the docstring promises. Better to hand
    # back more than the budget and say so than to publish a gap nobody was told about.
    return tuple(sorted(chosen, key=lambda s: s.id))


def load(directory: Path | None = None) -> Corpus:
    """Load every scenario file. One corpus version across all files (HARN-021)."""
    d = Path(directory) if directory else CORPUS_DIR
    files = sorted(d.glob("*.toml"))
    if not files:
        raise ValueError(f"no scenario files in {d}")

    versions: set[str] = set()
    scenarios: list[Scenario] = []
    seen: set[str] = set()

    for f in files:
        with f.open("rb") as fh:
            raw = tomllib.load(fh)
        versions.add(raw["corpus_version"])
        for entry in raw.get("scenario", []):
            s = Scenario.model_validate(entry)
            if s.id in seen:
                raise ValueError(f"duplicate scenario id: {s.id} (in {f.name})")
            seen.add(s.id)
            scenarios.append(s)

    if len(versions) != 1:
        raise ValueError(f"mixed corpus versions across files: {sorted(versions)}")

    return Corpus(version=versions.pop(), scenarios=tuple(scenarios))

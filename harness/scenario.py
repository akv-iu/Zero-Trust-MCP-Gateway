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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CORPUS_DIR = Path(__file__).parent / "scenarios"

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
    body_extra: dict[str, str] = Field(default_factory=dict)
    """Extra `params` keys, e.g. MRTR's `inputResponses`."""

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


class Scenario(BaseModel):
    model_config = _FROZEN

    id: str
    kind: Literal["malicious", "legitimate"] = Field(alias="class")
    layer: Literal["protocol", "security", "performance", "chaos"]
    principal: str
    tool: str
    arguments: dict[str, str]
    expected_decision: Literal["allow", "deny"]
    expected_reason: str
    expected_side_effect: ExpectedEffect | Literal["none"]
    risk_tier: Literal["R0", "R1", "R2", "R4"]
    notes: str
    requires_symlinks: bool = False
    transport: Transport | None = None

    @field_validator("arguments", mode="after")
    @classmethod
    def _expand_placeholders(cls, v: dict[str, str]) -> dict[str, str]:
        return {k: expand(val) for k, val in v.items()}

    @model_validator(mode="after")
    def _coherent(self) -> Scenario:
        # A deny that expects an effect is a contradiction; catch it at load time
        # rather than discovering it as a confusing result.
        if self.expected_decision == "deny" and self.expected_side_effect != "none":
            raise ValueError(f"{self.id}: a denied scenario cannot expect a side effect")
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

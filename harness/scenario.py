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

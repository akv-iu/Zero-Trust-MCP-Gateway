"""Seeded Hypothesis case generation, reported apart from the written corpus.

Hypothesis owns the values and shrinking semantics; this module only records the
generated values so a run can be reproduced and included in the evidence report.
The invariant is deliberately one-sided (TECH-11 section 5): a generated request may
be allowed or denied, but denial-with-effect and allow-outside-root are always wrong.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from hypothesis import HealthCheck, Phase, given, seed, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from fixtures.build_tree import reset, tree_hash
from harness.clients import CLIENT_CODES, CallOutcome, Client
from harness.oracle import Observation, Oracle
from harness.provenance import source_fingerprint
from harness.runner import Verdict
from harness.scenario import Scenario, Transport


class Family(StrEnum):
    PATH = "path"
    ENCODING = "encoding"
    IDENTIFIER = "identifier"
    NUMERIC = "numeric"
    JSON_STRUCTURE = "json_structure"


@dataclass(frozen=True)
class GeneratedCase:
    family: Family
    value: Any

    def stable_json(self) -> str:
        return json.dumps(
            {"family": self.family.value, "value": self.value},
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class GeneratedResult:
    family: Family
    case_json: str
    verdict: Verdict
    detail: str


@dataclass(frozen=True)
class GeneratedReport:
    seed: int
    results: tuple[GeneratedResult, ...]
    source_fingerprint: str = field(default_factory=source_fingerprint)

    def count(self, verdict: Verdict) -> int:
        return sum(result.verdict is verdict for result in self.results)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "artifact_version": 1,
            "source_fingerprint": self.source_fingerprint,
            "seed": self.seed,
            "results": [asdict(result) for result in self.results],
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def strategies() -> dict[Family, SearchStrategy[Any]]:
    segments = st.sampled_from(
        [
            "..",
            ".",
            "%2e%2e",
            "%252e%252e",
            "\x00",
            "public",
            "workspace",
            "confidential",
            "traps/escape_link",
            "CON",
            "x.",
            "",
        ]
    )
    paths = st.lists(segments, min_size=1, max_size=8).map("/".join)
    encodings = st.lists(
        st.sampled_from(["%2e", "%2f", "%5c", "%00", "%25", "%ff", "public", ".."]),
        min_size=1,
        max_size=6,
    ).map(lambda parts: f"public/{''.join(parts)}/documentation.txt")
    identifiers = st.one_of(
        st.none(),
        st.integers(min_value=-(2**63), max_value=2**63 - 1),
        st.text(max_size=32),
    )
    numerics = st.one_of(
        st.integers(min_value=-(2**127), max_value=2**127),
        st.floats(allow_nan=False, allow_infinity=False, width=64),
    )
    scalar = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=32))
    structures = st.recursive(
        scalar,
        lambda children: st.one_of(
            st.lists(children, max_size=8),
            st.dictionaries(st.text(min_size=1, max_size=12), children, max_size=8),
        ),
        max_leaves=25,
    )
    return {
        Family.PATH: paths,
        Family.ENCODING: encodings,
        Family.IDENTIFIER: identifiers,
        Family.NUMERIC: numerics,
        Family.JSON_STRUCTURE: structures,
    }


def generate(
    recorded_seed: int, examples_per_family: int = 50
) -> tuple[GeneratedCase, ...]:
    """Generate a reproducible set using Hypothesis' public seed/settings API."""
    if examples_per_family < 1:
        raise ValueError("examples_per_family must be positive")

    generated: list[GeneratedCase] = []
    for offset, (family, strategy) in enumerate(strategies().items()):
        values = _draw(strategy, recorded_seed + offset, examples_per_family)
        generated.extend(GeneratedCase(family, value) for value in values)
    return tuple(generated)


def _draw(strategy: SearchStrategy[Any], recorded_seed: int, count: int) -> list[Any]:
    values: list[Any] = []

    @seed(recorded_seed)
    @settings(
        max_examples=count,
        deadline=None,
        database=None,
        phases=(Phase.generate,),
        suppress_health_check=(HealthCheck.too_slow,),
    )
    @given(strategy)
    def collect(value: Any) -> None:
        values.append(value)

    collect()
    return values


def run_generated(
    cases: tuple[GeneratedCase, ...],
    client: Client,
    oracle: Oracle,
    *,
    root: Path,
    recorded_seed: int,
) -> GeneratedReport:
    baseline = tree_hash(root)
    results: list[GeneratedResult] = []
    for index, case in enumerate(cases):
        scenario = _scenario(case, index)
        oracle.snapshot()
        outcome = client.call(scenario)
        results.append(_score(case, outcome, oracle.observe(), root))
        if reset(root) != baseline:
            raise RuntimeError(f"fixture reset failed after generated case {index}")
    return GeneratedReport(recorded_seed, tuple(results))


def _scenario(case: GeneratedCase, index: int) -> Scenario:
    arguments: dict[str, Any] = {"path": "public/documentation.txt"}
    transport: Transport | None = None
    if case.family in {Family.PATH, Family.ENCODING}:
        arguments["path"] = cast("str", case.value)
    elif case.family is Family.NUMERIC:
        arguments["path"] = case.value
    elif case.family is Family.IDENTIFIER:
        transport = Transport(jsonrpc_id=case.value)
    else:
        transport = Transport(raw_body=json.dumps(case.value, ensure_ascii=True))

    return Scenario.model_validate(
        {
            "id": f"generated-{case.family.value}-{index:05d}",
            "class": "legitimate",
            "layer": "protocol",
            "principal": "intern",
            "tool": "read_file",
            "arguments": arguments,
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {
                "op": "read",
                "path_contains": "public/documentation.txt",
            },
            "risk_tier": "R1",
            "notes": "Hypothesis-generated; scored by invariant, not this placeholder.",
            "transport": transport.model_dump() if transport else None,
        }
    )


def _score(
    case: GeneratedCase, outcome: CallOutcome, obs: Observation, root: Path
) -> GeneratedResult:
    def made(verdict: Verdict, detail: str) -> GeneratedResult:
        return GeneratedResult(case.family, case.stable_json(), verdict, detail)

    root_real = root.resolve()
    escaped = [
        effect.resolved
        for effect in obs.effects
        if effect.resolved
        and not Path(effect.resolved).resolve().is_relative_to(root_real)
    ]
    if escaped:
        return made(Verdict.CRITICAL, f"effect escaped fixture root: {escaped}")
    if outcome.decision == "deny" and obs.any_effect:
        return made(Verdict.CRITICAL, "gateway denied after an undeclared effect")
    if outcome.audit is not None and outcome.audit.count != 1:
        return made(
            Verdict.INDETERMINATE,
            f"generated request joined to {outcome.audit.count} audit events",
        )
    if outcome.reason_code in CLIENT_CODES or outcome.decision == "error":
        return made(
            Verdict.FAIL,
            f"no gateway decision: {outcome.reason_code or outcome.error}",
        )
    return made(Verdict.PASS, f"{outcome.decision}, invariant held")


__all__ = [
    "Family",
    "GeneratedCase",
    "GeneratedReport",
    "GeneratedResult",
    "generate",
    "run_generated",
    "strategies",
]

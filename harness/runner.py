"""Scenario execution and scoring.

The scoring rules are the project's evidence semantics. Two of them matter more than
the rest:

HARN-007: a prohibited side effect is ALWAYS the headline finding, whatever the
gateway claimed. A gateway that says "deny" and performs the operation anyway is the
catastrophic case, and it must never be able to surface as an ordinary failure.

HARN-008: an allow whose expected effect did NOT occur is also a failure — a false
success. `REQ-OUT-005` forbids reporting a non-occurring operation as successful, and
only the oracle can catch it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from harness.clients import TRANSPORT_REJECTED, CallOutcome, Client
from harness.oracle import Observation, Oracle
from harness.scenario import ExpectedEffect, Scenario


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    CRITICAL = "CRITICAL"  # prohibited side effect observed
    FALSE_SUCCESS = "FALSE_SUCCESS"  # allowed, but the effect never happened
    INDETERMINATE = "INDETERMINATE"  # could not correlate; never counted as a pass
    SKIPPED = "SKIPPED"  # platform could not run it (e.g. symlinks)


@dataclass(frozen=True)
class ScenarioResult:
    scenario_id: str
    mode: str
    verdict: Verdict
    detail: str
    claimed_decision: str | None = None
    observed_ops: tuple[str, ...] = ()

    @property
    def is_lying_gateway(self) -> bool:
        """The worst outcome available: claimed a denial, performed the operation."""
        return self.verdict is Verdict.CRITICAL and self.claimed_decision == "deny"


def run(scenario: Scenario, client: Client, oracle: Oracle) -> ScenarioResult:
    oracle.snapshot()
    outcome = client.call(scenario)
    return score(scenario, outcome, oracle.observe(), client.mode)


def score(
    scenario: Scenario, outcome: CallOutcome, obs: Observation, mode: str
) -> ScenarioResult:
    ops = tuple(f"{e.op}:{e.requested}" for e in obs.effects)

    def made(verdict: Verdict, detail: str) -> ScenarioResult:
        return ScenarioResult(scenario.id, mode, verdict, detail, outcome.decision, ops)

    if scenario.expected_side_effect == "none":
        # Checked FIRST and unconditionally. A prohibited effect outranks every other
        # finding, including a wrong reason code — you cannot un-leak a file.
        if obs.any_effect:
            what = ops or ("state changed with no logged operation",)
            return made(
                Verdict.CRITICAL, f"prohibited side effect observed: {list(what)}"
            )
        if obs.attempted_only:
            # The fixture logged an attempt with no completion: it may have crashed
            # mid-operation. Neither "blocked" nor "happened" is provable.
            return made(
                Verdict.INDETERMINATE, "operation attempted, completion unrecorded"
            )
        unjoined = _audit_problem(scenario, outcome)
        if unjoined is not None:
            # HARN-009, and it outranks every remaining check because those all read
            # the gateway's own claim. A decision with no record behind it, or with
            # two, is not evidence of anything.
            return made(*unjoined)
        if scenario.transport is not None and scenario.transport.http_fate == "rejected":
            # A CR or LF inside a header value. h11 refuses the request, so the gateway
            # never runs and there is no reason code to compare — the defence is real
            # and it is one layer below us. Scored against the DECLARED fate, and
            # deliberately not against `expected_reason`: the client reports
            # `TRANSPORT_REJECTED` rather than echoing the code the row expects,
            # because a row that asserts what it just told the client to say asserts
            # nothing. There is no audit event either, which is correct rather than a
            # completeness hole — nothing reached the component that audits.
            if outcome.reason_code == TRANSPORT_REJECTED:
                return made(Verdict.PASS, "refused by the HTTP parser, as declared")
            return made(
                Verdict.FAIL,
                f"declared http_fate=rejected but the request was served: "
                f"{outcome.decision}/{outcome.reason_code}",
            )
        if outcome.decision != scenario.expected_decision:
            return made(
                Verdict.FAIL,
                f"expected {scenario.expected_decision}, got {outcome.decision}"
                + (" (no enforcement in direct mode)" if mode == "direct" else ""),
            )
        if outcome.reason_code != scenario.expected_reason:
            # HARN-003: denying for the wrong reason is a defect, not a pass.
            return made(
                Verdict.FAIL,
                f"expected reason {scenario.expected_reason}, got {outcome.reason_code}",
            )
        return made(Verdict.PASS, "denied, no side effect observed")

    # allow scenario: the effect must be observed to have HAPPENED
    unjoined = _audit_problem(scenario, outcome)
    if unjoined is not None:
        # HARN-009 is not conditional on the verdict being a denial. An allow with no
        # audit event is a side effect this gateway performed and did not record, which
        # is the completeness hole AUDIT-004 exists to measure rather than assume.
        return made(*unjoined)
    if outcome.decision != scenario.expected_decision:
        return made(Verdict.FAIL, f"expected allow, got {outcome.decision}")
    if not _matches(obs, scenario.expected_side_effect):
        return made(
            Verdict.FALSE_SUCCESS,
            f"expected {scenario.expected_side_effect.op} touching "
            f"{scenario.expected_side_effect.path_contains!r}; observed {list(ops)}",
        )
    return made(Verdict.PASS, "allowed, expected effect observed")


def _audit_problem(
    scenario: Scenario, outcome: CallOutcome
) -> tuple[Verdict, str] | None:
    """HARN-009: join the decision to the gateway's own record, or refuse to score it.

    Returns the verdict AND its wording, because the two failures here are not the same
    kind of thing. "There is no record" is INDETERMINATE — the spec's word, and the
    honest one: nothing is proven either way, and it must never land in the security
    rate as a pass. "The record contradicts the reply" is a FAIL, because that is a
    defect the gateway has, not evidence the harness is missing.

    `outcome.audit is None` means the client has no audit source at all — `direct` mode
    authorizes nothing and writes nothing. Those runs are the undefended baseline and
    are not evidence about the gateway, so demanding records from them would report 66
    INDETERMINATE verdicts about a log that was never supposed to exist.
    """
    join = outcome.audit
    if join is None:
        return None

    if scenario.transport is not None and scenario.transport.http_fate == "rejected":
        # h11 refused the request, so the gateway never ran and there is correctly no
        # record. An event here means the declared fate is wrong — a FAIL about the
        # corpus row, not missing evidence.
        if join.count:
            return (
                Verdict.FAIL,
                f"declared http_fate=rejected but the gateway audited "
                f"{join.count} request event(s)",
            )
        return None

    if join.count == 0:
        return (
            Verdict.INDETERMINATE,
            "the gateway answered but wrote no audit event; nothing to correlate",
        )
    if join.count > 1:
        return (
            Verdict.INDETERMINATE,
            f"{join.count} audit request events for one request; "
            "cannot attribute a decision to a record",
        )
    if (
        outcome.reason_code is not None
        and join.reason_code is not None
        and outcome.reason_code != join.reason_code
    ):
        return (
            Verdict.FAIL,
            f"the client was told {outcome.reason_code} and the record says "
            f"{join.reason_code}",
        )
    return None


def _matches(obs: Observation, expected: ExpectedEffect) -> bool:
    return any(
        e.op == expected.op and expected.path_contains in (e.requested + " " + e.resolved)
        for e in obs.effects
    )


# -- aggregate reporting ---------------------------------------------------


@dataclass(frozen=True)
class CorpusReport:
    mode: str
    results: tuple[ScenarioResult, ...]

    def count(self, v: Verdict) -> int:
        return sum(1 for r in self.results if r.verdict is v)

    @property
    def prohibited_effects(self) -> int:
        """HARN-019: reported even when zero. A measured zero is evidence."""
        return self.count(Verdict.CRITICAL)

    @property
    def lying_gateway(self) -> tuple[ScenarioResult, ...]:
        return tuple(r for r in self.results if r.is_lying_gateway)

    def summary(self) -> str:
        counted = [v for v in Verdict if self.count(v)]
        parts = ", ".join(f"{self.count(v)} {v.value}" for v in counted)
        return f"[{self.mode}] {len(self.results)} scenarios: {parts}"


def run_corpus(
    scenarios: tuple[Scenario, ...],
    client: Client,
    oracle: Oracle,
    *,
    reset_between: bool = True,
    root: Path | None = None,
) -> CorpusReport:
    """FIX-009: the tree is reset and VERIFIED between scenarios, not assumed."""
    from fixtures.build_tree import links_available, reset, tree_hash

    results: list[ScenarioResult] = []
    fixture_root = root or oracle.root
    baseline = tree_hash(fixture_root)

    for s in scenarios:
        if s.requires_symlinks and not links_available(fixture_root):
            results.append(
                ScenarioResult(s.id, client.mode, Verdict.SKIPPED, "symlinks unavailable")
            )
            continue
        if s.transport is not None and client.mode == "direct":
            # A scenario carrying a `transport` block IS its wire form — a header
            # disagreeing with the body, a duplicated header, a malformed envelope.
            # `direct` calls the fixture's Python function and never builds a
            # request, so there is nothing to damage. Running it would report a side
            # effect and score CRITICAL, inflating the undefended baseline with
            # damage the scenario never described.
            #
            # Keyed on `transport`, not on `layer == "protocol"`: the legitimate
            # control has no wire damage and MUST still run here. Skipping it was
            # the bug — the control exists precisely so that a gateway which denies
            # everything cannot score 100%, and a control that never runs controls
            # nothing.
            results.append(
                ScenarioResult(
                    s.id, client.mode, Verdict.SKIPPED, "no wire form in direct mode"
                )
            )
            continue
        if s.transport is not None and s.transport.http_fate == "normalized":
            # RFC 9110 strips edge OWS, so the request that ARRIVES is conforming and
            # the gateway allows it — correctly. The row's `expected_side_effect =
            # "none"` describes the guard's answer to a value this transport can never
            # deliver, so scoring it here would either report a legitimate public read
            # as a prohibited effect or require the corpus to carry a second, transport
            # -conditional expectation for one row.
            #
            # SKIPPED, and reported as skipped. The property it exists for — that the
            # value the guard compares is not always the value the client sent — is
            # asserted directly in tests/integration/test_protocol_over_http.py, which
            # counts the `normalized` rows and requires exactly those to pass the guard.
            results.append(
                ScenarioResult(
                    s.id,
                    client.mode,
                    Verdict.SKIPPED,
                    "transport-normalized into a conforming request; scored in "
                    "test_protocol_over_http.py",
                )
            )
            continue
        results.append(run(s, client, oracle))
        if reset_between:
            after = reset(fixture_root)
            if after != baseline:
                raise RuntimeError(f"fixture reset did not restore state after {s.id}")

    return CorpusReport(mode=client.mode, results=tuple(results))

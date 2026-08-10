"""`protected` mode: the corpus driven through real HTTP into a real gateway.

`scripts/run_corpus.py --mode protected` is the broad instrument and it scores all 66
rows. This file is the tripwire that keeps it honest, because a harness can break in
two directions and only one of them is loud:

  * it stops reaching the gateway — every row would go green for the wrong reason,
    and nothing in a green run says so;
  * it stops distinguishing principals — most of the policy matrix would then be
    scored against the wrong grants, silently.

Both are asserted here against observed fixture state rather than against the
gateway's own answer (CONV-018). SKIPPED, never passed, when OPA is absent.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from fixtures.build_tree import build
from harness.clients import protected, write_configs
from harness.oracle import Oracle
from harness.runner import Verdict, run
from harness.scenario import Scenario, load
from scripts.opa_sidecar import find_binary, sidecar

REPO = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.slow,
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


@pytest.fixture(scope="module")
def deployment(tmp_path_factory: pytest.TempPathFactory, opa_url: str) -> Iterator[Path]:
    """Fixture tree plus the environment the children inherit.

    Module-scoped because each principal costs one child process and one MCP
    handshake; a per-test deployment would spend most of the runtime spawning.
    """
    work = tmp_path_factory.mktemp("protected")
    root = work / "fixture"
    build(root)
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(work / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ["FIXTURE_MODE"] = ""
    yield work


def row(scenario_id: str) -> Scenario:
    """A row from the real corpus, by id.

    Deliberately not a scenario constructed here: these tests must fail when the
    published corpus changes meaning, and a hand-built copy would go on passing while
    the shipped row said something else.
    """
    for s in load().scenarios:
        if s.id == scenario_id:
            return s
    raise AssertionError(f"{scenario_id} is not in the corpus")


def test_protected_mode_denies_at_the_fixture_not_just_in_its_answer(
    deployment: Path, opa_url: str
) -> None:
    """One allowed row and one denied row, both scored by the oracle.

    `fs-sensitive-001` is an intern reading `confidential/fake_salaries.csv`. The
    assertion that matters is not the reason code — it is that the fixture's own
    operation log, written by the child process, never mentions the file.
    """
    root = deployment / "fixture"
    configs = write_configs(
        ("intern",),
        source=REPO / "config" / "gateway.toml",
        work=deployment,
        fixture_root=root,
        opa_url=opa_url,
    )
    oracle = Oracle(root)

    with protected(configs) as client:
        allowed = run(row("legit-read-001"), client, oracle)
        denied = run(row("fs-sensitive-001"), client, oracle)

    assert allowed.verdict is Verdict.PASS, allowed.detail
    assert denied.verdict is Verdict.PASS, denied.detail

    oplog = (deployment / "oplog.jsonl").read_text("utf-8")
    assert "documentation.txt" in oplog, "the allowed read never reached the fixture"
    assert "fake_salaries" not in oplog, "the DENIED read reached the fixture"


def test_the_principal_selects_the_gateway(deployment: Path, opa_url: str) -> None:
    """The property the whole `ProtectedClient` design rests on.

    Identity cannot ride on a request — `identity.resolve` never reads one (IDENT-003)
    — so `protected` runs one gateway per principal and picks by `scenario.principal`.
    If that dispatch were dropped, every row would be decided under whichever identity
    happened to be first, and the corpus would report a policy matrix it never tested.
    Breaking it deliberately produced three CRITICAL verdicts, which is what this
    pins: ONE byte-identical request, two principals, two decisions.

    This is also spec-03 test 6 discharged a second time, at the layer a client sees.
    """
    root = deployment / "fixture"
    configs = write_configs(
        ("intern", "auditor"),
        source=REPO / "config" / "gateway.toml",
        work=deployment,
        fixture_root=root,
        opa_url=opa_url,
    )

    confidential = row("fs-sensitive-001")
    assert confidential.principal == "intern", "the corpus row changed under this test"
    as_auditor = confidential.model_copy(update={"principal": "auditor"})

    with protected(configs) as client:
        assert client.principals == ("auditor", "intern")
        denied = client.call(confidential)
        allowed = client.call(as_auditor)

    assert denied.decision == "deny"
    assert denied.reason_code == confidential.expected_reason
    assert allowed.decision == "allow", (
        f"auditor may read confidential/ per grants.rego, but got "
        f"{allowed.reason_code}. If the dispatch is ignoring the principal, both "
        "calls hit one gateway and this is the only test that would notice."
    )


def test_an_unknown_principal_raises_rather_than_scoring_a_denial(
    deployment: Path, opa_url: str
) -> None:
    """A corpus typo must not read as the gateway defending something.

    The tempting implementation returns `deny` for a principal with no gateway, which
    scores PASS on every malicious row naming it — a misspelled principal would then
    make the corpus look MORE defended, not less.

    The exception is caught inside and asserted OUTSIDE the `protected` block on
    purpose. `bridge.upstream` rewrites any non-denial exception escaping its `with`
    into `ROUTE_UPSTREAM_UNAVAILABLE` (fail-closed, and right for production), so a
    `pytest.raises` that failed in there would report the bridge's code instead of
    what actually went wrong. Verified by running this file against a deliberately
    broken dispatch: the message was unreadable before this shape, and exact after.
    """
    root = deployment / "fixture"
    configs = write_configs(
        ("intern",),
        source=REPO / "config" / "gateway.toml",
        work=deployment,
        fixture_root=root,
        opa_url=opa_url,
    )
    typo = row("fs-sensitive-001").model_copy(update={"principal": "intren"})

    caught: BaseException | None = None
    with protected(configs) as client:
        try:
            client.call(typo)
        except KeyError as e:  # noqa: PERF203 - one call, not a loop
            caught = e

    assert isinstance(caught, KeyError) and "intren" in str(caught), (
        f"an unknown principal must raise, not score a denial; got {caught!r}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

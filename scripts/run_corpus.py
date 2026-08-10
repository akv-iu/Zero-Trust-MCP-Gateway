"""Score the corpus by hand and print a report.

    python -m scripts.run_corpus                    # direct mode: unprotected baseline
    python -m scripts.run_corpus --mode protected   # the system under test
    python -m scripts.run_corpus --break-enforcer   # negative control: harness blind?

`direct` establishes the "before" picture; `protected` is the number the project is
actually about. Neither is meaningful without the other, and neither is meaningful
without `--break-enforcer` having been seen to fail on a broken guard.

Protected mode needs a running OPA (`python -m scripts.opa_sidecar`, or the binary on
PATH / in `.tools/` / at `$ZTMG_OPA_BIN`) and starts one gateway per principal — see
`harness.clients.protected` for why identity cannot ride on the request.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Final

from harness.runner import CorpusReport, Verdict

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
B, R, G, Y, D, X = (
    ("\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m")
    if _TTY
    else ("",) * 6
)

COLOUR = {
    "PASS": G,
    "FAIL": Y,
    "CRITICAL": R,
    "FALSE_SUCCESS": Y,
    "INDETERMINATE": Y,
    "SKIPPED": D,
}


UNRESOLVED: Final = (
    Verdict.CRITICAL,
    Verdict.FAIL,
    Verdict.FALSE_SUCCESS,
    Verdict.INDETERMINATE,
)
"""Every verdict that is not a pass and not a skip.

`SKIPPED` is the one exemption, and it is exempt because it is reported as skipped and
counted separately — never folded into a pass.
"""


def protected_exit_code(report: CorpusReport, legitimate_ids: set[str]) -> int:
    """0 only when every scenario resolved and every legitimate row passed.

    Extracted from `main` so it can be tested, because the version buried in `main`
    was wrong in a way that reads as right: it gated on "no prohibited side effects
    and every legitimate row passes", which exits 0 while malicious rows sit at FAIL
    or INDETERMINATE. That is a green run meaning "the gateway denied things, possibly
    for the wrong reasons, possibly with no record that it did".

    Each of the four is a real finding, not a near-miss. A FAIL is a wrong reason code,
    which HARN-003 calls a defect precisely because a decision-only assertion hides it.
    A FALSE_SUCCESS is an operation reported as done that never happened (REQ-OUT-005).
    An INDETERMINATE is a decision that could not be joined to its audit event, which
    HARN-009 says is "never as a pass". A CRITICAL needs no argument.

    Both halves are required. A gateway that denied every request would have zero of
    all four and still be useless, which is why the corpus carries legitimate rows and
    why they are counted separately here.
    """
    if any(report.count(v) for v in UNRESOLVED):
        return 1
    passed = sum(
        1
        for r in report.results
        if r.scenario_id in legitimate_ids and r.verdict is Verdict.PASS
    )
    return 0 if passed == len(legitimate_ids) else 1


class _Unavailable(RuntimeError):
    """A mode this machine cannot run. Reported and exited 2 — never downgraded to a
    different mode, which would print a number for something other than what was
    asked for."""


@contextmanager
def _client(args: Any, work: Path, root: Path, chosen: Any) -> Generator[Any]:
    """The client for the requested mode, and everything it needs, torn down on exit."""
    if args.break_enforcer:
        os.environ["ZTMG_ALLOW_DIRECT"] = "1"
        from tests.unit.test_harness import StubEnforcer  # noqa: PLC0415

        yield StubEnforcer(containment_enabled=False), "BROKEN ENFORCER"
        return

    if args.mode == "direct":
        os.environ["ZTMG_ALLOW_DIRECT"] = "1"
        from harness.clients import DirectClient  # noqa: PLC0415

        yield DirectClient(), "direct (no gateway)"
        return

    # protected. `ZTMG_ALLOW_DIRECT` is deliberately NOT set: HARN-001 requires that
    # direct mode be unreachable from a protected configuration, and the cheapest way
    # to mean it is for the environment that could reach it not to exist here.
    from harness.clients import protected, write_configs  # noqa: PLC0415
    from scripts.opa_sidecar import find_binary, sidecar  # noqa: PLC0415

    if find_binary() is None:
        raise _Unavailable(
            "protected mode needs OPA: put the binary in .tools/, set $ZTMG_OPA_BIN, "
            "or add it to PATH. Refusing to run rather than reporting a partial score."
        )

    principals = tuple(sorted({s.principal for s in chosen}))
    with sidecar() as opa_url:
        configs = write_configs(
            principals,
            source=Path("config/gateway.toml"),
            work=work,
            fixture_root=root,
            opa_url=opa_url,
        )
        with protected(configs) as client:
            yield (
                client,
                f"protected ({len(principals)} gateways: {', '.join(principals)})",
            )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["direct", "protected"], default="direct")
    ap.add_argument(
        "--break-enforcer",
        action="store_true",
        help="negative control: run a deliberately broken enforcer",
    )
    ap.add_argument("--only", default="", help="substring filter on scenario id")
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="ztmg_corpus_"))
    root = work / "fixture"
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(work / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ.pop("FIXTURE_MODE", None)

    from fixtures.build_tree import build, links_available
    from harness import scenario as scen
    from harness.oracle import Oracle
    from harness.runner import run_corpus

    build(root)
    corpus = scen.load()
    chosen = tuple(s for s in corpus.scenarios if args.only in s.id)

    print(f"\n{B}Corpus {corpus.version} - {args.mode}{X}")
    print(f"{D}{len(chosen)} scenarios | symlink traps: {links_available(root)}{X}\n")

    try:
        with _client(args, work, root, chosen) as (client, label):
            print(f"{D}client: {label}{X}\n")
            report = run_corpus(chosen, client, Oracle(root), root=root)
    except _Unavailable as e:
        print(f"{R}{e}{X}")
        shutil.rmtree(work, ignore_errors=True)
        return 2

    for r in report.results:
        c = COLOUR.get(r.verdict.value, "")
        flag = f"  {R}<- GATEWAY LIED{X}" if r.is_lying_gateway else ""
        print(
            f"  {c}{r.verdict.value:<14}{X} {r.scenario_id:<22} "
            f"{D}{r.detail[:72]}{X}{flag}"
        )

    print(f"\n{B}{report.summary()}{X}")
    print(
        f"  prohibited side effects observed : "
        f"{(R if report.prohibited_effects else G)}{report.prohibited_effects}{X}"
    )
    print(
        f"  gateway claimed deny but acted   : "
        f"{(R if report.lying_gateway else G)}{len(report.lying_gateway)}{X}"
    )

    if args.break_enforcer:
        ok = report.prohibited_effects > 0
        verdict = (
            G + "PASS - the harness detected the broken enforcer" + X
            if ok
            else R + "FAIL - THE HARNESS IS BLIND" + X
        )
        print(f"\n{B}Negative control:{X} {verdict}")
        shutil.rmtree(work, ignore_errors=True)
        return 0 if ok else 1

    shutil.rmtree(work, ignore_errors=True)

    if args.mode == "direct":
        print(
            f"\n{D}Baseline established. The gateway must reduce CRITICAL to 0 while "
            f"keeping every legitimate scenario passing.{X}\n"
        )
        return 0 if report.count(Verdict.PASS) == len(corpus.legitimate()) else 1

    legit = {s.id for s in corpus.legitimate()}
    legit_passed = sum(
        1 for r in report.results if r.scenario_id in legit and r.verdict is Verdict.PASS
    )
    unresolved = {v: report.count(v) for v in UNRESOLVED}
    print(f"\n{D}legitimate passing : {legit_passed}/{len(legit)}{X}")
    print(
        f"{D}unresolved         : "
        + ", ".join(f"{n} {v.value}" for v, n in unresolved.items())
        + f"{X}\n"
    )
    if any(unresolved.values()):
        print(f"{R}FAIL - {sum(unresolved.values())} scenario(s) did not resolve.{X}\n")
    return protected_exit_code(report, legit)


if __name__ == "__main__":
    sys.exit(main())

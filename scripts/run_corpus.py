"""Score the corpus by hand and print a report.

    python -m scripts.run_corpus                    # direct mode: unprotected baseline
    python -m scripts.run_corpus --mode protected   # the system under test
    python -m scripts.run_corpus --break-enforcer   # negative control: harness blind?
    python -m scripts.run_corpus --profile full     # every row; required for evidence

`--profile smoke` is the DEFAULT and scores 50 deterministically chosen rows covering
every reason code and every fixture mode. It exists because a full protected run is
the slowest thing in this project and most of it re-proves rows that did not change.
It is a development signal: the banner says so, the artifact records `profile`, and
`harness.report` refuses to build evidence from anything but `full`.

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
import time
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
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
    if args.mode == "direct" and not args.break_enforcer:
        os.environ["ZTMG_ALLOW_DIRECT"] = "1"
        from harness.clients import DirectClient  # noqa: PLC0415

        yield DirectClient(), "direct (no gateway)"
        return

    # protected. `ZTMG_ALLOW_DIRECT` is deliberately NOT set: HARN-001 requires that
    # direct mode be unreachable from a protected configuration, and the cheapest way
    # to mean it is for the environment that could reach it not to exist here.
    from harness.clients import protected, write_deployments  # noqa: PLC0415
    from scripts.opa_sidecar import (  # noqa: PLC0415
        controlled_sidecar,
        find_binary,
        sidecar,
    )

    if find_binary() is None:
        raise _Unavailable(
            "protected mode needs OPA: put the binary in .tools/, set $ZTMG_OPA_BIN, "
            "or add it to PATH. Refusing to run rather than reporting a partial score."
        )

    principals = tuple(sorted({s.principal for s in chosen}))
    with ExitStack() as stack:
        bundle = _broken_policy_bundle(work) if args.break_enforcer else None
        opa_url = stack.enter_context(
            sidecar(bundle=bundle) if bundle is not None else sidecar()
        )
        killed = (
            stack.enter_context(controlled_sidecar())
            if any(s.gateway_fault == "opa_killed" for s in chosen)
            else None
        )
        configs = write_deployments(
            tuple(chosen),
            source=Path("config/gateway.toml"),
            work=work,
            fixture_root=root,
            opa_url=opa_url,
            killed_opa_url=killed.base_url if killed else None,
            on_opa_ready=killed.stop if killed else None,
        )
        with protected(configs) as client:
            yield (
                client,
                f"{'BROKEN REAL POLICY; ' if args.break_enforcer else ''}protected "
                f"({len(configs)} gateways; principals: "
                f"{', '.join(principals)})",
            )


def _broken_policy_bundle(work: Path) -> Path:
    """A real OPA bundle that deliberately allows every policy-stage request."""
    source = Path("policies/rego")
    destination = work / "broken-policy"
    shutil.copytree(source, destination)
    (destination / "gateway" / "decision.rego").write_text(
        """\
package gateway

import rego.v1

decision := {
    "decision": "allow",
    "reason_code": allow_code,
    "risk_tier": input.target.registry_risk_tier,
    "obligations": {"timeout_ms": 3000, "max_response_bytes": 1048576},
}

response(verdict, code) := {
    "decision": verdict,
    "reason_code": code,
    "risk_tier": input.target.registry_risk_tier,
    "obligations": {"timeout_ms": 3000, "max_response_bytes": 1048576},
}

is_discovery if input.target.tool_name == null

allow_code := "POLICY_METADATA_READ" if input.target.registry_risk_tier == "R0"
allow_code := "POLICY_SCOPED_READ" if {
    input.target.registry_risk_tier != "R0"
    input.arguments.operation == "read"
}
allow_code := "POLICY_SCOPED_WRITE" if {
    input.target.registry_risk_tier != "R0"
    input.arguments.operation != "read"
}
""",
        encoding="utf-8",
        newline="\n",
    )
    return destination


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["direct", "protected"], default="direct")
    ap.add_argument(
        "--break-enforcer",
        action="store_true",
        help="negative control: run a deliberately broken enforcer",
    )
    ap.add_argument(
        "--profile",
        choices=["smoke", "full"],
        default="smoke",
        help=(
            "smoke (default): the deterministic 50-row development lane. "
            "full: every row — required for any published number"
        ),
    )
    ap.add_argument("--only", default="", help="substring filter on scenario id")
    ap.add_argument("--out", type=Path, help="write scored oracle results as JSON")
    ap.add_argument(
        "--evidence-dir",
        type=Path,
        help="keep audit/oplog/config evidence here (directory must be empty)",
    )
    args = ap.parse_args(argv)

    keep_evidence = args.evidence_dir is not None
    if keep_evidence:
        work = args.evidence_dir
        if work.exists() and any(work.iterdir()):
            ap.error(f"--evidence-dir must be empty: {work}")
        work.mkdir(parents=True, exist_ok=True)
    else:
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
    pool = corpus.scenarios if args.profile == "full" else scen.smoke(corpus.scenarios)
    chosen = tuple(s for s in pool if args.only in s.id)
    if not chosen:
        # Zero scenarios resolve to zero failures, and every exit-code path below then
        # returns 0. A green run that scored nothing is the worst possible output, and
        # `--only` against the default smoke subset makes it easy to reach by accident:
        # a row that exists in the corpus but is not among the 50 matches nothing here.
        in_corpus = sum(1 for s in corpus.scenarios if args.only in s.id)
        hint = (
            f" — {in_corpus} row(s) match in the full corpus; add --profile full"
            if in_corpus
            else ""
        )
        ap.error(f"no scenarios matched --only {args.only!r} in {args.profile}{hint}")

    mode_label = "protected negative control" if args.break_enforcer else args.mode
    print(f"\n{B}Corpus {corpus.version} - {mode_label}{X}")
    print(f"{D}{len(chosen)} scenarios | symlink traps: {links_available(root)}{X}")
    if args.profile != "full":
        # Loud, and before the numbers rather than after them. A subset score read as
        # a corpus score is the one way this lane can do damage.
        print(
            f"{Y}{B}SMOKE PROFILE — {len(chosen)} of {len(corpus.scenarios)} rows.{X}"
            f"{Y} Development signal only; not evidence. Use --profile full for any "
            f"number that leaves this terminal.{X}"
        )
    print()

    started = time.perf_counter()
    try:
        with _client(args, work, root, chosen) as (client, label):
            booted = time.perf_counter()
            print(f"{D}client: {label}{X}")
            print(f"{D}deployments ready in {booted - started:.1f}s{X}\n")
            report = run_corpus(
                chosen, client, Oracle(root), root=root, profile=args.profile
            )
            scored = time.perf_counter()
    except _Unavailable as e:
        print(f"{R}{e}{X}")
        if not keep_evidence:
            shutil.rmtree(work, ignore_errors=True)
        return 2

    if args.out is not None:
        report.write(args.out, corpus_version=corpus.version)

    for r in report.results:
        c = COLOUR.get(r.verdict.value, "")
        flag = f"  {R}<- GATEWAY LIED{X}" if r.is_lying_gateway else ""
        print(
            f"  {c}{r.verdict.value:<14}{X} {r.scenario_id:<22} "
            f"{D}{r.detail[:72]}{X}{flag}"
        )

    print(f"\n{B}{report.summary()}{X}")
    # Split, because the two halves have different fixes: boot time comes down by
    # needing fewer deployment variants, scoring time by needing fewer rows. A single
    # wall-clock number would send you to optimise whichever one you guessed.
    print(
        f"{D}  boot {booted - started:.1f}s | scored {scored - booted:.1f}s "
        f"({(scored - booted) / max(len(chosen), 1):.1f}s per row){X}"
    )
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
        if not keep_evidence:
            shutil.rmtree(work, ignore_errors=True)
        return 0 if ok else 1

    if keep_evidence:
        print(f"\n{D}evidence kept at: {work}{X}")
    else:
        shutil.rmtree(work, ignore_errors=True)

    if args.mode == "direct":
        print(
            f"\n{D}Baseline established. The gateway must reduce CRITICAL to 0 while "
            f"keeping every legitimate scenario passing.{X}\n"
        )
        chosen_legitimate = sum(s.kind == "legitimate" for s in chosen)
        return 0 if report.count(Verdict.PASS) == chosen_legitimate else 1

    legit = {s.id for s in chosen if s.kind == "legitimate"}
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

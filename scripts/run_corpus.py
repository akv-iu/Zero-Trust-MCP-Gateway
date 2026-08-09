"""Score the corpus by hand and print a report.

    python -m scripts.run_corpus                 # direct mode (the unprotected baseline)
    python -m scripts.run_corpus --break-enforcer  # negative control: prove the harness works

`--protected` arrives with unit 01. Until then `direct` is the point: it establishes
the "before" picture the gateway must later reduce to zero.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
B, R, G, Y, D, X = (
    ("\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m")
    if _TTY
    else ("",) * 6
)

COLOUR = {"PASS": G, "FAIL": Y, "CRITICAL": R, "FALSE_SUCCESS": Y,
          "INDETERMINATE": Y, "SKIPPED": D}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["direct", "protected"], default="direct")
    ap.add_argument("--break-enforcer", action="store_true",
                    help="negative control: run a deliberately broken enforcer")
    ap.add_argument("--only", default="", help="substring filter on scenario id")
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="ztmg_corpus_"))
    root = work / "fixture"
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(work / "oplog.jsonl")
    os.environ["ZTMG_ALLOW_DIRECT"] = "1"
    os.environ.pop("FIXTURE_MODE", None)

    from fixtures.build_tree import build, links_available
    from harness import scenario as scen
    from harness.clients import DirectClient
    from harness.oracle import Oracle
    from harness.runner import Verdict, run_corpus

    build(root)
    corpus = scen.load()
    chosen = tuple(s for s in corpus.scenarios if args.only in s.id)

    if args.mode == "protected":
        print(f"{R}protected mode needs unit 01 (transport edge); not built yet.{X}")
        return 2

    if args.break_enforcer:
        from tests.unit.test_harness import _StubEnforcer  # noqa: PLC0415

        client, label = _StubEnforcer(containment_enabled=False), "BROKEN ENFORCER"
    else:
        client, label = DirectClient(), "direct (no gateway)"

    print(f"\n{B}Corpus {corpus.version} - {label}{X}")
    print(f"{D}{len(chosen)} scenarios | symlink traps: {links_available(root)}{X}\n")

    report = run_corpus(chosen, client, Oracle(root), root=root)

    for r in report.results:
        c = COLOUR.get(r.verdict.value, "")
        flag = f"  {R}<- GATEWAY LIED{X}" if r.is_lying_gateway else ""
        print(f"  {c}{r.verdict.value:<14}{X} {r.scenario_id:<22} {D}{r.detail[:72]}{X}{flag}")

    print(f"\n{B}{report.summary()}{X}")
    print(f"  prohibited side effects observed : "
          f"{(R if report.prohibited_effects else G)}{report.prohibited_effects}{X}")
    print(f"  gateway claimed deny but acted   : "
          f"{(R if report.lying_gateway else G)}{len(report.lying_gateway)}{X}")

    if args.break_enforcer:
        ok = report.prohibited_effects > 0
        print(f"\n{B}Negative control:{X} "
              f"{(G + 'PASS - the harness detected the broken enforcer' + X) if ok else (R + 'FAIL - THE HARNESS IS BLIND' + X)}")
        shutil.rmtree(work, ignore_errors=True)
        return 0 if ok else 1

    print(f"\n{D}Baseline established. The gateway must reduce CRITICAL to 0 while "
          f"keeping every legitimate scenario passing.{X}\n")
    shutil.rmtree(work, ignore_errors=True)
    return 0 if report.count(Verdict.PASS) == len(corpus.legitimate()) else 1


if __name__ == "__main__":
    sys.exit(main())

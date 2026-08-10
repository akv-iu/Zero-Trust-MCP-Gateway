"""Run seeded Hypothesis-generated cases through the real protected socket path."""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from fixtures.build_tree import build
from harness.clients import protected, write_configs
from harness.generated import generate, run_generated
from harness.oracle import Oracle
from harness.runner import Verdict
from scripts.opa_sidecar import find_binary, sidecar

PROFILE_COUNTS = {"dev": 50, "ci": 500, "release": 5_000}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--profile", choices=PROFILE_COUNTS, default="dev")
    parser.add_argument("--examples", type=int, help="override examples per family")
    parser.add_argument("--out", type=Path, default=Path("var/generated.json"))
    args = parser.parse_args(argv)
    if find_binary() is None:
        parser.error("OPA is required (set ZTMG_OPA_BIN or put it in .tools/)")
    count = args.examples or PROFILE_COUNTS[args.profile]
    if count < 1:
        parser.error("--examples must be positive")

    work = Path(tempfile.mkdtemp(prefix="ztmg_generated_"))
    root = work / "fixture"
    build(root)
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(work / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ.pop("FIXTURE_MODE", None)

    try:
        cases = generate(args.seed, count)
        with sidecar() as opa_url:
            configs = write_configs(
                ("intern",),
                source=Path("config/gateway.toml"),
                work=work,
                fixture_root=root,
                opa_url=opa_url,
            )
            with protected(configs) as client:
                report = run_generated(
                    cases,
                    client,
                    Oracle(root),
                    root=root,
                    recorded_seed=args.seed,
                )
        report.write(args.out)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    counts = ", ".join(f"{verdict.value}={report.count(verdict)}" for verdict in Verdict)
    print(f"generated={len(report.results)} seed={args.seed}: {counts}")
    print(f"wrote {args.out}")
    unresolved = sum(
        report.count(verdict)
        for verdict in (
            Verdict.CRITICAL,
            Verdict.FAIL,
            Verdict.FALSE_SUCCESS,
            Verdict.INDETERMINATE,
        )
    )
    return 1 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())

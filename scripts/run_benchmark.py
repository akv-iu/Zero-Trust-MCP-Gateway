"""Run the paired benchmark and write its JSON artifact.

    python -m scripts.run_benchmark --out var/bench.json

The command performs the required single-concurrency run and a separately labelled
modest-concurrency run.  It has no latency threshold and exits non-zero only when the
scripted legitimate request stops succeeding or the method cannot be completed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import tempfile
from pathlib import Path

from fixtures.build_tree import build
from harness.benchmark import (
    BenchmarkArtifact,
    BenchmarkRun,
    collect_pairs,
    direct_stdio,
    stages_from_audits,
    summarize,
)
from harness.clients import ALLOW_DIRECT_ENV, protected, write_configs
from harness.scenario import Scenario, load
from scripts.opa_sidecar import find_binary, sidecar


def _scenario(scenario_id: str) -> Scenario:
    for scenario in load().scenarios:
        if scenario.id == scenario_id:
            if scenario.expected_decision != "allow" or scenario.fixture_mode:
                raise ValueError("benchmark scenario must be an ordinary allowed row")
            return scenario.model_copy(update={"layer": "performance"})
    raise ValueError(f"unknown scenario id: {scenario_id}")


def _run(
    label: str,
    n: int,
    concurrency: int,
    scenario: Scenario,
    *,
    work: Path,
    root: Path,
    opa_url: str,
) -> BenchmarkRun:
    work.mkdir(parents=True, exist_ok=True)
    configs = write_configs(
        (scenario.principal,),
        source=Path("config/gateway.toml"),
        work=work,
        fixture_root=root,
        opa_url=opa_url,
        max_concurrent=concurrency,
    )
    config_path = configs[scenario.principal]
    with (
        direct_stdio(config_path) as direct,
        protected(configs, performance=concurrency > 1) as protected_client,
    ):
        samples = collect_pairs(
            n,
            scenario,
            direct,
            protected_client,
            concurrency=concurrency,
        )
        audit_paths = protected_client.audit_paths
        audit_timings = protected_client.audit_latency_by_request_id
    stages = stages_from_audits(audit_paths, audit_timings)
    return summarize(
        label,
        samples,
        concurrency=concurrency,
        aggregate_stages=stages,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("var/bench.json"))
    parser.add_argument("--n", type=int, default=1_000, help="pairs per run (>=1000)")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--scenario", default="legit-read-001")
    args = parser.parse_args(argv)
    if args.n < 1_000:
        parser.error("HARN-017 requires --n >= 1000")
    if args.concurrency < 2:
        parser.error("the second run must use modest concurrency >= 2")
    if find_binary() is None:
        parser.error("OPA is required (set ZTMG_OPA_BIN or put it in .tools/)")

    work = Path(tempfile.mkdtemp(prefix="ztmg_benchmark_"))
    root = work / "fixture"
    build(root)
    old_direct = os.environ.get(ALLOW_DIRECT_ENV)
    os.environ[ALLOW_DIRECT_ENV] = "1"
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(work / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ.pop("FIXTURE_MODE", None)

    try:
        scenario = _scenario(args.scenario)
        with sidecar() as opa_url:
            single = _run(
                "single-concurrency",
                args.n,
                1,
                scenario,
                work=work / "single",
                root=root,
                opa_url=opa_url,
            )
            modest = _run(
                "modest-concurrency",
                args.n,
                args.concurrency,
                scenario,
                work=work / "modest",
                root=root,
                opa_url=opa_url,
            )
        artifact = BenchmarkArtifact((single, modest))
        artifact.write(args.out)
    finally:
        if old_direct is None:
            os.environ.pop(ALLOW_DIRECT_ENV, None)
        else:
            os.environ[ALLOW_DIRECT_ENV] = old_direct
        shutil.rmtree(work, ignore_errors=True)

    for run in artifact.runs:
        overhead = run.added_overhead_ms
        print(
            f"{run.label}: n={overhead.n}, concurrency={run.concurrency}, "
            f"overhead p50={overhead.p50:.3f} ms p95={overhead.p95:.3f} ms "
            f"p99={overhead.p99:.3f} ms min={overhead.minimum:.3f} ms "
            f"max={overhead.maximum:.3f} ms"
        )
        if run.unavailable_stages:
            print(f"  unavailable audit stages: {', '.join(run.unavailable_stages)}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Strict, boring Markdown report generator for Unit 11.

Reads persisted corpus/oracle results, raw audit JSONL, generated-case results, and
the paired benchmark.  Validation happens before the output path is touched: mixed
audit schemas, incomplete metadata, stale corpus artifacts, or undersized benchmark
runs refuse to produce a document.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from fixtures.filesystem_server.isolation import detect_tier
from gateway.config import load as load_config
from harness.clients import TRANSPORT_REJECTED
from harness.provenance import source_fingerprint
from harness.scenario import Corpus, ExpectedEffect, Scenario, load
from scripts.opa_sidecar import find_binary, version_of

REPRODUCIBILITY_FIELDS = (
    "commit_sha",
    "source_fingerprint",
    "policy_revision",
    "corpus_version",
    "audit_schema_version",
    "hypothesis_seed",
    "os",
    "cpu",
    "ram_bytes",
    "python_version",
    "opa_version",
    "fixture_isolation",
    "timestamp",
)


class ReportError(ValueError):
    """The supplied evidence cannot support a report."""


def render_report(
    *,
    corpus: Corpus,
    run: dict[str, Any],
    generated: dict[str, Any],
    benchmark: dict[str, Any],
    audit_records: list[dict[str, Any]],
    oplog_records: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> str:
    versions = {record.get("schema_version") for record in audit_records}
    if len(versions) != 1 or None in versions:
        shown = sorted(str(version) for version in versions)
        raise ReportError(f"mixed or missing audit schema versions: {shown}")
    _require_metadata(metadata)
    if metadata["audit_schema_version"] != next(iter(versions)):
        raise ReportError("metadata audit schema version disagrees with audit JSONL")
    if run.get("corpus_version") != corpus.version:
        raise ReportError("run artifact corpus version differs from scenario files")
    if run.get("mode") != "protected":
        raise ReportError("report requires a protected corpus run artifact")
    # `full` is required, and a MISSING profile is refused rather than assumed full:
    # artifacts written before the smoke lane existed are indistinguishable from a
    # subset here, and defaulting the unknown to the permissive answer is how a
    # 50-row score would end up published as the corpus result.
    if run.get("profile") != "full":
        raise ReportError(
            f"report requires a full corpus run; artifact profile is "
            f"{run.get('profile')!r}. Re-run with `--profile full`."
        )
    if metadata["corpus_version"] != corpus.version:
        raise ReportError("metadata corpus version differs from scenario files")
    if generated.get("seed") != metadata["hypothesis_seed"]:
        raise ReportError("generated artifact seed differs from report metadata")
    for label, artifact in (
        ("corpus", run),
        ("generated", generated),
        ("benchmark", benchmark),
    ):
        if artifact.get("source_fingerprint") != metadata["source_fingerprint"]:
            raise ReportError(f"{label} artifact was produced by a different source tree")

    results = _objects(run.get("results"), "run results")
    verdicts = {"PASS", "FAIL", "CRITICAL", "FALSE_SUCCESS", "INDETERMINATE", "SKIPPED"}
    if any(result.get("verdict") not in verdicts for result in results):
        raise ReportError("run results contain a missing or unknown verdict")
    if any(not isinstance(result.get("audit_expected"), bool) for result in results):
        raise ReportError("run results contain a non-boolean audit_expected value")
    expected_ids = {scenario.id for scenario in corpus.scenarios}
    result_id_list = [str(result.get("scenario_id")) for result in results]
    result_ids = set(result_id_list)
    if len(result_ids) != len(result_id_list):
        raise ReportError("duplicate scenario_id in run results")
    if result_ids != expected_ids:
        missing = sorted(expected_ids - result_ids)
        extra = sorted(result_ids - expected_ids)
        raise ReportError(
            f"run/corpus scenario mismatch: missing={missing}, extra={extra}"
        )
    runs = _benchmark_runs(benchmark)
    generated_results = _objects(generated.get("results"), "generated results")

    scenarios = {scenario.id: scenario for scenario in corpus.scenarios}
    _validate_oracle_evidence(results, scenarios, oplog_records)
    attempted = [result for result in results if result.get("verdict") != "SKIPPED"]
    malicious = [
        result
        for result in attempted
        if scenarios[str(result["scenario_id"])].kind == "malicious"
    ]
    legitimate = [
        result
        for result in attempted
        if scenarios[str(result["scenario_id"])].kind == "legitimate"
    ]
    blocked = sum(result.get("verdict") == "PASS" for result in malicious)
    allowed = sum(result.get("verdict") == "PASS" for result in legitimate)
    prohibited = sum(result.get("verdict") == "CRITICAL" for result in results)
    indeterminate = sum(result.get("verdict") == "INDETERMINATE" for result in results)
    skipped = sum(result.get("verdict") == "SKIPPED" for result in results)
    false_positive = (len(legitimate) - allowed) / len(legitimate) if legitimate else 0.0
    enforcement = blocked / len(malicious) if malicious else 0.0

    request_events = [
        record for record in audit_records if record.get("event_type") == "request"
    ]
    request_ids = [str(record.get("request_id")) for record in request_events]
    if len(request_ids) != len(set(request_ids)):
        raise ReportError("duplicate request_id in audit evidence")
    audit_by_id = {str(record.get("request_id")): record for record in request_events}
    expected_request_ids: set[str] = set()
    for result in attempted:
        scenario = scenarios[str(result["scenario_id"])]
        audit_expected = not (
            scenario.transport is not None and scenario.transport.http_fate == "rejected"
        )
        if result.get("audit_expected") is not audit_expected:
            raise ReportError(
                f"{scenario.id}: audit_expected disagrees with corpus transport semantics"
            )
        if audit_expected:
            expected_request_ids.add(str(result.get("request_id")))
    if "None" in expected_request_ids:
        raise ReportError("auditable result is missing request_id")
    actual_request_ids = set(request_ids)
    if actual_request_ids != expected_request_ids:
        missing = sorted(expected_request_ids - actual_request_ids)
        extra = sorted(actual_request_ids - expected_request_ids)
        raise ReportError(
            f"run/audit request_id mismatch: missing={missing}, extra={extra}"
        )
    _validate_pass_claims(attempted, scenarios, audit_by_id)
    auditable = len(expected_request_ids)
    completeness = 1.0

    generated_failures = sum(
        result.get("verdict") != "PASS" for result in generated_results
    )
    claim = (
        f"Across {len(malicious)} malicious scenarios in corpus version "
        f"{corpus.version}, the side-effect oracle observed "
        f"{prohibited} prohibited state changes or disclosures at the protected "
        "system."
    )

    lines = [
        "# Zero-Trust MCP Gateway benchmark report",
        "",
        "## Scoped security claim",
        "",
        claim,
        "",
        "## Security measurements",
        "",
        "| Measure | Observed |",
        "|---|---:|",
        f"| Malicious scenarios attempted | {len(malicious)} |",
        f"| Malicious scenarios blocked with expected evidence | {blocked} |",
        f"| Prohibited side effects observed | {prohibited} |",
        f"| Security enforcement rate (corpus {corpus.version}) | {enforcement:.2%} |",
        f"| CRITICAL outcomes | {prohibited} |",
        f"| Indeterminate outcomes | {indeterminate} |",
        f"| Skipped hand-written scenarios | {skipped} |",
        "",
        "## False-positive measurement",
        "",
        f"Legitimate scenarios allowed: {allowed}/{len(legitimate)}. "
        f"Observed false-positive rate: **{false_positive:.2%}**.",
        "",
        "## Written and generated cases",
        "",
        f"Hand-written cases: **{len(results)}**. Hypothesis-generated cases: "
        f"**{len(generated_results)}**, with **{generated_failures}** non-pass outcomes. "
        "Generated cases are not blended into the hand-written count.",
        "",
        "## Paired overhead",
        "",
        "Client, gateway, policy engine, fixture, and load generator ran on the same "
        "machine. These are co-located development measurements, not capacity claims.",
        "",
    ]
    for bench_run in runs:
        lines.extend(_performance_table(bench_run))

    lines.extend(
        [
            "## Audit completeness",
            "",
            f"Request events written / auditable requests issued: "
            f"**{len(request_events)}/{auditable} ({completeness:.2%})**.",
            "",
            "## Reproducibility environment",
            "",
            "| Field | Value |",
            "|---|---|",
        ]
    )
    for key in REPRODUCIBILITY_FIELDS:
        lines.append(f"| {key.replace('_', ' ')} | {metadata[key]} |")
    lines.extend(
        [
            f"| case sensitive filesystem | {metadata['case_sensitive']} |",
            f"| durable audit writes | {metadata['audit_durable']} |",
            "",
            "## Limitations",
            "",
            "- Filesystem canonicalization is defense in depth; this project does "
            "not claim TOCTOU safety.",
            f"- Fixture isolation for this run was `{metadata['fixture_isolation']}`; "
            "weak isolation is not a container boundary.",
            f"- {skipped} hand-written row(s) were skipped and are not counted as "
            "passes; Windows commonly lacks the symlink traps without Developer Mode.",
            "- The client edge is loopback Streamable HTTP and the single upstream "
            "leg is stdio; this is not a multi-upstream or remote deployment result.",
            "- The loopback edge authenticates no caller and uses locally configured, "
            "unverified identity (ADR-001 D-1 status).",
        ]
    )
    unavailable = sorted(
        {
            stage
            for bench_run in runs
            for stage in cast("list[str]", bench_run.get("unavailable_stages", []))
        }
    )
    if unavailable:
        lines.append(
            "- The following requested internal stages were not present in the audit "
            f"events and are reported as unavailable, not zero: {', '.join(unavailable)}."
        )
    lines.extend(
        [
            "",
            "## External contributions",
            "",
            "No externally contributed failing case was recorded in this run. Additions "
            "retain their scenario id and fix history when one is received.",
            "",
        ]
    )
    return "\n".join(lines)


def collect_metadata(
    *,
    corpus_version: str,
    audit_schema_version: int,
    hypothesis_seed: int,
    policy_revision: str,
) -> dict[str, Any]:
    binary = find_binary()
    if binary is None:
        raise ReportError("OPA version unavailable")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
    )
    return {
        "commit_sha": f"{commit}{' (working tree dirty)' if dirty else ''}",
        "source_fingerprint": source_fingerprint(),
        "policy_revision": policy_revision,
        "corpus_version": corpus_version,
        "audit_schema_version": audit_schema_version,
        "hypothesis_seed": hypothesis_seed,
        "os": platform.platform(),
        "cpu": platform.processor() or platform.machine(),
        "ram_bytes": _ram_bytes(),
        "python_version": sys.version.replace("\n", " "),
        "opa_version": version_of(binary),
        "fixture_isolation": detect_tier(),
        "timestamp": datetime.now(UTC).isoformat(),
        "case_sensitive": _case_sensitive(),
        "audit_durable": load_config("config/gateway.toml").audit.durable,
    }


def _benchmark_runs(benchmark: dict[str, Any]) -> list[dict[str, Any]]:
    runs = _objects(benchmark.get("runs"), "benchmark runs")
    if not any(run.get("concurrency") == 1 for run in runs):
        raise ReportError("benchmark has no single-concurrency run")
    if not any(cast("int", run.get("concurrency", 0)) > 1 for run in runs):
        raise ReportError("benchmark has no modest-concurrency run")
    if any(cast("int", run.get("pairs_requested", 0)) < 1_000 for run in runs):
        raise ReportError("benchmark contains fewer than 1,000 paired samples")
    for run in runs:
        pairs = cast("int", run["pairs_requested"])
        warmup = cast("int", run.get("warmup_discarded", -1))
        if warmup != int(pairs * 0.10):
            raise ReportError("benchmark warm-up count is not 10% of paired samples")
        order = cast("list[Any]", run.get("sample_order"))
        expected_order = [
            "direct-protected" if index % 2 == 0 else "protected-direct"
            for index in range(pairs)
        ]
        if order != expected_order:
            raise ReportError("benchmark sample order is not alternating by pair")
        kept = pairs - warmup
        distributions = [
            cast("dict[str, Any]", run.get(name, {}))
            for name in ("direct_ms", "protected_ms", "added_overhead_ms")
        ]
        distributions.extend(
            cast("dict[str, Any]", value)
            for value in cast("dict[str, Any]", run.get("stages_ms", {})).values()
        )
        if any(dist.get("n") != kept for dist in distributions):
            raise ReportError("benchmark distribution count disagrees with warm-up")
    return runs


def _validate_oracle_evidence(
    results: list[dict[str, Any]],
    scenarios: dict[str, Scenario],
    oplog_records: list[dict[str, Any]],
) -> None:
    raw: dict[str, str] = {}
    for record in oplog_records:
        if record.get("phase") != "end" or record.get("outcome") != "ok":
            continue
        try:
            key = f"{int(record['pid'])}:{int(record['seq'])}"
            operation = f"{record['op']}:{record['requested']}"
        except (KeyError, TypeError, ValueError) as error:
            raise ReportError(
                "successful op-log record lacks evidence identity"
            ) from error
        if key in raw:
            raise ReportError(f"duplicate successful op-log evidence key: {key}")
        raw[key] = operation

    reported: list[str] = []
    for result in results:
        scenario_id = str(result.get("scenario_id"))
        if scenario_id not in scenarios:
            continue
        operations = _string_list(
            result.get("observed_ops"), f"{scenario_id}: observed_ops"
        )
        evidence = _string_list(
            result.get("observed_evidence"), f"{scenario_id}: observed_evidence"
        )
        _string_list(result.get("incomplete_ops"), f"{scenario_id}: incomplete_ops")
        if not isinstance(result.get("tree_changed"), bool):
            raise ReportError(f"{scenario_id}: tree_changed must be boolean")
        if len(operations) != len(evidence):
            raise ReportError(f"{scenario_id}: operations do not match evidence keys")
        for key, operation in zip(evidence, operations, strict=True):
            if raw.get(key) != operation:
                raise ReportError(
                    f"{scenario_id}: op-log evidence {key!r} does not support "
                    f"{operation!r}"
                )
        reported.extend(evidence)

    if Counter(reported) != Counter(raw.keys()):
        raise ReportError(
            "run observations do not cover the successful raw op-log evidence"
        )


def _validate_pass_claims(
    results: list[dict[str, Any]],
    scenarios: dict[str, Scenario],
    audit_by_id: dict[str, dict[str, Any]],
) -> None:
    for result in results:
        scenario = scenarios[str(result["scenario_id"])]
        operations = cast("list[str]", result["observed_ops"])
        tree_changed = cast("bool", result["tree_changed"])
        incomplete = cast("list[str]", result["incomplete_ops"])
        unexpected = _unexpected_effect(scenario, operations, tree_changed)
        if unexpected != (result.get("verdict") == "CRITICAL"):
            raise ReportError(
                f"{scenario.id}: persisted verdict disagrees with oracle observations"
            )

        if result.get("audit_expected"):
            audit = audit_by_id.get(str(result.get("request_id")))
            if audit is None:
                continue  # the exact set check reports the more useful mismatch
            if audit.get("reason_code") != result.get("reason_code"):
                raise ReportError(
                    f"{scenario.id}: result reason disagrees with raw audit event"
                )

        if result.get("verdict") != "PASS":
            continue
        if result.get("claimed_decision") != scenario.expected_decision:
            raise ReportError(f"{scenario.id}: PASS carries the wrong decision")
        expected_reason = (
            TRANSPORT_REJECTED
            if scenario.transport is not None
            and scenario.transport.http_fate == "rejected"
            else scenario.expected_reason
        )
        if result.get("reason_code") != expected_reason:
            raise ReportError(f"{scenario.id}: PASS carries the wrong reason code")
        if incomplete:
            raise ReportError(f"{scenario.id}: PASS carries an incomplete operation")
        if scenario.expected_side_effect == "none":
            if operations or tree_changed:
                raise ReportError(f"{scenario.id}: PASS carries a prohibited effect")
            continue
        if len(operations) != 1 or not _operation_matches(
            operations[0], scenario.expected_side_effect
        ):
            raise ReportError(f"{scenario.id}: PASS lacks its one declared effect")


def _unexpected_effect(
    scenario: Scenario, operations: list[str], tree_changed: bool
) -> bool:
    expected = scenario.expected_side_effect
    if expected == "none":
        return bool(operations) or tree_changed
    unexpected_state = tree_changed and (
        not operations or expected.op in {"read", "list", "stat"}
    )
    return (
        unexpected_state
        or bool(operations)
        and (len(operations) != 1 or not _operation_matches(operations[0], expected))
    )


def _operation_matches(operation: str, expected: ExpectedEffect) -> bool:
    op, separator, path = operation.partition(":")
    return bool(separator) and op == expected.op and expected.path_contains in path


def _performance_table(run: dict[str, Any]) -> list[str]:
    label = str(run.get("label"))
    rows = [
        f"### {label} (concurrency {run.get('concurrency')})",
        "",
        "| Distribution (ms) | n | p50 | p95 | p99 | min | max |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ("direct_ms", "protected_ms", "added_overhead_ms"):
        dist = cast("dict[str, Any]", run[name])
        rows.append(_distribution_row(name, dist))
    for name, value in cast("dict[str, dict[str, Any]]", run["stages_ms"]).items():
        rows.append(_distribution_row(f"stage: {name}", value))
    for stage in cast("list[str]", run.get("unavailable_stages", [])):
        rows.append(f"| stage: {stage} | unavailable | — | — | — | — | — |")
    rows.append("")
    return rows


def _distribution_row(name: str, dist: dict[str, Any]) -> str:
    return (
        f"| {name} | {dist['n']} | {dist['p50']:.3f} | {dist['p95']:.3f} | "
        f"{dist['p99']:.3f} | {dist['minimum']:.3f} | {dist['maximum']:.3f} |"
    )


def _require_metadata(metadata: dict[str, Any]) -> None:
    missing = [key for key in REPRODUCIBILITY_FIELDS if metadata.get(key) in (None, "")]
    if missing:
        raise ReportError(f"missing reproducibility metadata: {missing}")
    for extra in ("case_sensitive", "audit_durable"):
        if extra not in metadata:
            raise ReportError(f"missing reproducibility metadata: {extra}")


def _objects(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ReportError(f"{label} must be a JSON array of objects")
    items = cast("list[Any]", value)
    if not all(isinstance(item, dict) for item in items):
        raise ReportError(f"{label} must be a JSON array of objects")
    return cast("list[dict[str, Any]]", items)


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ReportError(f"{label} must be a string array")
    items = cast("list[Any]", value)
    if not all(isinstance(item, str) for item in items):
        raise ReportError(f"{label} must be a string array")
    return cast("list[str]", items)


def _ram_bytes() -> int:
    if os.name != "nt":
        try:
            return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
        except (AttributeError, OSError, ValueError):
            pass

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_ulong),
            ("memory_load", ctypes.c_ulong),
            ("total_physical", ctypes.c_ulonglong),
            ("available_physical", ctypes.c_ulonglong),
            ("total_page_file", ctypes.c_ulonglong),
            ("available_page_file", ctypes.c_ulonglong),
            ("total_virtual", ctypes.c_ulonglong),
            ("available_virtual", ctypes.c_ulonglong),
            ("available_extended_virtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # type: ignore[attr-defined]
        raise ReportError("cannot determine total RAM")
    return int(status.total_physical)


def _case_sensitive() -> bool:
    with tempfile.TemporaryDirectory(prefix="ztmg_case_probe_") as directory:
        root = Path(directory)
        (root / "Probe").write_text("x", encoding="utf-8")
        return not (root / "probe").exists()


def _json(path: Path) -> dict[str, Any]:
    value: Any = json.loads(path.read_text("utf-8"))
    if not isinstance(value, dict):
        raise ReportError(f"{path} must contain a JSON object")
    return cast("dict[str, Any]", value)


def _jsonl(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value: Any = json.loads(line)
            if not isinstance(value, dict):
                raise ReportError(f"{path}:{line_number} is not a JSON object")
            records.append(cast("dict[str, Any]", value))
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, nargs="+", required=True)
    parser.add_argument("--oplog", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, default=Path("harness/scenarios"))
    parser.add_argument("--bench", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--hypothesis-seed", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    # Parse the raw operation log too.  Verdicts come from the persisted oracle
    # windows, but a missing/corrupt fixture evidence stream still invalidates them.
    oplog = _jsonl([args.oplog])
    audit = _jsonl(args.audit)
    versions = {record.get("schema_version") for record in audit}
    if len(versions) != 1 or None in versions:
        shown = sorted(str(version) for version in versions)
        raise ReportError(f"mixed or missing audit schema versions: {shown}")
    revisions = {
        str(record["policy_revision"])
        for record in audit
        if record.get("event_type") == "request" and record.get("policy_revision")
    }
    if len(revisions) != 1:
        raise ReportError(f"expected one policy revision, found {sorted(revisions)}")

    corpus = load(args.corpus)
    metadata = collect_metadata(
        corpus_version=corpus.version,
        audit_schema_version=cast("int", next(iter(versions))),
        hypothesis_seed=args.hypothesis_seed,
        policy_revision=next(iter(revisions)),
    )
    markdown = render_report(
        corpus=corpus,
        run=_json(args.results),
        generated=_json(args.generated),
        benchmark=_json(args.bench),
        audit_records=audit,
        oplog_records=oplog,
        metadata=metadata,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

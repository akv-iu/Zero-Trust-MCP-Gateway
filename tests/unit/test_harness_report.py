"""HARN-019 through HARN-022 and report refusal acceptance tests."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from harness.report import ReportError, render_report
from harness.scenario import Corpus, Scenario


def _distribution() -> dict[str, Any]:
    return {
        "n": 900,
        "p50": 1.0,
        "p95": 2.0,
        "p99": 3.0,
        "minimum": -0.2,
        "maximum": 5.0,
    }


def _benchmark() -> dict[str, Any]:
    def run(label: str, concurrency: int) -> dict[str, Any]:
        order = [
            "direct-protected" if index % 2 == 0 else "protected-direct"
            for index in range(1000)
        ]
        return {
            "label": label,
            "concurrency": concurrency,
            "pairs_requested": 1000,
            "warmup_discarded": 100,
            "direct_ms": _distribution(),
            "protected_ms": _distribution(),
            "added_overhead_ms": _distribution(),
            "stages_ms": {
                "protocol+canonicalization": _distribution(),
                "policy": _distribution(),
                "upstream": _distribution(),
                "audit": _distribution(),
            },
            "unavailable_stages": [],
            "sample_order": order,
        }

    return {"runs": [run("single", 1), run("modest", 4)]}


def _inputs() -> dict[str, Any]:
    malicious = Scenario.model_validate(
        {
            "id": "malicious-denial",
            "class": "malicious",
            "layer": "security",
            "principal": "intern",
            "tool": "read_file",
            "arguments": {"path": "confidential/fake_salaries.csv"},
            "expected_decision": "deny",
            "expected_reason": "POLICY_PATH_NOT_PERMITTED",
            "expected_side_effect": "none",
            "risk_tier": "R1",
            "notes": "report fixture",
        }
    )
    legitimate = Scenario.model_validate(
        {
            "id": "legitimate-read",
            "class": "legitimate",
            "layer": "security",
            "principal": "intern",
            "tool": "read_file",
            "arguments": {"path": "public/documentation.txt"},
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {
                "op": "read",
                "path_contains": "public/documentation.txt",
            },
            "risk_tier": "R1",
            "notes": "report fixture",
        }
    )
    corpus = Corpus(version="test-1", scenarios=(malicious, legitimate))
    results = [
        {
            "scenario_id": malicious.id,
            "verdict": "PASS",
            "claimed_decision": "deny",
            "reason_code": "POLICY_PATH_NOT_PERMITTED",
            "request_id": "request-malicious",
            "audit_expected": True,
            "observed_ops": [],
            "observed_evidence": [],
            "tree_changed": False,
            "incomplete_ops": [],
        },
        {
            "scenario_id": legitimate.id,
            "verdict": "PASS",
            "claimed_decision": "allow",
            "reason_code": "POLICY_SCOPED_READ",
            "request_id": "request-legitimate",
            "audit_expected": True,
            "observed_ops": ["read:public/documentation.txt"],
            "observed_evidence": ["7:1"],
            "tree_changed": False,
            "incomplete_ops": [],
        },
    ]
    return {
        "corpus": corpus,
        "run": {
            "source_fingerprint": "source-test",
            "corpus_version": corpus.version,
            "mode": "protected",
            "profile": "full",
            "results": results,
        },
        "generated": {
            "source_fingerprint": "source-test",
            "seed": 17,
            "results": [],
        },
        "benchmark": {**_benchmark(), "source_fingerprint": "source-test"},
        "audit_records": [
            {"schema_version": 3, "event_type": "lifecycle", "kind": "ready"},
            {
                "schema_version": 3,
                "event_type": "request",
                "request_id": "request-malicious",
                "reason_code": "POLICY_PATH_NOT_PERMITTED",
            },
            {
                "schema_version": 3,
                "event_type": "request",
                "request_id": "request-legitimate",
                "reason_code": "POLICY_SCOPED_READ",
            },
        ],
        "oplog_records": [
            {
                "phase": "end",
                "outcome": "ok",
                "pid": 7,
                "seq": 1,
                "op": "read",
                "requested": "public/documentation.txt",
            }
        ],
        "metadata": {
            "commit_sha": "abc",
            "source_fingerprint": "source-test",
            "policy_revision": "rev",
            "corpus_version": corpus.version,
            "audit_schema_version": 3,
            "hypothesis_seed": 17,
            "os": "test-os",
            "cpu": "test-cpu",
            "ram_bytes": 1,
            "python_version": "3.13",
            "opa_version": "1.19.0",
            "fixture_isolation": "weak",
            "timestamp": "2026-08-10T00:00:00+00:00",
            "case_sensitive": False,
            "audit_durable": True,
        },
    }


def test_report_refuses_mixed_audit_schema_versions() -> None:
    inputs = _inputs()
    inputs["audit_records"].append(
        {"schema_version": 4, "event_type": "lifecycle", "kind": "ready"}
    )
    with pytest.raises(ReportError, match="mixed or missing audit schema"):
        render_report(**inputs)


def test_report_refuses_incomplete_reproducibility_metadata() -> None:
    inputs = _inputs()
    del inputs["metadata"]["cpu"]
    with pytest.raises(ReportError, match="missing reproducibility metadata"):
        render_report(**inputs)


def test_report_leads_with_scoped_claim_and_keeps_negative_numbers() -> None:
    report = render_report(**_inputs())
    assert report.index("Scoped security claim") < report.index("Paired overhead")
    assert "-0.200" in report
    assert "Indeterminate outcomes" in report
    assert "co-located development measurements" in report


def test_forbidden_unscoped_claim_is_absent_from_docs() -> None:
    phrase = "zero " + "authorization bypasses"
    found = [
        str(path)
        for path in Path("docs").rglob("*")
        if path.is_file() and phrase in path.read_text("utf-8", errors="ignore").lower()
    ]
    assert not found, found


def test_report_refuses_a_stale_corpus_artifact() -> None:
    inputs = deepcopy(_inputs())
    inputs["run"]["results"].pop()
    with pytest.raises(ReportError, match="run/corpus scenario mismatch"):
        render_report(**inputs)


def test_report_refuses_a_direct_baseline_artifact() -> None:
    inputs = _inputs()
    inputs["run"]["mode"] = "direct"
    with pytest.raises(ReportError, match="requires a protected corpus run"):
        render_report(**inputs)


@pytest.mark.parametrize("profile", ["smoke", None], ids=["smoke", "absent"])
def test_report_refuses_a_run_that_did_not_score_the_whole_corpus(
    profile: str | None,
) -> None:
    """`run_corpus` defaults to a 50-row subset, so this is the likely artifact.

    Both parameters matter and the second is the one that would have been missed. A
    `smoke` artifact is refused because it says what it is. An artifact with NO
    profile is refused because it does not: run artifacts written before the smoke
    lane existed are byte-indistinguishable from a subset here, and treating the
    unknown as `full` is precisely how a 50-row score reaches a published table.
    """
    inputs = deepcopy(_inputs())
    if profile is None:
        del inputs["run"]["profile"]
    else:
        inputs["run"]["profile"] = profile
    with pytest.raises(ReportError, match="requires a full corpus run"):
        render_report(**inputs)


def test_report_refuses_an_unknown_verdict() -> None:
    inputs = _inputs()
    inputs["run"]["results"][0]["verdict"] = "MOSTLY_FINE"
    with pytest.raises(ReportError, match="unknown verdict"):
        render_report(**inputs)


def test_report_refuses_evidence_from_a_different_source_tree() -> None:
    inputs = _inputs()
    inputs["benchmark"]["source_fingerprint"] = "other-source"
    with pytest.raises(ReportError, match="different source tree"):
        render_report(**inputs)


def test_report_derives_audit_expectation_from_the_corpus() -> None:
    inputs = _inputs()
    inputs["run"]["results"][0]["audit_expected"] = False
    with pytest.raises(ReportError, match="audit_expected disagrees"):
        render_report(**inputs)


def test_report_refuses_oracle_results_that_omit_raw_successful_operations() -> None:
    inputs = _inputs()
    inputs["run"]["results"][1]["observed_ops"] = []
    inputs["run"]["results"][1]["observed_evidence"] = []
    with pytest.raises(ReportError, match="do not cover the successful raw op-log"):
        render_report(**inputs)


def test_report_refuses_a_pass_that_hides_an_extra_operation() -> None:
    inputs = _inputs()
    result = inputs["run"]["results"][1]
    result["observed_ops"].append("read:confidential/fake_salaries.csv")
    result["observed_evidence"].append("7:2")
    inputs["oplog_records"].append(
        {
            "phase": "end",
            "outcome": "ok",
            "pid": 7,
            "seq": 2,
            "op": "read",
            "requested": "confidential/fake_salaries.csv",
        }
    )
    with pytest.raises(ReportError, match="verdict disagrees with oracle"):
        render_report(**inputs)


def test_report_refuses_equal_count_audit_evidence_for_other_requests() -> None:
    inputs = _inputs()
    first = inputs["run"]["results"][0]
    first["request_id"] = "expected-request"
    with pytest.raises(ReportError, match="run/audit request_id mismatch"):
        render_report(**inputs)


def test_report_refuses_non_alternating_benchmark_evidence() -> None:
    inputs = _inputs()
    inputs["benchmark"]["runs"][0]["sample_order"][1] = "direct-protected"
    with pytest.raises(ReportError, match="sample order is not alternating"):
        render_report(**inputs)

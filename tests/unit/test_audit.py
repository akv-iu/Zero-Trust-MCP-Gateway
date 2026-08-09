"""Unit 09 acceptance tests.

The audit log is the evidence. Every number in the final report reads out of it, so
these tests are as much about what must NEVER appear in a record as about what must.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from gateway.audit import (
    AuditBuilder,
    AuditSink,
    CorruptAuditLog,
    completeness,
    read_events,
)
from gateway.audit_schema import LifecycleEvent, RequestEvent
from gateway.errors import (
    AuditFailure,
    CanonicalizationDenial,
    PolicyDenial,
    ProgrammingError,
    ReasonCode,
    RouteDenial,
    Stage,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def sink(tmp_path: Path) -> AuditSink:
    s = AuditSink(tmp_path / "audit.jsonl")
    s.open()
    return s


def _lines(sink: AuditSink) -> list[dict]:
    return [json.loads(ln) for ln in sink.path.read_text("utf-8").splitlines() if ln.strip()]


# ===========================================================================
# Exactly one event, always (AUDIT-001)
# ===========================================================================


async def test_one_event_per_request(sink: AuditSink) -> None:
    b = AuditBuilder("r1")
    b.set(mcp_method="tools/call", tool_name="read_file")
    b.set_outcome("allowed")
    await b.finalize_and_write(sink)
    assert len(_lines(sink)) == 1


async def test_double_write_is_a_programming_error(sink: AuditSink) -> None:
    """Two events for one request corrupts the completeness ratio silently."""
    b = AuditBuilder("r1")
    b.set_outcome("allowed")
    await b.finalize_and_write(sink)
    with pytest.raises(ProgrammingError, match="already written"):
        await b.finalize_and_write(sink)


async def test_early_rejection_still_produces_a_complete_event(sink: AuditSink) -> None:
    """A stage-2 denial has no tool name. The record must still be valid, not truncated."""
    b = AuditBuilder("r1")
    b.record_denial(CanonicalizationDenial(ReasonCode.PROTO_HEADER_BODY_METHOD_MISMATCH))
    await b.finalize_and_write(sink)
    ev = _lines(sink)[0]
    assert ev["outcome"] == "denied"
    assert ev["tool_name"] is None
    assert RequestEvent.model_validate(ev)


async def test_write_survives_cancellation(tmp_path: Path) -> None:
    """THE SUBTLE ONE.

    Without shielding, an `await` inside a cancelled scope raises immediately, the
    event is never written, and the completeness ratio drops below 1.0 in a way that
    reads as a measurement artifact instead of the bug it is.
    """
    s = AuditSink(tmp_path / "a.jsonl")
    s.open()
    b = AuditBuilder("cancelled-req")
    b.record_cancellation()

    # No shield here on purpose: the test must rely on the one INSIDE
    # finalize_and_write. Wrapping it here would make the test self-fulfilling —
    # it would pass with the production shield removed.
    with anyio.CancelScope() as scope:
        scope.cancel()
        await b.finalize_and_write(s)

    assert scope.cancel_called
    events = _lines(s)
    assert len(events) == 1, "the event was lost to cancellation - shield is missing"
    assert events[0]["outcome"] == "cancelled"


# ===========================================================================
# Outcomes are distinguished (AUDIT-002)
# ===========================================================================


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (ReasonCode.CANON_OUTSIDE_ROOT, "denied"),
        (ReasonCode.ROUTE_CANCELLED, "cancelled"),
        (ReasonCode.ROUTE_TIMEOUT, "timeout"),
        (ReasonCode.POLICY_TIMEOUT, "timeout"),
        (ReasonCode.POLICY_UNAVAILABLE, "error"),
        (ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE, "error"),
    ],
)
async def test_outcomes_are_not_collapsed(
    sink: AuditSink, code: ReasonCode, expected: str
) -> None:
    b = AuditBuilder("r1")
    b.record_denial(RouteDenial(code))
    await b.finalize_and_write(sink)
    assert _lines(sink)[0]["outcome"] == expected


async def test_internal_error_denies_never_allows(sink: AuditSink) -> None:
    b = AuditBuilder("r1")
    b.record_internal_error(ValueError("boom"))
    await b.finalize_and_write(sink)
    ev = _lines(sink)[0]
    assert ev["decision"] == "deny"
    assert ev["reason_code"] == "INTERNAL_ERROR"


# ===========================================================================
# Minimisation (AUDIT-005 .. 007)
# ===========================================================================


def test_unknown_field_is_refused_at_the_call_site() -> None:
    """AUDIT-007: minimisation is structural, not a regex over a blob."""
    b = AuditBuilder("r1")
    with pytest.raises(ProgrammingError, match="unknown audit fields"):
        b.set(prompt="the entire user prompt")
    with pytest.raises(ProgrammingError):
        b.set(bearer_token="secret")


async def test_denial_detail_never_reaches_the_record(sink: AuditSink) -> None:
    """`detail` carries diagnostic context — including paths. It must stay out."""
    b = AuditBuilder("r1")
    b.record_denial(
        CanonicalizationDenial(ReasonCode.CANON_OUTSIDE_ROOT, detail="/etc/shadow")
    )
    await b.finalize_and_write(sink)
    assert "/etc/shadow" not in sink.path.read_text("utf-8")


async def test_fixture_canaries_never_appear_in_a_record(sink: AuditSink) -> None:
    from fixtures.manifest import CANARIES

    b = AuditBuilder("r1")
    b.set(canonical_resource="/fixture/public/doc.txt", arg_hash="sha256:abc")
    b.set_outcome("allowed")
    await b.finalize_and_write(sink)
    text = sink.path.read_text("utf-8")
    for canary in CANARIES:
        assert canary not in text


# ===========================================================================
# Log injection (AUDIT-014)
# ===========================================================================


async def test_forged_record_cannot_be_injected(sink: AuditSink) -> None:
    """The difference between "we JSON-encode" and "we proved it cannot happen"."""
    forged = 'x\n{"event_type":"request","outcome":"allowed","request_id":"fake"}\n'
    b = AuditBuilder("r1")
    b.set(canonical_resource=forged)
    b.set_outcome("denied")
    await b.finalize_and_write(sink)

    raw = sink.path.read_text("utf-8")
    assert len(raw.strip().splitlines()) == 1
    assert "fake" not in [json.loads(raw)["request_id"]]
    assert "\\n" in raw  # the newline was escaped, not emitted


# ===========================================================================
# Failure behaviour (AUDIT-009, AUDIT-010)
# ===========================================================================


async def test_unwritable_sink_raises_audit_failure(tmp_path: Path) -> None:
    """The chaos case: the protected operation must be DENIED, not silently unlogged."""
    p = tmp_path / "audit.jsonl"
    s = AuditSink(p)
    s.open()
    s.close()
    p.chmod(stat.S_IREAD)
    s._fh = None  # force reopen against the read-only file

    b = AuditBuilder("r1")
    b.set_outcome("allowed")
    try:
        with pytest.raises((AuditFailure, PermissionError, OSError)):
            await b.finalize_and_write(s)
    finally:
        p.chmod(stat.S_IWRITE | stat.S_IREAD)


def test_readiness_probe_reports_writability(sink: AuditSink) -> None:
    assert sink.readiness_probe() is True
    events = _lines(sink)
    assert events[-1]["event_type"] == "lifecycle" and events[-1]["kind"] == "ready"


# ===========================================================================
# Timing (feeds the benchmark)
# ===========================================================================


async def test_stage_latencies_are_recorded_and_consistent(sink: AuditSink) -> None:
    b = AuditBuilder("r1")
    for st in (Stage.PROTOCOL, Stage.POLICY, Stage.ROUTE):
        with b.stage(st):
            pass
    b.set_outcome("allowed")
    await b.finalize_and_write(sink)

    ev = _lines(sink)[0]
    assert set(ev["stage_latency_ms"]) == {"protocol", "policy", "route"}
    assert sum(ev["stage_latency_ms"].values()) <= ev["total_latency_ms"] + 1e-6


# ===========================================================================
# Reader / retention / schema
# ===========================================================================


async def test_reader_round_trips(sink: AuditSink) -> None:
    b = AuditBuilder("r1")
    b.set(tool_name="read_file", decision="deny", reason_code="CANON_OUTSIDE_ROOT")
    b.set_outcome("denied")
    await b.finalize_and_write(sink)
    events = list(read_events(sink.path))
    assert len(events) == 1
    assert events[0].request_id == "r1"


def test_reader_refuses_a_corrupt_line(sink: AuditSink) -> None:
    """A corrupt line fails the report rather than being skipped."""
    sink.path.write_text('{"event_type":"request","bogus":1}\n', encoding="utf-8")
    with pytest.raises(CorruptAuditLog):
        list(read_events(sink.path))


def test_discriminated_union_handles_all_three_kinds(sink: AuditSink) -> None:
    sink.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="startup"))
    from gateway.audit_schema import DriftEvent

    sink.write_sync(
        DriftEvent(
            ts=datetime.now(UTC),
            server_id="filesystem-fixture",
            tool_name="read_file",
            reason_code="REG_SCHEMA_DRIFT",
        )
    )
    kinds = [e.event_type for e in read_events(sink.path)]
    assert kinds == ["lifecycle", "drift"]


async def test_completeness_is_measured(sink: AuditSink) -> None:
    for i in range(5):
        b = AuditBuilder(f"r{i}")
        b.set_outcome("allowed")
        await b.finalize_and_write(sink)
    assert completeness(sink.path, 5) == 1.0
    assert completeness(sink.path, 10) == 0.5  # measured, not asserted


def test_rotation_preserves_history(tmp_path: Path) -> None:
    s = AuditSink(tmp_path / "a.jsonl", max_bytes=200, rotate_keep=3)
    s.open()
    for i in range(20):
        s.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="startup", detail={"n": str(i)}))
    assert (tmp_path / "a.jsonl.1").exists()
    assert list(read_events(tmp_path / "a.jsonl.1"))


def test_records_are_newline_delimited_on_every_platform(sink: AuditSink) -> None:
    """Explicit newline="\\n": without it Windows writes \\r\\n and byte comparisons diverge."""
    sink.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="startup"))
    assert b"\r\n" not in sink.path.read_bytes()


def test_schema_version_is_stamped(sink: AuditSink) -> None:
    sink.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="startup"))
    assert _lines(sink)[0]["schema_version"] == 1


async def test_null_fields_are_present_not_omitted(sink: AuditSink) -> None:
    """Present-and-null, consistently, so downstream `jq` sees a stable shape."""
    b = AuditBuilder("r1")
    b.set_outcome("denied")
    await b.finalize_and_write(sink)
    ev = _lines(sink)[0]
    assert "tool_name" in ev and ev["tool_name"] is None

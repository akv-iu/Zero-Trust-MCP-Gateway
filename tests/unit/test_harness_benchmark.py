"""The benchmark's method is tested; its latency is deliberately never gated."""

from __future__ import annotations

from typing import Any

import pytest

from harness.benchmark import collect_pairs, summarize
from harness.clients import AuditJoin, CallOutcome, _TimedAuditSink
from harness.scenario import load


class RecordingClient:
    mode = "direct"

    def __init__(
        self,
        label: str,
        order: list[str],
        *,
        audited: bool = False,
        decision: str = "allow",
    ) -> None:
        self.label = label
        self.order = order
        self.audited = audited
        self.decision = decision

    def call(self, scenario: Any) -> CallOutcome:
        self.order.append(self.label)
        audit = (
            AuditJoin(
                1,
                request_id=f"r-{len(self.order)}",
                stage_latency_ms={
                    "protocol": 1.0,
                    "canonical": 2.0,
                    "policy": 3.0,
                    "audit": 0.5,
                },
                upstream_latency_ms=4.0,
            )
            if self.audited
            else None
        )
        return CallOutcome(self.decision, audit=audit)

    def call_unjoined(self, scenario: Any) -> CallOutcome:
        return self.call(scenario)


def test_pairs_alternate_the_order_inside_one_run() -> None:
    order: list[str] = []
    direct = RecordingClient("direct", order)
    protected = RecordingClient("protected", order, audited=True)
    scenario = load().legitimate()[0].model_copy(update={"layer": "performance"})

    samples = collect_pairs(4, scenario, direct, protected)  # type: ignore[arg-type]

    assert order == [
        "direct",
        "protected",
        "protected",
        "direct",
        "direct",
        "protected",
        "protected",
        "direct",
    ]
    assert [sample.order for sample in samples] == [
        "direct-protected",
        "protected-direct",
        "direct-protected",
        "protected-direct",
    ]


def test_summary_discards_ten_percent_and_has_no_threshold() -> None:
    order: list[str] = []
    direct = RecordingClient("direct", order)
    protected = RecordingClient("protected", order, audited=True)
    samples = collect_pairs(20, load().legitimate()[0], direct, protected)  # type: ignore[arg-type]
    run = summarize("test", samples, concurrency=1, require_release_size=False)
    assert run.warmup_discarded == 2
    assert run.added_overhead_ms.n == 18
    assert set(run.stages_ms) == {
        "protocol+canonicalization",
        "policy",
        "upstream",
        "audit",
    }


def test_a_direct_failure_aborts_instead_of_becoming_a_fast_baseline() -> None:
    order: list[str] = []
    direct = RecordingClient("direct", order, decision="error")
    protected = RecordingClient("protected", order, audited=True)
    scenario = load().legitimate()[0].model_copy(update={"layer": "performance"})

    with pytest.raises(RuntimeError, match="benchmark direct scenario"):
        collect_pairs(1, scenario, direct, protected)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_timed_sink_sums_write_ahead_and_terminal_audit_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Sink:
        async def write(self, event: Any) -> None:
            return None

    class Event:
        request_id = "request-1"

    ticks = iter((0, 2_000_000, 3_000_000, 7_000_000))
    monkeypatch.setattr("harness.clients.time.perf_counter_ns", lambda: next(ticks))
    timings: dict[str, float] = {}
    sink = _TimedAuditSink(Sink(), timings)

    await sink.write(Event())
    await sink.write(Event())

    assert timings == {"request-1": 6.0}

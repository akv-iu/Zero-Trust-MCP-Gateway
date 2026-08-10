"""Paired direct-vs-protected measurement (HARN-014 through HARN-018).

This is reporting code, never a pytest latency gate.  Tests assert ordering and math;
the real command enforces N >= 1,000 and publishes whatever values are observed.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Generator, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from functools import partial
from pathlib import Path
from statistics import quantiles
from typing import Any, Literal

from anyio.from_thread import BlockingPortal, start_blocking_portal

from gateway import bridge, startup
from gateway.audit import read_events
from harness.clients import ALLOW_DIRECT_ENV, CallOutcome, Client, ProtectedClient
from harness.provenance import source_fingerprint
from harness.scenario import Scenario

COLOCATION_CAVEAT = (
    "Client, gateway, policy engine, fixture, and load generator ran on the same "
    "machine. These are co-located development measurements, not capacity claims."
)


@dataclass(frozen=True)
class PairSample:
    order: Literal["direct-protected", "protected-direct"]
    direct_ns: int
    protected_ns: int
    stage_latency_ms: dict[str, float] | None = None
    upstream_latency_ms: float | None = None


@dataclass(frozen=True)
class Distribution:
    n: int
    p50: float
    p95: float
    p99: float
    minimum: float
    maximum: float


@dataclass(frozen=True)
class BenchmarkRun:
    label: str
    concurrency: int
    pairs_requested: int
    warmup_discarded: int
    direct_ms: Distribution
    protected_ms: Distribution
    added_overhead_ms: Distribution
    stages_ms: dict[str, Distribution]
    unavailable_stages: tuple[str, ...]
    sample_order: tuple[str, ...]
    caveat: str = COLOCATION_CAVEAT


@dataclass(frozen=True)
class BenchmarkArtifact:
    runs: tuple[BenchmarkRun, ...]
    source_fingerprint: str = field(default_factory=source_fingerprint)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")


class StdioDirectClient:
    """Real MCP stdio baseline; unlike the damage-demo client, no Python shortcut."""

    mode = "direct"

    def __init__(self, portal: BlockingPortal, upstream: bridge.UpstreamHandle) -> None:
        if os.environ.get(ALLOW_DIRECT_ENV) != "1":
            raise RuntimeError(f"direct benchmark requires {ALLOW_DIRECT_ENV}=1")
        self._portal = portal
        self._upstream = upstream

    def call(self, scenario: Scenario) -> CallOutcome:
        try:
            result = self._portal.call(
                partial(
                    self._upstream.call_tool,
                    scenario.tool,
                    dict(scenario.arguments),
                )
            )
            return CallOutcome("allow", result=result)
        except Exception as error:  # noqa: BLE001 - benchmark records the real failure
            return CallOutcome("error", error=f"{type(error).__name__}: {error}")


@contextmanager
def direct_stdio(config_path: Path) -> Generator[StdioDirectClient]:
    """Start the same approved child as the gateway, but with no gateway in front."""
    cfg, registry = startup.load_all(config_path)
    child = registry.server.child_config(cfg.child)
    old_mode = os.environ.get("FIXTURE_MODE")
    os.environ["FIXTURE_MODE"] = ""
    try:
        with (
            start_blocking_portal() as portal,
            portal.wrap_async_context_manager(bridge.upstream(child)) as upstream,
        ):
            yield StdioDirectClient(portal, upstream)
    finally:
        if old_mode is None:
            os.environ.pop("FIXTURE_MODE", None)
        else:
            os.environ["FIXTURE_MODE"] = old_mode


def collect_pairs(
    n: int,
    scenario: Scenario,
    direct: Client,
    protected: ProtectedClient,
    *,
    concurrency: int = 1,
) -> tuple[PairSample, ...]:
    """Alternate order inside each pair; optionally schedule pairs concurrently."""
    if n < 1 or concurrency < 1:
        raise ValueError("n and concurrency must be positive")

    def one(index: int) -> PairSample:
        if index % 2 == 0:
            direct_ns, direct_outcome = _timed(direct.call, scenario)
            protected_ns, outcome = _timed(
                protected.call if concurrency == 1 else protected.call_unjoined,
                scenario,
            )
            order: Literal["direct-protected", "protected-direct"] = "direct-protected"
        else:
            protected_ns, outcome = _timed(
                protected.call if concurrency == 1 else protected.call_unjoined,
                scenario,
            )
            direct_ns, direct_outcome = _timed(direct.call, scenario)
            order = "protected-direct"
        for label, observed in (("direct", direct_outcome), ("protected", outcome)):
            if observed.decision != "allow":
                raise RuntimeError(
                    f"benchmark {label} scenario {scenario.id} did not succeed: "
                    f"{observed.reason_code or observed.error}"
                )
        audit = outcome.audit
        return PairSample(
            order,
            direct_ns,
            protected_ns,
            audit.stage_latency_ms if audit else None,
            audit.upstream_latency_ms if audit else None,
        )

    if concurrency == 1:
        return tuple(one(index) for index in range(n))
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        return tuple(pool.map(one, range(n)))


def summarize(
    label: str,
    samples: tuple[PairSample, ...],
    *,
    concurrency: int,
    aggregate_stages: dict[str, list[float]] | None = None,
    require_release_size: bool = True,
) -> BenchmarkRun:
    if require_release_size and len(samples) < 1_000:
        raise ValueError("HARN-017 requires at least 1,000 paired samples")
    warmup = int(len(samples) * 0.10)
    kept = samples[warmup:]
    direct = [sample.direct_ns / 1_000_000 for sample in kept]
    protected = [sample.protected_ns / 1_000_000 for sample in kept]
    overhead = [p - d for d, p in zip(direct, protected, strict=True)]

    stage_values = aggregate_stages or _sample_stages(kept)
    stage_stats: dict[str, Distribution] = {}
    for stage, values in stage_values.items():
        selected = values[warmup:] if aggregate_stages else values
        if selected:
            stage_stats[stage] = _distribution(selected)
    required = {"protocol+canonicalization", "policy", "upstream", "audit"}
    return BenchmarkRun(
        label=label,
        concurrency=concurrency,
        pairs_requested=len(samples),
        warmup_discarded=warmup,
        direct_ms=_distribution(direct),
        protected_ms=_distribution(protected),
        added_overhead_ms=_distribution(overhead),
        stages_ms=stage_stats,
        unavailable_stages=tuple(sorted(required - stage_stats.keys())),
        sample_order=tuple(sample.order for sample in samples),
    )


def stages_from_audits(
    paths: tuple[Path, ...], audit_timings: Mapping[str, float] | None = None
) -> dict[str, list[float]]:
    rows: list[tuple[str, str, dict[str, float], float | None]] = []
    for path in paths:
        for event in read_events(path):
            if event.event_type == "request" and event.outcome == "allowed":
                rows.append(
                    (
                        event.ts_start.isoformat(),
                        event.request_id,
                        dict(event.stage_latency_ms),
                        event.upstream_latency_ms,
                    )
                )
    rows.sort(key=lambda row: row[0])
    values: dict[str, list[float]] = {}
    for _, request_id, stages, upstream in rows:
        _append_stages(values, stages, upstream)
        if audit_timings is not None and request_id in audit_timings:
            values.setdefault("audit", []).append(audit_timings[request_id])
    return values


def _sample_stages(samples: tuple[PairSample, ...]) -> dict[str, list[float]]:
    values: dict[str, list[float]] = {}
    for sample in samples:
        _append_stages(values, sample.stage_latency_ms or {}, sample.upstream_latency_ms)
    return values


def _append_stages(
    values: dict[str, list[float]],
    stages: dict[str, float],
    upstream: float | None,
) -> None:
    if "protocol" in stages and "canonical" in stages:
        values.setdefault("protocol+canonicalization", []).append(
            stages["protocol"] + stages["canonical"]
        )
    if "policy" in stages:
        values.setdefault("policy", []).append(stages["policy"])
    if upstream is not None:
        values.setdefault("upstream", []).append(upstream)
    if "audit" in stages:
        values.setdefault("audit", []).append(stages["audit"])


def _timed(call: Any, scenario: Scenario) -> tuple[int, CallOutcome]:
    started = time.perf_counter_ns()
    outcome = call(scenario)
    return time.perf_counter_ns() - started, outcome


def _distribution(values: list[float]) -> Distribution:
    if not values:
        raise ValueError("cannot summarize an empty distribution")
    if len(values) == 1:
        p50 = p95 = p99 = values[0]
    else:
        percentiles = quantiles(values, n=100, method="inclusive")
        p50, p95, p99 = percentiles[49], percentiles[94], percentiles[98]
    return Distribution(len(values), p50, p95, p99, min(values), max(values))


__all__ = [
    "BenchmarkArtifact",
    "BenchmarkRun",
    "COLOCATION_CAVEAT",
    "Distribution",
    "PairSample",
    "StdioDirectClient",
    "collect_pairs",
    "direct_stdio",
    "stages_from_audits",
    "summarize",
]

"""Per-stage timing. `perf_counter_ns` only — never wall clock for durations.

The benchmark's entire stage breakdown reads out of this (`HARN-016`).

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager

from gateway.errors import Stage


class StageTimer:
    """Accumulates per-stage nanoseconds. Composed by the audit builder (unit 09)."""

    __slots__ = ("_ns", "_started_ns")

    def __init__(self) -> None:
        self._ns: dict[str, int] = {}
        self._started_ns = time.perf_counter_ns()

    @contextmanager
    def stage(self, name: Stage | str) -> Generator[None]:
        key = name.value if isinstance(name, Stage) else name
        t0 = time.perf_counter_ns()
        try:
            yield
        finally:
            # += so a stage entered twice accumulates rather than silently overwriting.
            self._ns[key] = self._ns.get(key, 0) + (time.perf_counter_ns() - t0)

    @property
    def elapsed_ns(self) -> int:
        return time.perf_counter_ns() - self._started_ns

    def as_ms(self) -> dict[str, float]:
        return {k: v / 1_000_000 for k, v in self._ns.items()}

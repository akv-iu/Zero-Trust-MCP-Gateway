"""09 - JSONL audit events. The project's evidence artifact.

Spec: _specs/09-svc-audit-log.md   Tech: _tech/09-svc-audit-log.md
Owner: wave 1, agent B.

The schema lives in `gateway/audit_schema.py` (wave-0 spine). This module owns the
builder and the sink. Agent B implements every `NotImplementedError` below without
changing a signature.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Iterator

from gateway.audit_schema import AuditRecord, Outcome, RequestEvent
from gateway.config import Config
from gateway.errors import GatewayDenial, ProgrammingError, Stage
from gateway.timing import StageTimer


class AuditBuilder:
    """Mutable per-request accumulator that validates into a frozen event.

    AUDIT-007: `set()` rejects any key absent from RequestEvent, so a sensitive field
    cannot be written by accident — only by editing the schema, which is reviewable.
    """

    __slots__ = ("request_id", "_fields", "_timer", "_ts_start", "_sealed")

    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        self._fields: dict[str, object] = {}
        self._timer = StageTimer()
        self._ts_start = datetime.now(UTC)
        self._sealed = False

    def set(self, **kw: object) -> None:
        unknown = kw.keys() - RequestEvent.model_fields.keys()
        if unknown:
            raise ProgrammingError(f"unknown audit fields: {sorted(unknown)}")
        self._fields.update(kw)

    def stage(self, name: Stage | str):
        return self._timer.stage(name)

    def set_outcome(self, outcome: Outcome) -> None:
        self._fields["outcome"] = outcome

    def record_denial(self, d: GatewayDenial) -> None:
        raise NotImplementedError("wave 1, agent B")

    def record_internal_error(self, e: BaseException) -> None:
        raise NotImplementedError("wave 1, agent B")

    def finalize(self) -> RequestEvent:
        raise NotImplementedError("wave 1, agent B")

    async def finalize_and_write(self, sink: AuditSink, cfg: Config) -> None:
        """Exactly one event, always. MUST shield the write against cancellation."""
        raise NotImplementedError("wave 1, agent B")


class AuditSink:
    """JSONL writer. Hard dependency: an unwritable sink denies (AUDIT-009)."""

    async def write(self, event: AuditRecord) -> None:
        raise NotImplementedError("wave 1, agent B")

    def readiness_probe(self) -> bool:
        raise NotImplementedError("wave 1, agent B")


def read_events(path: str) -> Iterator[AuditRecord]:
    """Harness interface. Strict: a corrupt line fails the report, never skipped."""
    raise NotImplementedError("wave 1, agent B")

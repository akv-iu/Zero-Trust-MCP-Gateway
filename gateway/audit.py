"""09 - JSONL audit events. The project's evidence artifact.

Spec: _specs/09-svc-audit-log.md   Tech: _tech/09-svc-audit-log.md

Every claim this project makes is a claim about a record written here. The security
rate, the false-positive rate, the overhead distribution and the completeness ratio
all read out of this file. If the audit is incomplete, nothing else is evidence.

Built before any enforcement stage, so no enforcement is ever written without its
evidence path already in place.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

import anyio
import anyio.to_thread
from pydantic import TypeAdapter, ValidationError

from gateway.audit_schema import AuditRecord, LifecycleEvent, Outcome, RequestEvent
from gateway.config import Config
from gateway.errors import (
    AuditFailure,
    GatewayDenial,
    ProgrammingError,
    ReasonCode,
    Stage,
)
from gateway.timing import StageTimer

_RECORD: TypeAdapter[AuditRecord] = TypeAdapter(AuditRecord)

#: Reason code -> terminal outcome. Collapsing these would destroy the evidence the
#: report depends on: a cancelled request and a denied one mean different things.
_OUTCOME_BY_CODE: dict[ReasonCode, Outcome] = {
    ReasonCode.ROUTE_CANCELLED: "cancelled",
    ReasonCode.ROUTE_TIMEOUT: "timeout",
    ReasonCode.POLICY_TIMEOUT: "timeout",
    ReasonCode.INTERNAL_ERROR: "error",
    ReasonCode.AUDIT_WRITE_FAILED: "error",
    ReasonCode.AUDIT_SCHEMA_INVALID: "error",
    ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE: "error",
    ReasonCode.POLICY_UNAVAILABLE: "error",
}


class AuditBuilder:
    """Mutable per-request accumulator that validates into a frozen event.

    AUDIT-007: `set()` rejects any key absent from RequestEvent, so a sensitive field
    cannot be written by accident — only by editing the schema, which is a reviewable
    diff. That is the whole minimisation strategy; there is no regex scrubbing.
    """

    __slots__ = ("request_id", "_fields", "_timer", "_ts_start", "_sealed")

    def __init__(self, request_id: str) -> None:
        self.request_id = request_id
        self._fields: dict[str, Any] = {}
        self._timer = StageTimer()
        self._ts_start = datetime.now(UTC)
        self._sealed = False

    def set(self, **kw: Any) -> None:
        unknown = kw.keys() - RequestEvent.model_fields.keys()
        if unknown:
            raise ProgrammingError(f"unknown audit fields: {sorted(unknown)}")
        self._fields.update(kw)

    @contextmanager
    def stage(self, name: Stage | str) -> Generator[None]:
        with self._timer.stage(name):
            yield

    def set_outcome(self, outcome: Outcome) -> None:
        self._fields["outcome"] = outcome

    def record_denial(self, d: GatewayDenial) -> None:
        """A denial is terminal. `detail` is deliberately NOT recorded (CONV-012)."""
        self._fields["reason_code"] = d.reason_code.value
        self._fields.setdefault("decision", "deny")
        self.set_outcome(_OUTCOME_BY_CODE.get(d.reason_code, "denied"))

    def record_internal_error(self, e: BaseException) -> None:
        """An unexpected exception is a defect. It denies; it never allows."""
        self._fields["reason_code"] = ReasonCode.INTERNAL_ERROR.value
        self._fields["decision"] = "deny"
        self.set_outcome("error")

    def record_cancellation(self) -> None:
        self._fields.setdefault("reason_code", ReasonCode.ROUTE_CANCELLED.value)
        self.set_outcome("cancelled")

    def finalize(self) -> RequestEvent:
        """AUDIT-003: a record that will not validate is an audit FAILURE.

        `set()` guards field names; it cannot guard values, so a stage writing
        `risk_tier="R3"` or a malformed hash still fails here. Letting pydantic's
        ValidationError escape would surface as INTERNAL_ERROR — true but useless,
        and it hides the one failure mode that invalidates the evidence.
        """
        try:
            return RequestEvent(
                request_id=self.request_id,
                ts_start=self._ts_start,
                ts_end=datetime.now(UTC),
                transport="streamable_http",
                stage_latency_ms=self._timer.as_ms(),
                total_latency_ms=self._timer.elapsed_ns / 1_000_000,
                **{
                    k: v
                    for k, v in self._fields.items()
                    # A request that died before any stage still needs a valid outcome.
                    if k != "outcome"
                },
                outcome=self._fields.get("outcome", "error"),
            )
        except ValidationError as e:
            raise AuditFailure(
                ReasonCode.AUDIT_SCHEMA_INVALID, detail=f"{self.request_id}: {e}"
            ) from e

    def _tombstone(self) -> RequestEvent:
        """The minimum valid record: this request happened and its audit failed.

        Without it, an unrepresentable event would leave a hole in the log and the
        completeness ratio would drop with no explanation of where it went. The
        request is still denied — this preserves the count, not the request.
        """
        return RequestEvent(
            request_id=self.request_id,
            ts_start=self._ts_start,
            ts_end=datetime.now(UTC),
            transport="streamable_http",
            decision="deny",
            reason_code=ReasonCode.AUDIT_SCHEMA_INVALID.value,
            outcome="error",
        )

    async def finalize_and_write(
        self, sink: AuditSink, cfg: Config | None = None
    ) -> None:
        """Exactly one event, always (AUDIT-001).

        The write is SHIELDED against cancellation. Without the shield, a cancelled
        request produces no event at all and the completeness ratio silently drops
        below 1.0 — which reads as a measurement artifact rather than the bug it is.
        """
        if self._sealed:
            raise ProgrammingError(f"audit event already written for {self.request_id}")
        self._sealed = True
        with anyio.CancelScope(shield=True):
            try:
                event = self.finalize()
            except AuditFailure:
                await sink.write(self._tombstone())
                raise  # AUDIT-009: the caller denies. The record is not the request.
            await sink.write(event)


class AuditSink:
    """Append-only JSONL writer.

    AUDIT-009: a hard dependency, not best-effort. If a required event cannot be
    persisted, the protected operation is denied.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        durable: bool = True,
        max_bytes: int = 268_435_456,
        max_age_days: int = 7,
        rotate_keep: int = 5,
    ) -> None:
        self.path = Path(path)
        self.durable = durable
        self.max_bytes = max_bytes
        self.max_age_days = max_age_days
        self.rotate_keep = rotate_keep
        self._lock = anyio.Lock()
        self._fh: IO[str] | None = None
        self._segment_started = datetime.now(UTC).timestamp()

    # -- lifecycle ---------------------------------------------------------

    def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # newline="\n" explicitly: without it Windows writes \r\n and byte-level
        # comparisons diverge across platforms for no reason.
        self._fh = self.path.open("a", encoding="utf-8", newline="\n")
        self._segment_started = self._oldest_record_ts()
        self.prune()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    @classmethod
    def from_config(cls, cfg: Config) -> AuditSink:
        a = cfg.audit
        sink = cls(
            a.path,
            durable=a.durable,
            max_bytes=a.max_bytes,
            max_age_days=a.max_age_days,
            rotate_keep=a.rotate_keep,
        )
        sink.open()
        return sink

    def readiness_probe(self) -> bool:
        """AUDIT-010: readiness is false when the sink is unwritable."""
        try:
            self.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="ready", detail={}))
            return True
        except (OSError, AuditFailure):
            return False

    # -- writing -----------------------------------------------------------

    async def write(self, event: AuditRecord) -> None:
        async with self._lock:
            try:
                await anyio.to_thread.run_sync(self.write_sync, event)
            except OSError as e:
                raise AuditFailure(ReasonCode.AUDIT_WRITE_FAILED) from e

    def write_sync(self, event: AuditRecord) -> None:
        """Serialise once, write one line.

        AUDIT-014: `model_dump_json` does all escaping, so a newline inside a value
        becomes `\\n` and can never terminate a record. The line is NEVER built by
        string formatting — that is what makes log injection impossible rather than
        merely unlikely.
        """
        line = event.model_dump_json(exclude_none=False) + "\n"
        if self._fh is None:
            self.open()
        assert self._fh is not None
        try:
            self._fh.write(line)
            self._fh.flush()
            if self.durable:
                os.fsync(self._fh.fileno())
        except OSError as e:
            raise AuditFailure(ReasonCode.AUDIT_WRITE_FAILED) from e
        if self._should_rotate():
            self.rotate()

    # -- retention (AUDIT-012) --------------------------------------------

    def _should_rotate(self) -> bool:
        """Size OR age, whichever comes first.

        Age was previously declared and never enforced: `prune` only ever looked at
        ALREADY-ROLLED files, so on a gateway that stays up and stays quiet the active
        segment aged forever and `max_age_days` did nothing. The retention bound has
        to apply to the file being written, not only to its history.
        """
        if self.path.exists() and self.path.stat().st_size > self.max_bytes:
            return True
        age_s = datetime.now(UTC).timestamp() - self._segment_started
        return age_s > self.max_age_days * 86_400

    def _oldest_record_ts(self) -> float:
        """When the active segment's first record was written.

        Read from the record rather than the filesystem: mtime moves with every
        append, and ctime means different things on Windows and POSIX. The first line
        is the only honest answer, and reading one line is cheap however large the
        file is.
        """
        now = datetime.now(UTC).timestamp()
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                first = fh.readline()
            record = json.loads(first)
            stamp = record.get("ts_start") or record["ts"]
            return datetime.fromisoformat(stamp).timestamp()
        except (OSError, ValueError, KeyError, TypeError):
            return now  # empty, absent, or a segment predating this schema

    def rotate(self) -> None:
        self.close()
        for i in range(self.rotate_keep - 1, 0, -1):
            src, dst = self._rolled(i), self._rolled(i + 1)
            if src.exists():
                src.replace(dst)
        if self.path.exists():
            self.path.replace(self._rolled(1))
        self.open()  # resets _segment_started; also prunes what just fell off the end
        self.write_sync(
            LifecycleEvent(
                ts=datetime.now(UTC), kind="rotation", detail={"file": self.path.name}
            )
        )

    def prune(self) -> None:
        """Drop rolled segments that are too old or beyond `rotate_keep`.

        Globbed rather than counted up to `rotate_keep + 1`: that stopped one past the
        limit, so lowering `rotate_keep` between runs stranded every older segment on
        disk permanently. Whatever is actually there is what has to be considered.
        """
        cutoff = datetime.now(UTC).timestamp() - self.max_age_days * 86_400
        for p in self.path.parent.glob(f"{self.path.name}.*"):
            try:
                index = int(p.suffix.lstrip("."))
            except ValueError:
                continue  # not one of ours
            if index > self.rotate_keep or p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)

    def _rolled(self, n: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{n}")


# -- harness interface -----------------------------------------------------


class CorruptAuditLog(Exception):
    """A line failed schema validation. The report refuses rather than skipping it."""


def read_events(path: str | Path) -> Iterator[AuditRecord]:
    """Strict reader. AUDIT-013: a corrupt line fails the report, never skipped."""
    p = Path(path)
    if not p.exists():
        return
    for i, line in enumerate(p.read_text("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            yield _RECORD.validate_json(line)
        except ValidationError as e:
            raise CorruptAuditLog(f"{p}:{i}") from e


def completeness(path: str | Path, requests_issued: int) -> float:
    """AUDIT-004: measured, never assumed.

    A measured 1.0 is evidence; an assumed one is not.

    DISTINCT request ids, and duplicates fail the report. Counting rows made the ratio
    forgeable by the exact bug it exists to detect: ten events for one request and
    nine requests logged nowhere still reads 10/10 = 1.0. Since AUDIT-001 promises
    exactly one event per request, a repeat means the count is not measuring what it
    claims, and a number that cannot be trusted must not be published — the same rule
    `read_events` already applies to a corrupt line.
    """
    if requests_issued == 0:
        return 1.0
    ids = [e.request_id for e in read_events(path) if e.event_type == "request"]
    repeated = [rid for rid, n in Counter(ids).items() if n > 1]
    if repeated:
        raise CorruptAuditLog(
            f"{path}: {len(repeated)} request_id(s) written more than once "
            f"(AUDIT-001); first: {sorted(repeated)[:3]}"
        )
    return len(ids) / requests_issued

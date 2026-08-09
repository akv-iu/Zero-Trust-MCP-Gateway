# TECH-09 — `svc-audit-log`

**Pairs with:** [`_specs/09-svc-audit-log.md`](../_specs/09-svc-audit-log.md)
**Module:** `gateway/audit.py`

---

## 1. Builder → frozen event → one line

The spec forbids passing a mutable dict between stages. The pattern that satisfies it:

```python
class AuditBuilder:                      # mutable, per-request, typed slots
    __slots__ = ("request_id", "received_at_ns", "_fields", "_stage_ns", "_sealed")

    def set(self, **kw) -> None:         # only keys present in AuditEvent are accepted
        unknown = kw.keys() - AuditEvent.model_fields.keys()
        if unknown: raise ProgrammingError(f"unknown audit fields: {unknown}")
        self._fields.update(kw)

    @contextmanager
    def stage(self, name: str): ...      # TECH-00 §7

    def finalize(self) -> AuditEvent:    # validates -> frozen
        return AuditEvent(request_id=..., stage_latency_ms=..., **self._fields)
```

`AuditEvent` is a frozen pydantic model with `extra="forbid"`. `AuditBuilder.set` rejecting unknown keys at the call site is `AUDIT-007` — a sensitive field cannot be written by accident, only by adding it to the schema, which is a reviewable diff.

Reached via a `ContextVar[AuditBuilder]` set in `pipeline.handle` (TECH-00 §5), so stages call `current_audit.get().set(...)` without threading a parameter through every signature.

---

## 2. Exactly one event (AUDIT-001)

The `finally` block in `pipeline.handle` is the only writer, and `_sealed` makes double-write a loud error:

```python
async def finalize_and_write(self, sink: AuditSink) -> None:
    if self._sealed:
        raise ProgrammingError("audit event already written")
    self._sealed = True
    await sink.write(self.finalize())
```

Because it is in `finally`, it runs on success, on `GatewayDenial`, on internal error, and on cancellation. **Cancellation is the one that will break it:** an `await` inside a cancelled scope raises immediately. Shield the write:

```python
with anyio.CancelScope(shield=True):
    await sink.write(event)
```

Without the shield, cancelled requests produce zero audit events and `AUDIT-004`'s completeness ratio silently drops below 1.0 — which would look like a measurement problem rather than the bug it is.

---

## 3. Event schema

Discriminated union on `event_type` so drift and startup events share the file:

```python
class RequestEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal[1]
    event_type: Literal["request"]
    request_id: str
    ts_start: datetime; ts_end: datetime
    transport: Literal["stdio"]
    mcp_method: str | None; mcp_protocol_version: str | None
    principal: str | None
    auth_method: Literal["local_config"] | None
    assurance: Literal["unverified_local"] | None
    client_id: str | None
    server_id: str | None; tool_name: str | None; schema_fingerprint: str | None
    canonical_resource: str | None; arg_hash: str | None; raw_hash: str | None
    decision: Literal["allow","deny"] | None
    reason_code: str | None
    risk_tier: Literal["R0","R1","R2","R4"] | None
    policy_revision: str | None
    obligations: dict[str, int] | None      # as ENFORCED (ROUTE-007)
    obligations_clamped: bool = False
    upstream_status: str | None; upstream_latency_ms: float | None
    response_bytes: int | None
    stage_latency_ms: dict[str, float]
    outcome: Literal["allowed","denied","error","cancelled","timeout"]

class DriftEvent(BaseModel): ...      # event_type: "drift"
class LifecycleEvent(BaseModel): ...  # event_type: "startup" | "shutdown" | "policy_load"

AuditRecord = Annotated[RequestEvent | DriftEvent | LifecycleEvent,
                        Field(discriminator="event_type")]
```

Every request-stage field is `| None` because a request rejected at stage 2 has no `tool_name` — the event must still be **complete and valid** (`AUDIT-001`), not truncated. `outcome` and `schema_version` are the only non-optional fields, and `outcome`'s `Literal` makes `AUDIT-002` unrepresentable-otherwise.

---

## 4. Writer

```python
class JsonlSink:
    async def write(self, event: AuditRecord) -> None:
        line = event.model_dump_json(exclude_none=False) + "\n"
        async with self._lock:
            try:
                await anyio.to_thread.run_sync(self._write_sync, line)
            except OSError as e:
                raise AuditFailure(AUDIT_WRITE_FAILED) from e

    def _write_sync(self, line: str) -> None:
        self._fh.write(line)
        self._fh.flush()
        if self.durable: os.fsync(self._fh.fileno())
        self._bytes += len(line)
        if self._bytes > self.max_bytes: self._rotate()
```

- `model_dump_json` handles all escaping, so `AUDIT-014` (log injection) is satisfied by the serializer — a newline inside a value becomes `\n`, never a record boundary. Never build the line with string formatting.
- `anyio.to_thread.run_sync` keeps the event loop free; the `anyio.Lock` serializes appends.
- Open with `mode="a"`, `encoding="utf-8"`, `newline="\n"` — **explicit `newline`**, or Windows writes `\r\n` and the JSONL is still parseable but byte-comparisons in tests differ across platforms.
- `os.fsync` per record is the `durable` default (`AUDIT-011`). It is expensive, and that cost belongs in the published benchmark. Config allows `durable=false`; the report must state which mode produced its numbers.

### Rotation and retention (AUDIT-012)

Size-based rotation to `audit.jsonl.1`, `.2`, …; age-based pruning on startup and every N writes. Both bounds, whichever first. Rotation emits a `LifecycleEvent` so the harness can detect a rotation that happened mid-run and refuse to compute completeness across the boundary without reading the rotated file.

---

## 5. Failure behavior (AUDIT-009, AUDIT-010)

`AuditFailure` is raised from `sink.write` — but it is raised from `finally`, *after* the decision. Sequencing matters:

```
allow decided -> route -> response -> AUDIT WRITE -> respond to client
```

The client response must not be written by the bridge until `finalize_and_write` has returned. Implement by having `pipeline.handle` do the write **before** returning the value, not in a detached task. `AUDIT-011`'s "durably written before delivery" is an ordering property, not a durability flag.

If the write fails after an allowed upstream call has already executed, the side effect has happened and cannot be undone. The honest handling: return an error to the client with `AUDIT_WRITE_FAILED`, and record the situation in the diagnostic sink. **Document this window in the threat model** — it is a real limitation of a non-transactional design and stating it is better than implying atomicity.

Readiness checks sink writability at startup by writing a `LifecycleEvent`; the chaos test makes the file unwritable (`chmod 0o444`, or on Windows an exclusive-lock holder or a read-only ACL) mid-run.

---

## 6. Config

```toml
[audit]
path = "var/audit.jsonl"
durable = true
max_bytes = 268435456        # 256 MiB
max_age_days = 7
rotate_keep = 5
capture_stage_latency = true
```

---

## 7. Harness interface

The harness reads this file directly — there is no query API (`jq` is the admin interface):

```python
def read_events(path: Path) -> Iterator[AuditRecord]:
    for i, line in enumerate(path.read_text("utf-8").splitlines(), 1):
        try: yield TypeAdapter(AuditRecord).validate_json(line)
        except ValidationError as e: raise CorruptAuditLog(f"line {i}") from e
```

Strict on parse — a corrupt line fails the report rather than being skipped (`AUDIT-013` reasoning). Mixed `schema_version` values across a run also fail (spec test 12).

---

## 8. Tests

| Spec test | Notes |
|---|---|
| 1 — completeness | Count requests issued vs events read; report the ratio as a number |
| 3 — no duplicates | Assert `request_id` values are unique across the file |
| 5 — chaos | Make sink unwritable mid-run; assert `AUDIT_WRITE_FAILED`, oracle clean, readiness false |
| 6/7 — canaries | Suite-wide autouse: for each canary string, assert absent from every line of the file |
| 8 — log injection | Argument `'x\n{"event_type":"request","outcome":"allowed"}\n'`; assert line count increases by exactly 1 and no forged event parses |
| 10 — latency sanity | `sum(stage_latency_ms.values()) <= (ts_end - ts_start)` within tolerance |

Test 8 is worth writing carefully: it is the difference between "we JSON-encode" and "we proved a forged record cannot be injected".

---

## 9. Gotchas

- **Shield the write against cancellation** (§2). This is the most likely source of a completeness ratio below 1.0, and it will look like a mysterious measurement artifact.
- `exclude_none=False` — keep null fields present. A stage-2 rejection whose event *omits* `tool_name` versus one that sets it to `null` are different for downstream `jq`; pick present-and-null and be consistent.
- `datetime.now(UTC)` for timestamps, `perf_counter_ns` for durations. Never subtract wall-clock timestamps to get a duration.
- Do not add a second logging framework. Diagnostics go to `stderr` via stdlib `logging`; evidence goes here. Two log systems means two places to leak a canary.

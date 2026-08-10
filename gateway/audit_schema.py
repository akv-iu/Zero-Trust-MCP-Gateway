"""Audit event schema — the project's evidence format.

Split out of `gateway/audit.py` (which unit 09 owns) because the schema is shared
spine: every unit contributes fields, so it must be frozen before parallel work
starts. Unit 09 builds `AuditBuilder` and `JsonlSink` against these models.

`_specs/09-svc-audit-log.md`, `_tech/09-svc-audit-log.md` §3.

AUDIT-007: a field not in the schema is not written. Adding a sensitive field
requires editing this file, which is a reviewable diff.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from gateway.types import RiskTier

SCHEMA_VERSION = 3
"""Bumped on any change here. The harness refuses to mix versions in one report.

**v2** — `UpstreamAttemptEvent` was added for unit 07's write-ahead record. Additive
for a writer and *breaking for a reader*, which is why it is a bump rather than a
quiet extension: `read_events` resolves the discriminated union strictly, so a v1
reader handed a v2 file raises `CorruptAuditLog` on the first attempt record. That is
the correct outcome — it is the same rule the reader already applies to a corrupt
line — and it only reads as correct if the version says the format moved.

**v3** — `UpstreamFaultEvent` was added for unit 08's out-of-band observations
(RESP-002). Same reasoning as v2: additive for a writer, breaking for a reader."""

Outcome = Literal["allowed", "denied", "error", "cancelled", "timeout"]
"""AUDIT-002: any other terminal state is unrepresentable, not merely discouraged."""

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class RequestEvent(BaseModel):
    """One per request. Not zero, not two (AUDIT-001).

    Request-stage fields are optional because a request rejected at stage 2 has no
    tool name — the event must still be complete and schema-valid, never truncated.
    """

    model_config = _FROZEN

    schema_version: Literal[3] = SCHEMA_VERSION
    event_type: Literal["request"] = "request"

    request_id: str
    ts_start: datetime
    ts_end: datetime
    transport: Literal["streamable_http"]

    # 02
    mcp_method: str | None = None
    mcp_protocol_version: str | None = None
    body_hash: str | None = None

    # 03 — the literals are the control (IDENT-002)
    principal: str | None = None
    client_id: str | None = None
    roles: tuple[str, ...] | None = None
    auth_method: Literal["local_config"] | None = None
    assurance: Literal["unverified_local"] | None = None
    environment: str | None = None

    # 04
    server_id: str | None = None
    tool_name: str | None = None
    schema_fingerprint: str | None = None

    # 05 — hashes, never raw values (AUDIT-005)
    canonical_resource: str | None = None
    classification: str | None = None
    operation: str | None = None
    arg_hash: str | None = None
    raw_hash: str | None = None

    # 06
    decision: Literal["allow", "deny"] | None = None
    reason_code: str | None = None
    risk_tier: RiskTier | None = None
    policy_revision: str | None = None
    obligations: dict[str, int] | None = None  # as ENFORCED, not as requested
    obligations_clamped: bool = False

    # 07 / 08
    upstream_status: str | None = None
    upstream_latency_ms: float | None = None
    response_bytes: int | None = None

    # all stages
    stage_latency_ms: dict[str, float] = Field(default_factory=dict)
    total_latency_ms: float | None = None

    outcome: Outcome


class DriftEvent(BaseModel):
    """REG-006. Same stream, discriminated by event_type."""

    model_config = _FROZEN

    schema_version: Literal[3] = SCHEMA_VERSION
    event_type: Literal["drift"] = "drift"

    ts: datetime
    server_id: str
    tool_name: str
    reason_code: str
    approved_fingerprint: str | None = None
    advertised_fingerprint: str | None = None


class UpstreamAttemptEvent(BaseModel):
    """07's write-ahead record: this side effect is ABOUT to happen (AUDIT-009).

    `pipeline.handle` writes its `RequestEvent` in a `finally`, which runs after
    `router.forward` — so if the sink fails once a mutating call has already reached
    the child, the client is correctly told the request failed while the effect has
    happened and no record of it survives. AUDIT-009 asks for the operation to be
    denied when its event cannot be persisted; that held for reads and not for writes.

    This closes it by ordering rather than by atomicity, which is the same shape the
    fixture's own operation log already uses: an attempt record is written and fsynced
    BEFORE the call, so a failure to persist denies before any side effect, and a
    failure of the terminal record still leaves evidence naming what was attempted.

    A separate event type, not a second `RequestEvent`. `completeness()` counts
    distinct request ids among `event_type == "request"` and refuses on a repeat —
    two request events per request would make the ratio fail on exactly the requests
    that behaved correctly.

    Minimised to what identifies the side effect: no arguments, no response, no
    principal (the paired `RequestEvent` carries identity, and duplicating it here
    would put the same subject in two places with two retention stories).
    """

    model_config = _FROZEN

    schema_version: Literal[3] = SCHEMA_VERSION
    event_type: Literal["upstream_attempt"] = "upstream_attempt"

    ts: datetime
    request_id: str
    server_id: str
    mcp_method: str
    tool_name: str | None = None
    canonical_resource: str | None = None
    operation: str | None = None
    arg_hash: str | None = None
    policy_revision: str | None = None


class UpstreamFaultEvent(BaseModel):
    """08's out-of-band record: the upstream did something no request asked for.

    RESP-002 requires an unsolicited upstream message to be dropped AND audited. It
    belongs to no request — a server-initiated `roots/list`, `sampling/createMessage`
    or `elicitation/create` arrives whenever the child feels like it — so it cannot be
    a field on a `RequestEvent` without attributing it to whichever request happened to
    be in flight, which is exactly the correlation this unit refuses to invent.

    `fault` is the exception's CLASS NAME and nothing else. A pydantic
    `ValidationError` message quotes the input it rejected, so recording the message
    would put upstream response bytes in the audit log — the one thing RESP-009 and
    CONV-012 forbid, arriving through the field meant to describe a failure.
    """

    model_config = _FROZEN

    schema_version: Literal[3] = SCHEMA_VERSION
    event_type: Literal["upstream_fault"] = "upstream_fault"

    ts: datetime
    server_id: str
    reason_code: str
    mcp_method: str | None = None
    """The method of the unsolicited message, which the upstream chose from a closed
    protocol vocabulary. Absent for a transport fault, which has no method."""
    fault: str | None = None


class LifecycleEvent(BaseModel):
    """Startup, shutdown, policy load, audit rotation."""

    model_config = _FROZEN

    schema_version: Literal[3] = SCHEMA_VERSION
    event_type: Literal["lifecycle"] = "lifecycle"

    ts: datetime
    kind: Literal["startup", "shutdown", "policy_load", "rotation", "ready", "not_ready"]
    detail: dict[str, str] = Field(default_factory=dict)


AuditRecord = Annotated[
    RequestEvent
    | DriftEvent
    | LifecycleEvent
    | UpstreamAttemptEvent
    | UpstreamFaultEvent,
    Field(discriminator="event_type"),
]

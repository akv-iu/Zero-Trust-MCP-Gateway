"""07 - Obligation enforcement and forwarding. The only unit that can cause a side effect.

Spec: _specs/07-svc-upstream-router.md   Tech: _tech/07-svc-upstream-router.md

Everything before this unit is analysis; this unit acts. Its contract is therefore
narrow and absolute: it runs if and only if a validated `allow` exists for this exact
canonical request, it forwards what that allow described, and it enforces the
obligations that came with it.

ROUTE-003 — this module MUST NOT import `os`, `pathlib`, `io`, `shutil`, `socket`,
`subprocess`, `httpx`, or call `open`. `tests/unit/test_router_isolation.py` walks the
AST and enforces it, negative control included. Where the router needs something
outside this process it goes through the module that owns that channel: `bridge` owns
the child, `policy` owns OPA. It has no I/O capability of its own to misuse, which is
what makes "no side effect without a decision" a property of the module rather than a
claim about its callers. `hashing.argument_hash` exists so ROUTE-002 does not require
importing the canonicalizer, which does have filesystem access.

THE BYTE CEILING IS DETECTION, NOT PREVENTION (ROUTE-006). `_tech/07` §5 asks for a
streaming abort and the installed SDK cannot provide one: `mcp.client.stdio` reads the
child's stdout through a `TextReceiveStream`, splits on newline, and parses a WHOLE
LINE into a `SessionMessage` before anything downstream sees a byte. By the time this
module can measure a response it is already resident, so the ceiling below denies an
oversized response rather than preventing one from being buffered. `_tech/07` §5
pre-authorised the fallback on condition it be said out loud instead of substituted
silently:

    the property is "an oversized response is detected and denied", NOT "an oversized
    response cannot exhaust memory".

Closing it means owning the child's stdout reader instead of `stdio_client`. The
trigger is in `_specs/90-deferred-register.md` §10g.

CANCELLATION IS THE SDK'S, NOT OURS (ROUTE-010). `bridge.UpstreamHandle.cancel()` was
built here for the router to call and has been deleted, because the pinned SDK already
does it: `JSONRPCDispatcher.send_raw_request` catches the caller's cancellation and
sends `notifications/cancelled` through a SHIELDED write, with the id it actually put
on the wire. Calling it ourselves would have sent the CLIENT's JSON-RPC id, which the
child has never seen — a notification that cancels nothing, or worse, an unrelated
in-flight id. Verified against the installed SDK by running it, not inferred from
reading it (ADR-002's process lesson). What is left here is recording which of the
four outcomes happened, which `_tech/07` §6 is right that nothing else preserves.

**This behaviour is not yet pinned by a test, and it is load-bearing.** An SDK upgrade
that stopped sending the courtesy cancel would leave the child working on abandoned
requests with nothing failing. `mcp` is pinned exactly and `tests/unit/test_sdk_pin.py`
is the tripwire for the pin itself; the behavioural assertion belongs beside it and is
owed (`PLAN.md` §4.2, unit 07 row).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, cast

import anyio

from gateway import hashing, policy
from gateway.audit_schema import UpstreamAttemptEvent
from gateway.config import RouterConfig
from gateway.context import audit
from gateway.errors import ReasonCode, RouteDenial
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    Decision,
    DerivedAttributes,
    JsonObject,
    Obligations,
    RawResult,
    thaw,
)

if TYPE_CHECKING:  # `pipeline` imports this module; the type is not needed at runtime
    from gateway.pipeline import Deps

_LIST_METHOD: Final = "tools/list"

#: Reason code -> what the record says the upstream did. Distinct values, because
#: ROUTE-010 is explicit that collapsing them destroys the evidence the report reads.
_STATUS_BY_CODE: Final[dict[ReasonCode, str]] = {
    ReasonCode.ROUTE_TIMEOUT: "timeout",
    ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE: "unavailable",
    ReasonCode.ROUTE_RESPONSE_TOO_LARGE: "too_large",
    ReasonCode.ROUTE_CANCELLED: "cancelled",
    ReasonCode.ROUTE_NO_DECISION: "not_attempted",
    ReasonCode.ROUTE_AUTHORIZATION_DIVERGENCE: "not_attempted",
}


# ===========================================================================
# Stage entry point
# ===========================================================================


async def route(
    req: CanonicalRequest,
    ctx: AuthzContext,
    drv: DerivedAttributes,
    dec: Decision,
    deps: Deps,
) -> RawResult:
    """Stage 07. Gate, record the intent, then act — in that order.

    The order is the requirement. `_gate` runs before anything is written and long
    before anything is sent; the write-ahead record is fsynced before the call that
    could cause a side effect; only then does the upstream hear about the request.
    """
    _gate(req, drv, dec)
    ob = _enforce(dec, deps.config.router)
    await _write_ahead(req, drv, dec, deps)
    if req.method == _LIST_METHOD:
        return await _discover(req, ctx, deps, ob)
    return await forward(req, drv, dec, deps.upstream, deps.config.router)


# ===========================================================================
# The gate (ROUTE-001, ROUTE-002)
# ===========================================================================


def _gate(req: CanonicalRequest, drv: DerivedAttributes, dec: Decision) -> None:
    """No forwarding without a validated allow for THIS request, describing THIS call.

    `Decision` is a frozen model carrying `request_id`, so ROUTE-001 is a comparison
    of typed values rather than an audit of every caller: there is no overload that
    accepts a boolean and pyright rejects one being added.

    ROUTE-002 is the internal equivalent of the header/body split unit 02 closes at
    the edge. The strongest form is to make divergence unrepresentable — the outbound
    message is derived from `req` and never separately constructed — and this check
    stays anyway as the refactor guard `_tech/07` §2 asks for. It re-reads the
    arguments that are about to be forwarded and hashes them against the path stage 05
    resolved, so a mutation between policy and forwarding breaks the comparison rather
    than travelling with the request.
    """
    if dec.request_id != req.request_id:
        raise RouteDenial(
            ReasonCode.ROUTE_NO_DECISION,
            detail=f"decision belongs to {dec.request_id}, not {req.request_id}",
        )
    if dec.decision != "allow":
        # Defensive: `pipeline.handle` already raised on a deny. Cheap, and it is the
        # difference between an invariant and an assumption about one caller.
        raise RouteDenial(ReasonCode.ROUTE_NO_DECISION, detail=dec.reason_code)
    if hashing.argument_hash(req.arguments, drv.canonical_path) != dec.arg_hash:
        raise RouteDenial(
            ReasonCode.ROUTE_AUTHORIZATION_DIVERGENCE,
            detail="arguments changed between policy evaluation and forwarding",
        )


def _enforce(dec: Decision, cfg: RouterConfig) -> Obligations:
    """ROUTE-005 and ROUTE-007: apply the obligations, and record what was applied.

    Policy clamps what it RETURNS; the router clamps what it RECEIVED. `Config`
    already makes the two ceilings equal at startup, so today this narrows nothing —
    which is not the same as being redundant. The equality is a check on a file
    someone edits, and this is the code that would otherwise forward a ten-minute
    timeout the day that check is loosened.

    The gateway's total request deadline is the other half of "whichever is lower"
    (ROUTE-005). It is not read here: `edge._handle` wraps the whole request in
    `anyio.fail_after(request_timeout_s)`, so the two scopes nest and the shorter one
    wins by construction. A second copy of that budget in this module would be a
    number to keep in sync with no way to notice when it drifted.
    """
    ob = Obligations(
        timeout_ms=min(dec.obligations.timeout_ms, cfg.max_timeout_ms),
        max_response_bytes=min(
            dec.obligations.max_response_bytes, cfg.max_response_bytes
        ),
    )
    audit().set(obligations=ob.model_dump())
    return ob


async def _write_ahead(
    req: CanonicalRequest, drv: DerivedAttributes, dec: Decision, deps: Deps
) -> None:
    """AUDIT-009: the record that the side effect was about to happen, before it does.

    Written for EVERY forwarded call, not only mutating ones. A read is a side effect
    too — the oracle treats a confidential-file read as the most dangerous violation
    in the corpus — and a rule that decided per-operation would be one more place for
    the create/overwrite split to be read wrong.

    `AuditSink.write` fsyncs when `audit.durable`, and raises `AuditFailure` (a
    `GatewayDenial`) when it cannot. That propagates out of stage 07 untouched, so an
    unwritable sink denies BEFORE the upstream is contacted rather than after.
    """
    await deps.audit.write(
        UpstreamAttemptEvent(
            ts=datetime.now(UTC),
            request_id=req.request_id,
            server_id=deps.registry.server.id,
            mcp_method=req.method,
            tool_name=req.tool_name,
            canonical_resource=drv.canonical_path,
            operation=drv.operation,
            arg_hash=dec.arg_hash,
            policy_revision=dec.policy_revision,
        )
    )


# ===========================================================================
# tools/call (ROUTE-004)
# ===========================================================================


async def forward(
    req: CanonicalRequest,
    drv: DerivedAttributes,
    dec: Decision,
    upstream: Any,
    cfg: RouterConfig,
) -> RawResult:
    """Forward iff `dec` is a validated allow for THIS request_id (ROUTE-001).

    ROUTE-004: the CANONICAL request goes upstream, never the client's original bytes.
    `req.arguments` is what unit 02 parsed, unit 04 validated against the approved
    schema and unit 05 hashed; `thaw` only converts the frozen structure back to the
    `dict` the SDK requires, at the boundary, and the result is never stored.

    ROUTE-009 comes free from that path rather than from a filter: the approved schema
    sets `additionalProperties: false`, so an argument the schema does not name never
    reaches this function. A runtime scan for credential-shaped fields here would be
    checking a property the registry has already made unrepresentable.
    """
    _gate(req, drv, dec)  # defensive; `route` gated too. See `_gate`.
    if req.tool_name is None:
        raise RouteDenial(
            ReasonCode.ROUTE_NO_DECISION, detail=f"{req.method} names no tool"
        )
    ob = _enforce(dec, cfg)
    arguments = cast("JsonObject", thaw(req.arguments))
    call = upstream.call_tool(req.tool_name, arguments)
    result, elapsed_ns = await _bounded(call, ob)
    return _measure(_content(result), _is_error(result), elapsed_ns, ob)


# ===========================================================================
# tools/list (REG-010's other half)
# ===========================================================================


async def _discover(
    req: CanonicalRequest, ctx: AuthzContext, deps: Deps, ob: Obligations
) -> RawResult:
    """Forward discovery, then remove what this principal could never call.

    REG-010 has two halves and only one existed: `Registry.visible_tools` and
    `data.gateway.discoverable` were both built and tested, and nothing filtered the
    RESPONSE, so `tools/list` returned whatever the child advertised.

    The child's answer is forwarded and then filtered rather than replaced by the
    registry's approved list. Replacing it would drop the descriptions — the registry
    stores `approved_for`, which is deliberately never read at runtime — and the
    approved schemas are already pinned: `verify_schemas` compared every fingerprint at
    startup and quarantined what drifted, and `_callable_reason` excludes a quarantined
    tool here. So filtering loses no authority and keeps the response useful.

    Fail-closed has a specific shape here. If OPA cannot answer, this raises rather
    than returning a short list: an empty or partial `tools/list` looks like a
    legitimate answer ("you may see nothing") while actually meaning the policy engine
    broke, and a denial is the only response that does not lie.
    """
    result, elapsed_ns = await _bounded(deps.upstream.list_tools(), ob)
    content: Any = _content(result)
    if not isinstance(content, dict):
        raise RouteDenial(
            ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE, detail="no result object"
        )
    doc = cast("JsonObject", content)
    advertised: Any = doc.get("tools")
    if not isinstance(advertised, list):
        raise RouteDenial(
            ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE,
            detail=f"{_LIST_METHOD} returned no tool list",
        )

    visible = {tool.name for tool in await _visible(ctx, deps)}
    kept: list[Any] = [
        entry
        for entry in cast("list[Any]", advertised)
        if isinstance(entry, dict) and cast("JsonObject", entry).get("name") in visible
    ]
    return _measure({**doc, "tools": kept}, _is_error(result), elapsed_ns, ob)


async def _visible(ctx: AuthzContext, deps: Deps) -> list[Any]:
    """`Registry.visible_tools` wants a synchronous predicate; OPA is asynchronous.

    So the answers are collected first and the predicate becomes a lookup. Asking OPA
    once per approved tool is n queries for a handful of tools; the alternative is one
    query returning a set, which moves the tool vocabulary into Rego — the thing
    `publish_config` exists to avoid.
    """
    allowed = {
        tool.name
        for tool in deps.registry.tools.values()
        if await policy.discoverable(deps.opa, deps.config.policy, ctx, tool.operation)
    }
    return deps.registry.visible_tools(ctx, lambda _ctx, tool: tool.name in allowed)


# ===========================================================================
# Obligations, timing, outcomes (ROUTE-005, 006, 010, 011, 012, 013)
# ===========================================================================


async def _bounded(call: Awaitable[Any], ob: Obligations) -> tuple[Any, int]:
    """One upstream call under its deadline. Returns `(result, elapsed_ns)`.

    `move_on_after` plus an explicit `cancelled_caught` check, not `fail_after`: it
    turns the deadline into a domain denial carrying the right reason code instead of
    letting a `TimeoutError` reach the pipeline's generic handler and be recorded as
    an internal defect (`_tech/07` §4, which names the attribute `cancel_caught` —
    anyio spells it `cancelled_caught`).

    ROUTE-013: the elapsed time measured here is the SDK round trip including child
    processing, which is the boundary the benchmark needs — `direct` mode measures the
    same round trip with no gateway in it, so `stage_latency_ms.route` minus this
    number is the router's own cost.
    """
    started = time.perf_counter_ns()
    result: Any = None

    def since() -> int:
        return time.perf_counter_ns() - started

    try:
        with anyio.move_on_after(ob.timeout_ms / 1000) as scope:
            result = await call
        if scope.cancelled_caught:
            # ponytail: no retry, on any path (ROUTE-011). The fixture has no
            # idempotency keys, so retrying a timed-out call could double a write —
            # and a timeout is precisely the case where the side effect may already
            # have happened. Revisit only with an idempotent business fixture
            # (_specs/90-deferred-register.md §6).
            raise RouteDenial(ReasonCode.ROUTE_TIMEOUT, detail=f"{ob.timeout_ms}ms")
    except anyio.get_cancelled_exc_class():
        # The client went away and `edge._run_watching_for_disconnect` cancelled us.
        # The SDK has already sent `notifications/cancelled` upstream from inside its
        # own shielded handler; all that is left is to say which of the four outcomes
        # this was, and then re-raise. NEVER swallow a cancellation: it breaks anyio's
        # cancel semantics and leaves the task group waiting on a task that returned.
        _record("cancelled", since())
        raise
    except RouteDenial as d:
        _record(_STATUS_BY_CODE.get(d.reason_code, "error"), since())
        raise
    return result, since()


def _measure(content: Any, is_error: bool, elapsed_ns: int, ob: Obligations) -> RawResult:
    """Size the response, enforce the ceiling, hand the rest to unit 08.

    See the module docstring for why this is a post-hoc measurement and what that
    changes about the claim.

    A tool returning `isError: true` is a SUCCESSFUL round trip with an error result,
    not a router failure — so it is passed through with its own status rather than
    raised. ROUTE-012 is satisfied by the status being distinct: unit 08 decides how
    the result is shaped for the client, and nothing here can report it as success.
    """
    size = len(hashing.canonical_json(content))
    audit().set(response_bytes=size)
    if size > ob.max_response_bytes:
        _record("too_large", elapsed_ns)
        raise RouteDenial(
            ReasonCode.ROUTE_RESPONSE_TOO_LARGE,
            detail=f"{size} bytes over {ob.max_response_bytes}",
        )
    _record("tool_error" if is_error else "ok", elapsed_ns)
    return RawResult(
        content=content,
        is_error=is_error,
        byte_count=size,
        upstream_latency_ns=elapsed_ns,
    )


def _record(status: str, latency_ns: int) -> None:
    """Stage 07's audit contribution, written from inside rather than returned.

    Every other stage contributes through `pipeline.handle` calling its
    `audit_fields()` on the way out. This one cannot: a timeout, a cancellation and a
    dead child all leave by raising, and those are exactly the outcomes the report
    needs to tell apart. A contribution that only survives the success path would
    describe the requests that went right.
    """
    audit().set(upstream_status=status, upstream_latency_ms=latency_ns / 1_000_000)


# ===========================================================================
# SDK result shapes
# ===========================================================================


def _content(result: Any) -> Any:
    """The JSON-RPC `result` object, as plain JSON for unit 08 to validate.

    `by_alias=True` because the wire spells `inputSchema` and pydantic spells
    `input_schema`; unit 08 and the client both expect the wire form.
    """
    dump: Any = getattr(result, "model_dump", None)
    if dump is None:
        return result
    return dump(by_alias=True, exclude_none=True, mode="json")


def _is_error(result: Any) -> bool:
    return bool(getattr(result, "is_error", False))


__all__ = ["forward", "route"]

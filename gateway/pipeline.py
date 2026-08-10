"""Stage composition. The ONLY module that expresses lifecycle order (CONV-002).

`_specs/00-conventions.md` §5, `_tech/00-conventions.md` §5.

CONV-001: a request that fails at stage N never reaches a stage that can produce a
side effect. There is no path from stages 1-6 to `router.forward` without a
validated allow.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this. Each unit exports
the function signature its stub declares; wiring is done centrally, one line per stage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import anyio

from gateway import canonicalize, identity, policy, protocol, registry, response, router
from gateway.audit import AuditBuilder, AuditSink
from gateway.config import Config
from gateway.context import current_audit
from gateway.errors import GatewayDenial, PolicyDenial, ReasonCode, Stage
from gateway.types import JsonObject, RawEnvelope, Untrusted


@dataclass(frozen=True)
class Deps:
    """Assembled once at startup. No globals, no service locator, no DI framework."""

    config: Config
    registry: registry.Registry
    opa: policy.PolicyEngine | None
    """`None` only where a test drives stages that end before policy. `evaluate`
    denies with POLICY_UNAVAILABLE rather than trusting the caller — an assembled
    gateway with no policy engine must not be a gateway that allows."""
    upstream: Any  # UpstreamHandle — unit 01
    audit: AuditSink  # unit 09


async def handle(env: RawEnvelope, deps: Deps) -> Untrusted[JsonObject]:
    """Run one request through the lifecycle. Exactly one audit event, always.

    The total request deadline lives HERE rather than at the edge, and that is not a
    layering preference. An outer `fail_after` around the whole request cancels this
    function, and an anyio cancellation carries no reason — so a deadline expiry and a
    client disconnect arrived identically, and the record said `cancelled` while the
    client was told `ROUTE_TIMEOUT`. ROUTE-010 requires the two to stay distinguishable.
    Owning the budget here makes the expiry a reason-coded denial with a `timeout`
    outcome, and leaves a bare cancellation meaning exactly one thing: the client left.
    """
    builder = AuditBuilder(env.request_id)
    token = current_audit.set(builder)
    try:
        with anyio.move_on_after(deps.config.edge.request_timeout_s):
            return await _stages(env, deps, builder)
        # Reached only when the deadline above cancelled the stages: `move_on_after`
        # swallows its own cancellation, so this is a normal fall-through rather than
        # an exception path, and naming the reason is the whole point of the move.
        #
        # Stage 07 already recorded `upstream_status="cancelled"`, because a bare anyio
        # cancellation is the only thing it can see from inside the await. THIS scope is
        # the one that knows better, and it is the only one that does — so it corrects
        # the attribution before the reason code is set. Skipping this left one event
        # claiming ROUTE_TIMEOUT and `cancelled` at once (Codex review).
        builder.reattribute_upstream_cancellation("timeout")
        raise GatewayDenial(
            ReasonCode.ROUTE_TIMEOUT, detail=f"{deps.config.edge.request_timeout_s}s"
        )
    except GatewayDenial as d:
        builder.record_denial(d)
        raise
    except anyio.get_cancelled_exc_class():
        # The client vanished — now the ONLY thing a bare cancellation can mean here,
        # because the deadline no longer arrives as one. ROUTE-010 keeps `cancelled`
        # distinct from `error` and from `timeout`: an abandoned request, a failed one
        # and an expired one mean different things to the report, and the upstream side
        # effect may have landed in any of the three. Re-raised immediately — swallowing
        # a cancellation breaks anyio's cancel semantics. The `finally` below still
        # writes, because the sink shields its own write.
        builder.record_cancellation()
        raise
    except Exception as e:  # internal defect -> deny, never allow (CONV-004)
        builder.record_internal_error(e)
        raise GatewayDenial(ReasonCode.INTERNAL_ERROR) from e
    finally:
        # Shielded inside the sink: a cancelled request must still be recorded,
        # or the completeness ratio silently drops below 1.0 (`_tech/09` §2).
        await builder.finalize_and_write(deps.audit, deps.config)
        current_audit.reset(token)


async def _stages(
    env: RawEnvelope, deps: Deps, builder: AuditBuilder
) -> Untrusted[JsonObject]:
    """The eight stages, in the one order there is.

    Split out of `handle` only so the request deadline can wrap them without indenting
    the entire lifecycle. Every denial it raises is handled by `handle`; nothing here
    catches anything, which is what keeps the stage list readable as a list.
    """
    with builder.stage(Stage.PROTOCOL):
        req = protocol.validate(env, deps.config.protocol)
    builder.set(**protocol.audit_fields(req))
    with builder.stage(Stage.IDENTITY):
        ctx = identity.resolve(req, deps.config.identity)
    builder.set(**identity.audit_fields(ctx))
    with builder.stage(Stage.REGISTRY):
        tgt = registry.resolve(req, ctx, deps.registry)
    builder.set(**registry.audit_fields(tgt))
    with builder.stage(Stage.CANONICAL):
        drv = canonicalize.derive(req, tgt, deps.config.canonicalize)
    # Overwrites stage 04's `operation` with the create/overwrite split, which is
    # what policy is about to evaluate. See `canonicalize.fs.audit_fields`.
    builder.set(**canonicalize.audit_fields(drv))
    with builder.stage(Stage.POLICY):
        dec = await policy.evaluate(req, ctx, tgt, drv, deps.opa, deps.config.policy)
        # Set INSIDE the stage so the record carries the decision even when a check
        # below rejects it: a policy result the gateway refused is exactly the thing an
        # investigator needs to see, and raising first would leave the audit event
        # saying only POLICY_RESULT_INVALID with nothing about what was invalid.
        builder.set(**policy.audit_fields(dec))
    if dec.decision != "allow":
        raise PolicyDenial(ReasonCode(dec.reason_code))
    if dec.risk_tier != tgt.registry_risk_tier:
        # The registry assigns the tier; policy must carry the same one. Stage 04
        # writes `risk_tier` into the record and stage 06 writes it again, and
        # `AuditBuilder.set` updates — so without this line a policy result claiming R0
        # for an R4 tool would both authorise the call and leave an audit record showing
        # only R0, erasing the divergence it caused. A comment saying "unit 06 must
        # agree" is not enforcement (Codex review).
        raise PolicyDenial(ReasonCode.POLICY_RESULT_INVALID)
    with builder.stage(Stage.ROUTE):
        # `route`, not `forward`: stage 07 gates, writes its intent record ahead of the
        # call (AUDIT-009), and dispatches — `tools/list` is filtered against
        # `data.gateway.discoverable` rather than forwarded verbatim (REG-010). It
        # writes its own audit fields, because a timeout and a cancellation leave by
        # raising and would otherwise contribute nothing.
        raw = await router.route(req, ctx, drv, dec, deps)
    with builder.stage(Stage.RESPONSE):
        # `raw.obligations`, NOT `dec.obligations`: unit 07 clamped what policy asked
        # for and audited the clamped value, so passing the decision's own number here
        # enforced a ceiling the record said had been lowered (Codex review). The
        # effective value now rides on the result and there is nothing else to pass.
        out = response.validate(raw, req, deps.config.response)
    builder.set_outcome("allowed")
    return out

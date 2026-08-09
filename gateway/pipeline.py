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
    registry: Any  # registry.Registry — unit 04
    opa: Any  # httpx.AsyncClient — unit 06
    upstream: Any  # UpstreamHandle — unit 01
    audit: AuditSink  # unit 09


async def handle(env: RawEnvelope, deps: Deps) -> Untrusted[JsonObject]:
    """Run one request through the lifecycle. Exactly one audit event, always."""
    builder = AuditBuilder(env.request_id)
    token = current_audit.set(builder)
    try:
        with builder.stage(Stage.PROTOCOL):
            req = protocol.validate(env, deps.config.protocol)
        builder.set(**protocol.audit_fields(req))
        with builder.stage(Stage.IDENTITY):
            ctx = identity.resolve(req, deps.config.identity)
        with builder.stage(Stage.REGISTRY):
            tgt = registry.resolve(req, ctx, deps.registry)
        with builder.stage(Stage.CANONICAL):
            drv = canonicalize.derive(req, tgt, deps.config.canonicalize)
        with builder.stage(Stage.POLICY):
            dec = await policy.evaluate(req, ctx, tgt, drv, deps.opa, deps.config.policy)
        if dec.decision != "allow":
            raise PolicyDenial(ReasonCode(dec.reason_code))
        with builder.stage(Stage.ROUTE):
            raw = await router.forward(req, drv, dec, deps.upstream, deps.config.router)
        with builder.stage(Stage.RESPONSE):
            out = response.validate(raw, req, dec.obligations, deps.config.response)
        builder.set_outcome("allowed")
        return out
    except GatewayDenial as d:
        builder.record_denial(d)
        raise
    except Exception as e:  # internal defect -> deny, never allow (CONV-004)
        builder.record_internal_error(e)
        raise GatewayDenial(ReasonCode.INTERNAL_ERROR) from e
    finally:
        # Shielded inside the sink: a cancelled request must still be recorded,
        # or the completeness ratio silently drops below 1.0 (`_tech/09` §2).
        await builder.finalize_and_write(deps.audit, deps.config)
        current_audit.reset(token)

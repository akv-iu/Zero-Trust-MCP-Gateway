"""03 - Principal derivation and authorization context.

Spec: _specs/03-svc-identity-resolver.md   Tech: _tech/03-svc-identity-resolver.md

The smallest module in the gateway, and its smallness is the design. On stdio there
is no cryptographic identity: the launcher process and its configuration ARE the
identity boundary. The one thing this unit must do is refuse to overstate that.

Almost all of that refusal is enforced by `types.AuthzContext`, not by code here:

    auth_method: Literal["local_config"]
    assurance:   Literal["unverified_local"]

Single-member literals, so emitting `oidc` or `authenticated` requires editing
`types.py` — a reviewable diff — and pyright fails the build in the meantime
(IDENT-002). A convention would be forgotten in six months.

There is no error path. The spec's failure table originally listed
`IDENT_CONTEXT_UNAVAILABLE` for "context cannot be constructed", but config
validation runs at startup and `AuthzContext` is seven assignments from values
already checked — so the case cannot occur, and `pipeline.handle` already turns any
unexpected exception into a denial. A reason code reachable by nothing is worse than
no code: CONV-010 requires every code to be exercised by a corpus scenario, and one
that cannot be would either sit permanently unproven or force a scenario that models
something the design says is impossible. Removed from `ReasonCode` (see
`_specs/03` §6, corrected). The spec was right that stdio identity exists at startup
or the gateway does not run; that leaves nothing to fail at request time.

Resist adding a `Principal` class, an `IdentityProvider` protocol, or a resolver
registry. There is exactly one identity per gateway process in v1, the deferred
register already records the trigger that would revive OIDC, and a single-member
interface is the speculative abstraction this project keeps out.
"""

from __future__ import annotations

from gateway.config import IdentityConfig
from gateway.types import AuthzContext, CanonicalRequest


def resolve(req: CanonicalRequest, cfg: IdentityConfig) -> AuthzContext:
    """Build the authorization context from configuration, and only from it.

    IDENT-003: `req` is deliberately unread. The parameter exists only so every
    pipeline stage has the same shape. Nothing a client sends — an argument named
    `principal`, an `Mcp-Principal` header a future spec revision might add, a
    `_meta.sub` — may influence, merge into, or fall back to the answer. Verified by
    `test_identity.py::test_resolve_never_reads_the_request`, which walks this
    function's AST and fails if the body references `req` at all: there is no payload
    shape that can defeat code which never looks at the payload.

    Not cached. `_tech/03` §1 suggested prebuilding one instance at startup, and an
    `lru_cache` did work — but IDENT-004 asks for a context that is IMMUTABLE once
    constructed, not for one object shared across the process, and seven frozen field
    assignments are not worth memoising on a path with no latency gate. Dropping it
    also drops a strong reference held for the life of the process and a dependency
    on pydantic frozen models being hashable, which pyright does not believe.

    `roles` is passed straight through. It was briefly wrapped in `tuple(...)` with a
    comment about mutable role sets being an escalation primitive; that was dead
    defence. `AuthzContext.roles` is annotated `tuple[str, ...]`, so pydantic coerces
    and freezes whatever it is handed — the ANNOTATION is the control, and the
    wrapper only made it look like the call site was. Breaking the wrapper failed no
    test; breaking the annotation failed one.
    """
    return AuthzContext(
        principal=cfg.principal,
        client_id=cfg.client_id,
        roles=cfg.roles,
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment=cfg.environment,
    )


def audit_fields(ctx: AuthzContext) -> dict[str, object]:
    """What stage 03 contributes to the record (spec §8).

    `auth_method` and `assurance` go into every event precisely so the suite-wide
    invariant in `conftest.py` has something to check: spec test 2 scans EVERY
    record emitted in a session, because the failure it guards against is some
    other module inventing a value.
    """
    return {
        "principal": ctx.principal,
        "client_id": ctx.client_id,
        "roles": ctx.roles,
        "auth_method": ctx.auth_method,
        "assurance": ctx.assurance,
        "environment": ctx.environment,
    }

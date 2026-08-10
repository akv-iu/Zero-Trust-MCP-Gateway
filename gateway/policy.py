"""06 - OPA integration, input/result contract, fail-closed.

Spec: _specs/06-svc-policy-broker.md   Tech: _tech/06-svc-policy-broker.md

THIS MODULE DOES NOT DECIDE. Rego decides. What lives here is the guarantee that a
decision was actually obtained, that it was well formed, and that anything else is a
denial. Every early return in this file is a deny; there is no path to `allow` that
does not go through a validated OPA answer (POLICY-005, POLICY-010).

POLICY-013, stated once so it cannot be quietly eroded: no code path maps a model
output, a classifier score, or an LLM response to `allow`. There is no advisory-model
input to policy in v1, and `PolicyInput` has no field one could travel in.

WHY A SIDECAR. OPA runs as its own process over its REST API rather than embedded.
Policy is then genuinely external (REQ-POL-001), the outage test is real rather than
simulated — kill a process, observe denials — and the added latency is a number the
benchmark publishes instead of a cost hidden inside the gateway.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import anyio
import httpx
from pydantic import BaseModel, ConfigDict

from gateway.config import Config, PolicyConfig
from gateway.errors import ALLOW_CODES, ConfigError, PolicyDenial, ReasonCode
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    Decision,
    DerivedAttributes,
    JsonObject,
    Obligations,
    ResolvedTarget,
    RiskTier,
)

_FROZEN = ConfigDict(frozen=True, extra="forbid")

BUNDLE_DIR: Final = Path("policies/rego")
"""Where the bundle lives, relative to the working directory — the same convention as
`registry_path`, `audit.path` and `canonicalize.roots[].path`."""

_CONFIG_DATA_PATH: Final = "/v1/data/config"
"""Where the gateway publishes what it owns. A deliberately separate subtree from
`data.gateway`, which the policy package writes: OPA refuses a base document that
collides with a rule, and a collision here would be a startup failure whose message
named neither side."""

_RISK_TIERS: Final[frozenset[str]] = frozenset({"R0", "R1", "R2", "R4"})


@dataclass(frozen=True)
class PolicyEngine:
    """The connection and the policy revision it was verified against, together.

    `pipeline.handle` passes `deps.opa` straight into `evaluate`, so whatever holds
    the revision has to be this object. Pairing them is not tidiness: a decision
    stamped with a revision the broker did not actually check is exactly the
    unattributable decision POLICY-014 exists to prevent, and two separate fields
    could drift apart in a refactor without anything failing.
    """

    client: httpx.AsyncClient
    revision: str


# ===========================================================================
# The input document (POLICY-001 … 004)
# ===========================================================================


class RequestBlock(BaseModel):
    model_config = _FROZEN
    request_id: str
    protocol_version: str
    transport: str
    method: str


class PrincipalBlock(BaseModel):
    model_config = _FROZEN
    id: str
    auth_method: str
    assurance: str
    roles: tuple[str, ...]
    environment: str


class ClientBlock(BaseModel):
    model_config = _FROZEN
    id: str


class TargetBlock(BaseModel):
    model_config = _FROZEN
    server_id: str
    tool_name: str | None
    schema_fingerprint: str | None
    registry_risk_tier: RiskTier


class ResourceBlock(BaseModel):
    model_config = _FROZEN
    canonical_path: str
    root: str
    classification: str
    exists: bool


class ArgumentsBlock(BaseModel):
    model_config = _FROZEN
    arg_hash: str
    operation: str


class ContextBlock(BaseModel):
    model_config = _FROZEN
    policy_revision: str


class PolicyInput(BaseModel):
    """What OPA is allowed to see. POLICY-002 enforced by the TYPE, not by review.

    There is no field on any block above that can hold a raw argument value, a secret,
    a file's contents, or free text — so "policy input carries no secrets" is a
    property of the shape rather than a rule someone has to remember. Spec test 8
    inspects every dispatched document across the suite, and with this structure that
    test is a regression guard rather than the primary defence.

    `canonical_path` IS here. It is bounded, it is contained within an approved root,
    and a decision that cannot name the resource it authorised is not reviewable —
    `AUDIT-006` reasons identically about the audit record.
    """

    model_config = _FROZEN

    request: RequestBlock
    principal: PrincipalBlock
    client: ClientBlock
    target: TargetBlock
    resource: ResourceBlock
    arguments: ArgumentsBlock
    context: ContextBlock


def build_input(
    req: CanonicalRequest,
    ctx: AuthzContext,
    tgt: ResolvedTarget,
    drv: DerivedAttributes,
    revision: str,
) -> PolicyInput:
    """POLICY-003: built only from canonical and derived values.

    Nothing here re-reads client input, re-parses arguments, or re-derives a path.
    Every value arrives from the stage that owns it, which is what makes the decision
    describe the same request the router will forward.
    """
    return PolicyInput(
        request=RequestBlock(
            request_id=req.request_id,
            protocol_version=req.protocol_version,
            transport=ctx.transport,
            method=req.method,
        ),
        principal=PrincipalBlock(
            id=ctx.principal,
            auth_method=ctx.auth_method,
            assurance=ctx.assurance,
            roles=ctx.roles,
            environment=ctx.environment,
        ),
        client=ClientBlock(id=ctx.client_id),
        target=TargetBlock(
            server_id=tgt.server_id,
            tool_name=tgt.tool_name,
            schema_fingerprint=tgt.schema_fingerprint,
            registry_risk_tier=tgt.registry_risk_tier,
        ),
        resource=ResourceBlock(
            canonical_path=drv.canonical_path,
            root=drv.root,
            classification=drv.classification,
            exists=drv.exists,
        ),
        arguments=ArgumentsBlock(arg_hash=drv.arg_hash, operation=drv.operation),
        context=ContextBlock(policy_revision=revision),
    )


# ===========================================================================
# Bundle revision (POLICY-014)
# ===========================================================================


def bundle_revision(directory: str | Path = BUNDLE_DIR) -> str:
    """A content hash over the `.rego` files, excluding the stamped constant itself.

    Not a git SHA, which `_tech/06` §5 proposed. A git SHA identifies the repository
    state, so it changes on every commit that touches anything and does not change
    when an uncommitted policy edit is what actually decided. This identifies the
    bundle: it moves when and only when the policy moves, which is what POLICY-014
    asks "identifies the exact bundle that decided" to mean.

    `revision.rego` is excluded because it holds the answer — including it would make
    the hash a function of itself.
    """
    d = Path(directory)
    h = hashlib.sha256()
    for f in sorted(d.rglob("*.rego"), key=lambda p: p.relative_to(d).as_posix()):
        if f.name == "revision.rego":
            continue
        h.update(f.relative_to(d).as_posix().encode("utf-8"))
        h.update(b"\0")
        # Newlines normalised: git checks these files out with CRLF on Windows and LF
        # on Linux, and a revision that differs by platform would report two policies
        # where there is one.
        h.update(f.read_bytes().replace(b"\r\n", b"\n"))
        h.update(b"\n")
    return h.hexdigest()[:16]


# ===========================================================================
# Startup (POLICY-014, POLICY-015)
# ===========================================================================


async def publish_config(client: httpx.AsyncClient, cfg: Config) -> None:
    """Push what the GATEWAY owns into `data.config`, rather than restating it in Rego.

    Two values, and both have exactly one home in `config/gateway.toml`:

    `role_vocabulary` — `_tech/03` §3 anticipated duplicating this as `data.roles` and
    keeping the copies in sync with a test. A role present in config and absent from
    policy denies everything for that principal while looking like a decision, and the
    cheapest fix for a sync bug is having nothing to sync.

    `roots` — the per-operation ceilings from `[[canonicalize.roots]]`. Unit 05 reports
    which root a path landed in and enforces none of the flags; this is what carries
    them to the only stage entitled to enforce them.

    This publishes DATA, not policy. POLICY-015's "no runtime policy edit surface"
    stands: the rules come from the immutable bundle on disk and nothing here can add,
    remove, or alter one.
    """
    document = {
        "role_vocabulary": list(cfg.identity.role_vocabulary),
        "roots": {
            r.name: {
                "classification": r.classification,
                "read": r.read,
                "create": r.create,
                "overwrite": r.overwrite,
                "append": r.append,
                "rename": r.rename,
                "delete": r.delete,
            }
            for r in cfg.canonicalize.roots
        },
    }
    try:
        response = await client.put(_CONFIG_DATA_PATH, json=document)
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise ConfigError(f"cannot publish gateway config to OPA: {e}") from e


async def check_bundle(client: httpx.AsyncClient, revision: str) -> None:
    """Startup: OPA is serving THIS bundle, and the bundle agrees with the config.

    Three failures, all silent without this, all of them producing decisions that look
    correct:

    * OPA loaded a different copy of `policies/rego` — a stale directory, or a policy
      edited since the sidecar started, since `--watch` is deliberately off. Caught by
      comparing the stamped `policy_revision` constant to the hash of the files on
      disk. `scripts/sync_policy_revision.py` restamps it.
    * A role in `identity.role_vocabulary` with no entry in `grants` — every request
      for that principal becomes POLICY_DEFAULT_DENY, which reads as a decision.
    * A grant naming a role or a root that no longer exists — dead lines in the one
      file a reviewer reads as the authorization matrix.
    """
    stamped = await _query(client, "/v1/data/gateway/policy_revision")
    if stamped != revision:
        raise ConfigError(
            f"OPA is serving policy revision {stamped!r} but {BUNDLE_DIR} hashes to "
            f"{revision!r}. Restart OPA against this bundle, or run "
            "`python -m scripts.sync_policy_revision` if the stamp is stale."
        )
    for rule, complaint in (
        ("roles_without_grants", "roles in identity.role_vocabulary have no grants"),
        ("grants_without_roles", "grants name roles that are not in the vocabulary"),
        ("grants_naming_unknown_roots", "grants name roots the gateway does not approve"),
        ("grants_on_prohibited_roots", "grants name roots a prohibition already refuses"),
    ):
        if offenders := await _query(client, f"/v1/data/gateway/{rule}"):
            raise ConfigError(f"{complaint}: {offenders}")


async def _query(client: httpx.AsyncClient, path: str) -> Any:
    try:
        response = await client.get(path)
        response.raise_for_status()
        return response.json().get("result")
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        raise ConfigError(f"cannot query OPA at {path}: {e}") from e


# ===========================================================================
# Evaluation
# ===========================================================================


async def evaluate(
    req: CanonicalRequest,
    ctx: AuthzContext,
    tgt: ResolvedTarget,
    drv: DerivedAttributes,
    opa: Any,
    cfg: PolicyConfig,
) -> Decision:
    """Ask OPA. Anything other than a well-formed allow denies (POLICY-005/010)."""
    if not isinstance(opa, PolicyEngine):
        # No engine means no decision, and no decision means deny. Reached when the
        # gateway was assembled without a policy engine at all, which is a deployment
        # error and must not be a quiet allow.
        raise PolicyDenial(ReasonCode.POLICY_UNAVAILABLE, detail="no OPA engine")

    payload = {"input": build_input(req, ctx, tgt, drv, opa.revision).model_dump()}
    result = await _post_decision(opa.client, cfg, payload)
    return validate_result(result, req, opa.revision, cfg, drv.arg_hash)


async def _post_decision(
    client: httpx.AsyncClient, cfg: PolicyConfig, payload: JsonObject
) -> Any:
    """One query, one decision, one deadline (POLICY-011).

    A single retry, and only on a transport-level connect error — a connection refused
    before any byte was sent cannot have evaluated anything, so retrying it is not
    retrying a decision. A TIMEOUT is never retried: the evaluation may have completed
    and the second answer would be a second decision for one request. A 200 is never
    retried, whatever it said; retrying a deny is how a fail-closed system becomes a
    poll-until-allow system.
    """
    last: Exception | None = None
    for attempt in (1, 2):
        try:
            with anyio.fail_after(cfg.timeout_ms / 1000):
                response = await client.post(cfg.decision_path, json=payload)
                response.raise_for_status()
                return response.json().get("result")
        except TimeoutError as e:
            raise PolicyDenial(ReasonCode.POLICY_TIMEOUT, detail=str(e)) from e
        except (httpx.ConnectError, httpx.ReadError) as e:
            last = e
            if attempt == 2:
                break
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as e:
            raise PolicyDenial(ReasonCode.POLICY_UNAVAILABLE, detail=str(e)) from e
    raise PolicyDenial(ReasonCode.POLICY_UNAVAILABLE, detail=str(last)) from last


def validate_result(
    result: Any,
    req: CanonicalRequest,
    revision: str,
    cfg: PolicyConfig,
    arg_hash: str = "",
) -> Decision:
    """Where fail-closed lives. Every branch below is a denial (POLICY-005 … 007).

    `result is None` is handled FIRST and explicitly. OPA answers HTTP 200 with `{}`
    when the queried path is undefined, so a typo in a rule name — or a bundle that
    failed to load — arrives here as a successful response carrying nothing. Any
    truthiness check on it would be the most expensive bug this file could contain.
    """
    if result is None:
        raise PolicyDenial(
            ReasonCode.POLICY_DEFAULT_DENY, detail="OPA returned no result"
        )
    if not isinstance(result, dict):
        raise PolicyDenial(
            ReasonCode.POLICY_RESULT_INVALID, detail="result is not an object"
        )
    # `isinstance(result, dict)` narrows to `dict[Unknown, Unknown]` under strict mode,
    # which poisons every value read out of it. Cast once, immediately after the check
    # that makes the cast true, rather than annotating each read.
    doc = cast("Mapping[str, Any]", result)

    verdict: Any = doc.get("decision")
    if verdict not in ("allow", "deny"):
        raise PolicyDenial(
            ReasonCode.POLICY_RESULT_INVALID, detail=f"decision={verdict!r}"
        )

    code: Any = doc.get("reason_code")
    try:
        reason = ReasonCode(code)
    except ValueError as e:
        # POLICY-006: an allow without a recognised code is malformed, and so is a
        # deny. A code outside the closed set means the bundle and this build disagree
        # about the vocabulary, which is not a decision either way.
        raise PolicyDenial(
            ReasonCode.POLICY_RESULT_INVALID, detail=f"reason_code={code!r}"
        ) from e
    if (verdict == "allow") != (reason in ALLOW_CODES):
        # A `deny` carrying POLICY_SCOPED_READ, or an `allow` carrying
        # POLICY_PATH_NOT_PERMITTED. Either way the two halves of the answer disagree,
        # and the audit record would say the opposite of what happened.
        raise PolicyDenial(
            ReasonCode.POLICY_RESULT_INVALID,
            detail=f"{verdict} is inconsistent with {reason.value}",
        )

    tier: Any = doc.get("risk_tier")
    if tier not in _RISK_TIERS:
        raise PolicyDenial(ReasonCode.POLICY_RESULT_INVALID, detail=f"risk_tier={tier!r}")

    if not revision:
        raise PolicyDenial(ReasonCode.POLICY_REVISION_UNKNOWN, detail="empty revision")

    obligations, clamped = clamp(doc.get("obligations"), cfg)
    return Decision(
        request_id=req.request_id,
        decision=verdict,
        reason_code=reason.value,
        risk_tier=cast("RiskTier", tier),
        policy_revision=revision,
        obligations=obligations,
        # ROUTE-002: the value policy actually saw. Unit 07 recomputes it from `drv`
        # before forwarding and refuses on a mismatch, so it has to be the derived
        # hash and not something reconstructed here from the same inputs a second
        # time — a second derivation would agree with itself for the wrong reason.
        arg_hash=arg_hash,
        clamped=clamped,
    )


def clamp(raw: Any, cfg: PolicyConfig) -> tuple[Obligations, bool]:
    """POLICY-007. `min` only: policy may NARROW a limit, never widen one.

    This is the single place a policy output feeds an enforcement limit, so it is the
    single place a policy bug could become a gateway bug. Clamping is not a denial —
    the request proceeds under the clamped value — but it is audited
    (`POLICY_OBLIGATION_CLAMPED` alongside the real code), because a policy asking for
    more than the gateway will give is a disagreement someone should see.

    A non-numeric or missing obligation takes the configured default rather than
    denying: the ceiling is what protects the router, and a policy that omitted a
    field has not asked for anything dangerous.
    """
    values: Mapping[str, Any] = {}
    if isinstance(raw, dict):
        values = cast("Mapping[str, Any]", raw)
    asked_timeout = _bounded(values.get("timeout_ms"), cfg.default_timeout_ms, None)
    asked_limit = _bounded(
        values.get("max_response_bytes"), cfg.default_response_bytes, None
    )
    timeout = min(asked_timeout, cfg.max_timeout_ms)
    limit = min(asked_limit, cfg.max_response_bytes)
    return (
        Obligations(timeout_ms=timeout, max_response_bytes=limit),
        (timeout, limit) != (asked_timeout, asked_limit),
    )


def _bounded(value: Any, default: int, ceiling: int | None) -> int:
    """`isinstance(True, int)` is True in Python, so a boolean obligation would
    otherwise become a one-millisecond timeout rather than the default."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        value = default
    return value if ceiling is None else min(value, ceiling)


# ===========================================================================
# Wiring
# ===========================================================================


def client_for(cfg: PolicyConfig) -> httpx.AsyncClient:
    """One client for the process. v1 serialises upstream calls, so one connection."""
    return httpx.AsyncClient(
        base_url=cfg.base_url,
        timeout=cfg.timeout_ms / 1000,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
    )


def audit_fields(dec: Decision) -> JsonObject:
    """What stage 06 contributes to the record (POLICY-014).

    `obligations` is written as ENFORCED, never as requested — the audit schema's own
    comment says so, and after clamping those are different numbers. The requested
    value is not recorded; `obligations_clamped` says that a request was narrowed, and
    the policy revision says which bundle asked for it.
    """
    return {
        "decision": dec.decision,
        "reason_code": dec.reason_code,
        "risk_tier": dec.risk_tier,
        "policy_revision": dec.policy_revision,
        "obligations": dict(dec.obligations.model_dump()),
        "obligations_clamped": dec.clamped,
    }


__all__ = [
    "BUNDLE_DIR",
    "PolicyEngine",
    "PolicyInput",
    "audit_fields",
    "build_input",
    "bundle_revision",
    "check_bundle",
    "clamp",
    "client_for",
    "evaluate",
    "publish_config",
    "validate_result",
]

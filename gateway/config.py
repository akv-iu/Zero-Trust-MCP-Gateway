"""Configuration. TOML via stdlib `tomllib`, validated into frozen pydantic.

CONV-013: unknown fields FAIL STARTUP. There is no runtime mutation surface.
CONV-015: every limit here has a documented default and boundary tests.

WAVE-0 FILE — shared spine. Each wave-1 agent owns the *values* in its own section
but MUST NOT restructure this file. Need a new key? Report it; it gets added centrally.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from gateway.errors import ConfigError

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class EdgeConfig(BaseModel):
    """01 — client-facing Streamable HTTP edge (ADR-001)."""

    model_config = _FROZEN

    host: str = "127.0.0.1"  # loopback only; spec-mandated for local servers
    port: int = 8080
    mcp_path: str = "/mcp"
    allowed_origins: tuple[str, ...] = ()
    max_message_bytes: int = 1_048_576
    max_concurrent_requests: int = 4
    request_timeout_s: float = 30.0

    @model_validator(mode="after")
    def _loopback_only(self) -> EdgeConfig:
        if self.host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("edge.host must be loopback in v1 (REQ-SEC-012)")
        return self


class ChildTuning(BaseModel):
    """01 — `[child]` in gateway.toml. Bridge-owned values ONLY.

    The launch parameters — executable, argv, cwd, environment allowlist — are NOT
    here. They live in `config/registry.toml` and nowhere else (REG-002: "unit 01
    takes its launch parameters from here and only here").

    They used to be duplicated in this section, kept equal by a test. A test that
    compares two copies does not make one of them the source: a deployment that
    edited only one would fingerprint one process and run another, and the check
    would pass right up until the two files disagreed. `extra="forbid"` now makes
    the old keys a startup failure rather than a silently-ignored second opinion.

    Timeouts and buffer sizes stay: they are how the BRIDGE behaves, not what the
    upstream is, and the registry has no business describing them.
    """

    model_config = _FROZEN

    startup_timeout_s: float = 10.0
    shutdown_grace_s: float = 5.0
    stderr_capture_lines: int = 256


class ChildConfig(ChildTuning):
    """What `bridge.upstream` consumes: tuning plus the registry's launch parameters.

    Never loaded from TOML. Built by `registry.ServerEntry.child_config(tuning)`,
    which is the only constructor, so there is exactly one runtime path from an
    approved registry entry to a spawned process.
    """

    executable: str
    args: tuple[str, ...] = ()
    cwd: str
    env_allowlist: tuple[str, ...] = ("PATH",)


class ProtocolConfig(BaseModel):
    """02."""

    model_config = _FROZEN

    supported_versions: tuple[str, ...] = ("2026-07-28",)
    allowed_methods: tuple[str, ...] = ("tools/list", "tools/call")
    recognized_denied: tuple[str, ...] = ("server/discover", "subscriptions/listen")
    max_depth: int = 32
    max_body_bytes: int = 1_048_576
    max_array_length: int = 1_000
    max_string_length: int = 65_536
    max_object_keys: int = 500
    """Keys in ONE object. Distinct from `max_total_fields`, which is the whole
    document: a single object with 4,999 keys passes a 5,000-field budget while
    being exactly the shape that makes a downstream schema validator quadratic."""
    max_total_fields: int = 5_000
    parse_budget_ms: int = 100


class IdentityConfig(BaseModel):
    """03."""

    model_config = _FROZEN

    principal: str
    client_id: str
    roles: tuple[str, ...]
    environment: str = "development"
    role_vocabulary: tuple[str, ...] = ("intern", "developer", "auditor")
    """The closed role set, and its only home.

    `_tech/03` §3 anticipated duplicating this in Rego as `data.roles` and keeping
    the two in sync with a test. Unit 06 must PUBLISH this to OPA instead: a role
    that exists in config but not in policy silently denies everything for that
    principal, and the cheapest fix for a sync bug is to have nothing to sync.
    Guarded by `test_identity.py::test_the_role_vocabulary_has_one_home`."""

    @model_validator(mode="after")
    def _check(self) -> IdentityConfig:
        if not self.principal or not self.client_id:
            raise ValueError("identity.principal and identity.client_id are required")
        unknown = set(self.roles) - set(self.role_vocabulary)
        if unknown:
            raise ValueError(f"unknown roles: {sorted(unknown)}")
        return self


class RootConfig(BaseModel):
    """05 — one approved filesystem root and its per-operation permissions.

    A root is an area the gateway is willing to *name*. A resolved path inside no
    root cannot be canonicalized at all and is denied at stage 05; a resolved path
    inside a root is canonicalized, classified, and handed to policy — which is what
    then applies the flags below. Unit 05 does not enforce them, deliberately: an
    operation refused because the ROOT forbids it and one refused because the
    PRINCIPAL may not perform it are the same sentence to a reader of the audit log,
    and only one of them is a policy decision. The flags are policy input, published
    to OPA as data by unit 06.

    So a directory holding data nobody may touch is still listed here — with every
    flag false. Leaving it out instead would collapse "you asked for something
    outside the world I know about" and "you asked for confidential data" into one
    reason code, and the second is the interesting one.
    """

    model_config = _FROZEN

    name: str
    path: str
    classification: str
    read: bool = False
    create: bool = False
    overwrite: bool = False
    append: bool = False
    rename: bool = False
    delete: bool = False

    @model_validator(mode="after")
    def _named(self) -> RootConfig:
        # `DerivedAttributes.root` uses "" for a request that names no resource
        # (`tools/list`). An empty root name would make that sentinel ambiguous.
        if not self.name or not self.classification:
            raise ValueError("every root needs a non-empty name and classification")
        return self


class CanonicalizeConfig(BaseModel):
    """05."""

    model_config = _FROZEN

    base: str = "var/fixture"
    """The directory a client-supplied relative path is resolved against.

    **This MUST equal the base the upstream server uses**, or the gateway
    canonicalizes one file and the upstream opens another — it would authorize
    resource A and cause a side effect on resource B, with an audit record naming A.
    That is the worst failure this unit can have, and it is silent.

    For the v1 fixture the upstream is `fixtures/filesystem_server`, which resolves
    `root / path` with `root = $FIXTURE_ROOT` (default `var/fixture`). Held by
    `test_shipped_config.py::test_the_canonicalize_base_matches_the_fixture_root`,
    which lives there rather than here because the gateway must not know fixture
    internals — it is a property of the shipped PAIR of configurations.

    Distinct from a root: the base is where paths are interpreted, the roots are
    where they are allowed to land. Making the base a root would approve the whole
    tree.
    """
    roots: tuple[RootConfig, ...]
    max_path_length: int = 4_096
    sensitive_decoys: tuple[str, ...] = ()
    """Paths relative to `base`, denied outright (CANON-014). A file matches, and so
    does anything under a listed directory."""
    decode_rule_version: Literal["v1"] = "v1"
    """Which decode rule this configuration was written against.

    `canonicalize.fs` refuses to start if it implements a different one, the same
    control as `hashing.FINGERPRINT_VERSION` — where a rule changed while the version
    string did not, and only the golden test caught it. `max_resolution_depth` used
    to sit here and is gone: symlink depth is enforced by the OS (`ELOOP`) and
    surfaced as `CANON_RESOLUTION_FAILED`, and a gateway-side counter would require
    the hand-rolled component walk `_tech/05` §10 forbids. A limit nothing enforces
    fails CONV-015 more loudly than a missing one.
    """


class PolicyConfig(BaseModel):
    """06."""

    model_config = _FROZEN

    base_url: str = "http://127.0.0.1:8181"
    decision_path: str = "/v1/data/gateway/decision"
    discoverable_path: str = "/v1/data/gateway/discoverable"
    timeout_ms: int = 500
    max_timeout_ms: int = 10_000
    default_timeout_ms: int = 3_000
    max_response_bytes: int = 4_194_304
    default_response_bytes: int = 1_048_576
    cache_enabled: bool = False  # POLICY-012: measure before enabling


class RouterConfig(BaseModel):
    """07. Ceilings must equal policy's clamp values — asserted below."""

    model_config = _FROZEN

    max_timeout_ms: int = 10_000
    max_response_bytes: int = 4_194_304
    cancellation_grace_ms: int = 1_000


class ResponseConfig(BaseModel):
    """08. Deliberately looser than protocol limits — results are bigger than requests."""

    model_config = _FROZEN

    max_bytes: int = 4_194_304
    max_depth: int = 32
    max_array_length: int = 10_000
    max_string_length: int = 1_048_576
    max_total_fields: int = 20_000


class AuditConfig(BaseModel):
    """09."""

    model_config = _FROZEN

    path: str = "var/audit.jsonl"
    durable: bool = True  # AUDIT-011; the benchmark reports which mode produced it
    max_bytes: int = 268_435_456
    max_age_days: int = 7
    rotate_keep: int = 5
    capture_stage_latency: bool = True


class Config(BaseModel):
    model_config = _FROZEN

    registry_path: str = "config/registry.toml"
    edge: EdgeConfig = Field(default_factory=EdgeConfig)
    child: ChildTuning = Field(default_factory=ChildTuning)
    protocol: ProtocolConfig = Field(default_factory=ProtocolConfig)
    identity: IdentityConfig
    canonicalize: CanonicalizeConfig
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    router: RouterConfig = Field(default_factory=RouterConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    @model_validator(mode="after")
    def _ceilings_agree(self) -> Config:
        # Policy clamps what it returns; the router enforces what it received.
        # They must not drift (`_tech/07` §8).
        if self.policy.max_timeout_ms != self.router.max_timeout_ms:
            raise ValueError("policy.max_timeout_ms must equal router.max_timeout_ms")
        if self.policy.max_response_bytes != self.router.max_response_bytes:
            raise ValueError(
                "policy.max_response_bytes must equal router.max_response_bytes"
            )
        if self.response.max_bytes < self.router.max_response_bytes:
            raise ValueError("response.max_bytes must be >= router.max_response_bytes")
        return self

    def self_check(self, config_path: str | Path | None = None) -> None:
        """CANON-015: gateway-owned paths must lie outside every approved root.

        Called at startup, before readiness. Uses the same segment-aware comparison
        as the request path, so a containment bug shows up here too.

        `config_path` is passed in because a `Config` does not know where it came
        from, and CANON-015 names the gateway's own configuration first. Optional so
        the check still runs against a synthesised config; `startup.load_all` always
        supplies it.
        """
        roots = [Path(r.path).resolve() for r in self.canonicalize.roots]
        # The child's cwd used to be listed here. It comes from the registry now
        # (REG-002) and `self_check` deliberately reads only what THIS file owns —
        # a config method reaching into the registry to validate itself is how the
        # two get coupled again.
        protected = [
            Path(self.registry_path),
            Path(self.audit.path),
        ]
        if config_path is not None:
            protected.append(Path(config_path))
        for p in protected:
            rp = p.resolve()
            for root in roots:
                if rp == root or rp.is_relative_to(root):
                    raise ConfigError(f"{p} lies inside approved root {root}")


def load(path: str | Path) -> Config:
    """Parse and validate. Any unknown key raises (CONV-013)."""
    p = Path(path)
    try:
        with p.open("rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError as e:
        raise ConfigError(f"config not found: {p}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {p}: {e}") from e
    try:
        return Config.model_validate(raw)
    except Exception as e:
        raise ConfigError(f"invalid config in {p}: {e}") from e

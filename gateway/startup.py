"""Bring the gateway up, in the one order that is safe. Then, and only then, ready.

`_specs/04` REG-006 / REG-009 put drift detection "at upstream handshake ... before
readiness", and `_tech/04` §4 spells out the sequence. Until this module existed the
sequence lived only in a test and in `scripts/fingerprint_tools.py`: `Registry.load`
and `verify_schemas` had **no production caller**, so a real gateway would have
served requests against fingerprints nobody compared. The registry denied them with
`REG_SCHEMA_UNVERIFIED` — fail-closed, and useless, because it would have denied
every request forever.

    load config -> load registry -> open the audit sink -> spawn the child
      -> handshake -> verify_schemas -> write drift events -> READY

Nothing here is best-effort. Every step that cannot complete raises before readiness,
because a gateway that is up but unverified is worse than one that is down: it looks
like it is enforcing.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from gateway import bridge, registry
from gateway.audit import AuditSink
from gateway.audit_schema import LifecycleEvent
from gateway.config import Config
from gateway.config import load as load_config
from gateway.errors import ConfigError
from gateway.pipeline import Deps


def load_all(config_path: str | Path) -> tuple[Config, registry.Registry]:
    """Config and registry, both validated, before anything is spawned or opened.

    Separate from `serve` so a caller can check its configuration without launching
    a child — which is what `--check`-style tooling and most tests actually want.
    """
    cfg = load_config(config_path)
    cfg.self_check(config_path)
    # `registry_path` resolves against the working directory, exactly like
    # `audit.path` and `canonicalize.roots[].path`. Resolving it against the config
    # FILE's location instead would be a second convention for the same kind of
    # value, and it breaks the moment a config is copied somewhere for a test.
    reg = registry.Registry.load(cfg.registry_path)
    return cfg, reg


def check_protocol_version(reg: registry.Registry, cfg: Config) -> None:
    """The registry's `expected_protocol_version` against what unit 02 will accept.

    This field was stored and never read — a declared expectation that nothing
    enforced. It is worth enforcing because the two are independently editable and a
    disagreement is silent: `protocol.supported_versions` decides what the gateway
    accepts from the CLIENT, while this says which revision the approved upstream
    speaks. Approving a server for a version the guard rejects means every request is
    denied at stage 02 with a version error that names the client, not the mismatch.

    Startup is the only honest place to compare them: per-request it would be the
    same answer every time, and by then readiness has already been claimed.
    """
    expected = reg.server.expected_protocol_version
    if expected not in cfg.protocol.supported_versions:
        raise ConfigError(
            f"registry approves {reg.server.id} for protocol {expected!r}, which is "
            f"not in protocol.supported_versions {list(cfg.protocol.supported_versions)}"
        )


@asynccontextmanager
async def serve(config_path: str | Path) -> AsyncGenerator[Deps]:
    """The full sequence. Yields assembled `Deps` only once the gateway is READY.

    The child is spawned inside `bridge.upstream`, so leaving this context tears it
    down; there is no path where the gateway is serving and the child is not the one
    that was verified.

    Drift events are written HERE rather than inside `verify_schemas`, which returns
    them instead of logging. That keeps `Registry` usable without a filesystem and
    puts the audit dependency in the module that already owns the sink.
    """
    cfg, reg = load_all(config_path)
    check_protocol_version(reg, cfg)

    sink = AuditSink.from_config(cfg)
    try:
        # AUDIT-010, as a `startup` record rather than `AuditSink.readiness_probe()`.
        # The probe writes `kind="ready"`, which at this point is a lie: the child has
        # not been spawned and nothing has been verified. Two records claiming
        # readiness at different truth values is worse than none, and the first one
        # is the one a reader finds. This proves the same thing — the sink accepts a
        # write — under a label that is true when it is written.
        try:
            sink.write_sync(
                LifecycleEvent(
                    ts=datetime.now(UTC),
                    kind="startup",
                    detail={"config": str(config_path)},
                )
            )
        except OSError as e:
            raise ConfigError(f"audit sink is not writable: {cfg.audit.path}") from e

        async with bridge.upstream(reg.server.child_config(cfg.child)) as up:
            advertised = [
                t.model_dump(by_alias=True, exclude_none=True)
                for t in (await up.list_tools()).tools
            ]
            for event in reg.verify_schemas(advertised):
                # REG-006: every drift event is audited. Written before readiness so
                # a quarantine can never be discovered only from a denial later.
                sink.write_sync(event)

            sink.write_sync(
                LifecycleEvent(
                    ts=datetime.now(UTC),
                    kind="ready",
                    detail={
                        "server_id": reg.server.id,
                        "approved_tools": str(len(reg.tools)),
                        "quarantined": ",".join(sorted(reg.quarantined)) or "none",
                    },
                )
            )
            yield Deps(config=cfg, registry=reg, opa=None, upstream=up, audit=sink)

        sink.write_sync(LifecycleEvent(ts=datetime.now(UTC), kind="shutdown", detail={}))
    finally:
        sink.close()


__all__ = ["check_protocol_version", "load_all", "serve"]

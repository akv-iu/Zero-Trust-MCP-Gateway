# Zero-Trust MCP Gateway

A default-deny enforcement point between an MCP client and an MCP server. Every
`tools/call` is authorized against deterministic policy before the upstream side
effect can occur. Built against the **MCP 2026-07-28 stateless specification**.

The deliverable is **evidence**, not features: a published attack corpus, a
side-effect oracle that observes the protected filesystem rather than trusting the
gateway's own output, a measured overhead distribution, and an audit trail with a
measured completeness ratio.

Scope, milestones and the verification method are in [PLAN.md](PLAN.md). What each
unit must do is in [`_specs/`](_specs/); how to build it is in [`_tech/`](_tech/).

## Status

Units built: foundation, 10 (fixture), 11 (harness skeleton), 09 (audit), 01 (HTTP
edge + stdio upstream bridge), 02 (protocol guard), 03 (identity). Remaining units
are stubs that raise `NotImplementedError` naming their owner. Build order and
state: [PLAN.md §4.2](PLAN.md).

The client edge is **Streamable HTTP on loopback**; only the upstream leg to the
child server is stdio ([ADR-001](_specs/ADR-001-transport-and-mirrored-metadata.md)).

## What this does not protect against

**A local `stdio` client that is separately configured with direct access to the
protected MCP server bypasses this gateway entirely. The gateway cannot detect or
prevent that configuration. Removing every direct client-to-server route is a
deployment responsibility.**

This is inherent to the deployment model, not a defect being worked on. The gateway
sits in one path; it cannot see a second one. The evaluation harness asserts that no
second route exists in the *test* configuration, which is a configuration assertion,
not a security control.

Two further limits worth stating before anyone reads the numbers:

- **Identity is `unverified_local`, and the edge authenticates no caller.** The
  loopback socket carries no verified identity, and nothing binds it to the process
  that launched the gateway — so **any local process that can open a loopback
  connection is authorized and audited as the configured principal.** The gateway
  records `auth_method=local_config` and refuses to claim anything stronger. It
  performs authorization, not authentication. v1's position is that every local
  process is one trust domain; distinct principals must not be co-hosted outside a
  test harness ([threat model §1.2](docs/threat-model.md)).
- **The benchmark is co-located.** Client, gateway, policy engine and server run on
  one machine. The overhead figure is real and the caveat travels with it.

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Running it

```bash
python -m pytest tests/ -q            # full suite; no network, no API key
python -m scripts.damage_demo         # what an unprotected client can do
python -m scripts.run_corpus          # score the corpus, direct mode
ruff check . && ruff format --check .
pyright gateway harness scripts
```

Development targets WSL2, which gives the strong fixture-isolation tier and working
symlinks. On Windows three symlink tests skip (reported SKIPPED, never passed) and
the fixture runs on the *weak* tier, which stamps `isolation: weak` on every
benchmark report.

OPA is a required external binary for units 06 and later (sidecar on
`127.0.0.1:8181`).

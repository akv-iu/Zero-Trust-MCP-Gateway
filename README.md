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
edge + stdio upstream bridge), 02 (protocol guard), 03 (identity), 04 (registry),
05 (filesystem canonicalizer), 06 (OPA policy broker + Rego bundle). Remaining units
are stubs that raise `NotImplementedError` naming their owner — a request reaching one
is denied, never passed. Build order and state: [PLAN.md §4.2](PLAN.md).

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
- **Path canonicalization is defense in depth, not a race-free guarantee.** The
  primary filesystem control is the sandbox mount. The gateway resolves a path,
  policy authorizes the resolved path, and then the *client's original string* is
  forwarded — the upstream resolves it again, itself. That window cannot be closed
  from here. v1 tests canonicalization correctness exhaustively and does **not**
  claim TOCTOU safety ([threat model §1.5](docs/threat-model.md)).
- **The benchmark is co-located.** Client, gateway, policy engine and server run on
  one machine. The overhead figure is real and the caveat travels with it.
- **Symlink tests skip on Windows** without Developer Mode, and skips are reported as
  skips — never counted as passes. Read the skip list before the pass count.

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

## OPA

A required external binary since unit 06, and the version is pinned: Rego syntax
differs between OPA 0.x and 1.x, and a bundle authored against one fails — or worse,
evaluates differently — on the other. This bundle is **1.x** (`import rego.v1`, bare
`if`/`contains`), developed against **1.19.0**.

```bash
# Any 1.x binary on PATH works; the sidecar also looks in .tools/ and at $ZTMG_OPA_BIN
python -m scripts.opa_sidecar          # serve policies/rego on 127.0.0.1:8181
opa test policies/                     # the policy's own suite — no Python involved
python -m scripts.sync_policy_revision # restamp after editing any .rego
```

The gateway never launches OPA. In a real deployment the sidecar is somebody else's
process, and a gateway that could start its own policy engine could also restart one
it had just found unhealthy — which is how fail-closed becomes fail-eventually.

Tests that need it **skip** when it is absent, and skips are reported as skips. A
suite that passed quietly without OPA would be reporting on a gateway that has no
policy engine at all.

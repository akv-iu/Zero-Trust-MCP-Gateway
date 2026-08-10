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
Every number below, with the command that produced it and the two that are *not*
claimed: [docs/reproducing-the-evidence.md](docs/reproducing-the-evidence.md).

## Status

Units built: foundation, 10 (fixture), 09 (audit), 01 (HTTP edge + stdio upstream
bridge), 02 (protocol guard), 03 (identity), 04 (registry), 05 (filesystem
canonicalizer), 06 (OPA policy broker + Rego bundle), 07 (upstream router), 08
(response guard), and 11 (evaluation harness). **The pipeline completes end to end** —
a request goes in one end and a tool result comes out the other, against a real policy
engine and a real child server. Build order and state: [PLAN.md §4.2](PLAN.md).

**The corpus now scores in `protected` mode.** Every row goes over a real HTTP socket
into a real gateway, against a real policy engine and a real child server, and each
verdict is decided by the side-effect oracle reading the fixture's own operation log —
not by the gateway's answer. Corpus version 0.1.0 now contains **118 hand-written
scenarios** (97 malicious, 21 legitimate), including real fixture-mode deployments,
all structural limits at/below/above their boundaries, and both sides of the complete
three-principal policy matrix.

| Mode | Prohibited side effects observed | Legitimate rows passing |
|---|---|---|
| `direct` — no gateway | 23 | 21/21 |
| broken real policy — negative control | 13 detected | n/a |
| `protected` — the system under test | **0** | **21/21** |

115 PASS, 3 SKIPPED (two need symlinks, unavailable on Windows; one is normalized by a
conforming HTTP transport into a legitimate request and is scored in
`tests/integration/test_protocol_over_http.py` instead). `direct` skips 52 rows because
a scenario carrying wire damage has no wire to damage without a gateway in the path.

Every scored row is joined to its own audit event; a decision that cannot be correlated
to a record is reported `INDETERMINATE` and never as a pass. Read the middle row before
the last one: the negative control exists so that a `0` in the bottom row is evidence
the harness can see failure, rather than evidence it is blind.

Those figures are from `--profile full` — all 118 rows. There is a 50-row smoke lane for
development and it is never the source of a published number; see
[Fast lanes](#fast-lanes-and-when-not-to-use-them).

Unit 11 now includes seeded Hypothesis generation (five required families), the
alternating paired benchmark (N ≥ 1,000 plus a separately labelled modest-concurrency
run), and the strict Markdown report generator. Those tools publish observed numbers
without a latency threshold and refuse stale, mixed, incomplete, or provenance-mismatched
evidence. The current [benchmark report](docs/benchmark-report.md) records 2,500/2,500
CI-profile generated cases passing from seed `11011`. A 25,000-case release-profile
attempt reached the two-hour local timeout without completing, so no release-profile
result is claimed.

Current co-located added overhead, from 900 retained pairs after the documented 10%
warmup of each N=1,000 run:

| Run | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|
| Single concurrency | 54.347 ms | 84.462 ms | 118.346 ms | 26.077 ms | 137.964 ms |
| Concurrency 4 | 19.092 ms | 25.486 ms | 28.331 ms | 8.464 ms | 49.418 ms |

These are development measurements, not throughput or capacity claims.

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
  primary filesystem control is the sandbox mount. The gateway resolves a path, policy
  authorizes the resolved path, and the *resolved* path is what gets forwarded — the
  upstream then resolves it again, itself, against the same base. That last window
  cannot be closed from here. v1 tests canonicalization correctness exhaustively and
  does **not** claim TOCTOU safety ([threat model §1.5](docs/threat-model.md)).
- **The benchmark is co-located.** Client, gateway, policy engine and server run on
  one machine. The overhead figure is real and the caveat travels with it.
- **Symlink tests skip on Windows** without Developer Mode, and skips are reported as
  skips — never counted as passes. Read the skip list before the pass count.

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Running it

```bash
python -m pytest tests/ -q                    # full suite; no network, no API key
python -m pytest tests/ -q -m "not slow"      # fast lane: skips the process-spawning tests
python -m scripts.damage_demo                 # what an unprotected client can do
python -m scripts.run_corpus                  # 50-row direct smoke lane
python -m scripts.run_corpus --mode protected # 50-row protected smoke lane (needs OPA)
python -m scripts.run_corpus --mode protected --profile full --out var/corpus.json
python -m scripts.run_corpus --break-enforcer --profile full # publishable negative control
python -m scripts.run_generated --seed 11011 --profile ci --out var/generated.json
python -m scripts.run_benchmark --out var/bench.json
python -m harness.report --help              # strict evidence -> Markdown builder
ruff check . && ruff format --check .
pyright gateway harness scripts
```

### Fast lanes, and when not to use them

The corpus and the generator both default to a subset, because the full runs are the
two slowest things here and most of a development session re-proves rows that did not
change:

| Command | Default | Full |
|---|---|---|
| `pytest` | `-m "not slow"`, unit-focused lane | all tests; platform skips reported |
| `run_corpus` | `--profile smoke`, 50 rows, **~45 s** protected | `--profile full`, 118 rows, **~53 s** |
| `run_generated` | `--profile dev`, 250 cases, **~26 s** | `--profile release`, 25,000 cases, **hours** |

`slow` is applied automatically to everything under `tests/integration/` — it had been
applied by hand to five tests, which made the fast lane worth twelve seconds. Expensive
*unit* tests still carry the marker explicitly, since nothing structural separates them
from the fast ones in the same file.

The smoke 50 are picked coverage-greedily over
`(layer, expected_reason, fixture_mode, gateway_fault)` in id order — deterministic, so
a smoke failure reproduces — and they cover all 35 reason codes, all 11 fixture modes
and all 3 principals. The remaining budget goes to legitimate rows first, so a gateway
that simply refused everything could not look healthy in the fast lane.

**No hand-written corpus number in this README comes from the smoke lane.**
`harness.report` refuses a corpus artifact whose `profile` is not `full`, and refuses
a missing profile rather than assuming one. Generated evidence is labelled separately:
the current published result uses the 2,500-case `ci` profile, not the 250-case `dev`
lane or the incomplete 25,000-case `release` attempt.

Development targets WSL2, which gives the strong fixture-isolation tier and working
symlinks. On Windows, symlink-dependent tests skip (reported SKIPPED, never passed)
and the fixture runs on the *weak* tier, which stamps `isolation: weak` on every
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

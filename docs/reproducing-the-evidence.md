# Reproducing the evidence

Every number this project publishes, and the command that produced it.

The deliverable here is evidence, not features, and evidence you cannot re-derive is
just a claim with a table around it. So: each figure below names the artifact it came
from, the command that writes that artifact, and what would have to be true for the
number to be wrong.

Two of the numbers are **not** claimed. They are in here too, with the reason, because
a reproducibility guide that only lists the successes is the same kind of selective
reporting the project exists to avoid.

## Before anything

```bash
python -m pip install -e .          # runtime deps; NOT the `agent` extra (CONV-016)
python -m pip install pytest pytest-anyio hypothesis ruff pyright
python -m scripts.fetch_opa         # pinned OPA 1.19.0, checksum-verified into .tools/
```

`GROQ_API_KEY` must be unset and no network is required past that install. That is
CONV-016 and it is enforced in CI by a step that fails if `pydantic_ai` is importable
— a claim about a missing dependency needs a check, not a comment.

Development targets **WSL2**, which gives the strong fixture-isolation tier and working
symlinks. On Windows three symlink tests skip — reported as skips, never as passes —
and the fixture runs on the *weak* tier, which stamps `isolation: weak` on the report.
The published report was produced on Windows and says so.

---

## 1. The security claim

**Published:** *"Across 94 malicious scenarios in corpus version 0.1.0, the side-effect
oracle observed 0 prohibited state changes or disclosures at the protected system."*

```bash
python -m scripts.run_corpus --mode protected --profile full \
    --out var/corpus.json --evidence-dir var/evidence
```

| Figure | Value | Where it comes from |
|---|---:|---|
| Hand-written scenarios | 118 | `harness/scenarios/*.toml`, corpus version 0.1.0 |
| Malicious / legitimate | 97 / 21 | `class` field on each row |
| Malicious attempted (after skips) | 94 | 97 minus 3 declared skips |
| Prohibited side effects | **0** | oracle verdicts of `CRITICAL` |
| Legitimate rows passing | **21/21** | oracle verdicts on `class = "legitimate"` |
| Declared skips | 3 | 2 need symlinks (Windows), 1 is transport-normalized |

`--profile full` matters. The default is a 50-row `smoke` subset for development, and
`harness.report` refuses any artifact whose `profile` is not `full` — including one
with no `profile` at all, since artifacts predating the smoke lane are
indistinguishable from a subset.

**What makes the zero mean anything.** A verdict is decided by the side-effect oracle
reading the fixture's own operation log and a tree hash — never by the gateway's
answer. A gateway that returned `deny` while performing the operation scores
`CRITICAL` and sets `is_lying_gateway`, the worst outcome available. Runtime is about
51 s: 27 s booting 14 deployment variants, 24 s scoring.

## 2. The undefended baseline

```bash
python -m scripts.run_corpus --profile full          # direct: no gateway in the path
```

| Figure | Value |
|---|---:|
| Prohibited side effects | **23** |
| Legitimate rows passing | 21/21 |
| Rows skipped | 52 |

The 52 skips are structural, not a shortfall: a scenario carrying wire damage has no
wire to damage when the client calls the fixture's Python function directly.

## 3. The negative control — read this before believing §1

```bash
python -m scripts.run_corpus --break-enforcer --profile full
```

| Figure | Value |
|---|---:|
| CRITICAL outcomes detected | **13** |
| Exit status | 0 *if the harness detected them* |

This swaps in a **real allow-all Rego bundle** — not a mocked decision — and requires
the harness to notice. A zero in §1 from a harness that has never been observed
reporting non-zero is evidence of blindness, not of enforcement. That is why the README
prints this row in the middle of the table rather than at the bottom.

Inverted exit code by design: this command **fails** when it finds nothing.

## 4. Generated cases

```bash
python -m scripts.run_generated --seed 11011 --profile ci --out var/generated.json
```

| Figure | Value |
|---|---:|
| Generated cases | **2,500** |
| Non-pass outcomes | **0** |
| Seed | 11011 |
| Families | 5 (path, encoding, identifier, numeric boundary, JSON structure) |

Re-running with the same seed reproduces the identical case set; that reproducibility
is itself a test (spec-11 §10 test 7). Generated counts are reported **separately** and
never blended into the hand-written 118 — they are a different kind of evidence and
merging them would inflate the corpus figure with cases nobody reviewed.

> **Not claimed: the 25,000-case `release` profile.** It reached a two-hour local
> timeout without completing. The published figure is the `ci` profile and is labelled
> as such everywhere it appears.
>
> The profile counts are **per family**, not totals: `PROFILE_COUNTS = {"dev": 50,
> "ci": 500, "release": 5_000}` and there are five families, so `dev` produces 250
> cases, `ci` produces the 2,500 above, and `release` produces **5,000 × 5 = 25,000**.
> Budget hours, not minutes.

## 5. Paired overhead

```bash
python -m scripts.run_benchmark --out var/bench.json
```

Alternating `direct` and `protected` within one run — never two runs compared after the
fact — at N = 1,000 pairs, with the first 10% discarded as warm-up, leaving **900
retained pairs** per run.

| Run | p50 | p95 | p99 | min | max |
|---|---:|---:|---:|---:|---:|
| Single concurrency | 54.347 ms | 84.462 ms | 118.346 ms | 26.077 ms | 137.964 ms |
| Concurrency 4 | 19.092 ms | 25.486 ms | 28.331 ms | 8.464 ms | 49.418 ms |

Where it goes, single concurrency: upstream 5.981 ms, audit 2.856 ms, policy 1.865 ms,
protocol+canonicalization 0.728 ms (p50). The stages are reported separately because
if OPA dominated, that would be the finding — here it does not, and the largest single
component is the upstream round trip the gateway does not control.

**There is no latency gate and there must never be one** (`PLAN.md` §6.1). The
benchmark publishes whatever number comes out, with the co-location caveat attached:
client, gateway, policy engine, fixture and load generator all ran on one machine.
These are development measurements, not throughput or capacity claims. A threshold
assertion here would convert an honest measurement into a target to tune against, which
is why the benchmark is kept out of pytest — so one cannot creep in.

The concurrency-4 run being *faster* per operation is a co-location artifact, not a
scaling result, and it is labelled as a separate run for exactly that reason.

## 6. Audit completeness

**Published: 113/113 (100.00%)** — request events written over auditable requests
issued.

Computed by `harness.report` from the raw audit JSONL captured by `--evidence-dir`.
It counts **distinct request ids and refuses on a repeat**: counting rows would make
the ratio forgeable by the exact bug it exists to detect, since ten events for one
request while nine went unlogged reads as 10/10.

## 7. Building the report itself

```bash
python -m harness.report \
    --results var/corpus.json \
    --audit var/evidence/audit-*.jsonl \
    --oplog var/evidence/oplog.jsonl \
    --generated var/generated.json \
    --bench var/bench.json \
    --hypothesis-seed 11011 \
    --out docs/benchmark-report.md
```

`--audit` takes **all fourteen** files, not one. `protected` mode runs one gateway per
deployment variant — three principals plus eleven fixture-fault and OPA-outage variants
— and each writes its own sink, so `--evidence-dir` contains `audit-intern.jsonl`,
`audit-intern-fixture-hang-fault-none.jsonl` and so on. There is no `audit.jsonl`.
Passing one of them would compute the completeness ratio over a fraction of the run
while looking entirely successful; the glob above is the point, and on a shell without
glob expansion the files must be listed. The oplog is genuinely single — one file is
what makes byte-offset correlation valid, which `assert_serialised` enforces.

Validation runs **before the output path is touched**, so a refusal leaves the previous
report intact rather than half-overwritten. It refuses to build on:

- mixed or missing audit schema versions;
- incomplete reproducibility metadata (all 13 fields required);
- a corpus artifact whose version differs from the scenario files;
- a `direct` artifact, or one whose `profile` is not `full`;
- artifacts from different source trees (each carries a `source_fingerprint`);
- a benchmark under 1,000 pairs, or one whose sample order is not alternating.

Every published report therefore carries commit SHA, source fingerprint, policy
revision, corpus version, audit schema version, seed, OS, CPU, RAM, Python version, OPA
version, fixture isolation tier and timestamp. The current one records
`fixture isolation: weak` and a dirty working tree, both of which are true and neither
of which is hidden.

## 8. The gates

```bash
python -m pytest tests/ -q                    # 751 passed, 7 skipped — 2 m 29 s
python -m pytest tests/ -q -m "not slow"      # fast lane, 686 tests — 43 s
python -m ruff check . && python -m ruff format --check .
python -m pyright gateway harness scripts
python -m scripts.check_claims                # the phrase PLAN.md §6.2 replaced
.tools/opa test policies/                     # 46/46, no Python involved
python -m scripts.sync_policy_revision --check
```

All of these run in CI on Python 3.12 and 3.13, because `requires-python = ">=3.12"` is
a published claim and testing only the version we develop on would leave the floor of
that range asserted and never exercised.

---

## What is still owed

- **The MCP Inspector interoperability check** (week 2 gate). It needs `npx` and a
  human at a browser, so no suite can discharge it. It is an interoperability check
  against a third-party client, not a security control.
- **The 25,000-case release generation profile**, as above.

Both are recorded in `PLAN.md` rather than quietly dropped, and neither blocks the v1
exit gate, which is stated in terms of the published corpus, the audit trail, and the
offline suite.

## What this evidence does not establish

The corpus is written by the same author as the enforcement, which is why the claim is
scoped to *this published corpus* and the observation method rather than to the space
of attacks (`PLAN.md` §6.2). The corpus, fixture and policy bundle all ship in the repo
with an [add-a-scenario path](../harness/scenarios/README.md) precisely so that someone
else can try to break it. **An externally contributed failing case belongs in the
report with its fix** — that is what converts a self-graded exam into evidence.

The threat model's standing limits — the second-route bypass, `unverified_local`
identity, and the absence of a TOCTOU claim — are in
[docs/threat-model.md](threat-model.md) and are not repeated here.

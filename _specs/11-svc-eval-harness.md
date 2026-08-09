# SPEC-11 — `svc-eval-harness`

**Role:** Scenario corpus, side-effect oracle, execution modes, benchmark and report
**Phase:** v1 · **Build order:** 2nd (skeleton), 12th (full)
**Depends on:** `10-fixture-filesystem-mcp` (skeleton); all units (full)
**Consumed by:** the benchmark report — the project's actual deliverable
**Source lineage:** `REQ-HARNESS-001` … `REQ-HARNESS-009`, `REQ-HARNESS-017`, `REQ-HARNESS-019`, `REQ-HARNESS-021`, `REQ-PRINCIPLE-007`

---

## 1. Purpose

The gateway is the artifact; this is the evidence. Every number in the report comes from here, and the rules in this spec are what separate a measurement from a demo.

Two rules dominate everything else:

> **1. A denial is proven at the fixture, never by the gateway's own output** (`CONV-018`).
> **2. Every claim names the corpus it is scoped to, and the corpus is published.**

---

## 2. In scope

- The scenario schema and the versioned corpus.
- The side-effect oracle.
- `direct` and `protected` execution modes.
- Paired overhead measurement.
- Property-based case generation.
- The report: security rate, false-positive rate, audit completeness, overhead distribution, reproducibility metadata.

## 3. Out of scope

- Model calls of any kind — unit 12, v1.1. **The v1 harness runs with no API key and no network** (`CONV-016`).
- Load, soak, and chaos-at-scale (`REQ-HARNESS-016`) — reduced to the specific chaos cases named below (OPA outage, audit-sink failure, upstream hang/crash, cancellation), which are targeted correctness tests rather than a load programme.
- LLM-judged scoring — prohibited; all v1 verdicts are deterministic oracles.

---

## 4. Execution modes

| Mode | Path | Purpose |
|---|---|---|
| `direct` | test client → fixture | Demonstrates the unsafe baseline; produces the "before" latency for the paired measurement |
| `protected` | test client → gateway → fixture | The system under test |

**HARN-001 (`REQ-HARNESS-003`)** — `direct` mode exists only for isolated synthetic fixtures and MUST NOT be reachable from any protected client configuration. The harness MUST assert this (a configuration check, not a security control — see `IDENT-007`).

**HARN-002** — `shadow` mode from the source document is cut with policy simulation. Two modes are enough to produce every v1 number.

---

## 5. Scenario schema

Every scenario declares — and the harness refuses to run one that omits any field:

| Field | Purpose |
|---|---|
| `id` | Stable, referenced by the report |
| `class` | `malicious` \| `legitimate` |
| `layer` | `protocol` \| `security` \| `performance` \| `chaos` |
| `principal` | Which configured identity |
| `tool`, `arguments` | The request |
| `expected_decision` | `allow` \| `deny` |
| `expected_reason` | The exact reason code |
| `expected_side_effect` | `none` \| a specific described operation |
| `risk_tier` | R0/R1/R2/R4 |
| `notes` | Why this case exists — one line, human-facing |

**HARN-003 (`REQ-HARNESS-006`)** — `expected_reason` is mandatory, not optional. "Denied for some reason" is not a passing test; a case that denies for the wrong reason is a defect that a decision-only assertion would hide.

**HARN-004** — `expected_side_effect` is mandatory and is asserted against the fixture's operation log, always — including for `allow` scenarios, where the expected effect must be *observed to have occurred*.

---

## 6. The side-effect oracle

**HARN-005 (`REQ-HARNESS-005`, `CONV-018`)** — Every scenario MUST be scored on **two independent observations**: the gateway's decision, and the protected system's actual state. A denial message is never sufficient evidence.

**HARN-006** — The oracle observes at the fixture using two sources: the fixture's operation log (unit 10) and direct filesystem state comparison (hash the tree before and after). Log-only would miss an operation the fixture failed to log; state-only would miss a read, which changes no state but is a disclosure. **Both are required** — a read of a confidential file is the most common expected violation in this corpus and produces no state change at all.

**HARN-007** — A scenario where the gateway says `deny` but the oracle observes an effect is a **critical failure**, reported prominently and separately. This is the failure the whole project exists to prevent, and it must never be able to appear as a passing test.

**HARN-008** — A scenario where the gateway says `allow` but the expected effect did not occur is also a failure — a false-success. `REQ-OUT-005` forbids reporting a non-occurring operation as successful, and only the oracle can catch it.

**HARN-009** — Oracle observations MUST be correlated to the audit event by `request_id`. A scenario whose gateway decision, audit event, and fixture observation cannot be joined is reported as **indeterminate**, never as a pass.

---

## 7. Corpus

**HARN-010 (`REQ-HARNESS-008`)** — Versioned, published in the repository, and split into `malicious` and `legitimate` with both counted and reported. A corpus that is 100% attacks cannot produce a false-positive rate, and a false-positive rate is what distinguishes a working gateway from one that denies everything.

**HARN-011** — Minimum v1 coverage, ≥100 hand-written scenarios spanning:

- Header/body consistency — every disagreement shape in `02-svc-protocol-guard.md` §6.
- JSON-RPC malformation and every structural limit at, below, and above the boundary.
- Protocol version rejection.
- Method allowlist rejection.
- Path traversal — every row of `05-svc-canonicalizer-fs.md` §9.
- Sensitive decoy access, per principal.
- Unregistered server and unregistered tool.
- Schema drift and poisoned annotation.
- Argument schema violations and unknown fields.
- Policy matrix across all three principals, allow and deny sides.
- Response guard: oversized, malformed, mismatched identifier, unsolicited, injected instruction text.
- Chaos: OPA killed, audit sink unwritable, upstream hang, upstream crash, client cancellation.
- Legitimate operations for every tool and every principal that should succeed.

**HARN-012 (`REQ-HARNESS-009`, `CONV-019`)** — Hypothesis generates path, encoding, identifier, numeric-boundary, and JSON-structure variants from a **recorded seed**. Generated results are counted and reported **separately** from hand-written ones — they are the part of the evidence the author did not choose (`PLAN.md` §6.2), and blending them would hide exactly the thing that makes them valuable.

**HARN-013** — The repository documents how to add a scenario, and the report records any externally contributed failing case together with its fix. This is what converts a self-graded exam into evidence.

---

## 8. Performance measurement

**HARN-014 (`REQ-HARNESS-004`)** — Overhead is measured with the **same scripted request** alternating `direct` and `protected` within one run — never two separate runs compared after the fact. Reported as the paired difference distribution.

**HARN-015** — No model call appears in any latency path measured in v1. There are none in v1 at all.

**HARN-016 (`REQ-HARNESS-019`)** — Report p50, p95, p99, min and max for: direct latency, protected latency, added overhead, and each stage — protocol+canonicalization, policy, upstream, audit. Stage numbers come from the audit log's `stage_latency_ms`.

**HARN-017 (`PLAN.md` §6.1)** — **There is no latency gate.** The harness measures and publishes; it does not pass or fail on a threshold. N ≥ 1,000 paired samples at single concurrency; a second run at modest concurrency is labelled a co-located development measurement.

**HARN-018** — Every performance report MUST carry the co-location caveat: the same machine is client, gateway, policy engine, fixture, and load generator, so these are development measurements and not capacity claims.

---

## 9. Reported metrics

**HARN-019 (`REQ-HARNESS-017`)** — Security metrics, each a measured number:

```text
malicious scenarios attempted / blocked
prohibited side effects observed          <- must be reported even when zero
security enforcement rate (scoped to corpus version)
legitimate scenarios attempted / allowed
false-positive rate
indeterminate outcomes                    <- reported, never silently dropped
audit completeness (events written / requests issued)
hand-written vs generated case counts, reported separately
```

**HARN-020** — The security claim is stated in its scoped form and never generalized:

> *"Across N scenarios in corpus version X, the side-effect oracle observed zero prohibited state changes or disclosures at the protected system."*

The phrase "zero authorization bypasses" MUST NOT appear in any report (`PLAN.md` §7.3).

**HARN-021 (`REQ-HARNESS-021`)** — Every report carries: commit SHA, policy revision, corpus version, audit schema version, Hypothesis seed, OS, CPU, RAM, Python version, OPA version, fixture isolation mechanism, and timestamp.

**HARN-022 (`REQ-PRINCIPLE-007`)** — The report publishes observed numbers including disappointing ones. A missed expectation is reported with its explanation, never omitted or re-run until favorable.

---

## 10. Acceptance tests

The harness tests itself, because a broken oracle produces confident wrong results.

1. **Oracle negative control:** deliberately disable a gateway guard; the affected malicious scenarios must **fail**. A harness that cannot detect a broken gateway is not measuring anything, and this test is the proof that it can.
2. **Oracle read-detection:** a scenario that reads a confidential file with no state change is still detected via the operation log — proving `HARN-006`'s two-source requirement is actually wired.
3. A scenario denied for the wrong reason code fails, not passes.
4. A scenario allowed whose expected effect did not occur fails as a false-success.
5. A scenario whose decision, audit event, and fixture observation cannot be joined reports `indeterminate`.
6. Paired measurement alternates modes within a run; asserted by inspecting the sample ordering.
7. Rerunning with the same Hypothesis seed reproduces the identical generated case set.
8. Fixture reset between scenarios is verified by tree hash; a deliberately skipped reset causes a detectable failure.
9. The report refuses to build when audit schema versions are mixed.
10. The report refuses to build when reproducibility metadata is incomplete.
11. The whole suite passes with no network and no `GROQ_API_KEY`.

---

## 11. Notes for the tech sheet

- pytest + Hypothesis, with scenarios as data files rather than as test functions, so the corpus is publishable and reviewable independently of the test code. The corpus is a deliverable in its own right.
- Test 1 — the negative control — is the most important test in the project and is the one most likely to be skipped. Build it in week 1 with the oracle skeleton and run it every release: mutate a guard, confirm the harness screams.
- Tree hashing for state comparison is cheap at fixture scale; do it before and after every scenario rather than sampling.
- Keep the report generator boring: read the JSONL audit log plus the oracle's observations, join on `request_id`, emit markdown. Resist a dashboard. `PLAN.md` §3.3 cut three UI surfaces for a reason.
- The report is the deliverable a hiring manager reads in five minutes. Lead with the scoped claim, the measured overhead distribution, and the stated limitations — in that order.

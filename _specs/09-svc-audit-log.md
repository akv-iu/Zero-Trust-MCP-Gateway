# SPEC-09 — `svc-audit-log`

**Role:** JSONL audit events, the project's evidence artifact
**Phase:** v1 · **Build order:** 4th (before any enforcement)
**Depends on:** nothing
**Consumed by:** every unit; read by `11-svc-eval-harness`
**Source lineage:** `REQ-AUDIT-001`, `REQ-AUDIT-002`, `REQ-AUDIT-004`, `REQ-AUDIT-005`, `REQ-OBS-003`

---

## 1. Purpose

Every claim this project makes is a claim about a record. The benchmark's security rate, false-positive rate, overhead distribution, and audit completeness all read out of this log. If the audit is incomplete or dishonest, nothing else in the project is evidence.

It is built **fourth** — before any enforcement stage — so that no enforcement is ever written without its evidence path already in place.

---

## 2. In scope

- The audit event schema and its versioning.
- Exactly-one-event-per-request accounting.
- Redaction and minimization rules.
- JSONL writing, with bounded size and retention.
- Audit-failure behavior.
- The per-stage latency numbers the benchmark consumes.

## 3. Out of scope

- Tamper evidence, signing, append-only storage (`REQ-AUDIT-003`) — cut, P2, explicitly not v1.
- PostgreSQL storage, searchable persistence — deferred; `jq` over JSONL is v1's query interface.
- Metrics endpoint, OTel collector, dashboards — deferred. v1 derives its numbers from this log rather than running a parallel telemetry stack.

---

## 4. Contract

**Input:** field contributions from every unit, keyed by `request_id`.
**Output:** one JSONL line per request, schema-validated, plus a small set of non-request events (drift, startup, policy-load) written in the same stream with a distinct event type.

The full shared field list is fixed in `00-conventions.md` §9 and is not restated here. This spec owns the rules **about** those fields.

---

## 5. Requirements

### 5.1 Completeness

**AUDIT-001 (`REQ-AUDIT-001`, `CONV-011`)** — Exactly one event per request. Not zero, not two. A request rejected at stage 2 produces a complete, well-formed event with later fields absent — never a truncated or partial record.

**AUDIT-002** — Every terminal outcome MUST be represented: `allowed`, `denied`, `error`, `cancelled`, `timeout`. A request that ends any other way is a defect, and the schema MUST make it unrepresentable.

**AUDIT-003 (`REQ-AUDIT-004`)** — The `request_id` MUST correlate the audit event to the client's response, the fixture's observed operation, and the harness's scenario result. Correlation is verified in tests, not assumed.

**AUDIT-004** — Audit completeness MUST be **measured and reported**, not asserted. The harness counts requests issued versus events written and publishes the ratio (`PLAN.md` §6). A ratio of 1.0 that was measured is evidence; one that was assumed is not.

### 5.2 Minimization

**AUDIT-005 (`REQ-AUDIT-002`, `CONV-012`)** — Never recorded: raw secrets, tokens, private keys, passwords, full file contents, full tool output, full prompts, raw argument values.

**AUDIT-006** — Sensitive values are represented by hashes (`arg_hash`, `raw_hash`), classifications, or bounded derived attributes. The `canonical_path` is recorded because it is bounded, contained within an approved root, and necessary to make a decision reviewable — but it is the *canonical* path, never the raw supplied string.

**AUDIT-007** — The writer MUST enforce minimization structurally: a field not in the schema is not written, and adding a sensitive field requires a schema change visible in review. Redaction MUST NOT depend on a regex applied to a free-form blob.

**AUDIT-008 (`REQ-OBS-003`)** — Any counter or aggregate derived from the log MUST have bounded cardinality. Request identifiers, canonical paths, and argument hashes MUST NOT become aggregation keys.

### 5.3 Failure behavior

**AUDIT-009 (`REQ-PRINCIPLE-005`)** — If a required audit event cannot be persisted, the protected operation MUST be denied. **The audit sink is a hard dependency, not best-effort.** This has a dedicated chaos test.

**AUDIT-010** — Readiness MUST be false when the audit sink is unwritable (`CONV-006`).

**AUDIT-011** — The write path MUST be ordered such that an allow is never delivered to the client without its event durably written. If ordering is relaxed for latency, the relaxation MUST be a named configuration value, off by default, and the benchmark MUST report which mode produced its numbers.

### 5.4 Storage

**AUDIT-012 (`REQ-AUDIT-005`)** — Retention is bounded by both age and size, whichever is reached first, with documented defaults. Disk growth during fuzz and load runs is a real laptop failure mode and the bound is what prevents it.

**AUDIT-013** — The schema MUST carry a version field. A schema change bumps it; the harness refuses to mix versions in one report.

**AUDIT-014** — Log injection MUST be impossible: every value is JSON-encoded, newlines within values cannot terminate a record, and no value is ever concatenated into the line as raw text.

---

## 6. Failure modes

| Condition | Outcome | Reason code |
|---|---|---|
| Sink unwritable at startup | not ready; deny protected calls | — |
| Write fails for a request | deny that request | `AUDIT_WRITE_FAILED` |
| Event fails schema validation | deny; log an internal-defect event | `AUDIT_SCHEMA_INVALID` |
| Retention bound reached | rotate/prune per policy, audited | — |

---

## 7. Configuration surface

Sink path; schema version; max file size; max age; rotation policy; durability mode (default: durable-before-response); per-stage latency capture toggle (default on).

---

## 8. Acceptance tests

1. **Completeness:** across the full corpus, events written equals requests issued. Reported as a measured number.
2. A request rejected at stage 2 produces one complete, schema-valid event.
3. A request that completes fully produces exactly one event — no duplicate from a second code path.
4. Every event validates against the schema; the suite fails on any that does not.
5. **The chaos test:** make the sink unwritable mid-run. Protected calls are denied with `AUDIT_WRITE_FAILED`; the oracle confirms no side effect occurred; readiness goes false.
6. No event in the entire suite contains a raw secret, raw argument value, token, or file content — asserted by scanning every emitted record against the fixture's synthetic canary values.
7. A synthetic canary secret planted in the fixture never appears in the log.
8. Log injection: an argument containing newlines, JSON fragments, and fake record delimiters produces exactly one parseable line, and the injected text does not create a second record.
9. `request_id` correlates the event to the fixture's observed operation and the harness's scenario result, for every scenario.
10. Per-stage latencies are present, sum consistently with total request latency, and are what the benchmark reads.
11. Retention bounds trigger correctly on both age and size.
12. A schema version mismatch causes the harness to refuse the report rather than produce a blended one.

---

## 9. Notes for the tech sheet

- Build the event as a validated model, serialize once at the end of the request, write one line. Never build it incrementally as a mutable dict passed between stages — that is how duplicate and partial events happen, and how sensitive fields sneak in.
- Durable-before-response (`AUDIT-011`) costs latency, and that cost belongs in the published benchmark rather than being optimized away silently. If it turns out to dominate the overhead number, that is a genuinely interesting finding for the report.
- Test 6 is worth automating as a suite-wide invariant rather than a single test: plant canaries in the fixture, then assert no canary ever appears in any emitted record across every run.
- `jq` over JSONL is the v1 admin interface, and saying so explicitly in the README is better than building a dashboard nobody asked for.

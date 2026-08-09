# SPEC-00 — Conventions

**Applies to:** all specs in this directory
**Phase:** v1
**Status:** normative

---

## 1. Purpose

Shared vocabulary, identifier scheme, and cross-cutting contracts that every other spec references instead of restating. Read this once; the other specs assume it.

---

## 2. Requirement language

**MUST** — required; a unit is not complete without it and its acceptance test.
**SHOULD** — expected; a documented reason is required to omit.
**MAY** — optional.

A requirement is complete only when its acceptance test passes. **A feature that exists without a test does not exist.**

Every spec's requirements are numbered `<UNIT>-NNN`, e.g. `PROTO-004`, `CANON-011`. Where a requirement carries forward from the archival source document (`Zero_Trust_MCP_Gateway_Final.md`), the original `REQ-*` identifier is cited in parentheses so the lineage is traceable. Where this plan overrides the source, the spec says so explicitly.

---

## 3. Deployment reality

**v1 is not microservices.** It is:

- one Python process (the gateway, units 01–09),
- one OPA process,
- one child MCP server process (unit 10, spawned and supervised by the gateway),
- test processes (unit 11) that run on demand.

Units are separated by **contract**, not by deployment. Each unit owns one testable input→output contract and can be unit-tested in isolation. Do not add process boundaries, HTTP hops, queues, or service discovery between them. If a unit ever needs to be extracted, its contract is already the seam.

---

## 4. Vocabulary

| Term | Meaning in this project |
|---|---|
| **Client** | The MCP client speaking to the gateway over `stdio` — test driver, MCP Inspector, or the v1.1 agent harness. |
| **Upstream** | The protected MCP server the gateway forwards to. In v1, always the filesystem fixture (unit 10). |
| **Principal** | The identity a request is authorized as. In v1, derived from launcher configuration, never cryptographically verified. |
| **Protected action** | Any MCP operation that can cause or reveal state at the upstream. In v1: `tools/call`, and `tools/list` insofar as it discloses tool existence. |
| **Canonical request** | The single normalized view of a request that all downstream stages authorize and act on. Produced by units 02 and 05. Nothing after unit 05 may re-read raw client input. |
| **Decision** | The policy engine's structured verdict: `allow`, `deny`, or `error`. |
| **Obligation** | A constraint attached to an `allow` — timeout, max response bytes, and similar. |
| **Side effect** | An observable state change or disclosure at the upstream, measured by the oracle (unit 11) at the upstream, never inferred from the gateway's own output. |
| **Corpus** | The versioned, published set of scenarios. Hand-written cases and Hypothesis-generated cases are counted and reported separately. |

---

## 5. The canonical request lifecycle

The source document specified thirteen stages. v1 implements **eight**, in this fixed order. Stages removed from the source's list are not deferred logic hidden elsewhere — they belong to cut scope (see `90-deferred-register.md`).

| # | Stage | Unit |
|---|---|---|
| 1 | Transport acceptance and framing | 01 |
| 2 | Protocol validation + header/body consistency | 02 |
| 3 | Identity derivation | 03 |
| 4 | Registry resolution + schema fingerprint check | 04 |
| 5 | Canonicalization and derived attributes | 05 |
| 6 | Policy evaluation | 06 |
| 7 | Obligation enforcement and upstream invocation | 07 |
| 8 | Response validation | 08 |

Audit (09) is not a stage; it is a terminal action every stage performs on exit.

**CONV-001 (`REQ-PRINCIPLE-004`)** — A request that fails at stage *N* MUST NOT reach any stage that can produce a side effect. There MUST NOT be a code path from stages 1–6 that reaches unit 07 without a recorded `allow`.

**CONV-002** — Stages MUST NOT be reordered for performance. Combining adjacent stages internally is permitted only if the observable security semantics and the audit record are unchanged.

**CONV-003 (`REQ-GUARD-002`)** — Policy MUST evaluate canonical values. No stage after 05 may parse, decode, or re-interpret raw client-supplied text.

---

## 6. Fail-closed contract

**CONV-004 (`REQ-PRINCIPLE-005`)** — Every unit MUST fail closed for protected actions. On internal error, timeout, unavailable dependency, unparseable input, or unexpected state, the outcome MUST be `deny` with an error reason code — never `allow`, never a silent pass-through.

**CONV-005** — The gateway MUST NOT have a "degraded mode" that relaxes enforcement. Unavailable OPA, unavailable registry, and unwritable audit sink all mean protected calls are denied.

**CONV-006** — Health/readiness reporting MAY remain available while protected actions are denied, and MUST distinguish *live* (process running) from *ready* (policy, registry, audit sink, and upstream all usable).

---

## 7. Risk tiers

Carried from the source (`REQ-GUARD-005`), reduced to the tiers v1 can actually exercise.

| Tier | Meaning | v1 handling |
|---|---|---|
| **R0** | Metadata only, no protected side effect | Allow only by explicit policy (e.g. filtered `tools/list`) |
| **R1** | Scoped read of non-sensitive fixture data | Allow by explicit policy with obligations |
| **R2** | Reversible write inside the fixture sandbox | Allow by explicit policy, stronger audit |
| **R4** | Prohibited | Deny |

**R3 (approval required) is not implemented in v1** — there is no approval mechanism, and a tier that cannot be enforced must not appear in policy. It returns with the approval unit (see `90-deferred-register.md`).

**CONV-007 (`REQ-MCP-009`)** — A tool's self-declared annotations MAY inform an initial human review but MUST NOT be a source of risk classification at runtime. Tier assignment lives in the registry and policy, both under version control.

---

## 8. Reason codes

**CONV-008 (`REQ-POL-003`)** — Every terminal outcome MUST carry a stable, machine-readable reason code. Codes are `SCREAMING_SNAKE_CASE`, prefixed by the deciding unit, and are part of the public contract — a code may be added, but an existing code's meaning MUST NOT change.

Prefixes: `PROTO_`, `IDENT_`, `REG_`, `CANON_`, `POLICY_`, `ROUTE_`, `RESP_`, `AUDIT_`.

**CONV-009 (`REQ-OUT-005`)** — Client-facing error text MUST be derivable from the reason code and MUST NOT disclose policy internals, filesystem layout outside the approved root, registry contents, or the existence of objects the principal cannot discover.

**CONV-010** — Every reason code MUST have at least one scenario in the corpus that produces it. Unreachable codes are removed.

---

## 9. Audit field registry

Every unit that terminates a request contributes to a single audit event. The full field list and redaction rules are owned by `09-svc-audit-log.md`; this section fixes the *shared* fields so units do not invent variants.

| Field | Produced by | Notes |
|---|---|---|
| `request_id` | 01 | Stable for the request's whole life; the correlation key for everything |
| `ts_start`, `ts_end` | 01 | Monotonic-derived wall-clock, ISO 8601 UTC |
| `transport` | 01 | `stdio` in v1 |
| `mcp_method`, `mcp_protocol_version` | 02 | From the canonical request |
| `principal`, `auth_method` | 03 | `auth_method` is `local_config` in v1 — never `oidc` |
| `server_id`, `tool_name`, `schema_fingerprint` | 04 | |
| `canonical_resource`, `arg_hash` | 05 | Hash, never raw argument values |
| `decision`, `reason_code`, `risk_tier`, `policy_revision` | 06 | |
| `obligations` | 06 | As enforced, not as requested |
| `upstream_status`, `upstream_latency_ms` | 07 | |
| `response_bytes` | 08 | |
| `stage_latency_ms` | all | Per-stage map; the source of the benchmark numbers |
| `outcome` | terminal unit | `allowed` \| `denied` \| `error` \| `cancelled` \| `timeout` |

**CONV-011 (`REQ-AUDIT-001`)** — Exactly one audit event per request. Not zero, not two. A request rejected at stage 2 produces a complete event with the later fields absent, never a truncated or malformed record.

**CONV-012 (`REQ-AUDIT-002`)** — Audit records MUST NOT contain raw secrets, tokens, full file contents, full prompts, or arbitrary tool output. Sensitive values are represented by hashes or classifications.

---

## 10. Configuration

**CONV-013 (`REQ-ADMIN-003`)** — Configuration MUST have a validated schema with safe defaults. **Unknown fields MUST fail startup**, never be silently ignored. There is no runtime configuration mutation surface in v1.

**CONV-014 (`REQ-SEC-001`)** — Secrets come from environment injection or an ignored `.env`. Never committed, never logged, never in an audit record, never sent to a model provider. v1 requires no secrets at all; v1.1 requires exactly one (`GROQ_API_KEY`), scoped to unit 12.

**CONV-015** — Every limit (size, depth, count, duration) MUST be a named configuration value with a documented default, and MUST have tests at, below, and above the boundary.

---

## 11. Testing contract

**CONV-016 (`REQ-HARNESS-002`)** — The entire v1 test suite MUST pass with no model API key present and no network access. CI MUST NOT depend on any hosted model.

**CONV-017** — Every unit ships with its acceptance tests in the same change. A unit merged without its tests is incomplete regardless of whether it runs.

**CONV-018 (`REQ-HARNESS-005`)** — A denial is proven by the oracle observing no state change at the upstream. A denial message from the gateway is **not** evidence and MUST NOT be the sole assertion in any security test.

**CONV-019 (`REQ-HARNESS-009`)** — Property-based cases MUST be reproducible from a recorded seed, and the seed MUST appear in the report.

---

## 12. Determinism

**CONV-020 (`REQ-PRINCIPLE-001`)** — Replaying the same canonical request against the same policy revision and context MUST produce the same decision and reason code.

**CONV-021 (`REQ-MODEL-GUARD-001`)** — A model-generated tool call is an untrusted request, identical in standing to any other. No model output, explanation, confidence, or claim of user consent may influence a decision.

**CONV-022 (`REQ-MODEL-011`)** — No security claim may depend on a model refusing anything. Any prohibited action MUST be denied identically whether proposed by a deterministic client or any model.

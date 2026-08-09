# SPEC-06 — `svc-policy-broker`

**Role:** OPA integration, policy input/result contract, fail-closed authorization
**Phase:** v1 · **Build order:** 9th
**Depends on:** `03-svc-identity-resolver`, `04-svc-registry`, `05-svc-canonicalizer-fs`, `09-svc-audit-log`
**Consumed by:** `07-svc-upstream-router`
**Source lineage:** `REQ-POL-001` … `REQ-POL-008`, `REQ-PRINCIPLE-001`, `REQ-PRINCIPLE-002`, `REQ-PRINCIPLE-005`

---

## 1. Purpose

The authorization decision. The broker builds a bounded input document from the canonical request, authorization context, resolved target, and derived attributes; asks OPA; validates the answer; and returns a structured decision with obligations.

The broker's real responsibility is **not** deciding — Rego decides. The broker's responsibility is guaranteeing that a decision was actually obtained, that it was well-formed, and that anything else means deny.

---

## 2. In scope

- Constructing the policy input document.
- Invoking OPA and enforcing a decision deadline.
- Validating the decision's structure.
- Mapping the decision to an outcome and obligations.
- Reporting policy revision.

## 3. Out of scope

- Writing Rego (that is `policies/`, tested independently — see §9).
- Enforcing obligations — unit 07 enforces what this unit returns.
- Shadow mode, candidate-policy replay, policy simulation API — cut (`90-deferred-register.md`).
- Break-glass — cut, and explicitly not in the MVP.

---

## 4. Contract

**Input to OPA — bounded, documented, minimal.** Groups and their sources:

| Group | Contents | Source |
|---|---|---|
| `request` | request id, protocol version, transport, method | 02 |
| `principal` | id, auth_method, assurance, roles, environment | 03 |
| `client` | client id | 03 |
| `target` | server id, tool name, schema fingerprint, registry risk tier | 04 |
| `resource` | canonical path, root, classification, exists | 05 |
| `arguments` | arg hash, operation, other derived attributes | 05 |
| `context` | policy revision | broker |

**Output — the decision record:**

| Field | Notes |
|---|---|
| `decision` | `allow` \| `deny` |
| `reason_code` | Stable, `POLICY_*` or a policy-defined code from a closed set |
| `risk_tier` | R0/R1/R2/R4 (`CONV-007`; R3 not implemented in v1) |
| `policy_revision` | Identifies the exact bundle that decided |
| `obligations` | `timeout_ms`, `max_response_bytes` in v1 |

---

## 5. Requirements

### 5.1 Input discipline

**POLICY-001 (`REQ-POL-002`)** — The input document MUST be bounded and documented. Fields not needed for a decision MUST NOT be sent.

**POLICY-002 (`REQ-POL-002`, `CONV-012`)** — Raw secrets, tokens, full file contents, full argument values, and prompt text MUST NOT appear in policy input. Hashes and derived attributes are sufficient and are what the contract carries.

**POLICY-003 (`CONV-003`)** — Input MUST be built only from canonical and derived values. The broker MUST NOT re-read raw client input, re-parse arguments, or re-derive a path.

**POLICY-004** — The input document MUST be schema-validated before dispatch. A malformed input is an internal defect and MUST deny, not be sent hopefully.

### 5.2 Decision handling

**POLICY-005 (`REQ-PRINCIPLE-002`)** — Absence of an allow is a deny. The broker MUST NOT treat an empty result, missing field, null, or unrecognized decision value as permission.

**POLICY-006 (`REQ-POL-003`)** — Every decision MUST carry a stable machine-readable reason code from a closed set. An allow without a reason code is malformed and denies.

**POLICY-007 (`REQ-POL-003`)** — The result MUST be structurally validated: known decision value, known reason code, obligations within configured bounds. **An obligation exceeding a configured maximum MUST be clamped to the maximum and the clamping MUST be audited** — policy may narrow limits, never widen them past the gateway's ceiling.

**POLICY-008 (`REQ-POL-004`)** — Precedence MUST be documented and tested in the Rego test suite: explicit prohibition, then explicit deny, then allow-with-obligations, then default deny. An allow rule MUST NOT override an explicit prohibition. (The source's "required approval / step-up" precedence level is absent in v1 with R3.)

**POLICY-009 (`CONV-020`)** — Replaying the same input against the same policy revision MUST produce an identical decision, reason code, and obligation set.

### 5.3 Fail-closed

**POLICY-010 (`REQ-POL-008`, `REQ-PRINCIPLE-005`)** — If policy cannot be loaded or evaluated — OPA unreachable, OPA erroring, bundle missing, bundle invalid, evaluation timeout, malformed result — **every protected operation MUST be denied.** This is the project's single most important behavioral claim and has a dedicated test.

**POLICY-011** — Evaluation MUST have a deadline. Expiry is a denial, not a wait and not a retry-until-success. A bounded single retry on a transport-level error is permitted; a retry on a *deny* is prohibited.

**POLICY-012** — The gateway MUST NOT cache allow decisions across policy revisions. Any caching MUST key on the full input hash plus policy revision, and MUST be disabled by default in v1 (measure before optimizing).

**POLICY-013 (`REQ-PRINCIPLE-001`)** — No code path may map any model output, classifier score, or LLM response to `allow`. There is no advisory-model input to policy in v1 (`REQ-MODEL-GUARD-010` is deferred).

### 5.4 Provenance

**POLICY-014 (`REQ-POL-005`)** — Every decision MUST identify the active policy revision, and it MUST appear in the audit event. A decision whose revision cannot be determined is a denial.

**POLICY-015 (`REQ-POL-005`)** — Policy lives in version control and deploys as an immutable bundle. There is no runtime policy edit surface in v1.

**POLICY-016 (`REQ-POL-006`)** — Every allow and deny rule MUST have positive and negative Rego unit tests including boundary values and at least one bypass attempt. Rego tests run in CI and are independent of the gateway.

---

## 6. Reference policy scenarios

Reduced from the source's four-principal matrix (`§2.27`) to what the v1 fixture can actually exercise. Business tools and SQL are cut, so principals are defined over the filesystem only.

| Principal | Approved |
|---|---|
| `intern` | Read `public/**`. Deny confidential, production, and all writes. |
| `developer` | Read and write `workspace/**`; read `public/**`. Deny confidential, production, and sensitive decoys. |
| `auditor` | Read everything except sensitive decoys. No writes of any kind. |

`admin` is deliberately absent from v1: the source correctly notes an administrator must not automatically bypass risk controls, and without R3/approval there is no way to express a properly constrained admin. Adding one would only demonstrate the anti-pattern.

---

## 7. Failure modes

| Condition | Reason code |
|---|---|
| OPA unreachable / bundle unloadable | `POLICY_UNAVAILABLE` |
| Evaluation deadline exceeded | `POLICY_TIMEOUT` |
| Malformed or unrecognized result | `POLICY_RESULT_INVALID` |
| No matching allow rule | `POLICY_DEFAULT_DENY` |
| Explicit deny rule matched | policy-supplied code, e.g. `POLICY_PATH_NOT_PERMITTED` |
| Obligation above ceiling | clamped + `POLICY_OBLIGATION_CLAMPED` audited |
| Policy revision indeterminate | `POLICY_REVISION_UNKNOWN` |

---

## 8. Configuration surface

OPA endpoint and query path; evaluation deadline; obligation ceilings (`timeout_ms`, `max_response_bytes`); policy bundle path; policy revision source; decision cache (default off).

---

## 9. Acceptance tests

1. **The headline test:** kill the OPA process mid-suite. Every protected call is denied with `POLICY_UNAVAILABLE`; the oracle confirms the fixture observed nothing; liveness still answers; readiness is false.
2. OPA reachable but returning an empty document → deny.
3. OPA returning `allow` with no reason code → deny (`POLICY_RESULT_INVALID`).
4. OPA returning an unrecognized decision value → deny.
5. OPA returning `timeout_ms` above the ceiling → clamped, audited, request proceeds under the clamped value.
6. Evaluation deadline exceeded → deny, no retry loop.
7. Identical input replayed 100× against a fixed revision → identical decision, reason code, obligations every time.
8. Policy input contains no raw path, no raw argument values, no secrets — asserted by inspecting the actual dispatched document across the whole suite.
9. Precedence: an input matching both an explicit prohibition and an allow rule denies.
10. Each of the three principals produces the expected allow/deny matrix over the fixture — the false-positive side included.
11. Policy revision appears in every audit event and changes when the bundle changes.
12. Rego unit tests pass standalone with the gateway not running.
13. A request that reaches the broker with a missing derived attribute denies rather than evaluating a partial input.

---

## 10. Notes for the tech sheet

- OPA as a local sidecar process over its REST API is the right v1 choice: it keeps policy genuinely external, makes the outage test trivially real, and the added latency is a *number the report wants to publish* rather than a problem to hide.
- Build the input document from a frozen dataclass-like structure with a schema, so `POLICY-002` is enforced by construction rather than by review.
- Obligation clamping deserves care: it is the one place policy output feeds an enforcement limit, and "policy may narrow, never widen" is the invariant that keeps a policy bug from becoming a gateway bug.
- Do not build shadow mode. It is genuinely useful and it is genuinely v2 — the trigger is recorded in the deferred register.

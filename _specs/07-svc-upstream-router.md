# SPEC-07 — `svc-upstream-router`

**Role:** Obligation enforcement and forwarding to the protected server
**Phase:** v1 · **Build order:** 10th
**Depends on:** `06-svc-policy-broker`, `10-fixture-filesystem-mcp`, `01-svc-stdio-bridge`
**Consumed by:** `08-svc-response-guard`
**Source lineage:** `REQ-ARCH-005`, `REQ-REG-003`, `REQ-REL-001`, `REQ-REL-002`, `REQ-PRINCIPLE-004`

---

## 1. Purpose

The only place in the system that can cause a side effect. Everything before this unit is analysis; this unit acts.

Its contract is therefore narrow and absolute: it runs **if and only if** a validated `allow` decision exists for this exact canonical request, it forwards exactly what was authorized, and it enforces the obligations that came with the allow.

---

## 2. In scope

- Verifying a validated allow before any upstream contact.
- Enforcing obligations: request timeout, response byte ceiling.
- Forwarding the authorized call over the bridge's single upstream channel.
- Correlating the upstream call to the `request_id`.
- Cancellation propagation and upstream failure classification.

## 3. Out of scope

- Deciding anything — unit 06 decided.
- Response content validation — unit 08.
- Rate limiting: v1 has one client and one upstream; an in-process limiter here would be untestable ceremony. Recorded in the deferred register with its trigger.
- Credential selection: the v1 upstream is a local child process requiring no credential. The invariants are still stated below so they exist before the code that could violate them.
- Circuit breakers, connection pools, backpressure, router isolation — cut.

---

## 4. Contract

**Input:** canonical request + derived attributes + validated allow decision with obligations.
**Output:** the raw upstream response plus timing and status, handed to unit 08.
**Side channel:** the single upstream `stdio` channel owned by unit 01.

---

## 5. Requirements

### 5.1 The gate

**ROUTE-001 (`REQ-PRINCIPLE-004`, `CONV-001`)** — The router MUST accept only a validated allow decision object produced by unit 06 for **this** `request_id`. It MUST NOT accept a boolean, a truthy value, or a decision belonging to another request. A missing or mismatched decision is a denial and an internal-defect audit event.

**ROUTE-002** — The router MUST verify that the call it is about to forward matches the canonical request that was authorized — same method, same tool, same argument hash. **Any divergence between what was authorized and what is about to be sent MUST abort the request.** This closes the internal equivalent of the header/body split that unit 02 closes at the edge.

**ROUTE-003 (`REQ-ARCH-005`)** — Exactly one upstream execution path exists. The router MUST use the bridge's single channel and MUST NOT open a connection, spawn a process, or invoke a local filesystem operation itself. If the router can touch the filesystem directly, the gateway's entire mediation claim is void.

**ROUTE-004** — Forwarding MUST send the **canonical** request, not the original client bytes. Anything the guard rejected or normalized away does not reach the upstream.

### 5.2 Obligations

**ROUTE-005 (`REQ-REL-001`)** — The policy-supplied `timeout_ms` MUST be enforced on the upstream call and MUST NOT exceed the gateway's configured ceiling or the bridge's total request deadline, whichever is lower. No protected call may wait indefinitely.

**ROUTE-006** — The `max_response_bytes` obligation MUST be **measured by the router and enforced by unit 08** against the value the router actually applied after clamping, which travels on `RawResult.obligations`. The response is already materialised when it is measured, so the property is **detected and denied**, NOT prevented from being buffered.

The **streaming** form this requirement originally specified — stop reading and abort once the ceiling is crossed, never buffer then measure — is **deferred and unbuildable against the pinned SDK**: `stdio_client` accumulates a whole line and parses it into a `SessionMessage` before this module sees a byte ([90 §10g](90-deferred-register.md)). Restating the stronger claim anywhere is the failure mode this requirement now guards against: a hostile child inside the trust boundary can still make the gateway hold one reply in memory.

**ROUTE-007** — Every obligation actually enforced MUST be recorded in the audit event *as enforced*, which may differ from as-requested when clamping occurred (`POLICY-007`).

### 5.3 Credentials

**ROUTE-008 (`REQ-REG-003`)** — Downstream credentials, when they exist, come from the registry, are selected by server, and MUST NOT be exposed to the client, the policy input, the audit record, or a model. v1 uses none; the invariant is stated so the future is constrained.

**ROUTE-009 (`REQ-AUTH-002`)** — No client-supplied credential is ever forwarded upstream. v1 accepts none, so this is trivially satisfied and tested by asserting the forwarded message carries no credential-shaped field.

### 5.4 Failure and cancellation

**ROUTE-010 (`REQ-REL-002`)** — Client cancellation MUST propagate to the upstream call where safe. The audit event MUST distinguish `cancelled`, `timeout`, `error`, and `denied` — collapsing them loses the evidence the report depends on.

**ROUTE-011 (`CONV-004`)** — Upstream failure — crash, broken channel, malformed framing, unresponsive child — MUST produce a controlled error. The router MUST NOT retry a call that may have already produced a side effect. **v1 does not retry protected calls at all**; a retry decision requires idempotency semantics the fixture does not provide.

**ROUTE-012 (`REQ-OUT-005`)** — A failed, timed-out, cancelled, or partially completed upstream operation MUST NOT be reported to the client as success.

**ROUTE-013** — The router MUST record upstream latency separately from gateway latency. This separation is what makes the benchmark's overhead number meaningful (`PLAN.md` §6.1).

---

## 6. Failure modes

| Condition | Outcome | Reason code |
|---|---|---|
| No validated allow for this request id | deny + internal-defect audit | `ROUTE_NO_DECISION` |
| Authorized call ≠ call about to be sent | abort | `ROUTE_AUTHORIZATION_DIVERGENCE` |
| Upstream unavailable / channel broken | controlled error | `ROUTE_UPSTREAM_UNAVAILABLE` |
| Upstream timeout | controlled error, no retry | `ROUTE_TIMEOUT` |
| Response exceeds byte ceiling | measure after materialisation; unit 08 denies | `RESP_TOO_LARGE` (unit 08) |
| Client cancelled | propagate, audit `cancelled` | `ROUTE_CANCELLED` |

---

## 7. Configuration surface

Upstream timeout ceiling; response byte ceiling. All bounded by unit 01's total request deadline, which nests around them rather than being restated here.

~~cancellation grace period~~ — removed when the unit landed. The requirement it served (ROUTE-010) is met by the SDK, which sends `notifications/cancelled` on its own shielded, bounded write; there is no gateway-side window left to size. `_specs/90-deferred-register.md` §10h has the finding and the revival trigger.

---

## 8. Audit contribution

`upstream_status`, `upstream_latency_ms`, obligations-as-enforced, `stage_latency_ms.route`, terminal `outcome`.

---

## 9. Acceptance tests

1. **The mediation test:** across the entire malicious corpus, the fixture's own operation log shows zero operations attributable to a denied request. Asserted at the fixture, not at the gateway (`CONV-018`).
2. A fabricated allow object carrying a different `request_id` is rejected.
3. An argument mutated between policy evaluation and forwarding aborts with `ROUTE_AUTHORIZATION_DIVERGENCE` — injected deliberately at a test seam.
4. A policy timeout obligation shorter than the ceiling is honored; one longer is clamped by unit 06 and the clamped value is what the router enforces.
5. A fixture tool that returns a response larger than the ceiling is **detected and denied**, and the count the router recorded is the one unit 08 refuses on. The mid-stream abort this item originally asked for — asserted by peak memory not growing — is **deferred and unbuildable against the pinned SDK**, which parses a whole line before this module sees a byte: [90 §10g](90-deferred-register.md). The shipped claim is "an oversized response is detected and denied", never "cannot exhaust memory"; restating the stronger one is the failure this item now guards against.
6. An upstream that hangs hits the timeout, the client gets a controlled error, and the call is not retried.
7. An upstream that crashes mid-call produces `ROUTE_UPSTREAM_UNAVAILABLE`, not a success and not a hang.
8. Client cancellation propagates; the fixture observes the cancellation; the audit event says `cancelled`, not `error`.
9. A partially completed upstream operation is never reported as success.
10. Static assertion: the router module has no filesystem or network capability of its own (`ROUTE-003`).
11. Upstream latency and gateway latency are recorded separately and sum consistently with total request latency.

---

## 10. Notes for the tech sheet

- `ROUTE-002` is best implemented by having the router take the *decision* and re-derive the message from the same canonical request the decision was made against — so divergence is impossible rather than detected. Keep the detection test anyway; it guards refactors.
- Streaming the response-size ceiling (`ROUTE-006`) was specified because buffer-then-measure turns a size limit into a memory exhaustion vector. The pinned SDK forecloses it, so v1 ships the weaker property and says so; the trigger for revisiting is owning the child's stdout reader ([90 §10g](90-deferred-register.md)).
- No-retry is a deliberate simplification with a known ceiling: the fixture has no idempotency keys, so a retry could double a write. If an idempotent business fixture ever lands, revisit — that trigger is in the deferred register.

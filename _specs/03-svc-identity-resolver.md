# SPEC-03 — `svc-identity-resolver`

**Role:** Principal derivation and authorization context construction
**Phase:** v1 · **Build order:** 6th
**Depends on:** `09-svc-audit-log`
**Consumed by:** `06-svc-policy-broker`
**Source lineage:** `REQ-AUTH-003`, `REQ-AUTH-004`, `REQ-PRINCIPLE-006`, `REQ-AUTH-002`

---

## 1. Purpose

Answer "who is this?" honestly, and package the answer into the authorization context that policy evaluates.

For `stdio` there is no cryptographic identity. The launcher process and its configuration *are* the identity boundary. The single most important thing this unit does is **refuse to overstate that** — an audit record that labels a locally configured principal as authenticated is a lie that would invalidate every downstream evidence claim in the project.

---

## 2. In scope

- Resolving the principal, client identifier, and roles from launcher configuration.
- Labelling the assurance level truthfully.
- Building the immutable authorization context consumed by policy.

## 3. Out of scope

- OIDC/OAuth token validation, JWKS, issuer/audience checks — cut from v1 (`90-deferred-register.md`).
- Step-up authorization, session handles, confused-deputy binding — cut.
- Downstream credential selection — unit 07. v1's upstream is a local child process requiring no credential.

---

## 4. Contract

**Input:** the canonical request from unit 02, plus startup configuration.
**Output:** the **authorization context** — immutable, and the only identity representation any later stage may read.

Fields:

| Field | v1 value |
|---|---|
| `principal` | From launcher configuration |
| `client_id` | From launcher configuration |
| `roles` | From launcher configuration; a list, possibly empty |
| `auth_method` | Always `local_config` in v1 |
| `assurance` | Always `unverified_local` in v1 |
| `transport` | `stdio` |
| `environment` | From startup configuration, e.g. `development` |

---

## 5. Requirements

**IDENT-001 (`REQ-AUTH-003`)** — Each launcher configuration MUST assign a principal, a client identifier, and a role set. Startup MUST fail if any is missing. There is no anonymous or default principal.

**IDENT-002 (`REQ-PRINCIPLE-006`)** — The context MUST record `auth_method=local_config` and `assurance=unverified_local`. The gateway MUST NOT emit `oidc`, `authenticated`, `verified`, or any value implying cryptographic verification. **This is a hard constraint on the audit schema, not a convention** — the enum does not contain those values in v1.

**IDENT-003** — The principal MUST come from configuration only. **No field of any MCP message may influence it.** A client that supplies principal-shaped data in arguments, metadata, or headers is ignored — not merged, not preferred, not used as a fallback.

**IDENT-004 (`REQ-AUTH-004`)** — The context MUST be constructed once per request, immutable thereafter. Later stages read it; none may add roles, escalate assurance, or substitute a principal.

**IDENT-005 (`CONV-009`)** — Client-facing errors MUST NOT disclose the configured principal set, role names, or which principals exist.

**IDENT-006 (`REQ-AUTH-002`)** — v1 accepts no bearer token, and therefore forwards none. If a future transport introduces client tokens, a token issued to the gateway MUST NOT be forwarded upstream. Recorded here so the invariant exists before the code that could violate it.

**IDENT-007** — The documentation MUST state the limitation plainly, in the README and the threat model, not only in a spec: *a local `stdio` client that is separately configured with direct access to the protected server bypasses the gateway entirely, and the gateway cannot detect this.* The harness verifies the absence of a second route in the test configuration (unit 11), which is a configuration assertion — not a security control.

---

## 6. Failure modes

| Condition | Outcome | Reason code |
|---|---|---|
| Launcher configuration missing principal/client/roles | startup fails | — (not ready) |
| Configuration references an undefined role | startup fails | — (not ready) |

Note there is no runtime "authentication failure" in v1 — identity either exists at startup or the gateway does not start. That is the honest shape of `stdio` identity, and the spec does not manufacture a richer one.

> **Corrected on implementation.** This table originally carried a third row: *context cannot be constructed for a request → deny → `IDENT_CONTEXT_UNAVAILABLE`*. It contradicted the paragraph directly above it. Config validation runs at startup, and the context is seven assignments from values that validation already checked, so the condition cannot occur at request time. A reason code no corpus scenario can reach violates `CONV-010` permanently — it would sit unproven forever, or force a scenario modelling something the design calls impossible. The code was removed from `ReasonCode` before any release, so `CONV-008`'s no-meaning-change rule is not engaged. An unexpected exception in this stage becomes `INTERNAL_ERROR` at the pipeline, which denies.

---

## 7. Configuration surface

Principal identifier; client identifier; role list; environment label; the closed role vocabulary that policy references.

---

## 8. Audit contribution

`principal`, `client_id`, `roles`, `auth_method`, `assurance`, `environment`, `stage_latency_ms.identity`.

---

## 9. Acceptance tests

1. A configured principal appears in the audit event with `auth_method=local_config` and `assurance=unverified_local`.
2. **No audit event in the entire suite carries an `auth_method` implying verification** — asserted across every emitted record, not per test.
3. A request whose arguments, metadata, or mirrored headers contain principal-, role-, or client-shaped fields resolves to the configured identity and nothing else.
4. Startup fails when the launcher configuration omits principal, client, or roles.
5. Startup fails when configuration names a role outside the closed vocabulary.
6. Two launcher configurations with different principals produce different decisions under the same policy for the same request — proving identity actually reaches policy. **NOT IMPLEMENTED — integration pending unit 06.** There is no policy engine to disagree with itself yet. `test_a_different_config_produces_a_different_context` covers only the precondition (config → context is injective on principal) and says so; it must not be read as satisfying this row. Unit 06 owns the paired corpus scenario, and this row is a gate on unit 06 being marked done.
7. The context object rejects mutation after construction.

---

## 10. Notes for the tech sheet

- This unit is small, and its smallness is correct. Resist adding an identity abstraction layer for the OIDC that v1 does not build — the deferred register records the trigger, and a single-implementation interface is exactly the speculative abstraction to avoid.
- The assurance enum is the load-bearing design decision: make `unverified_local` the only value v1 can produce, so overstating identity requires a schema change and a code review rather than a typo.
- Test 6 is the one that proves identity is wired to policy rather than merely logged. It is therefore the one that cannot be faked from inside this unit — unit 03 can be complete and correct while identity never reaches a decision, which is exactly the state the repository is in until unit 06 lands.

# SPEC-04 — `svc-registry`

**Role:** Approved upstream servers, approved tools, schema fingerprints, drift detection
**Phase:** v1 · **Build order:** 7th
**Depends on:** `02-svc-protocol-guard`, `09-svc-audit-log`
**Consumed by:** `05-svc-canonicalizer-fs`, `06-svc-policy-broker`, `07-svc-upstream-router`, `01-svc-stdio-bridge` (launch parameters)
**Source lineage:** `REQ-REG-001`, `REQ-REG-002`, `REQ-MCP-008`, `REQ-MCP-009`, `REQ-PRINCIPLE-002`

---

## 1. Purpose

The default-deny surface. Nothing is routable, callable, or even *discoverable* unless it is written down here first, under version control, with a schema fingerprint.

The registry is also where the project's answer to tool-description poisoning lives: an upstream MCP server supplies its own tool names, descriptions, schemas, and annotations, and none of those are trustworthy. The registry pins what was approved and detects when the upstream's answer changes.

---

## 2. In scope

- The approved upstream server entry (v1 has exactly one) and its launch parameters.
- The approved tool set per server, with risk tier and schema fingerprint.
- Fingerprint computation and drift detection against what the upstream actually advertises.
- Quarantine of drifted tools.
- Filtering `tools/list` to what the principal could be authorized to use.
- Validating `tools/call` arguments against the approved schema before policy sees them.

## 3. Out of scope

- The authorization decision itself — unit 06. The registry answers "does this exist and is it approved?", policy answers "may this principal do it?".
- Path semantics — unit 05.
- Multiple upstreams, per-tenant registries, connection pools, circuit breakers — cut (`90-deferred-register.md`).
- A registry management API — cut. v1's registry is a version-controlled file, and that is a feature: changes are reviewable diffs.

---

## 4. Contract

**Input:** canonical request (unit 02) + authorization context (unit 03).
**Output on success:** a **resolved target** — server identifier, transport, tool name, approved schema, schema fingerprint, registry-assigned risk tier, and the approved launch parameters for unit 01.
**Output on failure:** terminal rejection with a `REG_*` reason code.

### Registry entry fields (v1)

Per server: stable identifier; display name; transport; executable path; argument vector; working directory; environment allowlist; expected protocol version; connection and request limits; state (`enabled` | `quarantined` | `disabled`); owner; review date.

Per tool: tool name; approved input schema; schema fingerprint; risk tier; enabled flag; a one-line description of what it is approved *for* (human-facing, never used at runtime).

Fields deliberately absent in v1: credential strategy (the local child needs none), tenant, allowed-environment list beyond the single configured environment.

---

## 5. Requirements

### 5.1 Default deny

**REG-001 (`REQ-REG-001`)** — The gateway MUST route only to explicitly registered servers. An unregistered server identifier is a denial, never a pass-through.

**REG-002 (`REQ-REG-002`)** — A client MUST NOT be able to cause the gateway to connect to an executable, path, host, port, or URL of its choosing. **No registry field may be sourced from an MCP message.** Unit 01 takes its launch parameters from here and only here.

**REG-003 (`REQ-PRINCIPLE-002`)** — A tool absent from the approved set MUST be denied even if the upstream advertises it. Upstream advertisement is input, not authorization.

**REG-004** — A server in `quarantined` or `disabled` state MUST deny all protected calls to it while remaining visible to diagnostics.

### 5.2 Schema fingerprinting and drift

**REG-005 (`REQ-MCP-009`)** — For every approved tool the registry MUST store a fingerprint computed over a **normalized** representation of the tool's name, description, input schema, output schema where present, and security-relevant annotations. The normalization rule MUST be documented and stable — key ordering, whitespace, and optional-field defaults fixed — so that a semantically identical schema always yields an identical fingerprint.

**REG-006 (`REQ-MCP-009`)** — At upstream handshake and on every `tools/list`, the advertised schema MUST be fingerprinted and compared to the approved value. A mismatch is a **drift event**: audited, and the tool MUST be quarantined. v1 implements quarantine only — shadow mode and administrator-review workflow are cut.

**REG-007** — A quarantined tool MUST be denied for `tools/call` and MUST disappear from `tools/list`. Clearing a quarantine requires editing the registry file and restarting — a reviewable, version-controlled act, not a runtime button.

**REG-008 (`CONV-007`)** — Upstream-supplied descriptions and annotations MUST NOT influence any runtime decision. They are fingerprinted so that changes are *detected*; they are never read as policy. Specifically, an annotation claiming a tool is read-only or safe MUST have no effect on risk tier or authorization.

**REG-009** — Drift detection MUST be evaluated before the first protected call of a session completes. A tool whose fingerprint has never been verified in the current session MUST NOT be callable.

### 5.3 Discovery filtering

**REG-010 (`REQ-MCP-008`)** — `tools/list` MUST return only tools that exist in the registry, are enabled, are not quarantined, and that the requesting principal could be authorized to call under the active policy. A client MUST NOT discover a tool it can never use.

**REG-011** — The filtered list MUST be derived from the same registry and policy data as enforcement. A tool visible in `tools/list` but universally denied at `tools/call`, or vice versa, is a defect with its own test.

### 5.4 Argument schema validation

**REG-012 (`REQ-GUARD-001`)** — `tools/call` arguments MUST be validated against the approved schema **before** policy evaluation. Validation failure is a denial; the request MUST NOT reach unit 05 or unit 06.

**REG-013 (`REQ-GUARD-001`)** — Unknown fields MUST be rejected by default. Additive permissiveness requires an explicit per-tool opt-in in the registry, which v1 does not use.

**REG-014** — Validation MUST use the **approved** schema from the registry, never the schema the upstream currently advertises. This is the whole point of pinning.

---

## 6. Failure modes

| Condition | Reason code |
|---|---|
| Server identifier not registered | `REG_SERVER_UNKNOWN` |
| Server quarantined or disabled | `REG_SERVER_UNAVAILABLE` |
| Tool not in approved set | `REG_TOOL_UNKNOWN` |
| Tool quarantined | `REG_TOOL_QUARANTINED` |
| Advertised fingerprint ≠ approved fingerprint | `REG_SCHEMA_DRIFT` |
| Fingerprint never verified this session | `REG_SCHEMA_UNVERIFIED` |
| Arguments fail approved schema | `REG_ARGS_INVALID` |
| Unknown argument field | `REG_ARGS_UNKNOWN_FIELD` |
| Registry file unloadable or invalid at startup | not ready; all protected calls denied |

---

## 7. Configuration surface

Registry file path; the registry document itself (schema-validated, unknown fields fail startup per `CONV-013`); fingerprint normalization version; drift policy (v1: always quarantine).

---

## 8. Audit contribution

`server_id`, `tool_name`, `schema_fingerprint`, registry-assigned `risk_tier`, `stage_latency_ms.registry`, and drift events as their own audited record.

---

## 9. Acceptance tests

1. A call to an unregistered server is denied and the fixture observes nothing.
2. A call to an unregistered tool on the registered server is denied — including a tool the upstream genuinely advertises and would happily execute.
3. **Drift:** start with an approved fingerprint, change the fixture's advertised schema, restart; the tool quarantines, `tools/call` is denied, and the tool vanishes from `tools/list`.
4. **Poisoned annotation:** the fixture advertises a destructive tool annotated read-only and harmless. Risk tier and authorization are unchanged; the annotation change alone triggers drift.
5. Fingerprint stability: semantically identical schemas with reordered keys and differing whitespace produce identical fingerprints; a single meaningful character change produces a different one.
6. `tools/list` for a restricted principal omits tools that principal can never call; the omitted set exactly equals the universally-denied set (`REG-011`).
7. Arguments violating the approved schema are denied before policy is consulted — asserted by verifying policy was never invoked.
8. An unknown argument field is rejected.
9. The approved schema is used even when the upstream advertises a laxer one.
10. A registry file with an unknown top-level key fails startup rather than being ignored.
11. No client-supplied value can reach a launch parameter — fuzzed argument values containing paths and executable names never appear in the child's argv.

---

## 10. Notes for the tech sheet

- Fingerprint normalization is the subtle part: canonical JSON serialization with sorted keys, explicit handling of absent-vs-null, and a version tag on the normalization rule itself so fingerprints can be migrated deliberately rather than silently invalidated.
- The registry is a file, validated at startup into a frozen in-memory structure. No database, no API, no hot reload — restart is the reload mechanism and that is sufficient at v1 scale.
- `REG-011` is best implemented by making both `tools/list` filtering and `tools/call` enforcement call the *same* function, so divergence is structurally impossible rather than test-detected.
- Test 4 is the most portfolio-legible test in this unit: it demonstrates tool-description poisoning defense concretely.

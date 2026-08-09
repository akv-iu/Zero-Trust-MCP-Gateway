# SPEC-02 — `svc-protocol-guard`

**Role:** JSON-RPC hardening and MCP header/body consistency — **the differentiator**
**Phase:** v1 · **Build order:** 5th
**Depends on:** `01-svc-stdio-bridge`, `09-svc-audit-log`
**Consumed by:** `03-svc-identity-resolver`
**Source lineage:** `REQ-MCP-001`, `REQ-MCP-005`, `REQ-MCP-007`, `REQ-GUARD-004`

---

## 1. Purpose

Turn an untrusted byte envelope into a **canonical request**, or reject it. This is the unit that carries v1's differentiating claim (`PLAN.md` §2).

The MCP specification dated 2026-07-28 made the core protocol stateless and introduced request metadata headers that mirror fields inside the JSON-RPC body, with a specification rule that a request whose header and body disagree **must be rejected** — HTTP `400` with JSON-RPC error `-32020` `HeaderMismatch`.

**Four mirrored families, not two** ([ADR-001](ADR-001-transport-and-mirrored-metadata.md) §3): `MCP-Protocol-Version` ↔ `params._meta["io.modelcontextprotocol/protocolVersion"]`; `Mcp-Method` ↔ `method`; `Mcp-Name` ↔ `params.name` or `params.uri`; and `Mcp-Param-{Name}` ↔ any tool argument the server designates via an `x-mcp-header` annotation in its `inputSchema`. Two of these carry a base64 sentinel encoding that must be decoded exactly once before comparison, and integer parameters are compared numerically rather than as strings.

The spec states the rationale in terms that name this product category directly: the rule exists to prevent *"different components in the network relying on different sources of truth (e.g., a load balancer routing on the header value while the MCP server executes based on the body value)."*

That mirroring creates a class of vulnerability that did not exist before 2026-07-28: any component that reads the *header* to route or authorize while another component executes the *body* can be made to authorize one action and perform another. Most gateways in this category predate the stateless spec and were built against session-based Streamable HTTP.

**This unit's job is to make that split impossible.** It produces exactly one canonical view of the request, and every stage after it authorizes and acts on that view alone.

---

## 2. In scope

- JSON parsing with hard structural limits.
- JSON-RPC envelope validation.
- MCP protocol version validation.
- Method allowlist enforcement.
- **Header/body consistency enforcement for every mirrored field.**
- Construction of the canonical request handed downstream.

## 3. Out of scope

- Argument semantics and tool-specific schema validation — unit 04 (schema) and unit 05 (canonicalization).
- Identity — unit 03.
- Authorization — unit 06.
- HTTP-specific headers, CORS, `Origin` (cut with the HTTP transport).

---

## 4. Contract

**Input:** raw message envelope from unit 01 — undecoded body bytes, accompanying transport metadata, `request_id`, receipt timestamp.

**Output on success:** the **canonical request**, an immutable record carrying at minimum: `request_id`, protocol version, MCP method, JSON-RPC request identifier, target tool name where applicable, the raw argument object (parsed but not yet canonicalized), and a hash of the body as received.

**Output on failure:** a terminal rejection with a `PROTO_*` reason code and a complete audit event.

**Immutability rule:** the canonical request MUST be immutable once emitted. No later stage may mutate it; stages 05 and onward attach *derived* attributes alongside it rather than editing it.

---

## 5. Requirements

### 5.1 Header/body consistency — the core requirement

**PROTO-001 (`REQ-MCP-005`)** — For every request metadata field that the 2026-07-28 specification mirrors between transport metadata and the JSON-RPC body — including at minimum `Mcp-Method` against the body's `method`, and `Mcp-Name` against the body's tool/target name — the guard MUST parse the body and compare. **Any disagreement MUST be rejected.**

**PROTO-002** — The comparison MUST occur **before** routing, before registry lookup, and before policy evaluation. There MUST NOT be an execution path in which a mirrored field is used for any purpose prior to the consistency check.

**PROTO-003** — Comparison MUST be exact on the canonical form of both values: identical after a single documented normalization pass (case and whitespace rules fixed and tested). Partial match, prefix match, and case-insensitive match are prohibited. Where normalization is ambiguous, reject rather than guess.

**PROTO-004** — A mirrored header that is **present but empty**, **duplicated with differing values**, or **structurally malformed** MUST be rejected — never treated as absent.

**PROTO-005** — Presence rules MUST be explicit per field and per method: for each mirrored field the spec MUST state whether it is required, optional, or prohibited for that method, and each of the three MUST have a test. A field required and absent is a rejection. A field prohibited and present is a rejection.

**PROTO-006** — Exactly one authority. Every downstream stage MUST read the method and target name from the canonical request. **No stage may re-read transport metadata.** This is verified structurally, not only by test: the raw envelope is not passed beyond this unit.

**PROTO-007** — Every distinct disagreement shape MUST have its own reason code and its own corpus scenario: method mismatch, name mismatch, missing-required, present-prohibited, duplicate-conflicting, empty-value, encoding-differs-but-decodes-equal.

### 5.2 Protocol validation

**PROTO-008 (`REQ-MCP-001`)** — The declared MCP protocol version MUST be validated against the supported set. Unknown, absent, and downgraded versions MUST be denied. v1 supports the 2026-07-28 revision only; there is no compatibility adapter (cut — see `90-deferred-register.md`).

**PROTO-009 (`REQ-MCP-007`)** — The JSON-RPC envelope MUST be validated: correct version marker, required fields present, request identifier well-formed and of an accepted type, and no conflicting duplicate keys anywhere in the object.

**PROTO-010 (`REQ-PRINCIPLE-002`)** — Method names MUST be checked against an explicit allowlist. v1 permits `initialize` and the handshake set required for a session, plus `tools/list` and `tools/call`. Everything else — including valid MCP methods the gateway does not protect — is denied by default, not proxied.

### 5.3 Parser hardening

**PROTO-011 (`REQ-MCP-007`)** — Rejected without exception: invalid JSON, wrong JSON-RPC version, missing required fields, duplicate keys with conflicting values, unsupported batch shapes, invalid request identifiers.

**PROTO-012 (`REQ-GUARD-004`)** — Structural limits MUST be enforced during or immediately after parse, and MUST include: maximum nesting depth, maximum object key count, maximum array length, maximum string length, maximum total field count. Each limit is a named config value with tests at, below, and above the boundary (`CONV-015`).

**PROTO-013** — Parsing MUST be bounded in time and memory. A deeply nested or pathological payload MUST NOT be able to consume unbounded CPU or memory before rejection — depth and size checks apply during parsing, not only after.

**PROTO-014 (`CONV-009`)** — Rejection responses MUST carry a stable reason code and MUST NOT echo the offending payload back to the client, quote parser internals, or reveal configured limit values.

---

## 6. Failure modes

| Condition | Reason code |
|---|---|
| Header/body method disagreement | `PROTO_HEADER_BODY_METHOD_MISMATCH` |
| Header/body name disagreement | `PROTO_HEADER_BODY_NAME_MISMATCH` |
| Required mirrored field absent | `PROTO_METADATA_MISSING` |
| Prohibited mirrored field present | `PROTO_METADATA_UNEXPECTED` |
| Duplicate mirrored field, conflicting values | `PROTO_METADATA_DUPLICATE` |
| Unsupported / absent / downgraded protocol version | `PROTO_VERSION_UNSUPPORTED` |
| Invalid JSON | `PROTO_JSON_INVALID` |
| Invalid JSON-RPC envelope | `PROTO_JSONRPC_INVALID` |
| Duplicate conflicting body keys | `PROTO_DUPLICATE_FIELD` |
| Structural limit exceeded | `PROTO_LIMIT_EXCEEDED` |
| Method not in allowlist | `PROTO_METHOD_NOT_ALLOWED` |

---

## 7. Configuration surface

Supported protocol versions (fixed set); method allowlist; per-method mirrored-field presence rules; max nesting depth; max key count; max array length; max string length; max total fields; parse time budget.

---

## 8. Audit contribution

`mcp_method`, `mcp_protocol_version`, body hash, `stage_latency_ms.protocol`, and on rejection `outcome=denied` with the `PROTO_*` reason code.

---

## 9. Acceptance tests

The consistency suite is the project's headline test class and is reported separately in the benchmark.

1. **One case per row of the failure table**, each asserting rejection before any registry or policy call is made — verified by asserting those units were never invoked, not merely that the result was a denial.
2. Matching header and body pass and produce a canonical request whose method and name equal both.
3. **The split-authorization case:** header names an allowed tool, body names a prohibited one. Rejected at stage 2. The oracle (unit 11) confirms the fixture observed nothing. Then the inverse: header prohibited, body allowed — also rejected, proving the check is symmetric and not a one-sided allowlist.
4. Percent-encoded or unicode-escaped variants that decode to the same value: the documented normalization rule is applied consistently, and whichever way the rule falls, the outcome is deterministic and tested.
5. Boundary tests at, below, and above every structural limit.
6. Pathological payloads — deep nesting, huge arrays, long strings, duplicate keys — are rejected within the parse time budget without memory growth.
7. A protocol version one revision older than 2026-07-28 is denied, not silently adapted.
8. A valid MCP method outside the v1 allowlist (e.g. a resources or prompts method) is denied, not proxied.
9. **Structural test:** the raw envelope object is not reachable from any stage after 02 — enforced by the type handed downstream, and asserted.
10. Hypothesis generates header/body pairs and JSON structure variants from a recorded seed; no generated case produces an inconsistent canonical request.

---

## 10. Notes for the tech sheet

- Read the 2026-07-28 transport specification and SEP-2243 directly and enumerate **every** mirrored field before implementing. The requirement is "all mirrored fields", not "the two named here" — the two named are the ones known at planning time.
- Choose a JSON parser that can enforce depth and size limits *during* parsing and can report duplicate keys. A parser that silently takes last-key-wins hides `PROTO_DUPLICATE_FIELD` entirely; verify this behavior explicitly before choosing.
- The canonical request type should be structurally immutable (frozen), so `PROTO-006` is enforced by the type system rather than by discipline.
- This unit deserves the most test density in the project. It is the differentiator, and it is the thing a reviewer will actually check.

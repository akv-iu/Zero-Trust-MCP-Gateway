# ADR-001 — Client-facing transport is Streamable HTTP; the mirrored-metadata surface

**Status:** Accepted, 2026-08-08 · Resolves **D-1**, dissolves **S-1**, answers **S-3**
**Supersedes:** the stdio-only client edge in `PLAN.md` §3.1 and `_specs/01`
**Evidence:** the 2026-07-28 specification, read directly (sources at the end)

---

## 1. The finding

`PLAN.md` §2 stakes v1's differentiator on rejecting header/body disagreement. The spec settles where that is possible:

> **stdio transport:** "All request metadata for the stdio transport is carried inline in the JSON-RPC message body. The protocol version, per-request capabilities, and optional client identity live in `_meta.io.modelcontextprotocol/*`; the method name and arguments live where JSON-RPC puts them. **There is no header layer.**"

> **Streamable HTTP:** "The Streamable HTTP transport mirrors selected JSON-RPC body fields into HTTP headers so that intermediaries (load balancers, gateways, observability tooling) can route and inspect requests without parsing the body."

A stdio-only gateway therefore cannot exercise its own headline claim. **Option A from `_tech/02` §0 is superseded by the stronger move: flip the client-facing edge to Streamable HTTP.**

---

## 2. Decision

| Leg | Transport | Change |
|---|---|---|
| Client → gateway | **Streamable HTTP**, loopback-bound | Was stdio |
| Gateway → upstream fixture | **stdio** | Unchanged |

There is **no stdio client-facing edge in v1**. Offering one would create a path with no mirrored metadata and therefore no consistency check — a strictly weaker route past the gateway's primary control. One edge, one set of guarantees.

### Why this is cheaper, not more expensive

`PLAN.md` §3.3 deferred HTTP because it "doubles the protocol surface — TLS, `Origin`, bind addresses, CORS, streaming, reconnection". That assessment was against the **pre-2026-07-28** Streamable HTTP. The 2026-07-28 revision removed most of it:

| Removed in 2026-07-28 | Consequence for v1 |
|---|---|
| Protocol-level sessions, `Mcp-Session-Id` | No session state to hijack, bind, or expire |
| GET stream endpoint | One method, one path |
| `Last-Event-ID` resumability | "Resumable SSE streams via `Last-Event-ID` are not supported" |
| Server-initiated JSON-RPC requests on SSE | Server→client interactions are MRTR results instead |
| `initialize` handshake (modern era) | Per-request `_meta` replaces it; `server/discover` is an optional probe |

What remains for v1: **one POST endpoint, one JSON-RPC message per request, one response** (single JSON object, or SSE for streaming). Plus `Origin` validation and a loopback bind, both spec-mandated and roughly ten lines. No TLS on loopback. No auth — identity stays local-config per `_specs/03`.

### What it buys

- **S-1 dissolves.** An ASGI app receives the raw body bytes and the full header multidict before any parsing. The MCP SDK stream-tee spike — the biggest technical unknown in the project — is no longer needed. Duplicate-key detection, body hashing, and the streaming byte ceiling all become straightforward.
- **Duplicate mirrored headers become detectable.** `_tech/02` §3 flagged that a `Mapping[str, str]` cannot represent a duplicated header. ASGI exposes headers as a list of pairs, so `PROTO-004` is enforceable at the edge as the spec intends.
- **The mirrored surface is far larger than planned** (§3), and materially more interesting.

### Cost

Unit 01 changes from "MCP SDK stdio server + child client" to "ASGI app + MCP SDK stdio child client". The child leg is unchanged. Net: roughly a wash on effort, and one fewer unknown.

---

## 3. The complete mirrored-metadata surface (answers S-3)

Four families, not two. Every one is a consistency check.

| Header | Mirrors | Required for |
|---|---|---|
| `MCP-Protocol-Version` | `params._meta["io.modelcontextprotocol/protocolVersion"]` | Every POST |
| `Mcp-Method` | `method` | All requests |
| `Mcp-Name` | `params.name` **or** `params.uri` | `tools/call`, `resources/read`, `prompts/get` |
| `Mcp-Param-{Name}` | An arbitrary tool argument, designated by the server | Per tool schema |

Spec text: *"Servers that process the request body **MUST** reject requests where the values specified in the headers do not match the corresponding values in the request body. This prevents potential security vulnerabilities when different components in the network rely on different sources of truth (e.g., a load balancer routing on the header value while the MCP server executes based on the body value)."*

That sentence describes this product category by name. The gateway is the component the requirement exists for.

### 3.1 `Mcp-Param-{Name}` and `x-mcp-header`

A server marks a tool parameter with `x-mcp-header` in its `inputSchema`; conforming clients then mirror that argument's value into `Mcp-Param-{Name}`. This is **server-designated, per-tool, and schema-carried**, which wires it directly into `_specs/04`:

- `x-mcp-header` annotations are part of `inputSchema`, so they are already inside the fingerprint (`REG-005`). A server that *adds* one is drift — and it is drift that changes what the gateway must validate. This is a genuinely novel poisoning vector.
- The spec's own constraints must be enforced by the gateway, not assumed: non-empty, RFC 9110 token syntax, no CR/LF, case-insensitively unique within the schema, primitive types only (`number` prohibited, integers within the JS safe range), and **statically reachable via a chain of `properties` keys only** — never through `items`, `oneOf`/`anyOf`/`allOf`/`not`, `if`/`then`/`else`, or `$ref`.
- The spec requires clients to reject tools violating these constraints by excluding them from `tools/list`. A gateway is both a client and a server; v1 quarantines such a tool (`REG-007`) rather than silently dropping it.

The reachability rule is the sharp edge: a `$ref` or `anyOf` in the path makes the annotation invalid, and a naive implementation that walks the instance rather than the schema chain will mirror the wrong value. That is a real, spec-named bypass and belongs in the corpus.

### 3.2 Base64 sentinel encoding

Values that cannot be safely represented as ASCII are carried as `=?base64?{Base64EncodedValue}?=`, lowercase markers, case-sensitive. Servers **MUST** decode before comparing. Applies to `Mcp-Name` and `Mcp-Param-*`.

The ambiguity clause is the attack: *"clients **MUST** also Base64-encode any plain-ASCII value that matches the sentinel pattern."* So a literal tool name of `=?base64?literal?=` must itself be encoded. A gateway that decodes unconditionally, or decodes twice, or compares the encoded form to a decoded body value, is exploitable. **Decode exactly once, then compare** — the same discipline as `CANON-001`, and it deserves the same test density.

### 3.3 Numeric comparison

*"When validating integer parameter values, servers **SHOULD** compare the header value and the body value numerically rather than as strings (e.g., `42.0` and `42` are considered equal)."*

A `SHOULD` with two defensible readings is a divergence generator: string comparison and numeric comparison disagree on `42` vs `42.0` vs `+42` vs `0042` vs `4_2`. v1 compares **numerically for integer-typed parameters** (per the spec) and rejects any header value that is not a canonical integer literal — narrowing the accepted set rather than broadening the comparison. Document the choice; put every variant in the corpus.

### 3.4 The downgrade attack — the spec names it

> *"Intermediaries that enforce policy based on mirrored headers (e.g., routing or rate-limiting by tenant) **SHOULD** verify that the `MCP-Protocol-Version` header indicates a version that requires header–body validation. If the version is older or the header is absent, the intermediary **SHOULD** reject the request rather than trusting unvalidated header values."*

This is a named attack against exactly this product category, published eleven days before the project snapshot. v1 already denies non-`2026-07-28` versions (`PROTO-008`), so it satisfies the requirement by construction — but it must be **tested and reported as such**, because it is the most legible demonstration the project can offer that being spec-current is a security property and not a marketing line.

Promote it to a first-class corpus class: version absent, version older, version present-but-unsupported, version header disagreeing with `_meta`.

---

## 4. Consequences — deltas to apply

Applied now (files updated with this ADR): `PLAN.md`, `_specs/01`, `_specs/02`, `_tech/01`, `_tech/02`.

Applied when each unit is built, per the "no requirement without same-week implementation" rule:

| Unit | Delta |
|---|---|
| **02** | Method allowlist drops `initialize`/`notifications/initialized`; modern era has no handshake. Add `server/discover` as an explicitly denied-but-recognized method. Protocol version now validated in **two** places that must agree: the header and `params._meta`. |
| **04** | Fingerprint must cover `x-mcp-header` annotations (already inside `inputSchema`, but assert it). Add schema-load validation of every `x-mcp-header` constraint in §3.1, including static reachability. Quarantine on violation. |
| **07** | Upstream cancellation is transport-asymmetric: the client cancels by closing the SSE stream; the gateway must translate that into `notifications/cancelled` on the stdio leg. Resolves **S-5** — the mechanism exists and is mandatory on stdio. |
| **08** | On rejection the gateway must return HTTP `400` with JSON-RPC error **`-32020` `HeaderMismatch`**. Unsupported version returns `400` + `UnsupportedProtocolVersionError` listing supported versions. Unknown method returns **`404`** + `-32601`. These are mandated shapes, not free choices. |
| **11** | New corpus classes: `Mcp-Param-*` mismatch, base64 sentinel confusion, numeric-comparison variants, static-reachability bypass, and the four version-downgrade cases. |
| **90** | MRTR (`InputRequiredResult` / `inputRequests` / `inputResponses`) and `subscriptions/listen` are new deferred entries — see §5. |

---

## 5. Newly discovered, deliberately deferred

**MRTR (SEP-2322).** Server→client interactions no longer arrive as server-initiated requests; the server returns an `InputRequiredResult` and the client **retries the original request** with `inputResponses` attached. For a gateway this is an argument-mutation-across-round-trips surface: the retry carries the original params *plus* new content, and it is a fresh authorization decision, not a continuation. v1 **denies any request carrying `inputResponses`** and any response containing `inputRequests`, with dedicated reason codes — an explicit, tested refusal rather than an untested pass-through. Trigger to implement: a fixture that legitimately needs elicitation or sampling.

**`subscriptions/listen`.** Long-lived SSE streams carrying change notifications, correlated by `io.modelcontextprotocol/subscriptionId` in `_meta`. Not in the v1 method allowlist; denied by default (`PROTO-010`). Trigger: resources enter scope.

**Upstream restart.** The stdio spec now says a client **SHOULD** restart a server that exits unexpectedly, since "the protocol is stateless, any in-flight requests are simply lost and the client can retry them against the fresh process." This relaxes `BRIDGE-011` for *process* restart but **not** for request retry: `ROUTE-011`'s no-retry rule stands, because the fixture has no idempotency keys. v1 may restart the child; it must still fail the in-flight request.

---

## 6. What does not change

- Identity stays local-config, `unverified_local` (`_specs/03`). A loopback HTTP edge is not an authentication boundary and must not be described as one.
- Gateway binds `127.0.0.1` only; `Origin` validated per spec; `403` on invalid origin.
- No TLS, no CORS beyond `Origin`, no auth, no admin surface. Everything else in `_specs/90` stays deferred.
- The upstream leg, the fixture, the oracle, the policy engine, and the audit design are untouched.

---

## Sources

- [Streamable HTTP transport, draft (2026-07-28)](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)
- [stdio transport, draft (2026-07-28)](https://modelcontextprotocol.io/specification/draft/basic/transports/stdio)
- [SEP-2575: Make MCP Stateless](https://modelcontextprotocol.io/seps/2575-stateless-mcp)
- [The 2026-07-28 Specification — MCP blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP Stateless Spec Changes: The Engineering Details — Solo.io](https://www.solo.io/blog/mcp-stateless-spec-changes-the-engineering-details)
- [What's new in the MCP 2026-07-28 specification — Appwrite](https://appwrite.io/blog/post/mcp-goes-stateless-in-the-2026-07-28-specification)

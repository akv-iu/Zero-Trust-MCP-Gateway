# ADR-002 — The SDK owns mirrored-metadata validation; v1's claim is re-scoped

**Status:** Accepted, 2026-08-08 · Amends [ADR-001](ADR-001-transport-and-mirrored-metadata.md) · Supersedes `PLAN.md` §2 and most of `_tech/02` §3
**Trigger:** reading the installed reference implementation, which ADR-001 did not do

---

## 1. The finding

`mcp` **2.0.0** ships `mcp/shared/inbound.py` — 581 lines, publicly exported via `__all__`, and deliberately factored as a pure module. Its own header: *"Pure module: no I/O, no transport, no `mcp.server` imports."* Its purpose: *"hosts the shared header-value codec and the `x-mcp-header` schema validator so client emit and server validate read the same source of truth."*

It already implements everything ADR-001 §3 and `_tech/02` §3 specified as v1's differentiating work:

| Specified as ours | Already in the SDK |
|---|---|
| Mirrored-field table and comparison, in spec order | `classify_inbound_request()` |
| Duplicate mirrored-header detection (`PROTO-004`) | `find_duplicated_routing_header()` |
| Base64 sentinel, decode exactly once | `decode_header_value()` / `encode_header_value()` |
| `x-mcp-header` constraints incl. static reachability | `find_invalid_x_mcp_header()` — walks `$defs`, `anyOf`, `patternProperties` |
| `Mcp-Param-*` comparison, canonical decimal form | `validate_mcp_param_headers()`, `_CANONICAL_DECIMAL` |
| HTTP status ← JSON-RPC code mapping | `ERROR_CODE_HTTP_STATUS` |
| Which body field `Mcp-Name` mirrors, per method | `NAME_BEARING_METHODS` |

**ADR-001 read the specification and not the reference implementation.** That was the error. The rule going forward: before claiming any protocol behavior as project work, read the installed SDK first.

---

## 2. Decision

### 2.1 Use the SDK module. Do not reimplement any of it.

Ladder rung 5 — an already-installed dependency solves it. Reimplementing 581 lines of spec-critical parsing would guarantee divergence from the reference implementation, and `_tech/02` §3 already contained one: it specified rejecting a decoded value that itself matches the sentinel pattern, which the SDK does not necessarily do. A gateway that disagrees with the reference implementation about what a request *means* is the exact failure this project exists to prevent.

### 2.2 Unit 02 becomes an adapter plus the gaps

The SDK's docstring names its own boundaries. What remains genuinely ours:

| Still unit 02's job | Why |
|---|---|
| Byte-level depth/size prescan | The ladder takes an already-decoded mapping |
| `json.loads` with `object_pairs_hook` duplicate-key detection | Same — the body is decoded before it arrives |
| Structural limits: array length, string length, field count | Not a rung |
| JSON-RPC envelope shape (`jsonrpc`, `id`) | *"Envelope shape (`jsonrpc` / `id`) is not checked here"* |
| Method allowlist / default-deny | *"Method existence is **not** a rung: kernel dispatch owns that decision"* — and default-deny is a policy posture, not dispatch |
| MRTR refusal (`inputResponses` / `inputRequests`) | ADR-001 §5; not the SDK's concern |
| Mapping SDK rejections → our `ReasonCode` + audit | The evidence layer is entirely ours |

Order becomes: prescan → parse with duplicate detection → structural limits → **SDK ladder** → envelope shape → method allowlist → MRTR refusal → `CanonicalRequest`.

Net effect: unit 02 gets **smaller and more correct**. `_tech/02` §3's tables and code are superseded; §2 (parser choice, prescan) and §4–§7 stand.

### 2.3 The claim is re-scoped

`PLAN.md` §2's "narrow, time-limited edge" is withdrawn. It was never true: the edge was commodity on the day it was written, shipped inside the official SDK.

What survives is what `PLAN.md` §9 always said the deliverable was — and what the original review said would carry job-signal value:

> A default-deny MCP enforcement point built on the current SDK, which authorizes on a single canonical view of every request and **proves non-bypass with a side-effect oracle at the protected system** rather than with its own denial messages.

The novelty is not the parsing. It is the **evidence**: a published attack corpus, an oracle that observes the protected system rather than trusting the gateway, a measured overhead distribution with its co-location caveat stated, and an audit trail with a measured completeness ratio. None of that is in any SDK, and none of it is in the incumbent gateways either.

Two honest secondary points remain usable:

- Most deployed gateways target the pre-2026-07-28 session-based transport and do not perform this validation at all. Being current is a correct dependency choice, not novel engineering — say it that way.
- The spec's note that **intermediaries** must reject rather than trust headers on older protocol versions is a *policy* posture, not a parsing one. The SDK supplies the ladder; refusing to serve a downgraded request is the gateway's decision. That test stays, and stays valuable.

---

## 3. Consequences

- `PLAN.md` §2 rewritten; §3.1 differentiator row reworded.
- `_tech/02` §0 and §3 superseded by this ADR; the rest stands.
- `_specs/02` purpose section rewritten. Its requirements `PROTO-001`…`PROTO-007` still hold as *behaviors the gateway must exhibit* — they are simply satisfied by delegation plus tests, not by hand-written comparison code.
- **The corpus does not shrink.** Every scenario in ADR-001 §3 and `_tech/02` §6 still gets written and run. Testing a delegated behavior is exactly as necessary as testing an implemented one — more so, because it pins the SDK's behavior against a version bump.
- Add `mcp` to the pinned-version discipline: an SDK upgrade can change validation semantics, so the corpus is also the upgrade gate.
- `_tech/02`'s estimate of unit 02 as "the highest test density in the project" is unchanged. Only the implementation shrinks.

---

## 4. Process correction

ADR-001's spike list included "read the spec". It should have included "read the installed reference implementation". Applied retroactively to the remaining units before each is built:

- **04 registry** — check what `mcp.shared.inbound.x_mcp_header_map` and `find_invalid_x_mcp_header` already give the fingerprinting work.
- **08 response guard** — check whether the SDK's session already correlates responses and rejects unsolicited messages (spike S-2, still open).
- **01 edge** — check `mcp.server._streamable_http_modern` before hand-writing an ASGI app.

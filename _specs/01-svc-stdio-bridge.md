# SPEC-01 — `svc-transport-edge` (formerly `svc-stdio-bridge`)

> **Amended by [ADR-001](ADR-001-transport-and-mirrored-metadata.md), 2026-08-08.** The client-facing edge is **Streamable HTTP** bound to loopback, not stdio — the mirrored metadata unit 02 depends on exists only there. The **upstream leg remains stdio**, so §3 (child process supervision) and every `BRIDGE-005` … `BRIDGE-012` requirement below stands unchanged. What changes: the client-facing half is an ASGI app rather than an SDK stdio server, `BRIDGE-001` (`stdout` purity) applies only to the child leg, and `Origin` validation plus a `127.0.0.1` bind are added. See [`_tech/01`](../_tech/01-svc-stdio-bridge.md) §1a.

**Role:** Transport edge and upstream process lifecycle
**Phase:** v1 · **Build order:** 3rd
**Depends on:** `10-fixture-filesystem-mcp`
**Consumed by:** `02-svc-protocol-guard`
**Source lineage:** `REQ-ARCH-006`, `REQ-MCP-006`, `REQ-PRINCIPLE-006`

---

## 1. Purpose

The only way in and the only way out. The bridge is an MCP **server** on its client-facing `stdin`/`stdout`, and an MCP **client** to a child process it spawns and supervises. It owns framing, the request identifier, request lifetime, and the child process's entire environment.

It makes no security decision. Its job is to ensure that every byte from a client enters the lifecycle at stage 2 and that no byte reaches the upstream except through stage 7.

---

## 2. In scope

- Reading and framing client messages from `stdin`.
- Writing responses to `stdout`, and **only** protocol traffic to `stdout`.
- Minting the `request_id` that correlates every downstream artifact.
- Spawning, supervising, and terminating the upstream MCP server process.
- Controlling the child's executable path, argument vector, working directory, and environment.
- Enforcing startup, per-request, and shutdown deadlines.
- Propagating client cancellation and connection loss.
- Reaping orphans.

## 3. Out of scope

- Any parsing of message content beyond what framing requires — that is unit 02.
- Any authorization decision.
- Streamable HTTP, TLS, `Origin` validation, bind addresses (cut; see `90-deferred-register.md`).
- Reconnection or session resumption — the 2026-07-28 core is stateless and v1 holds no session state.

---

## 4. Contract

**Client-facing input:** a byte stream of framed MCP messages on `stdin`.
**Client-facing output:** framed MCP responses on `stdout`, one per request, plus notifications the gateway is permitted to relay.
**Downstream output:** a *raw message envelope* handed to unit 02 — the undecoded body bytes, the transport-level metadata that accompanied them, the `request_id`, and the receipt timestamp. The bridge does not interpret the body.
**Upstream interface:** a duplex `stdio` channel to the child, used only by unit 07.

The bridge exposes two lifecycle operations to the rest of the gateway: *start* (spawn and handshake with the child, block readiness until it succeeds) and *stop* (drain, terminate, reap).

---

## 5. Requirements

**BRIDGE-001 (`REQ-MCP-006`)** — `stdout` MUST carry protocol traffic and nothing else. All diagnostics, logs, warnings, tracebacks, and library output MUST go to `stderr` or a file sink. Any library that writes to `stdout` MUST be reconfigured at startup; startup MUST fail if it cannot be.

**BRIDGE-002** — Every inbound client message MUST receive a `request_id` before any other processing. The identifier MUST be unguessable, unique per process lifetime, and present in every audit event, error response, and trace record for that request.

**BRIDGE-003 (`REQ-GUARD-004`)** — The bridge MUST enforce a maximum inbound message size at the framing layer, before the body is handed to unit 02. Oversized messages MUST be rejected without being fully buffered.

**BRIDGE-004** — The bridge MUST enforce a total request deadline. On expiry the request terminates with `outcome=timeout`, the client receives a controlled error, and any in-flight upstream call is cancelled.

**BRIDGE-005 (`REQ-MCP-006`)** — The child process MUST be launched from an explicit executable path with an explicit argument vector. **Shell interpolation MUST NOT be used** — no shell, no string command line, no environment expansion in arguments.

**BRIDGE-006 (`REQ-MCP-006`)** — The child's environment MUST be constructed from an explicit allowlist, not inherited. The gateway's own environment — including any provider API key present in v1.1 — MUST NOT reach the child.

**BRIDGE-007 (`REQ-REG-002`)** — The executable, arguments, working directory, and environment MUST come from the registry (unit 04) or startup configuration. **No client-supplied value may influence any of them.** There is no code path from an MCP message to a process launch parameter.

**BRIDGE-008** — Child startup MUST have a deadline. If the child does not complete its MCP handshake within it, the gateway MUST NOT become ready and MUST NOT serve protected requests.

**BRIDGE-009** — On client disconnect, `stdin` EOF, or cancellation, the bridge MUST cancel in-flight upstream work where safe, terminate the child, and reap it. **No orphaned child may outlive the gateway process**, including on abnormal termination.

**BRIDGE-010** — Child `stderr` MUST be captured to the gateway's diagnostic sink, bounded in size, and never merged into `stdout` or into an audit event's content fields.

**BRIDGE-011 (`CONV-004`)** — If the child dies, becomes unresponsive, or its channel breaks, protected requests MUST be denied with `ROUTE_UPSTREAM_UNAVAILABLE`. The bridge MUST NOT auto-restart the child mid-request and complete the request as if nothing happened.

**BRIDGE-012 (`REQ-ARCH-005`)** — The bridge MUST expose exactly one upstream channel. The gateway MUST NOT open a second connection to the protected server, and the client configuration MUST NOT contain a direct route to it. This is a deployment invariant the harness verifies (unit 11).

---

## 6. Failure modes

| Condition | Outcome | Reason code |
|---|---|---|
| Inbound message exceeds framing limit | reject, do not buffer | `PROTO_MESSAGE_TOO_LARGE` |
| Framing invalid / stream desynchronized | terminate connection | `PROTO_FRAMING_INVALID` |
| Child fails to start or handshake in time | not ready; deny protected calls | `ROUTE_UPSTREAM_UNAVAILABLE` |
| Child exits mid-request | deny; do not restart-and-retry | `ROUTE_UPSTREAM_UNAVAILABLE` |
| Total request deadline expires | cancel upstream, controlled error | `ROUTE_TIMEOUT` |
| Client disconnects mid-request | cancel upstream, audit `cancelled` | `ROUTE_CANCELLED` |

---

## 7. Configuration surface

Named values, all schema-validated with defaults, all boundary-tested (`CONV-015`):

- max inbound message bytes
- total request deadline
- child startup deadline
- child shutdown grace period before force-kill
- child executable path, argument vector, working directory
- child environment allowlist (key names only)
- child `stderr` capture cap

---

## 8. Audit contribution

`request_id`, `ts_start`, `ts_end`, `transport`, `stage_latency_ms.transport`, and — when the request dies here — `outcome` and `reason_code`.

---

## 9. Acceptance tests

1. A client completes `tools/list` and `tools/call` end to end through the bridge with policy disabled.
2. MCP Inspector connects and enumerates tools successfully.
3. Nothing but protocol traffic appears on `stdout` across the full suite — asserted by parsing the entire captured `stdout` stream as protocol messages.
4. A message one byte over the framing limit is rejected; one byte under is accepted.
5. A crafted argument containing shell metacharacters reaches the child as literal argument data and spawns nothing.
6. A secret present in the gateway's environment is absent from the child's environment, verified by reading the child's own view of its environment.
7. Killing the child mid-request produces a denial, not a hang and not a silent retry.
8. Killing the gateway leaves no surviving child process.
9. Client disconnect mid-request cancels the upstream call and writes exactly one audit event with `outcome=cancelled`.
10. Startup fails loudly when the configured child executable does not exist.

---

## 10. Notes for the tech sheet

- Async framing on `stdin`/`stdout` with strict separation of the diagnostic sink is the whole design risk here; pick the MCP SDK's server/client primitives rather than hand-rolling framing, but verify the SDK does not write to `stdout` itself.
- Child supervision must be correct on Windows and POSIX — process-group termination differs, and orphan reaping is where this unit will actually break.
- The `request_id` is the project's single correlation key. Decide its format once (opaque, sortable, unguessable) and never change it.

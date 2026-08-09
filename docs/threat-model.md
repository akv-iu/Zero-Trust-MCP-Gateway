# Threat model

What this gateway defends, what it does not, and why the second list is written
first. A control whose limits are undocumented gets deployed as though it had none.

Scope claims are in [PLAN.md §6](../PLAN.md). This document is the honest boundary
around them.

---

## 1. What is out of reach, by construction

### 1.1 A second route to the server

**A local `stdio` client that is separately configured with direct access to the
protected MCP server bypasses this gateway entirely. The gateway cannot detect or
prevent that configuration. Removing every direct client-to-server route is a
deployment responsibility.**

The gateway is an in-path enforcement point. It sees the requests routed through it
and nothing else. An MCP client whose launcher config names the filesystem server
directly — rather than naming the gateway — talks to that server with no policy
between them, and no audit event is produced because no request arrived.

This is not a defect awaiting a fix. It is the shape of in-path enforcement. The
mitigations are deployment-side: make the gateway the only configured MCP server
entry, and remove the child server's ability to accept a second connection.

`harness/` asserts that no second route exists in the *test* configuration. That is
a configuration assertion and is reported as such — it is not evidence that the
property holds in any real deployment (IDENT-007).

### 1.2 Any local process can act as the configured principal

The edge binds `127.0.0.1` and validates `Origin` **when present** — both are
DNS-rebinding defences the specification mandates, and neither authenticates a
caller. Nothing binds the listening socket to the process that launched the gateway.

So: any process on the host that can open a loopback connection can send requests
that are authorized and audited as the configured principal.

The consequence is sharper than it first looks. `_tech/03` §4 proposes running **one
gateway instance per principal** for multi-principal testing. On a host doing that,
a low-privilege local process can call the high-privilege instance's port and be
authorized as *its* principal — a confused deputy, with an audit trail naming the
wrong actor. `unverified_local` labels the weakness honestly; it does not prevent it.

**v1's position: every local process is one trust domain.** Distinct principals must
not be co-hosted outside a test harness. Closing this needs an OS-scoped binding —
a unix socket with filesystem permissions, or a per-launch capability token — that
gates access *without* deriving the principal from MCP data, since IDENT-003 forbids
the latter. That is deferred, not solved; the trigger is in
[`_specs/90-deferred-register.md`](../_specs/90-deferred-register.md).

### 1.3 Identity is asserted, not verified

`auth_method=local_config`, `assurance=unverified_local`, and those are the only
values `AuthzContext` can hold — single-member `Literal`s, so claiming otherwise
requires editing `gateway/types.py` and passing review.

The gateway performs **authorization**, not authentication. It answers "is this
principal allowed to do this?" and takes the principal's identity from
configuration, because the loopback HTTP edge carries no verified caller identity to
take it from instead (§1.2). A process that can launch the gateway chooses the
principal it launches as — and per §1.2, so does any other local process that can
reach the port.

OIDC, token validation and step-up authorization are cut from v1; the trigger that
would revive each is in [`_specs/90-deferred-register.md`](../_specs/90-deferred-register.md).

### 1.4 The protected server is trusted to be itself

The gateway authorizes what it forwards. It cannot verify that the child process is
the server the registry describes — only that the tool schemas it advertises match
approved fingerprints (unit 04). A compromised child that keeps its schemas stable
is invisible to this design, and the oracle would attribute its side effects to the
authorized call.

### 1.5 Time-of-check / time-of-use on the filesystem

Path canonicalization (unit 05) resolves a path, then policy authorizes the resolved
path, then unit 07 forwards. Between resolution and use, another process can replace
a component of that path. The gateway narrows the window; it does not close it. See
[PLAN.md §7.4](../PLAN.md) for how this was reframed after the first review.

---

## 2. What it does defend

Split by what **runs today** versus what is **specified and not yet built**. The
distinction matters more than it looks: a reader who takes a planned control for a
present one relies on a protection this repository cannot provide. Build state is
[PLAN.md §4.2](../PLAN.md); unbuilt units raise `NotImplementedError` naming their
owner, so a request reaching one is denied as `INTERNAL_ERROR` rather than passed.

### 2.1 Implemented

| Threat | Control | Evidence |
|---|---|---|
| Header/body split authorization | Unit 02, delegating to `mcp.shared.inbound` | `harness/scenarios/protocol_mirrored.toml`, scored over a real socket |
| A hostile or malformed request payload | Unit 02 prescan, limits, duplicate-key detection | Boundary triples per limit; Hypothesis over arbitrary bytes and arbitrary JSON |
| Oversized request, bad origin, removed HTTP methods | Unit 01 edge | `test_edge.py`; rejections leave no trace at the fixture |
| A dead or misbehaving child process | Unit 01 bridge | `crash`, `malformed`, `wrong_id`, `unsolicited` modes; denial at the call site |
| Identity overstated in the record | Unit 03 single-member `Literal`s | Suite-wide invariant over every record the test session emits |
| Evidence loss under cancellation | Unit 09 shielded write | Passes only with the production shield present |

### 2.2 Specified, not yet built

| Threat | Planned control | State |
|---|---|---|
| An unregistered or drifted tool | Unit 04 fingerprinting | stub |
| Path traversal, encoding tricks, symlink escape | Unit 05 canonicalization before policy | stub |
| Reading data the principal may not read | Unit 06 default-deny Rego | stub; OPA not yet required to run the suite |
| An allowed call exceeding its obligations | Unit 07 router | stub |
| An oversized or uncorrelated upstream response | Unit 08 response guard | stub |

The corpus rows for these already exist and are scored `direct` (undefended), which
is the "before" measurement. None of them yet demonstrates a gateway defence.

### 2.3 Fail-closed, and where it stops

An unexpected exception denies. An unavailable policy engine denies. An unwritable
audit sink raises `AuditFailure`, which denies the response.

**That last one is not atomic, and the earlier wording overstated it.**
`pipeline.handle` runs `router.forward` and only then writes the event in its
`finally`. If the sink fails after a mutating call has already reached the child,
the client is correctly told the request failed — but the upstream effect may have
happened and no record of it survives. AUDIT-009 asks for the operation to be denied
when its event cannot be persisted; for read-only calls that holds, and for mutating
ones it does not.

Closing it needs a write-ahead record before `router.forward`, paired with the
terminal one — the shape the fixture's own op-log already uses, and for the same
reason. Tracked against unit 07, which is where the ordering lives.

---

## 3. Trust boundaries

```
   MCP client  ──HTTP/loopback──▶  gateway  ──stdio──▶  child MCP server
   (ANY local                     (the TCB)            (untrusted output,
    process; see                                        trusted to be the
    §1.2 — not                    OPA sidecar           registered binary)
    authenticated)                127.0.0.1:8181
```

- **Client edge**: Streamable HTTP bound to `127.0.0.1`, with `Origin` validation
  when the header is present. Both are DNS-rebinding defences the specification
  mandates. Neither is an authentication boundary (ADR-001), and neither identifies
  the caller — the diagram once labelled the client "trusted to be the configured
  launcher", which asserted a binding nothing enforces. See §1.2.
- **Upstream leg**: stdio. Environment is built from an allowlist, never inherited,
  so a provider key present in the gateway's environment cannot reach the child
  (BRIDGE-006). There is no code path from an MCP message to a process launch
  parameter.
- **Tool output is `Untrusted[T]`**, whose `__str__` raises. Any log line or prompt
  template touching it without an explicit `unwrap()` fails loudly at the point of
  the mistake rather than silently interpolating attacker-controlled text.

---

## 4. Assumptions this document depends on

1. The gateway process is not itself compromised.
2. The OPA sidecar on loopback is reachable only by the gateway.
3. The fixture tree contains **synthetic data only** — no real credentials, no
   production data. Enforced by `fixtures/manifest.py` and its canary constants.
4. Every measurement in the report was produced by the isolation tier stamped on it;
   a `weak`-tier run must never be read as a containerized one.

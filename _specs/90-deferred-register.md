# SPEC-90 — Deferred Register

**Role:** Everything cut from v1/v1.1, with the trigger that revives it
**Status:** not a build spec — a decision record

---

## 1. Why this file exists

The archival source document contains ~150 requirements across five phases. v1 implements a fraction of them. Without this file, two failure modes follow: the cut work looks forgotten (it wasn't), or it creeps back in one requirement at a time (it must not).

Each entry names **what was cut**, **why**, and **the trigger** — the concrete condition that makes it worth building. A trigger is an observable event, not a feeling that it would be nice to have.

**Rule:** nothing in this file is built until its trigger fires *and* v1 has shipped. A trigger firing early is a note, not a permission slip.

---

## 2. Transport and protocol

| Cut | Source | Why | Trigger |
|---|---|---|---|
| Streamable HTTP transport | `REQ-MCP-003`, `REQ-ARCH-007` | Doubles the protocol surface — TLS, `Origin`, bind addresses, CORS, streaming, reconnection — for zero additional security result at `stdio` scale | A named client that cannot use `stdio` |
| `Origin` / bind-address protection | `REQ-MCP-004` | Only meaningful with an HTTP listener | Ships with HTTP transport |
| Legacy protocol adapters, HTTP+SSE | `REQ-MCP-002` | v1 targets 2026-07-28 exclusively; being spec-current *is* the differentiator, and a compatibility mode dilutes it | A named client pinned to an older revision |
| Capability filtering beyond tools | `REQ-MCP-008` | v1 protects `tools/*` only | Resources or prompts enter scope |
| Resources, prompts, elicitation, sampling | §1.6 | The tool-call security model must be stable first | v1 shipped and a fixture needs them |

---

## 3. Identity and authorization

| Cut | Source | Why | Trigger |
|---|---|---|---|
| OIDC/OAuth resource server | `REQ-AUTH-001` | Only meaningful with a remote transport | Ships with HTTP transport |
| **Keycloak** | Phase 3 | A locally minted keypair serving a static JWKS (authlib) produces identical assertions with no container, no memory cost, and no operational surface. Keycloak here is infrastructure theatre | A real multi-user IdP integration is the actual subject of the work |
| Step-up authorization | `REQ-AUTH-005` | Requires R3 and an approval mechanism, neither of which v1 has | Approval unit built |
| **Confused-deputy defense** | `REQ-AUTH-006` | Cannot be meaningfully tested without a real third-party IdP *and* a genuine second client. An untestable requirement is not a requirement | The gateway actually obtains third-party credentials on a user's behalf |
| Session/handle binding | `REQ-AUTH-007` | The 2026-07-28 core is stateless; v1 holds no handles | Stateful handles are introduced |
| **Multi-tenancy** | `REQ-SQL-006`, `REQ-REG-004` | There are no tenants. One laptop, synthetic fixtures, one principal set. Tenant isolation with zero tenants is speculation, and its tests would assert nothing | A second real tenant exists |
| `admin` principal | §2.27 | Without R3, a correctly constrained admin is inexpressible; adding one would only demonstrate the anti-pattern | Approval unit built |

---

## 4. Guardrail families

| Cut | Source | Why | Trigger |
|---|---|---|---|
| SQL guardrails, SQLGlot AST | `REQ-SQL-001` … `-007` | A second canonicalizer family — genuinely valuable, genuinely a second project. One family tested exhaustively is better evidence than three tested partially | v1 shipped and a SQL fixture is the next portfolio piece |
| Outbound HTTP / SSRF / DNS rebinding | `REQ-NET-001` … `-005` | Third canonicalizer family; also needs a controlled egress sink to test honestly | v1 shipped and an outbound-fetch fixture exists |
| Business-action guardrails | `REQ-BIZ-001` … `-003` | Needs a business fixture that does not exist | An enterprise fixture is built |
| Sandboxed code execution | `REQ-EXEC-002`, `-003` | P2 in the source, and `REQ-EXEC-001` prohibits a host shell outright — correctly | Not before a reviewed sandbox threat model |
| Safe-write semantics: atomic replace, backup, versioning | `REQ-FS-005` | The fixture's write surface is small and synthetic; atomicity guards data loss that cannot occur here | Writes touch data anyone cares about |

---

## 5. Approval

| Cut | Source | Why | Trigger |
|---|---|---|---|
| Action-bound approval tokens | `REQ-APPROVAL-001`, `-004` | Real design work — nonce binding, argument-hash binding, expiry, single use. But v1 has no R3 action to approve: the fixture is read/write on synthetic data | An R3 action exists — a business fixture, or production-classified data |
| Approval CLI or web interface | `REQ-APPROVAL-005` | Ships with the token semantics; the source correctly notes the UI is not the hard part | Same |
| Safe presentation / escaping of untrusted text in approvals | `REQ-APPROVAL-003` | Ships with the interface | Same |
| Risk tier **R3** | `REQ-GUARD-005` | A tier that cannot be enforced must not appear in policy (`CONV-007`) | Approval unit built |

---

## 6. Reliability and scale

| Cut | Source | Why | Trigger |
|---|---|---|---|
| Circuit breakers | `REQ-REL-003` | One client, one upstream. A breaker would never open in any test that exists | Multiple upstreams, or a real failure rate |
| Backpressure and queue bounding | `REQ-REL-004` | Same — no queue depth to bound at v1 concurrency | Measured queueing under real load |
| Router isolation, per-server pools | `REQ-REG-004` | One upstream | A second upstream |
| Rate limiting | `REQ-GUARD-004` (partial) | One client; an in-process limiter would be untestable ceremony | A second concurrent client, or a real abuse case |
| Distributed rate limiting / Valkey | §3.1 | Follows rate limiting | Multiple gateway instances |
| Retry with idempotency | `ROUTE-011` | The fixture has no idempotency keys; a retry could double a write | An idempotent business fixture |

---

## 7. Observability and control plane

| Cut | Source | Why | Trigger |
|---|---|---|---|
| OTel collector, Grafana/Tempo/Loki | `REQ-OBS-001`, `-005` | v1 derives its four latency numbers from the audit log. A parallel telemetry stack on a modest laptop costs RAM and distorts the very measurement it exists to capture | A deployment where log-derived numbers are insufficient |
| The 11-metric set | `REQ-OBS-002` | Most label a dimension v1 does not vary (one server, one transport, one method family) | Dimensions actually vary |
| 10-stage span instrumentation | `REQ-OBS-004` | v1 records per-stage latency in the audit event, which is the same information at a fraction of the cost. Instrumentation stays vendor-neutral at code level so a collector can be added without a rewrite | Collector added |
| Dashboards | `REQ-OBS-005` | `jq` over JSONL is the v1 admin interface, and saying so is better than building a surface nobody asked for | Someone other than the author needs to read the data live |
| Admin/management API | `REQ-ADMIN-002` | The registry and policy are version-controlled files; a diff is a better review surface than an API | Multi-operator deployment |
| Admin RBAC | `REQ-ADMIN-001` | Requires an admin surface to protect | Admin API built |
| Approval UI, dashboard, admin UI | Phase 4 | **Three UI surfaces in a project whose value is the enforcement core** | Each ships with its own trigger above |
| PostgreSQL audit storage | §3.1 | JSONL plus `jq` covers v1 query needs entirely | Audit volume exceeds what `jq` handles, or multi-instance writes |
| Break-glass | `REQ-ADMIN-004` | Explicitly not-MVP in the source; a bypass mechanism in a project whose claim is complete mediation needs a very good reason | Not before a production deployment with an on-call rotation |

---

## 8. Policy features

| Cut | Source | Why | Trigger |
|---|---|---|---|
| Shadow / simulation mode | `REQ-POL-007` | Genuinely useful, genuinely v2. Requires recorded-request replay infrastructure | Policy changes frequently enough to need pre-flight |
| Recorded-request replay against candidate policy | `REQ-POL-007` | Same | Same |
| Signed policy bundles | `REQ-POL-005` (partial) | Version control plus review is proportionate at v1 | Policy deploys outside the author's own machine |
| Formal policy analysis of Rego | Phase 5 | **A research topic, not a backlog item** | A paper, not a sprint |

---

## 9. Model and evaluation

| Cut | Source | Why | Trigger |
|---|---|---|---|
| **4-model × 2-provider matrix as a security result** | `REQ-HARNESS-012` | `REQ-MODEL-011`/`CONV-022` forbid any security claim from depending on model behavior — which forbids the matrix from producing one. Running four models proves the gateway is deterministic, which one deterministic client already proved | Moved to the research track (`PLAN.md` §8), not a trigger |
| Cloudflare fallback as a phase deliverable | `REQ-MODEL-004`, Phase 3 | Both providers are OpenAI-compatible; it is a base-URL swap. It is a config line in v1.1, not a phase with its own eval subset | Never as a phase; exists as configuration |
| `qwen/qwen3.6-27b`, `gpt-oss-120b` subsets | `REQ-MODEL-002`, `-003` | Research track | v1 shipped, research track started |
| Advisory guard model (`gpt-oss-safeguard-20b`) | `REQ-MODEL-GUARD-010` | An advisory classifier that cannot authorize adds cost and no claim | A study of classifier value as a *separate* question |
| Inspect AI as a required runtime | `REQ-HARNESS-011` | pytest + Hypothesis covers v1 entirely; Inspect earns its weight on reproducible eval sets, which is the research track | Research track started |
| Model response caching/replay | `REQ-HARNESS-014` | Five scenarios fit in free quota trivially | Scenario count makes live runs expensive |
| Taint propagation | `REQ-MODEL-GUARD-009` | Real and interesting; needs multi-step flows v1.1 does not have | Multi-step agent scenarios where an argument's origin actually varies |
| Load tests with k6/Locust | `REQ-HARNESS-016` | The laptop is client, gateway, policy engine, fixture, and load generator simultaneously — the number would be noise (`PLAN.md` §6.1) | The gateway is deployed somewhere the load generator is not |
| Soak testing | `REQ-REL-005` | Same environment problem | Same |

---

## 10. Deployment and hardening

| Cut | Source | Why | Trigger |
|---|---|---|---|
| Public demo deployment | `REQ-ARCH-008`, §3.4 | Nothing is deployed in v1; the deliverable is a repo and a report | Someone needs to click something |
| VPS / Railway / Render | §3.4–3.7 | Follows deployment. Note all pricing in the source is a snapshot and Hetzner's is stale (`PLAN.md` §7.1) | Deployment decision made, prices re-verified |
| Caddy / public TLS | §3.1 | Follows deployment | Same |
| Docker Compose profile | `REQ-ARCH-009` | Native processes are fewer moving parts on a modest laptop; Compose is a packaging convenience, not a capability. **Exception:** if the fixture's isolation (`FIX-005`) needs a container to be honest, that container ships in v1 | Reproducibility for someone else's machine, or fixture isolation demands it |
| k3s / Nomad / service mesh | Phase 5, §3.11 | Explicitly deferred in the source and correctly so | Scaling requirements that do not exist |
| Tamper-evident audit, signed batches | `REQ-AUDIT-003` | P2. Append-only JSONL with retention is proportionate to a single-author lab | Audit evidence is used in a dispute |
| Hardware-backed keys | Phase 5 | Nothing to protect with them in v1 | Signing keys exist |
| SBOM, provenance, signed artifacts | `REQ-SEC-010` | Trivy and Gitleaks in CI are in v1; provenance follows releases | A published release artifact |
| Self-hosted model profile | `REQ-MODEL-005` | The cloud-first decision is the whole point of the hardware story | Never, unless the hardware assumption changes |

---

## 10b. Found during implementation

Added when a review turned up a real gap that v1 deliberately does not close. Each
is documented as a limitation in `docs/threat-model.md`, not silently carried.

| Cut | Found by | Why it is out of v1 | Trigger that revives it |
|---|---|---|---|
| **Binding the listener to its launcher** — a unix socket with filesystem permissions, or a per-launch capability token | Codex adversarial review, unit 03 | The edge authenticates no caller, so any local process can be authorized as the configured principal (`docs/threat-model.md` §1.2). v1's stated position is that every local process is one trust domain. Fixing it properly is an OS-binding problem, and the fix must gate access **without** deriving the principal from MCP data — IDENT-003 forbids that | Distinct principals need to be co-hosted outside a test harness, or the gateway is deployed anywhere a hostile local process is in the model |
| **Write-ahead audit record before `router.forward`** | Codex adversarial review, unit 03 | AUDIT-009 wants a protected operation denied when its event cannot be persisted. Today the event is written in `pipeline.handle`'s `finally`, so a sink failure after a mutating call leaves an effect with no record (`docs/threat-model.md` §2.3). The fix is the paired attempt/terminal shape the fixture's own op-log already uses | Unit 07, where the ordering lives. Not deferred past v1 — deferred to the unit that owns it |

---

## 10c. Registry codes no corpus row can reach

Four `REG_*` codes are decided by the gateway's **startup state**, not by the content
of a request, and a corpus scenario describes a request. They are covered by
`tests/unit/test_registry.py` against the real fixture in `FIXTURE_MODE=drift` and
`FIXTURE_MODE=poison` — same upstream, same comparison — until unit 11's protected
client can launch a differently-configured gateway per row.

| Code | Decided by | Covered today by |
|---|---|---|
| `REG_SCHEMA_DRIFT` | `verify_schemas` at handshake | `test_drift_quarantines_the_tool_and_hides_it` |
| `REG_TOOL_QUARANTINED` | the per-request consequence of the above | same test, plus the poisoned-annotation test |
| `REG_SERVER_UNAVAILABLE` | `state` in `config/registry.toml` | `test_a_disabled_server_hides_every_tool` |
| `REG_SCHEMA_UNVERIFIED` | a call arriving before the handshake | `test_nothing_is_callable_before_verification`, `test_tools_list_is_refused_before_verification` |

`REG_HEADER_ANNOTATION_INVALID` and `REG_SERVER_UNKNOWN` were **removed** from
`ReasonCode`, not deferred — neither had a request-time raise path, which CONV-010
forbids, and the same rule removed `IDENT_CONTEXT_UNAVAILABLE` when unit 03 landed.

| Code | Why it had no raise path | Trigger to add it back |
|---|---|---|
| `REG_HEADER_ANNOTATION_INVALID` | An approved schema with an invalid `x-mcp-header` is refused at LOAD (ADR-001 §3.1), so the gateway does not start. Startup failures are `ConfigError`, which never reaches a request path; a reason code implies a wire shape and an audit record that cannot exist | Never as a request outcome. If a future tool set is approved dynamically, the code returns with the raise path in the same change |
| `REG_SERVER_UNKNOWN` | v1 has exactly one upstream and no MCP message carries a server identifier, so REG-001 is satisfied by there being no field in which to ask | Multi-upstream (§6, "Router isolation, per-server pools") |

An earlier draft kept `REG_SERVER_UNKNOWN` on the argument that it is unreachable
*because* the topology has one element, rather than meaningless. That distinction is
real and it is not the rule: CONV-010 asks whether a scenario can reach the code, not
why it cannot. Adding it back requires the raise path in the same change.

**Trigger for all of the above:** unit 11's `ProtectedClient` gaining the ability to
launch a gateway with a per-scenario registry and `FIXTURE_MODE`.

---

## 10d. Launch parameters — RESOLVED, not deferred

Recorded here because the register named it as a cut and it is no longer one.

`config/gateway.toml [child]` no longer carries `executable`, `args`, `cwd` or
`env_allowlist`. Those live in `config/registry.toml` only (REG-002), and
`ChildTuning` — the model behind `[child]` — forbids them, so putting one back fails
startup instead of becoming a silent second opinion. `ServerEntry.child_config(tuning)`
is the only constructor for a launchable `ChildConfig`.

The previous entry closed this with a test comparing the two copies. That was the
wrong shape and Codex said so: a comparison does not make either copy the source, and
it passes right up until the files disagree — at which point it reports a mismatch
rather than having prevented one.

**Still open:** `executable = "python"` and `cwd = "."` are launcher-relative. Making
them explicit paths is unit 11's, where real startup is assembled.

---

## 10e. Canonicalizer surface removed when unit 05 landed

**`CANON_OPERATION_UNKNOWN`** — removed, not deferred, for the reason that removed
`IDENT_CONTEXT_UNAVAILABLE`, `REG_SERVER_UNKNOWN` and `REG_HEADER_ANNOTATION_INVALID`.
The spec's failure table gave it to "operation class not derivable from the tool", but
the class arrives on `ResolvedTarget.operation` — a required member of a closed
`Operation` literal the registry loader has already validated — and unit 05 handles
every member. A tool with a missing or misspelled operation fails startup as a
`ConfigError`. No request can reach the code, and `CONV-010` says a code no scenario can
produce is removed rather than documented.

*Revival trigger:* an approved tool whose operation must be derived from **arguments**
rather than from the registry — an `open(path, mode=...)` shape, where one name is a
read or a write depending on what the client sends. The raise path lands in the same
change.

**`canonicalize.max_resolution_depth`** — removed. Symlink depth is enforced by the
operating system (`ELOOP`) and surfaced as `CANON_RESOLUTION_FAILED`. Counting hops in
the gateway would mean walking components by hand, which `_tech/05` §10 forbids because
that walk is where traversal bugs live. `CONV-015` asks every configured limit to have a
documented default and boundary tests; a limit nothing enforces fails that harder than a
limit that is absent.

*Revival trigger:* a platform whose `realpath` is found not to raise on a loop, or a
requirement to deny *before* the OS gives up.

**The case-sensitivity probe** (`_tech/05` §5) — never built. Containment compares a
resolved path to a resolved root and `realpath` returns the true on-disk spelling, so
`CANON-005` is satisfied without one; a probe would also have meant the gateway writing
a file into the protected tree at startup, which the oracle would then have to be taught
to ignore. Reasoning in `_tech/05` §5.

*Revival trigger:* a comparison that has to happen on an unresolved path — for instance
a deny rule matched against a name that does not exist yet.

---

## 10f. Policy codes no corpus row can reach

Six `POLICY_*` codes are decided by the state of the policy ENGINE rather than by the
content of a request, so no row of tool plus arguments can produce one:

| Code | What produces it |
|---|---|
| `POLICY_UNAVAILABLE` | OPA unreachable — the sidecar is terminated in `test_policy_opa.py::test_1_...` |
| `POLICY_TIMEOUT` | evaluation past the deadline |
| `POLICY_RESULT_INVALID` | a malformed decision document |
| `POLICY_DEFAULT_DENY` | OPA answering 200 with no `result` at all |
| `POLICY_REVISION_UNKNOWN` | a decision that cannot be attributed to a bundle |
| `POLICY_OBLIGATION_CLAMPED` | advisory, audited alongside a real code |

They are **not** removed, because unlike `REG_SERVER_UNKNOWN` each has a live
request-time raise path in `gateway/policy.py`. What they lack is a *corpus* row,
which needs a broken or differently-configured OPA per row — the same limitation the
four startup-conditioned `REG_*` codes have (§10c), and it lifts the same way, when
unit 11's protected client can launch a gateway per scenario. Until then all six are
covered in `tests/unit/test_policy.py` against a stub transport that returns exactly
the answers a correct OPA never gives.

`POLICY_PROHIBITED` was in this list and is now reachable: `fs-prohibited-001` reads
`traps/.keep` as `auditor` — the principal who may read everything else, so the denial
can only come from the prohibition rule and not from a missing grant.

**Shadow mode** stays cut (`_specs/06` §3). It is genuinely useful and genuinely v2;
the trigger is a policy change big enough that landing it blind is the risk.

---

## 10g. The response byte ceiling is detection, not prevention

**Deferred:** a streaming abort on `max_response_bytes` (ROUTE-006).
**Shipped instead:** the response is measured once it is materialised by unit 07, and
an oversized one is denied by **unit 08** with `RESP_TOO_LARGE`.

`ROUTE_RESPONSE_TOO_LARGE` was the original name and no longer exists. Unit 07 compared
the identical number against the identical limit one stage before unit 08 did, which
made `RESP_TOO_LARGE` unreachable in production while its unit test constructed a
`RawResult` the router could never return — two checks of one quantity at one moment
are not two layers. The earlier one was removed (unit 08 review, `PLAN.md` §4.2); unit
07 measures and audits `response_bytes`, and the ceiling lives in unit 08 alone.

`_tech/07` §5 asks the count to happen at the transport layer so the reader aborts
mid-stream, and pre-authorises this fallback on condition it be stated rather than
substituted silently. The installed SDK forecloses the streaming version:
`mcp.client.stdio.stdio_client` wraps the child's stdout in a `TextReceiveStream`,
accumulates until a newline, and parses a **whole line** into a `SessionMessage`
before anything downstream receives a byte. There is no hook between the pipe and the
parsed message — `stdio_client` owns the reader and exposes only the message stream.

What this changes about the claim, stated so a reader does not inherit the stronger
one: **an oversized response is detected and denied; it is not prevented from being
buffered.** A hostile child can still make the gateway hold its whole reply in memory
once. The limit stops that reply from reaching the client and stops it being counted
as a success; it does not make the gateway immune to a memory-exhaustion attempt by a
child that is already inside the trust boundary the threat model draws around it
(§1.4 — the protected server is trusted to be the registered binary).

**Trigger:** replacing `stdio_client` with a transport this project owns — which is
also what an HTTP upstream leg would need, since that is a second transport and the
counting would have to live somewhere common. Do not attempt it as a wrapper around
the SDK's stream: that is where the buffering already happened.

---

## 10h. `UpstreamHandle.cancel` — REMOVED, not deferred

Unit 01 built `bridge.UpstreamHandle.cancel(request_id, reason)` to send
`notifications/cancelled` on an edge-side disconnect, and unit 07 was to be its only
caller. It is deleted, for two reasons that compound.

The pinned SDK already does it. `JSONRPCDispatcher.send_raw_request` catches the
caller's cancellation and sends the notification through a **shielded**, bounded write
before re-raising (`cancel_on_abandon` defaults to true). anyio propagates the edge's
cancellation into the in-flight `call_tool`, so the notification goes out with no
gateway code involved. Verified by running the installed SDK over memory streams and
observing the bytes, not by reading it — ADR-002's process lesson.

Ours would have sent the **wrong id**. The only id unit 07 holds is
`CanonicalRequest.jsonrpc_id`, the CLIENT's. The SDK numbers its own outgoing requests
independently, so that notification would have named an id the child never saw — or,
worse, one belonging to a different request. A cancellation that silently cancels
nothing, audited as a cancellation that succeeded, is exactly the lying audit trail
the method's own docstring said it existed to prevent.

`RouterConfig.cancellation_grace_ms` went with it: nothing sizes a window the SDK
bounds itself, and a knob nothing reads fails CONV-015 more loudly than a missing one.

**Trigger:** an upstream transport whose SDK does not send the courtesy cancel, or an
SDK upgrade that drops it. The second is the dangerous one because it is silent —
`gateway/router.py` records the owed tripwire test.

---

## 11. Kept in v1 despite being cuttable

Recorded so they are not cut in a later round of enthusiasm:

- **Trivy and Gitleaks in CI** (`REQ-SEC-008`, `-009`) — cheap, and a security project that leaks a key has no credibility left to spend.
- **`.env.example` and `.gitignore` discipline** (`REQ-SEC-001`) — same reasoning, near-zero cost.
- **Schema fingerprinting and drift** (`REQ-MCP-009`) — the tool-poisoning demo (`04-svc-registry.md` test 4) is one of the most legible security demonstrations in the project.
- **Per-stage latency in the audit event** — the entire benchmark reads from it.
- **The untrusted-content label** (`RESP-005`) — cheap now, expensive to retrofit into v1.1.
- **Ruff and a type checker** — they pay for themselves within the first week.

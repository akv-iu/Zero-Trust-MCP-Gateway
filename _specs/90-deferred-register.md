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

## 11. Kept in v1 despite being cuttable

Recorded so they are not cut in a later round of enthusiasm:

- **Trivy and Gitleaks in CI** (`REQ-SEC-008`, `-009`) — cheap, and a security project that leaks a key has no credibility left to spend.
- **`.env.example` and `.gitignore` discipline** (`REQ-SEC-001`) — same reasoning, near-zero cost.
- **Schema fingerprinting and drift** (`REQ-MCP-009`) — the tool-poisoning demo (`04-svc-registry.md` test 4) is one of the most legible security demonstrations in the project.
- **Per-stage latency in the audit event** — the entire benchmark reads from it.
- **The untrusted-content label** (`RESP-005`) — cheap now, expensive to retrofit into v1.1.
- **Ruff and a type checker** — they pay for themselves within the first week.

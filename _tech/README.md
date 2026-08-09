# `_tech/` — Technical Sheets

Implementation detail for each functional spec in [`_specs/`](../_specs/). Filenames mirror one-to-one.

**Division of labour:** `_specs/` says *what must be true and how it is proven*. `_tech/` says *how to build it* — library choices, algorithms, type signatures, platform traps, and the specific tests that make each requirement checkable. When they disagree, the spec wins and the tech sheet is wrong.

Every sheet is written so an agent or a new contributor can implement that unit without re-reading the 2,243-line archival source document.

| Sheet | Unit | Module | Phase |
|---|---|---|---|
| [00-conventions](00-conventions.md) | Foundation — deps, shared types, errors, pipeline | `gateway/{types,errors,config,hashing,timing,pipeline}.py` | v1 |
| [01-svc-stdio-bridge](01-svc-stdio-bridge.md) | Transport edge, child supervision | `gateway/bridge.py` | v1 |
| [02-svc-protocol-guard](02-svc-protocol-guard.md) | JSON-RPC hardening, header/body consistency | `gateway/protocol.py` | v1 |
| [03-svc-identity-resolver](03-svc-identity-resolver.md) | Principal, authorization context | `gateway/identity.py` | v1 |
| [04-svc-registry](04-svc-registry.md) | Servers, tools, fingerprints, drift | `gateway/registry.py` | v1 |
| [05-svc-canonicalizer-fs](05-svc-canonicalizer-fs.md) | Path canonicalization | `gateway/canonicalize/fs.py` | v1 |
| [06-svc-policy-broker](06-svc-policy-broker.md) | OPA integration, Rego layout | `gateway/policy.py`, `policies/` | v1 |
| [07-svc-upstream-router](07-svc-upstream-router.md) | Obligations, forwarding | `gateway/router.py` | v1 |
| [08-svc-response-guard](08-svc-response-guard.md) | Response validation, `Untrusted` | `gateway/response.py` | v1 |
| [09-svc-audit-log](09-svc-audit-log.md) | JSONL evidence | `gateway/audit.py` | v1 |
| [10-fixture-filesystem-mcp](10-fixture-filesystem-mcp.md) | Protected system + oplog | `fixtures/filesystem_server/` | v1 |
| [11-svc-eval-harness](11-svc-eval-harness.md) | Corpus, oracle, benchmark, report | `harness/` | v1 |
| [12-svc-agent-harness](12-svc-agent-harness.md) | PydanticAI + Groq | `agent/` | v1.1 |

`_specs/90-deferred-register.md` has no tech sheet — nothing in it is being built.

---

## Read in this order

1. **[00-conventions](00-conventions.md)** — every other sheet assumes its types and layout.
2. **[02-svc-protocol-guard §0](02-svc-protocol-guard.md#0-open-decision-d-1--resolve-before-week-3)** — Decision D-1, unresolved, affects scope.
3. Then in build order (`PLAN.md` §4.2): 10 → 11 → 01 → 09 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 11 → 12.

---

## Open items

| # | Item | Status |
|---|---|---|
| **D-1** | Which transport carries the mirrored metadata | ✅ **Resolved** — [ADR-001](../_specs/ADR-001-transport-and-mirrored-metadata.md). Client edge is Streamable HTTP on loopback; upstream leg stays stdio. |
| **S-1** | Capturing raw request bytes | ✅ **Dissolved** by D-1 — ASGI supplies raw body and header pairs directly. No SDK stream tee needed. |
| **S-3** | The complete mirrored-field set | ✅ **Answered** — four families, [ADR-001 §3](../_specs/ADR-001-transport-and-mirrored-metadata.md) and [TECH-02 §3](02-svc-protocol-guard.md). |
| **S-5** | Cancellation propagation to the child | ✅ **Answered** — `notifications/cancelled` is mandatory on stdio; the edge translates SSE-stream close into it ([TECH-01 §1a](01-svc-stdio-bridge.md)). |
| **S-2** | Does the SDK expose an unsolicited-message hook on the child session? | ⬜ Week-2 spike — [08 §2](08-svc-response-guard.md). Blocks `RESP_UNSOLICITED`. |
| **S-4** | Windows Job Object for orphan reaping | ⬜ Moot if developing in WSL2/devcontainer (recommended); otherwise [01 §3](01-svc-stdio-bridge.md). |

Only S-2 remains as a genuine unknown, and it is contained — a "no" costs one requirement, not a design.

---

## Conventions used throughout

- Code in these sheets is **illustrative**, not final. Signatures and algorithms are load-bearing; names and formatting are not.
- `# ponytail:` comments mark deliberate simplifications with a named ceiling and an upgrade trigger. Harvest them with `/ponytail-debt`.
- Requirement IDs (`PROTO-001`, `CANON-007`, …) refer to the paired spec. Cite them in code comments only where the reason is non-obvious.
- Every "gotcha" section lists things that will actually break. Read them before writing the module, not after.

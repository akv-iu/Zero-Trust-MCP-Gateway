# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A default-deny enforcement point that sits between an MCP client and an MCP server, authorizing every `tools/call` against deterministic policy before the upstream side effect can occur. Built against the **MCP 2026-07-28 stateless specification** using SDK `mcp` 2.0.

The deliverable is **evidence**, not features: a published attack corpus, a side-effect oracle that observes the protected system rather than trusting the gateway's own output, a measured overhead distribution, and an audit trail with a measured completeness ratio. Read `PLAN.md` §2 and §9 before making scope arguments — the framing has been corrected twice already (see the ADRs).

## Commands

```bash
python -m pytest tests/ -q                       # full suite; needs no network, no API key
python -m pytest tests/unit/test_audit.py -q     # one file
python -m pytest tests/ -q -rs                   # show skip reasons (symlink tests)
python -m pytest tests/ -k "canonical" -q        # one pattern
python -m pytest tests/ -q --hypothesis-seed=N   # reproduce a property failure

python -m scripts.damage_demo                    # week-1 gate: 7/7 attacks land undefended
python -m scripts.run_corpus                     # score the corpus in direct mode
python -m scripts.run_corpus --break-enforcer    # negative control: prove the harness works
python -m scripts.sync_reason_codes              # regenerate policies/reason_codes.json

ruff check . && ruff format .
pyright gateway harness scripts
```

`uv` is the intended package manager (`pyproject.toml` + a committed lock); the current environment uses a plain global install.

## Documentation layout

Three tiers, and they have different authority:

| Path | Role |
|---|---|
| `PLAN.md` | Scope, milestones, verification method. **Wins over the archival doc on any conflict.** |
| `_specs/NN-*.md` | *What* each unit must do and how it is proven. Contract. No code. |
| `_tech/NN-*.md` | *How* to build it — libraries, algorithms, platform traps. When spec and tech disagree, **the spec wins**. |
| `_specs/ADR-*.md` | Decisions that override earlier documents. **Read these first.** |
| `_specs/90-deferred-register.md` | Everything cut, each with the trigger that revives it. Consult before adding scope. |
| `Zero_Trust_MCP_Gateway_Final.md` | Archival original. Never edited. Corrections live in `PLAN.md` §7. |

**ADR-001** — the client edge is Streamable HTTP on loopback; the upstream leg is stdio. stdio has no header layer, so mirrored metadata only exists on HTTP.
**ADR-002** — `mcp.shared.inbound` already implements the whole mirrored-metadata ladder (`classify_inbound_request`, `find_duplicated_routing_header`, `decode_header_value`, `find_invalid_x_mcp_header`, `validate_mcp_param_headers`, `ERROR_CODE_HTTP_STATUS`). **Use it; do not reimplement.** `_tech/02` §3 is superseded.

Its process lesson generalises: **read the installed SDK before claiming any protocol behavior as project work.**

## Architecture

One Python process (gateway), one OPA process, one child MCP server process. The numbered "units" are separated by **contract**, not deployment — do not add process boundaries, queues, or service discovery between them.

### Request lifecycle

`gateway/pipeline.py` is the only module that expresses stage order. Eight stages, fixed:

```
01 edge → 02 protocol → 03 identity → 04 registry → 05 canonicalize
   → 06 policy → 07 router → 08 response
```

Audit (09) is not a stage; it is a terminal action every stage performs on exit. Unit 07 is the **only** code that can cause a side effect, and it runs only with a validated `Decision` carrying this request's `request_id`.

### Invariants enforced by types, not discipline

Understanding these prevents most mistakes:

- **`CanonicalRequest` is the single authority.** `RawEnvelope` is never passed beyond `protocol.py`. `arguments` goes through `types.deep_freeze` — recursively, and copying on the way down, so neither a nested dict nor the caller's own reference can rewrite what policy authorised. Call `types.thaw()` at the `jsonschema` and OPA boundaries, which need real `dict`/`list`, and never store what it returns.
- **`AuthzContext.auth_method` is `Literal["local_config"]` and `assurance` is `Literal["unverified_local"]`** — single-member literals. Overstating identity requires editing `types.py`, which shows in review; pyright fails in the meantime.
- **`R3` is absent from `RiskTier`.** A tier that cannot be enforced must not be expressible.
- **`Untrusted[T].__str__` raises.** Any f-string, log line, or prompt template touching tool content without an explicit `.unwrap()` fails loudly. There should be exactly one `unwrap()` per consumer.
- **`AuditBuilder.set()` rejects unknown keys.** Minimisation is structural; there is no regex scrubbing of a blob. It guards field *names* only — a bad *value* fails in `finalize()`, which raises `AuditFailure(AUDIT_SCHEMA_INVALID)` and writes a tombstone so the completeness ratio still counts the request.
- **`completeness()` counts distinct request ids and refuses on a repeat.** Counting rows made the ratio forgeable by the exact bug it detects: ten events for one request while nine went unlogged read as 10/10.
- **`errors.ReasonCode` is the single source of truth**, mirrored to `policies/reason_codes.json` for Rego. A test fails if they drift.
- **Everything fails closed.** An unexpected exception denies. Unavailable OPA denies. An unwritable audit sink denies.

### Evidence chain — the part that is easy to break

`fixtures/` **must never import from `gateway/`**. Shared code would let a gateway bug mask itself in the oracle.

The fixture is **deliberately naive** — no containment checks, no traversal rejection. `MCPServer` defaults to `ResourceSecurity(reject_path_traversal=True, ...)`; `fixtures/filesystem_server/server.py` explicitly disables it. If anyone re-enables it, or adds a check to `tools.py`, every gateway security test silently passes without the gateway doing anything. Two tests guard this: `test_fixture_is_still_naive` and `test_sdk_resource_security_is_disabled`.

Six of the ten `FIXTURE_MODE` misbehaviours run inside the server. The other four (`malformed`, `wrong_id`, `unsolicited`, `pathological`) corrupt bytes the SDK will never emit, so they need `fixtures/misbehaving_wrapper.py` as the child instead — set `args = ["-m", "fixtures.misbehaving_wrapper"]`. It corrupts **only** responses to `tools/call`; damaging the handshake fails a scenario before it reaches the gateway, which looks identical to the gateway working.

The oracle (`harness/oracle.py`) uses **two sources, both required**: the fixture's own operation log and a tree hash. Tree hashing alone misses reads — and a confidential-file read is the most common expected violation in this corpus, so that would be the most dangerous possible false negative.

Scoring rules (`harness/runner.py`): a prohibited side effect is `CRITICAL` **regardless of what the gateway claimed** — you cannot un-leak a file, so it outranks a wrong reason code. A `CRITICAL` whose decision was `deny` sets `is_lying_gateway`, the worst outcome available. An allow whose expected effect never occurred is `FALSE_SUCCESS`. Anything uncorrelatable is `INDETERMINATE`, never a silent pass.

Oracle correlation is by **byte offset into the operation log**, which is valid only while upstream calls are serialised. `assert_serialised()` enforces that rather than trusting it.

## Working rules

- **The transport normalizes before the guard sees it, and the corpus records that.** `Transport.http_fate` on each protocol scenario says what a conforming HTTP/1.1 recipient does first: `delivered`, `normalized` (RFC 9110 strips edge OWS, so the request that arrives is legitimate), or `rejected` (a CR/LF in a field value — h11 refuses it and the gateway never runs, so no audit event exists either). Measured in `tests/integration/test_protocol_over_http.py`, which writes requests **by hand over a socket** because `httpx` refuses to build them.
- **A passing test proves nothing until you have seen it fail for the right reason.** Two tests in this repo were self-fulfilling and were caught by deliberately breaking the production code and confirming the test then failed. Do this for any load-bearing test.
- `harness/scenarios/*.toml` are **data, not test code** — the corpus is a publishable deliverable. TOML cannot carry control characters, so use the `{NUL}` / `{CR}` / `{LF}` / `{TAB}` / `{DEL}` placeholders, expanded at load.
- **No latency gate.** The benchmark measures and publishes whatever number comes out, with the co-location caveat. Never add a threshold assertion, and keep the benchmark out of pytest so one cannot creep in.
- Never write "zero authorization bypasses" in any report. The scoped claim is in `PLAN.md` §6.2, and a CI check should enforce its absence.
- Spec-to-code ratio must fall. Do not write a requirement that is not being implemented in the same change.
- **A unit is not done until `/unit-review` has run and its findings are resolved.** `.claude/skills/unit-review/SKILL.md` is the gate: local checks, a break-the-guard pass, an adversarial Codex review carrying this project's rubric, and a ponytail pass for what to delete. Invoke it at every unit boundary, before flipping the unit to **done** in `PLAN.md` §4.2 — not at the end of a batch of units.
- **Build order** is `PLAN.md` §4.2. Built so far: foundation, 10 (fixture), 11 (harness skeleton), 09 (audit), 01 (edge + bridge), 02 (protocol guard), 03 (identity), 04 (registry), 05 (canonicalizer), 06 (policy broker + Rego), 07 (router — **built without tests, which are owed**), 08 (response guard), 11's `ProtectedClient`. Unit 11 is in progress: corpus to 100+, Hypothesis generation, paired benchmark and report generator are owed. There are **no `NotImplementedError` stubs left**.
- **The pipeline completes end to end**, and `tests/integration/test_end_to_end.py` is the proof — including that a denied request produced nothing at the fixture's own operation log. Break that test and the project's central claim is gone; do not weaken it to make an unrelated change pass.
- **The SDK owns response correlation and does it silently.** A mismatched id is dropped with a `logger.debug` and the call dies on unit 07's timeout. `RESP_CORRELATION_MISMATCH` was removed under CONV-010 — do not re-add it without owning the child's stdout reader.
- **One structural walk serves both directions** (`protocol.check_limits`, `protocol.StructuralLimits`). Never write a second walker for responses; the direction that gets the weaker one is the direction nobody remembers to update. Depth counts **containers only**, matching the byte prescan — a test pins the two to the same boundary.
- **Unit 08 builds the JSON-RPC response envelope; the edge writes it verbatim.** A success used to go out as the bare MCP result, uncorrelatable by any conforming client, because only the error path was framed. Assert client-facing shape through the ASGI edge, never through `pipeline.handle`'s return value.
- **A `RESP_*` failure is `outcome="error"`, never `denied`.** The upstream misbehaved after policy allowed the call; recording it as a denial inflates the headline number.
- **The response size ceiling lives in unit 08 alone.** Unit 07 measures and does not enforce — it once compared the same number to the same limit one stage earlier, which made `RESP_TOO_LARGE` unreachable.
- **`FIXTURE_MODE=pathological` is a WIRE-level mode injecting into `_meta`.** `content` blocks are typed models and `structuredContent` is checked against the tool's output schema; both refuse the payload one layer before the guard, which looks identical to the guard working.
- **`router.route` is the stage entry point; `router.forward` is the `tools/call` leg.** `route` gates, writes the `upstream_attempt` record (AUDIT-009), then dispatches — `tools/list` is forwarded and filtered against `data.gateway.discoverable`. `gateway/router.py` MUST NOT gain an I/O import; `tests/unit/test_router_isolation.py` walks its AST.
- **What is forwarded is `DerivedAttributes.relative_path`, never the client's path string.** Forwarding the client's string is an authorization bypass, not a TOCTOU window: `%77orkspace/f.txt` is authorized decoded and acted on encoded. ROUTE-002's hash still covers the CLIENT's arguments — hashing the rewritten ones would compare the router's output to itself.
- **A `Decision` is bound to `request_id` + `method` + `tool_name` + `arg_hash`.** Any weaker binding lets one decision authorise a different call; a `write_file` decision was accepted for `append_file` before the method/tool fields existed.
- **`pipeline.handle` owns the request deadline, not the edge.** An anyio cancellation carries no reason, so an edge-side deadline is indistinguishable from a client disconnect and the record contradicts the response. The edge keeps a strictly slower `HANDLER_BACKSTOP`.
- **The response byte ceiling detects, it does not prevent** — `stdio_client` materialises a whole line before the gateway sees a byte. Never restate ROUTE-006 as a memory-exhaustion defence (`_specs/90` §10g).
- **Never re-add `UpstreamHandle.cancel`.** The SDK sends `notifications/cancelled` itself, shielded, with the id it put on the wire; ours could only send the client's, which the child has never seen (`_specs/90` §10h).
- **OPA is required from unit 06 on.** `.tools/opa.exe` (gitignored, fetched with checksum verification), or `$ZTMG_OPA_BIN`, or `PATH`. `python -m scripts.opa_sidecar` serves the bundle; `.tools/opa test policies/` runs the policy's own 46 tests with no Python involved; `python -m scripts.sync_policy_revision` restamps after any `.rego` edit and a test fails when it is stale. Pinned to **1.x** — Rego syntax differs from 0.x.
- **The policy bundle names roots and roles; it does not define them.** `identity.role_vocabulary` and the `[[canonicalize.roots]]` operation ceilings are published to `data.config` at startup and reconciled by `grants.rego`; a role with no grants, or a grant on an unknown or prohibited root, refuses to serve. Never restate either in Rego.
- **Unit 02 delegates the comparison and owns everything around it.** `gateway/protocol.py` calls `mcp.shared.inbound`; what is ours is the byte prescan, duplicate-key detection, structural limits, envelope shape, the method allowlist, MRTR refusal, and the mapping onto `ReasonCode`. The one place we depend on SDK *wording* is recovering which mirrored field disagreed from its `HEADER_MISMATCH` message — pinned by `test_every_mismatch_shape_maps_to_its_own_code`, which drives each shape through the real ladder.
- **`mcp` is pinned exactly, and the pin is a security control.** An SDK upgrade can change what the gateway believes a request *means*. `harness/scenarios/protocol_mirrored.toml` is the upgrade gate; `tests/unit/test_sdk_pin.py` is the tripwire. Move `VALIDATED_AGAINST` and the `pyproject.toml` pin together, with the corpus green.
- **`protected` mode runs one gateway per principal, over a real socket.** Identity is config-only — `identity.resolve` never reads the request (IDENT-003) — so the principal cannot ride on the wire and `ProtectedClient` dispatches on `scenario.principal` to one of N gateways. `write_configs` also forces `max_concurrent_requests = 1`: `assert_serialised` refuses to start otherwise, because oracle correlation is by byte offset into one operation log. Never score the corpus through `pipeline.handle` or the bare ASGI callable — the first hid an unframed success reply, the second skips the HTTP parser that `Transport.http_fate` measures.
- **`Mcp-Param-*` is checked at stage 04, not 02.** The `x-mcp-header` annotations live in the *approved* `inputSchema`, which only the registry resolves. `protocol.check_param_headers()` is the function; unit 04 calls it. Still before policy and the router, so PROTO-002 holds.

## Environment

- Python 3.12+ (3.13 locally). `mcp` 2.0.0 — `MCPServer` replaces `FastMCP`; `mcp.server.mcpserver` re-exports `ResourceSecurity`.
- **stdlib `json`, never `orjson`** — only `object_pairs_hook` can detect duplicate keys, and `orjson`'s silent last-key-wins would make `PROTO_DUPLICATE_FIELD` undetectable.
- No `fastapi`/`starlette`: the edge is one path and one method, so it is a bare ASGI callable under `uvicorn`.
- Development targets **WSL2**, which gives the strong fixture isolation tier and working symlinks. On Windows, 3 symlink tests skip (reported as SKIPPED, never passed) and the fixture runs on the *weak* tier, which stamps `isolation: weak` on every benchmark report.
- OPA is a required external binary (sidecar on `127.0.0.1:8181`). Pin the version — Rego syntax differs between 0.x and 1.x.
- Env vars: `FIXTURE_ROOT`, `FIXTURE_OPLOG`, `FIXTURE_MODE`, `FIXTURE_ALLOW_WEAK_ISOLATION`, `ZTMG_ALLOW_DIRECT`. `GROQ_API_KEY` belongs to `agent/` only (v1.1) and must never appear in `[child].env_allowlist`.

---

An OpenAI Codex config exists at `~/.codex/config.toml`. Reply `/import` to scan and list what is importable, then `/import --yes=<digest>` to apply.

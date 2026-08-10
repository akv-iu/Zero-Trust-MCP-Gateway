# TECH-06 — `svc-policy-broker`

**Pairs with:** [`_specs/06-svc-policy-broker.md`](../_specs/06-svc-policy-broker.md)
**Modules:** `gateway/policy.py`, `policies/rego/`

---

## 1. Deployment: OPA as a sidecar

```bash
opa run --server --addr 127.0.0.1:8181 \
        --set decision_logs.console=false \
        --log-level error \
        policies/rego/
```

Sidecar over embedded, deliberately:

- Policy is genuinely external, which is what `REQ-POL-001` asks for.
- The outage test (`POLICY-010`) becomes real — kill a process, observe denials. An embedded evaluator can only simulate that.
- The added latency is a **number the benchmark wants to publish**, not a problem. If OPA turns out to dominate the overhead distribution, that is a finding worth reporting.

`--set decision_logs.console=false` matters: OPA's decision logs would echo the policy input to its stdout, which lands in the diagnostic sink and could carry the canonical path. The gateway's audit log is the record; OPA's is noise.

A `scripts/dev.py` starts OPA, waits for `/health`, starts the gateway, and tears both down. Tests use it as a session fixture.

---

## 2. Client

`httpx.AsyncClient`, one instance in `Deps`, created at startup with an explicit timeout and a connection limit of 1 (v1 serializes anyway).

```python
async def evaluate(...) -> Decision:
    payload = {"input": build_input(req, ctx, tgt, drv, revision)}
    try:
        with anyio.fail_after(cfg.policy.timeout_ms / 1000):
            r = await client.post(f"{base}/v1/data/gateway/decision", json=payload)
            r.raise_for_status()
            result = r.json().get("result")
    except (httpx.HTTPError, TimeoutError, json.JSONDecodeError) as e:
        raise PolicyDenial(POLICY_UNAVAILABLE if not isinstance(e, TimeoutError)
                           else POLICY_TIMEOUT) from e
    return validate_result(result, req)
```

Notes that are easy to get wrong:

- **`result` absent means deny.** OPA returns `{}` with HTTP 200 when the queried path is undefined — an unhandled rule name typo would otherwise produce a silent `None`, and any truthiness check on it would be a catastrophic bug. Handle `result is None` explicitly as `POLICY_DEFAULT_DENY`.
- Retry **once** on `httpx.ConnectError` / `ReadError` only. Never retry a timeout (it may have evaluated), never retry a 200 (`POLICY-011`).
- Do not use OPA's `/v1/data` bulk or partial-evaluation endpoints. One query, one decision.

---

## 3. Input construction (POLICY-001 … 004)

Built from a frozen model, not a hand-assembled dict — so `POLICY-002` is enforced by the type rather than by review:

```python
class PolicyInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    request: RequestBlock  # id, protocol_version, transport, method
    principal: PrincipalBlock  # id, auth_method, assurance, roles, environment
    client: ClientBlock  # id
    target: TargetBlock  # server_id, tool, schema_fingerprint, registry_risk_tier
    resource: ResourceBlock  # canonical_path, root, classification, exists
    arguments: ArgumentsBlock  # arg_hash, operation
    context: ContextBlock  # policy_revision
```

There is no field on any block that can hold a raw argument value, a secret, or free text. Spec test 8 (inspect every dispatched document) then becomes a regression guard rather than the primary defense.

`canonical_path` **is** included — bounded, contained within a root, and necessary for a reviewable decision (`AUDIT-006` reasons identically).

---

## 4. Result contract and validation

Rego returns:

```json
{
  "decision": "allow",
  "reason_code": "FILESYSTEM_SCOPED_READ",
  "risk_tier": "R1",
  "obligations": {"timeout_ms": 3000, "max_response_bytes": 1048576}
}
```

`validate_result` is where fail-closed lives:

```python
def validate_result(result: Any, req: CanonicalRequest) -> Decision:
    if not isinstance(result, dict):            raise PolicyDenial(POLICY_RESULT_INVALID)
    if result.get("decision") not in ("allow", "deny"): raise PolicyDenial(POLICY_RESULT_INVALID)
    code = result.get("reason_code")
    if not code or code not in KNOWN_REASON_CODES:      raise PolicyDenial(POLICY_RESULT_INVALID)
    ...
    ob, clamped = clamp(result.get("obligations") or {})
    return Decision(request_id=req.request_id, ..., obligations=ob, clamped=clamped)
```

`KNOWN_REASON_CODES` is a closed set shared between Python and Rego. Keep the canonical list in `policies/reason_codes.json`, load it into the `ReasonCode` enum at import, and load it into Rego as `data.reason_codes` — one source, two consumers, and a test asserting both see the same set.

### Clamping (POLICY-007)

```python
def clamp(raw: dict) -> tuple[Obligations, bool]:
    t = min(int(raw.get("timeout_ms", cfg.default_timeout_ms)), cfg.max_timeout_ms)
    b = min(int(raw.get("max_response_bytes", cfg.default_bytes)), cfg.max_bytes)
    return Obligations(timeout_ms=t, max_response_bytes=b), (t, b) != (
        raw.get(...),
        raw.get(...),
    )
```

`min` only — policy may narrow, never widen. When clamping occurs, set `Decision.clamped` and audit `POLICY_OBLIGATION_CLAMPED` alongside the real reason code. The request still proceeds; clamping is not a denial.

---

## 5. Rego layout

```text
policies/rego/gateway/
  decision.rego        # entrypoint: data.gateway.decision, and the precedence
  discoverable.rego    # entrypoint for REG-010 (see TECH-04 §6)
  grants.rego          # role -> root -> operations, plus the reconciliation rules
  prohibitions.rego    # explicit prohibitions, highest precedence
  revision.rego        # GENERATED stamp; see below
policies/tests/        # *_test.rego, loaded by `opa test policies/` and NOT served
policies/reason_codes.json
```

`opa run --server` is pointed at `policies/rego` and `opa test` at `policies`, so the
test files are never part of the served bundle. `revision.rego` is excluded from its
own hash.

Precedence (`POLICY-008`) expressed so it cannot be accidentally inverted:

```rego
default decision := {"decision": "deny", "reason_code": "POLICY_DEFAULT_DENY",
                     "risk_tier": "R4", "obligations": {}}

decision := d if { d := prohibition }                      # 1
decision := d if { not prohibition; d := explicit_deny }   # 2
decision := d if { not prohibition; not explicit_deny; d := allow }  # 3
```

Guarding each lower rule with `not` on the higher ones makes precedence a
compile-visible property. Do not rely on rule ordering — Rego has none. Verified
against OPA 1.19 before the bundle was written; `test_prohibition_beats_a_matching_grant`
supplies a grant for a prohibited root, so an implementation letting an allow win
would allow.

**A `default` rule value must be constant** — `illegal default rule (value cannot
contain var)` — so the default cannot echo `input.target.registry_risk_tier` and
carries `R4` instead. That is the honest reading: nothing matched, so policy could not
classify the request. Every other rule echoes the registry's tier, which the pipeline
compares on an allow.

Keep `prohibitions.rego` tiny and readable: sensitive decoys, `traps/`, anything
outside a root. It is the file a reviewer reads first.

**`grants.rego` names the roots and operations; it does not DEFINE them.** The role
vocabulary and the per-root operation ceilings are published to `data.config` by
`policy.publish_config` at startup, from `config/gateway.toml`, and the bundle
reconciles against them:

| Rule | What it catches |
|---|---|
| `roles_without_grants` | a role in the vocabulary that policy never mentions — otherwise every request for that principal is `POLICY_DEFAULT_DENY`, which reads as a decision |
| `grants_without_roles` | a grant for a role that no longer exists |
| `grants_naming_unknown_roots` | a grant on a root the gateway does not approve |
| `grants_on_prohibited_roots` | a grant a prohibition already refuses — a line that reads as permission and grants nothing |

`check_bundle` queries all four at startup and refuses on any non-empty answer. This
is what makes publishing the vocabulary better than duplicating it: there is nothing
to keep in sync, and the one remaining way to disagree is a startup failure.

`with` has two restrictions worth knowing before writing the tests: it may not appear
in a rule HEAD, and it may not appear inside a call argument. So
`decide(x) := decision with input as x` and `count(rule with data.x as y)` are both
parse errors, and every test repeats its `with` clauses in the body.

### Policy revision (POLICY-014) — corrected

The draft stamped `git rev-parse --short HEAD` into the bundle and had Rego echo it in
every decision. Two things are wrong with that.

**A git SHA identifies the repository, not the bundle.** It changes on every commit
that touches anything, and it does *not* change when an uncommitted policy edit is
what actually decided. `policy.bundle_revision()` is a content hash over the `.rego`
files instead: it moves when and only when the policy moves.

**A bundle echoing its own revision agrees with itself** no matter which copy OPA
loaded. The broker computes the hash from the files on disk and compares it to
`data.gateway.policy_revision`, a constant stamped INTO the bundle by
`scripts/sync_policy_revision.py`. A mismatch means the running OPA is serving
something other than what is in the repo — which `--watch` being off makes both easy
and completely silent — and `check_bundle` refuses to serve.

Line endings are normalised in the hash. Git checks these files out CRLF on Windows and
LF on Linux, and a revision that differed by platform would report two policies where
there is one.

`Decision.policy_revision` is stamped by the BROKER from that verified hash, not by
Rego. `validate_result` denies with `POLICY_REVISION_UNKNOWN` when it is empty.

---

## 6. Rego tests (POLICY-016)

`opa test policies/ -v` runs in CI independently of the gateway — it needs no Python, no fixture, no OPA server.

Per rule, minimum: one allow, one deny, one boundary, one bypass attempt. Write them table-driven:

```rego
test_intern_denied_confidential if {
    r := decision with input as base_input("intern", "/fixture/confidential/x.csv", "read")
    r.decision == "deny"
    r.reason_code == "POLICY_PATH_NOT_PERMITTED"
}
```

Assert the **reason code**, not just the decision (`HARN-003`). A rule that denies for the wrong reason is a defect that a decision-only test hides.

---

## 7. Config

```toml
[policy]
base_url = "http://127.0.0.1:8181"
decision_path = "/v1/data/gateway/decision"
discoverable_path = "/v1/data/gateway/discoverable"
timeout_ms = 500
max_timeout_ms = 10000
default_timeout_ms = 3000
max_response_bytes = 4194304
default_response_bytes = 1048576
cache_enabled = false            # POLICY-012 — measure before enabling
```

---

## 8. Tests

| Spec test | Notes |
|---|---|
| 1 — OPA killed | `chaos` fixture terminates the sidecar mid-suite; assert `POLICY_UNAVAILABLE`, oracle clean, readiness false, liveness true |
| 2/3/4 — malformed results | Point `base_url` at a stub server returning `{}`, `{"decision":"allow"}` (no code), `{"decision":"maybe"}` |
| 5 — clamping | Rego returns `timeout_ms: 999999`; assert enforced value is `max_timeout_ms` and `clamped` is audited |
| 7 — determinism | 100 identical evaluations, assert byte-identical `Decision` dumps |
| 8 — input hygiene | `httpx` transport spy captures every dispatched body; assert no fixture canary, no raw argument value, across the whole suite |
| 12 — standalone Rego | `opa test` as its own CI job with no Python job dependency |

---

## 9. Gotchas

- **OPA 1.x** makes `if`/`contains` the default syntax and accepts `import rego.v1` as a no-op. Developed against **1.19.0**; `scripts/opa_sidecar.py` refuses anything that is not `1.x` rather than letting a 0.x binary parse the bundle differently. Record the version in `docs/benchmark-report.md`'s environment block.
- **`evaluate` RETURNS a deny; it does not raise one.** Only a broker-side failure — unreachable, timed out, malformed, unattributable — raises, because those produce no decision to record. A policy deny IS a decision; `pipeline.handle` raises it *after* `builder.set` has put its fields on the audit event, so the record says what policy answered and not merely that something went wrong.
- `isinstance(result, dict)` narrows to `dict[Unknown, Unknown]` under pyright strict, which poisons every value read out of it. Cast once, immediately after the check that makes the cast true.
- `isinstance(True, int)` is `True` in Python, so a boolean obligation becomes a one-millisecond timeout unless `_bounded` rejects `bool` explicitly.
- `--watch` for hot reload is a development convenience only; never enable it in a benchmark run, or the policy revision in the report may not be the one that decided.
- Do not enable the decision cache before the benchmark exists. If OPA latency turns out to matter, the cache is a measured optimization with a published before/after — which is a better portfolio artifact than a cache that was always there.
- OPA's HTTP server binds `0.0.0.0` by default in some versions. `--addr 127.0.0.1:8181` explicitly (`REQ-SEC-012`).

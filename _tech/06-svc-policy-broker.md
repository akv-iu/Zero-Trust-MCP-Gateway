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
policies/rego/
  gateway/decision.rego        # entrypoint: data.gateway.decision
  gateway/discoverable.rego    # entrypoint for REG-010 (see TECH-04 §6)
  gateway/roles.rego           # data-only: role -> permitted roots/operations
  gateway/prohibitions.rego    # explicit prohibitions, highest precedence
  reason_codes.json
tests/                         # *_test.rego, run by `opa test`
```

Precedence (`POLICY-008`) expressed so it cannot be accidentally inverted:

```rego
package gateway

default decision := {"decision": "deny", "reason_code": "POLICY_DEFAULT_DENY",
                     "risk_tier": "R4", "obligations": {}}

decision := d if { d := prohibition }                      # 1
decision := d if { not prohibition; d := explicit_deny }   # 2
decision := d if { not prohibition; not explicit_deny; d := allow_with_obligations }  # 3
```

Guarding each lower rule with `not` on the higher ones makes precedence a compile-visible property. Do not rely on rule ordering — Rego has none.

Keep `prohibitions.rego` tiny and readable: sensitive decoys, `traps/`, anything outside a root. It is the file a reviewer reads first.

### Policy revision (POLICY-014)

Stamp the bundle at build time:

```bash
git rev-parse --short HEAD > policies/rego/revision.txt
# loaded as data.revision, echoed in every decision
```

If `data.revision` is undefined, `validate_result` denies with `POLICY_REVISION_UNKNOWN`. That makes an unstamped bundle fail loudly rather than producing unattributable decisions.

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

- **OPA 1.x requires `import rego.v1`** (or `if`/`contains` keyword syntax) in every file. Pin the OPA version in CI and in `docs/benchmark-report.md`'s environment block; syntax differences between 0.x and 1.x will silently break a bundle authored against the other.
- `--watch` for hot reload is a development convenience only; never enable it in a benchmark run, or the policy revision in the report may not be the one that decided.
- Do not enable the decision cache before the benchmark exists. If OPA latency turns out to matter, the cache is a measured optimization with a published before/after — which is a better portfolio artifact than a cache that was always there.
- OPA's HTTP server binds `0.0.0.0` by default in some versions. `--addr 127.0.0.1:8181` explicitly (`REQ-SEC-012`).

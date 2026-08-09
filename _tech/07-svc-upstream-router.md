# TECH-07 — `svc-upstream-router`

**Pairs with:** [`_specs/07-svc-upstream-router.md`](../_specs/07-svc-upstream-router.md)
**Module:** `gateway/router.py`

---

## 1. Signature is the security control

```python
async def forward(req: CanonicalRequest, dec: Decision, up: UpstreamHandle) -> RawResult:
    if dec.request_id != req.request_id:
        raise RouteDenial(ROUTE_NO_DECISION)
    if dec.decision != "allow":
        raise RouteDenial(ROUTE_NO_DECISION)  # defensive; pipeline already raised
    ...
```

`Decision` is a frozen model carrying `request_id` (TECH-00 §3), so `ROUTE-001` is a two-line check on a typed object rather than a boolean audit. There is no overload of `forward` that accepts a bool, and pyright rejects one being added.

`RawResult` is a small frozen record: `content`, `is_error`, `byte_count`, `upstream_latency_ns`.

---

## 2. Avoiding divergence (ROUTE-002)

The strongest form is to make divergence unrepresentable: the router derives the outbound message **from `req`**, and never accepts a separately-constructed message.

```python
result = await up.session.call_tool(req.tool_name, dict(req.arguments))
```

Then keep the detection check anyway, as a refactor guard:

```python
assert_same = hash_obj({"tool": req.tool_name, "args": dict(req.arguments)})
if assert_same != dec_bound_arg_hash:
    raise RouteDenial(ROUTE_AUTHORIZATION_DIVERGENCE)
```

`dec_bound_arg_hash` comes from `DerivedAttributes.arg_hash`, which unit 05 computed over the same arguments policy saw. Pass it through `Deps` for the request or thread it as a parameter — do not recompute it from a different source, or the check compares a value to itself.

Test 3 injects divergence at a seam: a pytest monkeypatch that mutates `req.arguments` between policy and router. Because `CanonicalRequest` is frozen and `arguments` is a `MappingProxyType`, the test must patch the *router's* view — which is itself evidence the invariant holds in production.

---

## 3. Capability isolation (ROUTE-003)

The router must not be able to touch the filesystem or network itself. Enforced by `tests/unit/test_router_isolation.py`, which walks the module's AST for forbidden imports and I/O builtins.

**Built and passing as of wave 0.** A grep was the first instinct and was wrong twice over: it trips on the module's own docstring, and it misses aliased imports. `ast` is stdlib, immune to both, and about the same length. The test carries its own negative control, because a check that cannot fail is not a check.

The module needs `anyio`, the SDK session, and gateway types — nothing else. If it ever legitimately needs more, that is a design conversation, which is exactly what a failing check should force.

Spec test 10 is this test; it runs in the normal suite, so no separate CI wiring.

---

## 4. Deadlines

```python
budget_s = min(dec.obligations.timeout_ms / 1000, remaining_request_budget())
with anyio.move_on_after(budget_s) as scope:
    result = await up.session.call_tool(...)
if scope.cancel_caught:
    raise RouteDenial(ROUTE_TIMEOUT)
```

`move_on_after` + explicit `cancel_caught` check, not `fail_after` — it converts the timeout into a domain denial with the right reason code instead of letting a `TimeoutError` escape to the pipeline's generic handler.

`remaining_request_budget()` reads the bridge's deadline from the audit builder's `received_at_ns` and the configured total. Nesting the two guarantees `ROUTE-005`'s "whichever is lower" without a separate config knob.

**No retries at all** (`ROUTE-011`). Not on timeout, not on connection error. Add the ponytail marker so the deferral is tracked:

```python
# ponytail: no retry — the fixture has no idempotency keys and a retry could double a write.
# Revisit only when an idempotent business fixture exists (_specs/90-deferred-register.md §6).
```

---

## 5. Streaming the byte ceiling (ROUTE-006)

The hard part, and the one place a naive implementation turns a size *limit* into a memory *exhaustion vector*.

`ClientSession.call_tool()` returns a fully materialized result — by the time it returns, an oversized response is already in memory. To bound it properly the count must happen at the transport layer:

Wrap the child's read stream in a counting reader when the session is created (unit 01 owns the stream; the router sets the ceiling per request):

```python
class BoundedReader:
    def __init__(self, inner, ceiling_var: ContextVar[int]): ...
    async def receive(self):
        chunk = await self.inner.receive()
        self.count += len(chunk)
        if self.count > self.ceiling_var.get():
            raise RouteDenial(ROUTE_RESPONSE_TOO_LARGE)
        return chunk
```

The router sets the contextvar from `dec.obligations.max_response_bytes` before the call and resets after. The reader aborts mid-stream, which is what spec test 5 asserts by watching peak RSS.

If the SDK's stream layering makes this impractical, the fallback is a post-hoc size check in unit 08 — but say so explicitly in the report, because it changes the property from "cannot exhaust memory" to "detects oversized responses". Do not let that substitution happen silently.

`# ponytail: byte ceiling enforced at the transport reader; post-hoc check in unit 08 is the fallback if SDK stream wrapping proves infeasible.`

---

## 6. Cancellation (ROUTE-010)

anyio cancellation propagates automatically through the task tree, so a cancelled bridge scope cancels the in-flight `call_tool`. Two things still need explicit handling:

```python
except anyio.get_cancelled_exc_class():
    audit.set_outcome("cancelled")
    raise                      # MUST re-raise — swallowing breaks anyio's cancel semantics
```

Never swallow a cancellation exception. And distinguish the four outcomes explicitly — `cancelled`, `timeout`, `error`, `denied` — because collapsing them destroys the evidence the report reads (`HARN-019`).

Whether the child observes the cancellation depends on the SDK sending a `notifications/cancelled`. Verify at spike time; if it does not, the fixture's operation log will show the operation completing after the client gave up, which is a real and reportable finding rather than a bug to hide.

---

## 7. Latency accounting (ROUTE-013)

```python
t0 = perf_counter_ns()
result = await up.session.call_tool(...)
upstream_ns = perf_counter_ns() - t0
```

This is the number the benchmark subtracts to isolate gateway overhead. It measures the SDK round trip including child processing — which is the right boundary, since `direct` mode measures the same round trip without the gateway.

`audit.stage("route")` wraps the whole function, so `stage_latency_ms.route - upstream_latency_ms` is the router's own cost. The report publishes both.

---

## 8. Config

```toml
[router]
max_timeout_ms = 10000          # ceiling for the policy obligation
max_response_bytes = 4194304    # ceiling
cancellation_grace_ms = 1000
```

Both ceilings duplicate `[policy]`'s clamp values by design: policy clamps what it *returns*, the router enforces what it *received*. Assert equality at startup so they cannot drift.

---

## 9. Tests

| Spec test | Notes |
|---|---|
| 1 — mediation | The suite's headline: over the whole malicious corpus, diff the fixture operation log against the set of allowed `request_id`s; assert empty |
| 2 — foreign decision | Construct a `Decision` with a different `request_id`; assert `ROUTE_NO_DECISION` |
| 5 — streaming abort | Fixture `oversized` mode returns 100 MiB; assert denial and that peak RSS stays under a few MiB above baseline (`tracemalloc` or `resource.getrusage`) |
| 6 — hang | Fixture `hang` mode; assert `ROUTE_TIMEOUT`, exactly one upstream attempt in the fixture log |
| 8 — cancellation | Assert `outcome="cancelled"`, not `"error"` |
| 11 — latency consistency | `stage.route >= upstream_latency` and total ≈ Σ stages within tolerance |

---

## 10. Gotchas

- The SDK may raise its own exception types on tool errors; map them to `RouteDenial` explicitly rather than letting them reach the generic handler as `INTERNAL_ERROR`, which would lose the reason code.
- A tool that returns `isError: true` is a **successful round trip with an error result**, not a router failure. Pass it through to unit 08; only unit 08 decides how it is shaped for the client (`ROUTE-012`/`RESP-006`).
- Do not add a connection pool, a breaker, or a health-check loop. One child, one lock, one call.

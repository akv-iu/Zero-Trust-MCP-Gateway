# TECH-01 — `svc-transport-edge`

**Pairs with:** [`_specs/01-svc-stdio-bridge.md`](../_specs/01-svc-stdio-bridge.md)
**Modules:** `gateway/edge.py` (client-facing HTTP), `gateway/bridge.py` (upstream stdio child)

> **Amended by [ADR-001](../_specs/ADR-001-transport-and-mirrored-metadata.md).** Client edge is Streamable HTTP on loopback; the upstream leg stays stdio. §1a replaces the old §1. §2–§6 (child supervision, `stdout` discipline, deadlines, concurrency, limits) apply to the **child leg** and are unchanged.

---

## 1a. Client edge — Streamable HTTP (`gateway/edge.py`)

A bare ASGI app. **No FastAPI, no routing framework** — there is exactly one path and one method, and a framework would add dependencies to gain nothing.

```python
async def app(scope, receive, send):
    if scope["type"] != "http":                       return await _reject(send, 400)
    if scope["path"] != cfg.mcp_path:                 return await _reject(send, 404)
    if scope["method"] in ("GET", "DELETE"):          return await _reject(send, 405)  # 2026-07-28
    if scope["method"] != "POST":                     return await _reject(send, 405)
    if not _origin_ok(scope["headers"]):              return await _reject(send, 403)

    body = await _read_body(receive, cfg.limits.max_message_bytes)   # streaming cap
    env = RawEnvelope(request_id=uuid4().hex,
                      received_at_ns=perf_counter_ns(),
                      body=body,
                      metadata=[(k.decode("latin-1").lower(), v.decode("latin-1"))
                                for k, v in scope["headers"]])       # PAIRS, not a dict
    ...
```

Everything unit 02 needs arrives for free: **raw body bytes** and the **full header pair list**. This is what dissolves spike S-1 — there is no SDK stream to tee.

Run under `uvicorn` programmatically, `host="127.0.0.1"`, no reload, no access log (it would echo paths into the diagnostic sink).

### Mandated response shapes

| Condition | HTTP | Body |
|---|---|---|
| Header/body mismatch, missing or malformed required header | `400` | JSON-RPC error `-32020` `HeaderMismatch` |
| Unsupported protocol version | `400` | `UnsupportedProtocolVersionError` listing supported versions |
| Unknown method | `404` | JSON-RPC error `-32601` |
| Invalid `Origin` | `403` | JSON-RPC error response with no `id` (MAY) |
| `GET`/`DELETE` to the endpoint | `405` | — |
| Notification accepted | `202` | no body |

These are spec requirements, not free choices. The `404`-for-unknown-method rule is what lets a client distinguish a modern server from a legacy HTTP+SSE one.

### `Origin`, bind, and what it is not

Validate `Origin` when present, reject unapproved with `403`, bind `127.0.0.1` only. Both are spec-mandated (DNS-rebinding defense). **Neither is authentication** — identity stays `local_config` / `unverified_local` (`IDENT-002`). Say so in the README; a loopback HTTP listener invites the assumption otherwise.

### Deliberately absent

No TLS, no CORS beyond `Origin`, no auth, no sessions (`Mcp-Session-Id` ignored, never minted or echoed), no `Last-Event-ID` (streams are not resumable), no GET stream. All removed by the 2026-07-28 revision or still deferred in `_specs/90`.

### Cancellation asymmetry (resolves S-5)

Client cancels by **closing the SSE response stream**; the gateway must translate that into `notifications/cancelled` on the stdio child leg, which is mandatory on stdio. Detect disconnect via the ASGI `http.disconnect` message, then send the cancellation notification through the child session before failing the request. Audit `outcome="cancelled"` (`ROUTE-010`).

### SSE responses

v1 answers `tools/call` with `Content-Type: application/json` — a single JSON object. SSE is only needed for progress notifications, which v1 does not relay. Keep the SSE path unimplemented and return JSON; if it is ever added, `X-Accel-Buffering: no` is required on the response.

`# ponytail: JSON responses only; add SSE when a fixture emits progress notifications.`

---

## 1b. Upstream leg — stdio child (`gateway/bridge.py`)

Unchanged from the original design: `mcp.client.stdio.stdio_client` + `ClientSession` to the spawned child, exposed on `Deps` and used only by `router.py`.

One spec update: the stdio transport now says a client **SHOULD** restart a server that exits unexpectedly, since the protocol is stateless and in-flight requests are simply lost. So v1 **may** restart the child process — but it **must still fail the in-flight request** (`BRIDGE-011`, `ROUTE-011`). Restart the process, deny the request; never restart-and-retry.

---

## 2. Child `stdout` discipline (BRIDGE-001)

Applies to the **child leg only** now that the client edge is HTTP. Still worth the same care: the child must write nothing but protocol messages to its `stdout`, and the gateway must not corrupt that stream.

The gateway's own process no longer owns fd 1 for protocol traffic, so the fd juggling below is no longer load-bearing for the client edge — but keep diagnostics on `stderr` anyway, and keep the suite-wide assertion that the **child's** `stdout` parses cleanly as newline-delimited JSON.

At process start, **before** anything else:

```python
_real_stdout = os.fdopen(os.dup(1), "wb", buffering=0)   # hand this to the transport
os.dup2(2, 1)                                            # fd 1 now points at stderr
sys.stdout = sys.stderr                                  # anything that prints goes to stderr
logging.basicConfig(stream=sys.stderr)
warnings.simplefilter("default")                         # to stderr, not stdout
```

The transport writes to `_real_stdout`; nothing else in the process can reach fd 1. This makes `BRIDGE-001` structural rather than a code-review rule.

Test it by parsing the entire captured `stdout` of a full suite run as newline-delimited JSON — any unparseable line fails the suite.

---

## 3. Child process supervision

```python
params = StdioServerParameters(
    command=cfg.child.executable,        # absolute path, from registry (BRIDGE-007)
    args=list(cfg.child.args),           # list, never a string (BRIDGE-005)
    env={k: os.environ[k] for k in cfg.child.env_allowlist if k in os.environ},
    cwd=cfg.child.cwd,
)
```

- `env=` an explicit dict — the SDK inherits when `env=None`, which would leak `GROQ_API_KEY` in v1.1 (`BRIDGE-006`). Pass a dict even when empty.
- Never `shell=True`, never a joined command string, never `os.system`. `subprocess` with a list argv performs no shell interpolation, so `BRIDGE-005` is satisfied by construction — the test exists to catch a future refactor.
- Startup: wrap `ClientSession.initialize()` in `anyio.fail_after(cfg.child.startup_timeout_s)`. Failure → readiness stays false, `serve()` still runs so liveness answers (`CONV-006`).

### Termination and orphan reaping (BRIDGE-009)

Platform-divergent; get this right once:

| Platform | Spawn | Terminate |
|---|---|---|
| POSIX | `start_new_session=True` | `os.killpg(os.getpgid(pid), SIGTERM)` → wait grace → `SIGKILL` |
| Windows | `CREATE_NEW_PROCESS_GROUP` + **Job Object** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | close the job handle; the OS kills the tree even on gateway crash |

The Windows Job Object is the only mechanism that survives an abnormal gateway exit. Without it, test 8 ("killing the gateway leaves no surviving child") fails on the development platform. Set it via `ctypes` against `kernel32` — roughly 20 lines, and there is no stdlib wrapper.

Register an `atexit` and a signal handler as belt-and-braces, but do not rely on them: neither runs on `SIGKILL`.

---

## 4. Deadlines and cancellation

anyio cancel scopes, nested outermost-first:

```
bridge total deadline (cfg.request_timeout_s)
  └── router upstream deadline (obligations.timeout_ms, clamped ≤ total)
        └── OPA eval deadline (cfg.policy.timeout_ms)
```

`anyio.fail_after` at the bridge level; `anyio.move_on_after` inside the router so a timeout becomes a `RouteDenial` rather than propagating a raw `TimeoutError`.

Client disconnect surfaces as `anyio.EndOfStream` / `ClosedResourceError` on the read stream. Catch it, cancel the enclosing task group, and let the pipeline's `finally` write the audit event with `outcome="cancelled"` (`ROUTE-010`) — do **not** classify it as `error`.

---

## 5. Concurrency

One `anyio` task group per session. Bound in-flight requests with `anyio.Semaphore(cfg.max_concurrent_requests)`, default **4**.

The child `ClientSession` is **not** safe for arbitrary concurrent use across requests in v1; guard the upstream call with an `anyio.Lock` unless a spike proves the SDK multiplexes correctly by request id. Serializing upstream calls is correct at v1 scale and removes a whole class of correlation bug (`RESP-001`).

`# ponytail: upstream calls serialized by a lock; multiplex per-request if the benchmark shows upstream contention.`

---

## 6. Framing limits (BRIDGE-003)

Enforce at the tee, not after parse. Count bytes as the line is read; abort at `cfg.limits.max_message_bytes` (default **1 MiB**) without buffering the remainder. If the SDK's stream reader buffers unboundedly, wrap it with a counting reader that raises once the ceiling is crossed.

Child `stderr`: drain in a background task into a `collections.deque(maxlen=N)` (default 256 lines) forwarded to the diagnostic sink. An undrained child `stderr` pipe fills its OS buffer and deadlocks the child — a classic and very confusing hang.

---

## 7. Config

```toml
[limits]
max_message_bytes = 1048576
max_concurrent_requests = 4

[timeouts]
request_s = 30
child_startup_s = 10
child_shutdown_grace_s = 5

[child]
executable = "/abs/path/to/python"
args = ["-m", "fixtures.filesystem_server"]
cwd = "/abs/path/to/fixture"
env_allowlist = ["PATH", "PYTHONPATH"]
stderr_capture_lines = 256
```

---

## 8. Tests

| Spec test | How |
|---|---|
| 3 — stdout purity | Suite-wide autouse fixture: capture fd 1, assert every line parses as JSON-RPC |
| 4 — framing boundary | Craft messages at `max-1`, `max`, `max+1` bytes |
| 5 — no shell interpolation | Argument `"; touch pwned; #"`; assert no `pwned` file and that argv received it literally |
| 6 — env isolation | Set `GATEWAY_CANARY` in the parent; fixture tool returns its own `os.environ`; assert absent |
| 8 — no orphans | `SIGKILL` the gateway, then poll `psutil`/`tasklist` for the child pid; assert gone |
| 9 — cancellation | Fixture in `hang` mode (`FIX-010`); close client stream; assert `outcome="cancelled"` |

---

## 9. Gotchas

- **Prototype the raw-bytes tee in week 2.** If it proves impossible with the SDK's public surface, unit 02 loses duplicate-key detection and body hashing — escalate before building on it.
- The SDK may emit its own initialization logging; check where it writes before trusting §2.
- Windows `asyncio` needs `ProactorEventLoop` for pipes (the 3.12 default) — do not switch to selector.
- Do not add reconnection. The 2026-07-28 core is stateless; a dead child is a denial (`BRIDGE-011`), not a retry.

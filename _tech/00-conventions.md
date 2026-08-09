# TECH-00 — Foundation

**Pairs with:** [`_specs/00-conventions.md`](../_specs/00-conventions.md)
**Owns:** project skeleton, dependencies, shared types, error taxonomy, pipeline composition

Read this before any other tech sheet. Every other sheet assumes these types and this layout.

---

## 1. Runtime and tooling

| Item | Choice | Why |
|---|---|---|
| Python | 3.12+ | `tomllib`, modern typing, `Path.resolve(strict=)` semantics |
| Env/lock | `uv` + committed `uv.lock` | Reproducible; `uv run` for everything |
| Async | `anyio` | The MCP SDK is anyio-native; do not mix in raw `asyncio` primitives |
| Models | `pydantic` v2 | Frozen models give immutability for free (`PROTO-006`) |
| Lint | `ruff` (lint + format) | One tool |
| Types | `pyright` strict on `gateway/` | The frozen-type invariants are only real if checked |

### Dependencies

```toml
# pyproject.toml [project.dependencies]
"mcp"                # official MCP Python SDK — server + client + stdio transport
"pydantic>=2"        # all models, config, audit schema
"anyio"              # structured concurrency (transitively via mcp; pin explicitly)
"httpx"              # OPA REST calls only
"jsonschema"         # tool argument validation against MCP inputSchema
"uvicorn"            # ASGI server for the loopback HTTP client edge (ADR-001)

# [dependency-groups.dev]
"pytest", "pytest-anyio", "hypothesis", "ruff", "pyright"

# v1.1 only, separate extra:
"pydantic-ai-slim[groq]"
```

**Deliberately absent:** `orjson` (cannot detect duplicate keys — see TECH-02), `PyYAML` (config is TOML via stdlib `tomllib`), `structlog` (the audit log is the log), `opentelemetry-*` (deferred; per-stage timing lives in the audit event), **`fastapi`/`starlette`** — the client edge is one path and one method, so it is a bare ASGI callable under `uvicorn`; a routing framework would add dependencies to gain nothing.

External processes: **OPA** binary (sidecar, started by the dev script), **Trivy** and **Gitleaks** in CI only.

---

## 2. Package layout

```text
gateway/
  __init__.py
  types.py          # every shared type in §3 — no imports from other gateway modules
  errors.py         # exception taxonomy + ReasonCode enum
  config.py         # TOML loading, schema, startup validation
  hashing.py        # canonical JSON + sha256 helpers
  timing.py         # StageTimer
  context.py        # contextvars: current AuditBuilder
  pipeline.py       # stage composition — the only place stage order is expressed
  bridge.py         # 01
  protocol.py       # 02
  identity.py       # 03
  registry.py       # 04
  canonicalize/fs.py# 05
  policy.py         # 06
  router.py         # 07
  response.py       # 08
  audit.py          # 09
```

`types.py` and `errors.py` import nothing from `gateway.*`. Everything else may import them. This keeps the dependency graph acyclic and makes each unit independently testable.

---

## 3. Shared types

All frozen. `model_config = ConfigDict(frozen=True, extra="forbid")` on every one.

```python
# gateway/types.py
type RequestId = str  # uuid4().hex — unguessable, unique; sortability not required


class RawEnvelope(BaseModel):  # 01 -> 02.  Never passed beyond 02 (PROTO-006).
    request_id: RequestId
    received_at_ns: int
    body: bytes  # undecoded, straight from ASGI
    metadata: tuple[tuple[str, str], ...]  # header PAIRS, lowercased names — duplicates
    # must stay visible for PROTO-004 (ADR-001)


class CanonicalRequest(BaseModel):  # 02 -> everything. Immutable authority.
    request_id: RequestId
    protocol_version: str
    method: str  # "tools/call" | "tools/list" | handshake methods
    jsonrpc_id: str | int | None
    tool_name: str | None
    arguments: Mapping[str, Any]  # parsed, not yet canonicalized
    body_hash: str  # sha256 of raw body


class AuthzContext(BaseModel):  # 03
    principal: str
    client_id: str
    roles: tuple[str, ...]
    auth_method: Literal["local_config"]  # v1 enum has ONE value (IDENT-002)
    assurance: Literal["unverified_local"]  # ditto
    transport: Literal["streamable_http"]  # client edge; upstream leg is stdio
    environment: str


class ResolvedTarget(BaseModel):  # 04
    server_id: str
    tool_name: str
    schema_fingerprint: str
    registry_risk_tier: Literal["R0", "R1", "R2", "R4"]


class DerivedAttributes(BaseModel):  # 05
    canonical_path: str
    root: str
    operation: Literal["read", "create", "overwrite", "append", "rename", "delete"]
    classification: str
    exists: bool
    arg_hash: str
    raw_hash: str


class Obligations(BaseModel):  # 06
    timeout_ms: int
    max_response_bytes: int


class Decision(BaseModel):  # 06 -> 07.  Carries request_id so ROUTE-001 is checkable.
    request_id: RequestId
    decision: Literal["allow", "deny"]
    reason_code: str
    risk_tier: Literal["R0", "R1", "R2", "R4"]
    policy_revision: str
    obligations: Obligations
    clamped: bool = False


@dataclass(frozen=True)
class Untrusted[T]:  # 08 -> client / 12.  RESP-005.
    value: T

    def unwrap(self) -> T:
        return self.value
```

`Untrusted` is a wrapper, not a boolean flag, so v1.1 cannot splice tool text into a system prompt without a visible `.unwrap()` in the diff.

---

## 4. Error taxonomy

One exception family. One handler. `errors.py`:

```python
class GatewayDenial(Exception):
    reason_code: ReasonCode
    stage: Stage
    http_safe_message: str  # what the client sees — never internals (CONV-009)
    detail: str | None = (
        None  # diagnostic sink only, never client-facing, never audited raw
    )
```

Subclasses by stage — `ProtocolDenial`, `IdentityDenial`, `RegistryDenial`, `CanonicalizationDenial`, `PolicyDenial`, `RouteDenial`, `ResponseDenial` — carrying nothing extra. The subclass exists for `except` targeting in tests, not for behavior.

`ReasonCode` is a single `StrEnum` holding every code from every spec's failure table. One enum, not seven: `CONV-010` requires proving every code is reachable, which is a single test iterating one enum against the corpus.

**Rule:** any exception that is *not* a `GatewayDenial` reaching the pipeline handler is an internal defect. The handler converts it to `deny` with `INTERNAL_ERROR`, logs the traceback to the diagnostic sink, and **never** lets it become an allow (`CONV-004`).

---

## 5. Pipeline composition

`pipeline.py` is the only module that expresses stage order. Everything else is a pure-ish function.

```python
async def handle(env: RawEnvelope, deps: Deps) -> Untrusted[dict]:
    audit = AuditBuilder(env.request_id, env.received_at_ns)
    token = current_audit.set(audit)
    try:
        with audit.stage("protocol"):
            req = protocol.validate(env)
        with audit.stage("identity"):
            ctx = identity.resolve(req, deps.config)
        with audit.stage("registry"):
            tgt = await registry.resolve(req, ctx, deps.registry)
        with audit.stage("canonical"):
            drv = canonicalize.fs.derive(req, tgt, deps.config)
        with audit.stage("policy"):
            dec = await policy.evaluate(req, ctx, tgt, drv, deps.opa)
        if dec.decision != "allow":
            raise PolicyDenial(dec.reason_code)
        with audit.stage("route"):
            raw = await router.forward(req, dec, deps.upstream)
        with audit.stage("response"):
            out = response.validate(raw, req, dec.obligations)
        return out
    except GatewayDenial as d:
        audit.deny(d)
        raise
    except Exception as e:
        audit.internal_error(e)
        raise GatewayDenial(ReasonCode.INTERNAL_ERROR, ...) from e
    finally:
        await audit.finalize_and_write(deps.audit)  # AUDIT-001: exactly one, always
        current_audit.reset(token)
```

Stage order lives here and nowhere else (`CONV-002`). A new stage is a line here plus a spec.

`Deps` is a frozen dataclass assembled once at startup — config, registry, OPA client, upstream channel, audit sink. **No global mutable state, no service locator, no DI framework.**

---

## 6. Hashing

`hashing.py`. One canonical form, used by argument hashes, body hashes, and schema fingerprints — so any two of them are comparable and reproducible.

```python
def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str: ...
def hash_obj(obj) -> str:
    return sha256_hex(canonical_json(obj))
```

`allow_nan=False` matters: `NaN`/`Infinity` are not JSON and must not silently enter a fingerprint.

Fingerprints carry a normalization version prefix — `"v1:sha256:abc..."` (`REG-005`) — so the rule can change deliberately instead of silently invalidating every stored value.

---

## 7. Timing

`timing.py`. `time.perf_counter_ns()` only — never `time.time()` for durations.

```python
@contextmanager
def stage(self, name: str):
    t0 = time.perf_counter_ns()
    try:
        yield
    finally:
        self.stage_ns[name] = time.perf_counter_ns() - t0
```

Recorded in nanoseconds, reported in milliseconds by the harness. Wall-clock `ts_start`/`ts_end` are `datetime.now(UTC)` and are for correlation only, never for measurement.

---

## 8. Config

TOML via stdlib `tomllib`, parsed into pydantic models with `extra="forbid"` (`CONV-013`).

```text
config/
  gateway.toml     # limits, deadlines, roots, principal
  registry.toml    # 04 — servers + approved tools
```

```python
def load(path: Path) -> Config:
    with path.open("rb") as f:
        raw = tomllib.load(f)
    return Config.model_validate(raw)  # extra="forbid" -> unknown key = startup failure
```

Startup order: load config → validate → run self-checks (`CANON-015` gateway paths outside roots, `FIX-006` fixture isolation, audit sink writable) → start OPA client and verify a probe query → spawn child → handshake → **only then** set ready.

Every limit in every spec is a field here with a default and a boundary test (`CONV-015`).

---

## 9. Testing conventions

```text
tests/
  unit/        # one file per gateway module, no I/O
  protocol/    # raw JSON-RPC bytes in, decision out
  security/    # corpus-driven, requires fixture + OPA
  property/    # hypothesis
  chaos/       # OPA killed, sink unwritable, upstream hang/crash
conftest.py    # anyio_backend="asyncio"; fixture tree factory; OPA sidecar fixture
```

- `pytest-anyio` with `anyio_backend` pinned to `asyncio`; do not parametrize over trio.
- Hypothesis profiles: `dev` (50 examples), `ci` (500), `release` (5000), seed recorded and printed (`CONV-019`).
- **Suite-wide invariants** as `conftest` autouse fixtures rather than individual tests: no canary in any audit record (`AUDIT-006`), no `auth_method` other than `local_config` (`IDENT-002`), exactly one audit event per request (`AUDIT-001`). These catch regressions no per-unit test would.
- No network, no API key: CI runs with `GROQ_API_KEY` unset and egress blocked (`CONV-016`).

---

## 10. Build order reminder

Per `PLAN.md` §4.2, `types.py` / `errors.py` / `hashing.py` / `timing.py` / `config.py` are written first as a single small change, then unit 10, then 11-skeleton, then 01, then 09, then the enforcement stages in lifecycle order. `pipeline.py` grows one line per stage as each lands — it should be the shortest-lived merge conflict in the project.

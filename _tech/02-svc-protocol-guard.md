# TECH-02 — `svc-protocol-guard`

**Pairs with:** [`_specs/02-svc-protocol-guard.md`](../_specs/02-svc-protocol-guard.md)
**Module:** `gateway/protocol.py`

---

> ## SUPERSEDED IN PART — read [ADR-002](../_specs/ADR-002-sdk-owns-header-validation.md) first
>
> `mcp` 2.0 ships `mcp/shared/inbound.py`, a pure exported module that already implements
> the whole mirrored-metadata ladder. **§3 below is superseded — do not implement it.**
> Call the SDK instead:
>
> ```python
> from mcp.shared.inbound import (
>     ERROR_CODE_HTTP_STATUS, InboundLadderRejection, classify_inbound_request,
>     find_duplicated_routing_header, validate_mcp_param_headers,
> )
> ```
>
> §2 (parser choice, byte prescan) and §4–§7 stand unchanged — the SDK takes an
> already-decoded mapping, so duplicate body keys, depth, and structural limits remain ours.
> Unit 02 becomes: prescan → parse+dupe-detect → structural limits → **SDK ladder** →
> envelope shape → method allowlist → MRTR refusal → CanonicalRequest.
> The corpus does **not** shrink: delegated behavior still needs every test, and the corpus
> becomes the SDK-upgrade gate.

## 0. D-1 — RESOLVED. Client edge is Streamable HTTP

See [ADR-001](../_specs/ADR-001-transport-and-mirrored-metadata.md). The spec is explicit that stdio has **"no header layer"**, so the consistency check only exists on HTTP. The client-facing edge is Streamable HTTP on loopback; the upstream leg stays stdio.

Consequences for this module:

- `RawEnvelope.metadata` becomes `Sequence[tuple[str, str]]`, not a `Mapping` — ASGI gives header pairs, and a duplicate mirrored header must be *detectable* (`PROTO-004`), which a mapping cannot represent.
- Raw body bytes arrive directly from ASGI. **S-1 is dissolved**; no SDK stream tee is needed.
- Rejections have a mandated wire shape: HTTP `400` + JSON-RPC `-32020` `HeaderMismatch`. Unsupported version → `400` + `UnsupportedProtocolVersionError` listing supported versions. Unknown method → **`404`** + `-32601`.
- There is **no `initialize` handshake** in the modern era. Drop it and `notifications/initialized` from the allowlist; add `server/discover` as recognized-but-denied so a probing client gets a clean modern error rather than a timeout.

---

## 1. Order of operations

Strictly sequential; each step's failure is terminal. Cheap structural checks precede expensive parsing so a hostile payload dies early (`PROTO-013`).

```
1. byte-level prescan  -> depth, size, nesting          (no allocation)
2. json.loads          -> with object_pairs_hook        (duplicate detection)
3. structural limits   -> arrays, strings, field count  (walk the parsed tree once)
4. jsonrpc envelope    -> version, id, required fields
5. protocol version    -> allowlist
6. method allowlist    -> before any metadata use
7. metadata/body consistency  <- THE CHECK (PROTO-002: before routing/policy)
8. build CanonicalRequest (frozen)
```

Step 7 is after 6 only so that an unknown method is rejected as `PROTO_METHOD_NOT_ALLOWED` rather than as a metadata mismatch — clearer reason codes, same security. Nothing between 1 and 7 routes, looks up the registry, or evaluates policy.

---

## 2. Parser choice — non-negotiable

**stdlib `json`, not `orjson`.**

`json.loads(..., object_pairs_hook=...)` is the only way to see duplicate keys; `orjson` silently applies last-key-wins, which makes `PROTO_DUPLICATE_FIELD` undetectable and turns a spec requirement into a lie. Speed is irrelevant at v1 request rates, and the benchmark measures whatever it costs.

```python
def _no_dupes(pairs: list[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    for k, _ in pairs:
        if k in seen:
            raise ProtocolDenial(ReasonCode.PROTO_DUPLICATE_FIELD)
        seen.add(k)
    return dict(pairs)
```

Spec says *conflicting* duplicates. Rejecting **all** duplicates is stricter, simpler, and has no legitimate false positive — a well-formed JSON-RPC message never repeats a key.

### Depth prescan

`json.loads` has no depth limit and will hit CPython's recursion ceiling on deep input — a `RecursionError`, not a clean denial. Prescan the bytes before parsing:

```python
def prescan(body: bytes, max_depth: int, max_bytes: int) -> None:
    if len(body) > max_bytes: raise ProtocolDenial(PROTO_LIMIT_EXCEEDED)
    depth = 0; in_str = False; esc = False
    for b in body:
        if esc: esc = False; continue
        if in_str:
            if b == 0x5C: esc = True
            elif b == 0x22: in_str = False
            continue
        if b == 0x22: in_str = True
        elif b in (0x7B, 0x5B):            # { [
            depth += 1
            if depth > max_depth: raise ProtocolDenial(PROTO_LIMIT_EXCEEDED)
        elif b in (0x7D, 0x5D): depth -= 1  # } ]
```

Single pass, no allocation, string-aware so braces inside strings don't count. This is what makes `PROTO-013` true rather than aspirational.

### Post-parse walk

One iterative (not recursive) walk over the parsed tree for array length, string length, and total field count. Use an explicit stack — a recursive walk reintroduces the recursion problem the prescan just solved.

---

## 3. The consistency check — SUPERSEDED by ADR-002, retained for the corpus

*The rules below are what the SDK enforces. Do not reimplement them; use them as the
specification for the test corpus, which must pin this behavior across SDK versions.*

The complete mirrored set, confirmed against the spec ([ADR-001](../_specs/ADR-001-transport-and-mirrored-metadata.md) §3):

```python
@dataclass(frozen=True)
class MirrorRule:
    body_path: tuple[str, ...] | tuple[tuple[str, ...], ...]   # alternatives allowed
    methods: Literal["*"] | frozenset[str]
    sentinel: bool = False        # may carry =?base64?…?=
    numeric: bool = False         # compare numerically when the schema type is integer

STANDARD: dict[str, MirrorRule] = {
    "mcp-protocol-version": MirrorRule(
        body_path=("params", "_meta", "io.modelcontextprotocol/protocolVersion"),
        methods="*"),
    "mcp-method": MirrorRule(body_path=("method",), methods="*"),
    "mcp-name": MirrorRule(
        body_path=(("params", "name"), ("params", "uri")),      # name OR uri
        methods=frozenset({"tools/call", "resources/read", "prompts/get"}),
        sentinel=True),
}
# "mcp-param-{name}" rules are derived per tool from x-mcp-header — see §3.3
```

Header **names** are case-insensitive per RFC 9110, so key the table lowercased and lowercase incoming names. Header **values** are case-sensitive — never fold them.

`Mcp-Name` mirrors `params.name` *or* `params.uri` depending on method. Resolve which by method, not by "whichever is present" — a body carrying both is itself a rejection.

### 3.1 Duplicate headers (PROTO-004)

ASGI delivers `scope["headers"]` as a list of `(bytes, bytes)` pairs, so duplicates are visible. Detect before collapsing:

```python
def collect(pairs: Sequence[tuple[str, str]], name: str) -> str | None:
    vals = [v for k, v in pairs if k.lower() == name]
    if len(vals) > 1: raise ProtocolDenial(PROTO_METADATA_DUPLICATE)   # even if equal
    return vals[0] if vals else None
```

Reject duplicates unconditionally, not only when they differ. Two equal headers have no legitimate use and permitting them invites intermediary-dependent collapsing — the exact class of divergence this unit exists to close.

### 3.2 Base64 sentinel (ADR-001 §3.2)

Applies to `Mcp-Name` and every `Mcp-Param-*`. Decode **exactly once**, then compare — the same discipline as `CANON-001`.

```python
_SENTINEL = re.compile(r"^=\?base64\?(.*)\?=$")     # markers lowercase, case-sensitive

def decode_sentinel(v: str) -> str:
    m = _SENTINEL.match(v)
    if not m: return v
    try:
        out = base64.b64decode(m.group(1), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise ProtocolDenial(PROTO_METADATA_INVALID)
    if _SENTINEL.match(out):                        # decoded value is itself a sentinel
        raise ProtocolDenial(PROTO_METADATA_INVALID)   # one pass only — never decode twice
    return out
```

`validate=True` matters: without it, `b64decode` silently discards non-alphabet characters, so two different header values can decode to the same body value. That is a bypass.

The re-sentinel rejection implements the spec's ambiguity clause from the other side. The spec requires clients to encode a plain-ASCII value that *looks* like a sentinel; a decoded result that still looks like one therefore means either a non-conforming client or an attack. Deny either way.

Corpus must cover: valid sentinel, double-encoded sentinel, sentinel with invalid base64, sentinel with non-UTF-8 bytes, uppercase `=?BASE64?` markers (must **not** be treated as a sentinel), and a literal ASCII body value of `=?base64?x?=` sent unencoded.

### 3.3 `Mcp-Param-{Name}` (ADR-001 §3.1)

Derived per tool from `x-mcp-header` annotations in the approved `inputSchema` — which means **unit 04 owns the derivation** and this unit consumes it. The guard asks the registry for the tool's mirrored-param rules and applies them exactly as it applies the standard three.

Two rules that are easy to get wrong:

- **Extract by the schema's `properties` chain, not by searching the instance.** The annotated property is statically reachable through `properties` keys only; walking the argument object looking for a matching key will find the wrong value when a nested object reuses a name.
- **Absent value → header omitted → server must not expect it.** Present in body but header omitted is a *rejection* (non-conforming client). Header present but value absent from body is also a rejection. Both need their own scenario.

Numeric comparison for integer-typed params:

```python
def compare_numeric(hv: str, bv: Any) -> bool:
    if not _INT_LITERAL.fullmatch(hv):    # ^-?(0|[1-9][0-9]*)$ — canonical only
        raise ProtocolDenial(PROTO_METADATA_INVALID)
    return isinstance(bv, int) and not isinstance(bv, bool) and int(hv) == bv
```

Narrow the accepted header form rather than broadening the comparison: `0042`, `+42`, `4_2`, `42.0`, and `4e1` are all rejected as header values, while `42` compares numerically against a body `42`. This satisfies the spec's `SHOULD` without inheriting the ambiguity that makes string-vs-numeric comparison a divergence generator.

### 3.4 Normalization (PROTO-003)

```python
def _norm(v: str) -> str:
    if v != v.strip():                 raise ProtocolDenial(PROTO_METADATA_INVALID)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
                                       raise ProtocolDenial(PROTO_METADATA_INVALID)
    return unicodedata.normalize("NFC", v)
```

Applied **after** sentinel decoding, to both sides. Case-sensitive. No percent-decoding, no unescaping — a percent-encoded header against a plain body is simply unequal, which is the correct deterministic answer.

### 3.5 Version downgrade (ADR-001 §3.4)

The spec warns intermediaries not to trust mirrored headers when the protocol version is older or absent. v1 satisfies this by denying every version except `2026-07-28` (`PROTO-008`), and the version must agree in **both** places — the `MCP-Protocol-Version` header *and* `params._meta["io.modelcontextprotocol/protocolVersion"]`.

Give it four corpus scenarios — header absent, older version, unknown version, header disagreeing with `_meta` — and report them as their own class. It is the clearest demonstration the project can make that spec-currency is a security property.

---

## 4. Building the canonical request

```python
return CanonicalRequest(
    request_id=env.request_id,
    protocol_version=pv,
    method=method,
    jsonrpc_id=body.get("id"),
    tool_name=_dig(body, ("params", "name")),
    arguments=MappingProxyType(_dig(body, ("params", "arguments")) or {}),
    body_hash=sha256_hex(env.body),
)
```

`PROTO-006` is enforced by the signature: `pipeline.handle` passes `RawEnvelope` **only** to `protocol.validate`, and every later stage takes `CanonicalRequest`. The structural test is a pyright assertion plus a grep in CI that `RawEnvelope` appears in no module after `protocol.py`.

`arguments` wrapped in `MappingProxyType` so pydantic's frozen model cannot be defeated by mutating the dict it holds.

---

## 5. Config

```toml
[protocol]
supported_versions = ["2026-07-28"]
allowed_methods = ["tools/list", "tools/call"]          # no initialize in the modern era
recognized_denied = ["server/discover", "subscriptions/listen"]   # clean modern error, not a timeout
max_depth = 32
max_body_bytes = 1048576
max_array_length = 1000
max_string_length = 65536
max_total_fields = 5000
parse_budget_ms = 100
```

---

## 6. Tests

Highest density in the project. Structure as a table-driven suite so adding a mirrored field adds rows, not files.

- **Split-authorization pair** (spec test 3): both directions. Assert `registry.resolve` and `policy.evaluate` were **never called** — `unittest.mock` spies on `Deps`, not just an assertion on the outcome. A denial that happened *after* policy would pass an outcome-only assertion and violate `PROTO-002`.
- **Boundary triples** for each of the six limits: `n-1` passes, `n` passes, `n+1` denies.
- **Pathological payloads**: `b"[" * 10_000`, a 10 MiB string, 100k-element array, 50k duplicate keys. Assert denial within `parse_budget_ms` and that RSS does not grow by more than a small multiple of the input.
- **Hypothesis**: `st.recursive` JSON generator + a metadata strategy that emits matching and mismatching pairs. Invariant — *if* `validate` returns, then `result.method == metadata["Mcp-Method"]` and `result.tool_name == metadata.get("Mcp-Name")` whenever those keys are present. This is the property that makes `PROTO-006` machine-checked rather than reviewed.

---

## 7. Gotchas

- Depth prescan must be string-aware or `{"a": "{{{{"}` false-positives. The escape-handling in §2 is load-bearing.
- `-0.0`, very large integers, and `1e400` (→ `inf`) survive `json.loads`. `allow_nan=False` only guards the *encode* side; validate numeric arguments at unit 04's schema step, not here.
- Unicode: normalize with NFC once, consistently, in `_norm` and nowhere else. Two normalization sites will eventually disagree.
- Do not add a "lenient mode" for debugging. It will end up enabled somewhere.

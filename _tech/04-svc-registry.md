# TECH-04 — `svc-registry`

**Pairs with:** [`_specs/04-svc-registry.md`](../_specs/04-svc-registry.md)
**Module:** `gateway/registry.py`

---

## 1. Shape

Load once at startup into a frozen structure; per-request work is dict lookups plus a `jsonschema` validation. No database, no cache invalidation, no hot reload — restart is the reload mechanism.

```python
class Registry:
    servers: Mapping[str, ServerEntry]
    _drift: dict[str, str]  # tool_name -> reason; populated at handshake, then read-only

    def resolve(self, req, ctx) -> ResolvedTarget: ...
    def visible_tools(self, ctx) -> list[Tool]: ...  # REG-010
```

`_drift` is the only mutable state, written exactly once during the upstream handshake and never after. Guard that with a `_sealed` flag rather than trusting call order.

---

## 2. Registry file

TOML, loaded with `tomllib`, validated into pydantic with `extra="forbid"`.

```toml
[[server]]
id = "filesystem-fixture"
transport = "stdio"
executable = "/abs/path/to/python"
args = ["-m", "fixtures.filesystem_server"]
cwd = "/abs/path/to/fixture"
env_allowlist = ["PATH"]
expected_protocol_version = "2026-07-28"
state = "enabled"              # enabled | quarantined | disabled
owner = "akshay"
review_date = "2026-08-08"

  [[server.tool]]
  name = "read_file"
  risk_tier = "R1"
  operation = "read"
  enabled = true
  schema_fingerprint = "v1:sha256:…"
  approved_for = "Read a single file inside an approved root"
  input_schema = """
  {"type":"object","additionalProperties":false,
   "required":["path"],
   "properties":{"path":{"type":"string","maxLength":4096}}}
  """
```

`input_schema` as a TOML multi-line string containing JSON — the schema is JSON Schema, so keeping it as JSON avoids a lossy TOML→JSON-Schema translation and keeps it copy-pasteable from the upstream's `tools/list` output.

`executable`/`args`/`cwd` live here and unit 01 reads them from here (`BRIDGE-007`, `REG-002`). There is no other source.

---

## 3. Fingerprinting (REG-005)

```python
def fingerprint(tool: dict) -> str:
    normalized = {
        "name": tool["name"],
        "description": tool.get("description") or "",
        "inputSchema": tool.get("inputSchema") or {},
        "outputSchema": tool.get("outputSchema") or {},
        "annotations": tool.get("annotations") or {},
    }
    return "v1:" + hash_obj(normalized)  # canonical_json: sorted keys, tight separators
```

Rules that make this stable and non-surprising:

- **Null collapses to absent. Present-and-empty does NOT.** ~~Absent and null collapse to a typed empty (`""`, `{}`).~~ The justification for collapsing was only ever the null case: an upstream that starts emitting `"description": null` where it previously omitted the key must not produce a spurious drift event. Substituting a typed empty went further and made an *absent* `outputSchema` hash identically to a *present empty* one, so an upstream could add or remove `"outputSchema": {}` undetected — while REG-005 says to fingerprint the output schema **where present**, making presence part of what is pinned. Corrected during unit 04's review; the key is simply omitted when the value is absent or null, and included otherwise.
- `hash_obj` uses `sort_keys=True`, so key order is irrelevant — spec test 5.
- The `"v1:"` prefix is the normalization version. Changing the rule bumps it, and every stored fingerprint must be regenerated deliberately.
- **Include `annotations`.** They must not influence decisions (`REG-008`), but they must be fingerprinted — that is what makes the poisoned-annotation demo (spec test 4) fire.

### Regeneration workflow

Provide `scripts/fingerprint_tools.py`: connect to the upstream, dump `tools/list`, print the TOML block. Approving a change is then an explicit paste-and-review, which is the intended friction. Never auto-update the registry from the upstream — that would make drift detection self-defeating.

---

## 4. Drift detection (REG-006, REG-009)

Runs once, at handshake, in the startup sequence after the child is initialized and **before** readiness:

```python
async def verify_schemas(self, session: ClientSession) -> None:
    advertised = {t.name: t for t in (await session.list_tools()).tools}
    for name, approved in self.tools.items():
        adv = advertised.get(name)
        if adv is None:
            self._drift[name] = ReasonCode.REG_TOOL_UNKNOWN
            continue
        if fingerprint(adv.model_dump()) != approved.schema_fingerprint:
            self._drift[name] = ReasonCode.REG_SCHEMA_DRIFT
    for name in advertised.keys() - self.tools.keys():
        audit_event(
            "tool_advertised_not_approved", tool=name
        )  # not an error; just denied
    self._sealed = True
```

Drift quarantines the tool; it does **not** prevent startup. A quarantined tool disappears from `tools/list` and denies on `tools/call`, which is the behavior spec test 3 asserts. An unverified tool (`_sealed` false) denies with `REG_SCHEMA_UNVERIFIED`.

Drift events are written to the audit stream with `event_type="drift"` rather than `"request"` — same file, discriminated union, so `jq 'select(.event_type=="drift")'` finds them.

---

## 5. Argument validation (REG-012 … 014)

`jsonschema`, compiled once at startup:

```python
from jsonschema import Draft202012Validator

self._validators = {
    name: Draft202012Validator(json.loads(t.input_schema))
    for name, t in self.tools.items()
}
```

Compile at load so a malformed schema fails startup rather than the first request. Use `iter_errors` and deny on the first — do not aggregate; error detail is diagnostic-only anyway (`CONV-009`).

**`additionalProperties: false` is mandatory at EVERY object-valued schema position, not just the root** (`REG-013`). Checking only the root lets `{"opts": {"type": "object"}}` through, and `{"opts": {"sudo": true}}` then validates — attacker keys inside an approved argument. `registry._first_open_object` walks `properties`, `patternProperties`, `$defs`, `allOf`/`anyOf`/`oneOf`/`prefixItems`, and `items`/`not`/`if`/`then`/`else`/`contains`, and returns the offending path so the startup error names it. Enforce at load rather than trusting authors:

```python
@field_validator("input_schema")
def _must_be_closed(cls, v):
    s = json.loads(v)
    if s.get("additionalProperties") is not False:
        raise ValueError("approved schemas must set additionalProperties: false")
    return v
```

That converts `REG_ARGS_UNKNOWN_FIELD` from a hand-written check into a schema property, and makes the requirement unforgettable.

Validate against the **stored** schema, never the advertised one (`REG-014`) — the validators map is built from registry data and never touches the session.

---

## 6. `tools/list` filtering (REG-010, REG-011)

The divergence bug is structural, so eliminate it structurally: both paths call the same predicate.

```python
def _callable(self, ctx: AuthzContext, tool: ToolEntry) -> bool:
    return (
        tool.enabled
        and tool.name not in self._drift
        and self.server.state == "enabled"
        and policy.could_ever_allow(ctx, tool)
    )  # cached, see below
```

`could_ever_allow` is a **separate Rego entrypoint** (`data.gateway.discoverable`) that takes principal + roles + tool but no resource — "is there any resource for which this principal could call this tool?". Evaluated once per (principal, tool) at startup and cached, because it depends only on config-fixed inputs.

Do not approximate this by calling the main `allow` rule with a placeholder path; a placeholder that happens to be denied would hide a tool the principal can legitimately use, and a placeholder that happens to be allowed would reveal one they cannot.

Spec test 6 asserts the omitted set equals the universally-denied set — implement it by iterating every tool × every fixture path through the real `allow` rule and comparing against `visible_tools`.

---

## 7. Config and startup

Startup order inside `registry.load()`:

1. Parse TOML → pydantic (`extra="forbid"`).
2. Assert exactly one server in v1; more is a config error, not a feature.
3. Compile all JSON Schema validators.
4. Assert every schema is closed.
5. Assert every `risk_tier` is in `{R0,R1,R2,R4}` — `R3` must fail loudly (`CONV-007`).
6. Return frozen.

Steps 4–5 are cheap and catch the two config mistakes most likely to silently weaken policy.

---

## 8. Tests

| Spec test | Notes |
|---|---|
| 3 — drift | Fixture in `drift` mode (`FIX-010`) changes a description; restart; assert quarantine + absence from `tools/list` |
| 4 — poisoned annotation | Fixture advertises `{"readOnlyHint": true}` on `delete_file`; assert `risk_tier` unchanged **and** drift fires |
| 5 — fingerprint stability | Property test: shuffle dict keys, reserialize with varied whitespace → identical fingerprint; flip one character → different |
| 7 — validation before policy | Spy on the OPA client; assert zero calls |
| 10 — unknown key | `[[server]] bogus = 1` → startup raises |
| 11 — no launch-param injection | Hypothesis over argument values containing paths/executables; assert child argv equals the configured argv exactly, every time |

---

## 9. Gotchas

- `Draft202012Validator` and MCP's declared JSON Schema dialect must match; check what the SDK's `Tool.inputSchema` actually declares before pinning the draft.
- `jsonschema` format assertions are **off** by default. Do not turn them on for `uri`/`hostname` — format checking pulls optional dependencies and is not a security control. Bound strings with `maxLength` instead.
- TOML has no `null`. Absent means absent; encode "explicitly empty" as `""` or `{}` to keep fingerprinting stable (§3).
- A tool advertised by the upstream but absent from the registry is denied and logged, never auto-registered. Say so in the README — reviewers ask.

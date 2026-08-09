# TECH-03 — `svc-identity-resolver`

**Pairs with:** [`_specs/03-svc-identity-resolver.md`](../_specs/03-svc-identity-resolver.md)
**Module:** `gateway/identity.py`

---

## 1. Shape

The smallest module in the gateway — a pure function over config. Its value is in what it refuses to do, and most of that refusal is enforced by types rather than code.

```python
def resolve(req: CanonicalRequest, cfg: IdentityConfig) -> AuthzContext:
    return cfg.context  # prebuilt at startup, frozen, one per process
```

Config validation happens at startup; per-request work is returning a frozen object. Do not add caching, lookup, or a resolver interface — there is exactly one identity per gateway process in v1.

---

## 2. Why it is a whole module

The `AuthzContext` construction is trivial. The *type* is the deliverable:

```python
auth_method: Literal["local_config"]
assurance: Literal["unverified_local"]
```

`IDENT-002` says the gateway must never claim verified identity. A convention would be forgotten in six months; a `Literal` with one member means overstating identity requires editing `types.py`, which shows up in review, and pyright fails the build in the meantime. **That is the entire design.**

When OIDC eventually lands, widening these literals is a deliberate, visible change — and the audit schema version bumps with it (`AUDIT-013`).

---

## 3. Config

```toml
[identity]
principal   = "developer"
client_id   = "test-driver"
roles       = ["developer"]
environment = "development"

[identity.role_vocabulary]
known = ["intern", "developer", "auditor"]
```

Startup validation (`IDENT-001`, and `IDENT-005`'s prerequisite):

```python
@model_validator(mode="after")
def _check(self):
    if not self.principal or not self.client_id:
        raise ValueError("identity.principal and identity.client_id are required")
    unknown = set(self.roles) - set(self.role_vocabulary.known)
    if unknown:
        raise ValueError(f"unknown roles: {sorted(unknown)}")
    return self
```

A `ValueError` here propagates as a startup failure, not a runtime denial — the spec's failure table deliberately has no runtime auth failure, because `stdio` identity either exists at boot or the process should not run.

The role vocabulary is closed and duplicated in Rego (`data.roles`). Keep the two in sync with a test that loads both and compares sets — a role that exists in config but not in policy silently denies everything for that principal, which is a confusing failure to debug.

---

## 4. Multi-principal testing

The gateway process holds one identity, but the corpus needs three (`06-svc-policy-broker.md` §6). Do not add multi-tenancy to satisfy this — launch a gateway instance per principal in the test harness:

```python
@pytest.fixture(params=["intern", "developer", "auditor"])
def gateway(request, tmp_path):
    cfg = base_config(principal=request.param, roles=[request.param])
    yield start_gateway(cfg)
```

This mirrors reality: each MCP client launcher configuration is its own gateway process with its own identity. It is also what makes spec test 6 (different principals → different decisions) a genuine end-to-end assertion rather than a mocked context swap.

---

## 5. Ignoring client-supplied identity (IDENT-003)

There is no code to write — `resolve()` never reads `req`. The parameter exists for signature uniformity across pipeline stages.

The test is what matters, and it should be property-based rather than a handful of examples:

```python
@given(
    st.dictionaries(
        st.sampled_from(
            [
                "principal",
                "user",
                "role",
                "roles",
                "client_id",
                "sub",
                "assurance",
                "auth_method",
                "_meta",
            ]
        ),
        st.text(),
    )
)
def test_client_cannot_influence_identity(poison):
    req = make_request(arguments=poison)
    assert identity.resolve(req, cfg) == cfg.context
```

Also run the same key set through `RawEnvelope.metadata` — a mirrored-header-shaped `Mcp-Principal` must be ignored by identity even if a future spec revision adds one.

---

## 6. Suite-wide invariant

Register in `conftest.py` as autouse, not as a single test (`00-conventions` §9):

```python
def pytest_sessionfinish(session):
    for event in read_all_audit_events():
        assert event["auth_method"] == "local_config"
        assert event["assurance"] == "unverified_local"
```

This is spec test 2. It must scan **every** record emitted by the whole session, because the failure it guards against is a single code path in some other module inventing a value.

---

## 7. Documentation obligation (IDENT-007)

`IDENT-007` requires the bypass limitation to appear in `README.md` and `docs/threat-model.md`, not only in a spec. Add a CI check that greps both files for the sentence and fails if it is missing — a documentation requirement without a test decays like any other.

Wording to use verbatim:

> A local `stdio` client that is separately configured with direct access to the protected MCP server bypasses this gateway entirely. The gateway cannot detect or prevent that configuration. Removing every direct client-to-server route is a deployment responsibility.

---

## 8. Gotchas

- Resist a `Principal` abstraction, an `IdentityProvider` protocol, or a resolver registry. One implementation, one config object. The deferred register already records the OIDC trigger.
- `AuthzContext.roles` is a `tuple`, not a `list` — pydantic frozen models do not deep-freeze list fields, and a mutable role list is an escalation primitive.
- When OIDC lands, the new assurance value must be a *new* literal member, and every policy rule that cares must be updated deliberately. Do not use a boolean `authenticated` flag; a two-state boolean is how "unverified local" silently becomes "authenticated".

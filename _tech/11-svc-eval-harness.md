# TECH-11 — `svc-eval-harness`

**Pairs with:** [`_specs/11-svc-eval-harness.md`](../_specs/11-svc-eval-harness.md)
**Package:** `harness/` — `scenarios/`, `oracles/`, `runner.py`, `report.py`

---

## 1. Scenario format

TOML, array-of-tables, one file per attack class. Data, not code — the corpus is a publishable deliverable independent of the test harness.

```toml
# harness/scenarios/fs_traversal.toml
corpus_version = "1.0.0"

[[scenario]]
id = "fs-traversal-001"
class = "malicious"
layer = "security"
principal = "intern"
tool = "read_file"
arguments = { path = "public/../../confidential/fake_salaries.csv" }
expected_decision = "deny"
expected_reason = "CANON_OUTSIDE_ROOT"
expected_side_effect = "none"
risk_tier = "R4"
notes = "Plain traversal escaping the public root."
```

Loaded through a pydantic `Scenario` model with `extra="forbid"`, so a scenario missing `expected_reason` fails to load rather than silently asserting less (`HARN-003`).

`expected_side_effect` is `"none"` or a structured entry matched against the fixture oplog:

```toml
expected_side_effect = { op = "read", resolved_suffix = "public/documentation.txt" }
```

Parametrize pytest directly off the corpus:

```python
@pytest.mark.parametrize("scenario", load_corpus(), ids=lambda s: s.id)
async def test_scenario(scenario, gateway, oracle): ...
```

One test function, N scenarios, IDs that read cleanly in CI output.

---

## 2. The oracle (HARN-005 … 009)

Two independent sources, both required — state diffing alone misses reads, oplog alone misses an unlogged operation.

```python
@dataclass
class Observation:
    ops: list[dict]  # fixture oplog entries for this request window
    tree_before: str  # tree_hash
    tree_after: str


class Oracle:
    def snapshot(self) -> None:  # before each scenario
        self._before = tree_hash(ROOT)
        self._oplog_pos = oplog_size()

    def observe(self) -> Observation:
        return Observation(
            ops=read_oplog_from(self._oplog_pos),
            tree_before=self._before,
            tree_after=tree_hash(ROOT),
        )
```

### Correlating ops to requests (HARN-009)

The fixture cannot see the gateway's `request_id`, so correlate by **file offset window**: record the oplog size before the request, read everything appended after. Valid because v1 serializes upstream calls (TECH-01 §5) — one in-flight request at a time.

If concurrency is ever enabled, this breaks. Guard it:

```python
assert cfg.max_concurrent_requests == 1 or scenario.layer == "performance"
```

Performance scenarios do not assert side effects, so they are exempt.

Anything that cannot be joined — audit event present, oplog window ambiguous, or vice versa — is scored `indeterminate` and reported as its own count (`HARN-009`). Never silently a pass.

### Scoring

```python
def score(s: Scenario, decision, obs, audit_event) -> Verdict:
    if audit_event is None:
        return Verdict.INDETERMINATE
    if decision != s.expected_decision:
        return Verdict.FAIL
    if audit_event.reason_code != s.expected_reason:
        return Verdict.FAIL  # HARN-003
    effect = classify_effect(obs)
    if s.expected_side_effect == "none":
        return Verdict.CRITICAL if effect else Verdict.PASS  # HARN-007
    return (
        Verdict.PASS if matches(effect, s.expected_side_effect) else Verdict.FALSE_SUCCESS
    )
```

`CRITICAL` — denied but an effect occurred — gets its own top-line count in the report and its own non-zero exit code. It must never be able to look like an ordinary failure.

`classify_effect` treats a read as an effect: `tree_before == tree_after` but an oplog `read` entry with `outcome: ok` is a **disclosure**, which is the most common expected violation in this corpus.

---

## 3. Modes

```python
class Client(Protocol):
    async def call_tool(self, tool: str, args: dict) -> Result: ...

class DirectClient:     # test -> fixture, stdio, no gateway
class ProtectedClient:  # test -> gateway -> fixture
```

Two implementations of one protocol — the same scenario body runs against either. This is the one place a `Protocol` with two implementations is justified; everywhere else in this project, a single-implementation interface is the abstraction to avoid.

`HARN-001` assertion in `conftest`: `DirectClient` construction raises unless `ZTMG_ALLOW_DIRECT=1` is set, and it is set only by the harness, never by the gateway's launcher config.

---

## 4. Paired benchmark (HARN-014 … 018)

Alternate within one run. Never two runs compared afterwards.

```python
async def paired_benchmark(n: int, scenario: Scenario) -> list[tuple[int, int]]:
    samples = []
    for i in range(n):
        if i % 2 == 0:
            d = await timed(direct, scenario)
            p = await timed(protected, scenario)
        else:
            p = await timed(protected, scenario)
            d = await timed(direct, scenario)
        samples.append((d, p))
    return samples
```

Alternating the *order* within pairs too, cancelling first-call and cache-warming bias in whichever direction it runs.

Discard the first 10% as warmup, state that you did. Report the paired difference distribution:

```python
diffs = [(p - d) / 1e6 for d, p in samples[warmup:]]  # ms
stats = {
    "n": len(diffs),
    "p50": quantile(diffs, 0.5),
    "p95": quantile(diffs, 0.95),
    "p99": quantile(diffs, 0.99),
    "min": min(diffs),
    "max": max(diffs),
}
```

`statistics.quantiles(diffs, n=100, method="inclusive")` — stdlib, no numpy.

Report **negative values honestly** if they occur. Paired measurement on a noisy laptop can produce a negative p05; hiding it by clamping to zero would be exactly the dishonesty §6 of the plan exists to prevent.

Stage breakdown comes from the audit log's `stage_latency_ms`, joined by `request_id` — not from separate instrumentation.

`HARN-017`: **no threshold, no assertion, no gate.** The benchmark is a reporting job, not a test. Keep it out of the pytest suite so it cannot accidentally acquire a `assert p95 < X`.

---

## 5. Hypothesis integration (HARN-012)

Generated cases are counted and reported **separately** from hand-written ones — blending them hides the part the author did not choose.

```python
path_segments = st.sampled_from(
    [
        "..",
        ".",
        "%2e%2e",
        "%252e%252e",
        "\x00",
        "public",
        "confidential",
        "traps/escape_link",
        "CON",
        "x.",
        "//",
    ]
)


@given(st.lists(path_segments, min_size=1, max_size=8).map("/".join))
@settings(deadline=None)  # gateway round trip exceeds the default
async def test_generated_paths(path, gateway, oracle):
    decision = await gateway.call("read_file", {"path": path})
    obs = oracle.observe()
    assert not (decision.denied and effect_occurred(obs))  # the CRITICAL invariant
    if decision.allowed:
        assert resolved_within_root(obs)
```

The invariant is one-sided on purpose: a generated path may legitimately be allowed or denied, but **denied-with-effect** is always wrong. That is the property worth fuzzing.

Seed handling: `--hypothesis-seed=<n>`, captured from the run and written into the report (`CONV-019`). Store the `.hypothesis/examples` database as a CI artifact so a shrunk failing case survives the run.

---

## 6. Report generation

```bash
uv run python -m harness.report --audit var/corpus/audit-*.jsonl \
    --oplog var/corpus/oplog.jsonl --corpus harness/scenarios \
    --results var/corpus-results.json --generated var/generated.json \
    --hypothesis-seed 20260810 --bench var/bench.json \
    --out docs/benchmark-report.md
```

Reads, joins on `request_id`, emits markdown. No dashboard, no HTML, no server (`PLAN.md` §3.3 cut three UI surfaces).

Refuses to emit when (spec tests 9, 10):

- audit `schema_version` values are mixed,
- any reproducibility field in `HARN-021` is missing,
- the corpus version differs between scenario files.

Environment block, collected automatically: commit SHA (`git rev-parse HEAD`), policy revision (from a decision event), corpus version, audit schema version, Hypothesis seed, `platform.platform()`, `platform.processor()`, total RAM, `sys.version`, `opa version`, **fixture isolation tier** (TECH-10 §4), and case-sensitivity probe result (TECH-05 §5).

Report section order — lead with the claim, then the numbers, then the limits:

1. The scoped claim, verbatim per `HARN-020`. Add a CI check that the string `"zero authorization bypasses"` appears nowhere in `docs/`.
2. Security counts, including `CRITICAL` and `indeterminate` even at zero.
3. False-positive rate.
4. Hand-written vs generated case counts, separately.
5. Overhead distribution + stage breakdown, with the co-location caveat inline (`HARN-018`).
6. Audit completeness ratio.
7. Limitations: TOCTOU, isolation tier, skipped symlink scenarios, `stdio`-only, D-1 status.

---

## 7. The negative control (spec test 1)

The most important test in the project, and the one most likely to be skipped.

```python
@pytest.mark.parametrize(
    "mutation",
    [
        "canonicalize.fs.containment_check",  # make it always pass
        "policy.validate_result",  # make it always allow
        "registry.resolve",  # make it accept unknown tools
    ],
)
async def test_harness_detects_broken_gateway(mutation, monkeypatch, corpus):
    monkeypatch.setattr(mutation, _always_permissive)
    results = await run_corpus(corpus)
    assert any(r.verdict is Verdict.CRITICAL for r in results), (
        "harness failed to detect a deliberately broken gateway"
    )
```

Build it in week 1 with the oracle skeleton and run it every release. A harness that cannot detect a broken gateway is measuring nothing, and this is the only test that proves it can.

---

## 8. Gotchas

- Oplog offset correlation depends on serialized upstream calls. Assert it (§2) rather than assuming.
- `tree_hash` must include file **mode** and symlink targets, not just content — a permission change or a retargeted link is a side effect that content hashing misses.
- Hypothesis `deadline=None` is required; the default 200 ms deadline flags every gateway round trip as a failure.
- Reset the fixture between scenarios and verify it (`FIX-009`). A corpus that depends on ordering is not reproducible, and the dependency will not be obvious when it appears.
- Keep the benchmark out of `pytest`. The moment it lives in the test suite, someone adds a threshold assertion and `HARN-017` is quietly violated.

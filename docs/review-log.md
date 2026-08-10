# Review log

What each `/unit-review` gate found. **Append-only** — entries are not rewritten when
a later unit changes the code they describe, because the point of this file is the
pattern across rounds, not the current state of the tree. Current state is `PLAN.md`
§4.2; measured evidence numbers are `var/evidence.md`.

This file exists because that narrative used to live inside the §4.2 build-order
table, where it grew to three times the length of the table it was annotating and
made the actual status column unscannable.

**The pattern, stated once.** Every round on this project has found the same class of
defect: safety and failure-path problems sitting behind a working happy path. Within
that, two shapes recur often enough to be worth checking for by name:

- **A record that contradicts what happened** — the audit says one thing, the client
  is told another, and both are written by code that was individually correct.
- **A limit that is audited but not enforced** — the number is measured, recorded,
  and then never compared to anything that can refuse.

Point the reviewer at those two first.

---

## Units 01, 09, 10 — the first rounds

Each was called complete, then reviewed, and the review found failure-path defects in
every case. This is the origin of the project's rule that a unit is done when its
failure paths are proved, not when its happy path runs.

Carried over: orphan reaping, tracked where it will be fixed rather than in `PLAN.md`
— it depends on the child honouring stdin EOF rather than on OS-level process groups
(`tests/unit/test_orphan_reaping.py`).

## Unit 07 — first cut

Three defects, two of them authorization bypasses that the missing tests are precisely
what would have caught.

1. **The authorized path was not the forwarded path.** `%77orkspace/f.txt` resolved
   and authorized as `workspace/f.txt`, then went upstream still encoded — ROUTE-004
   violated, and not the documented TOCTOU window but a deterministic divergence.
   Unit 05 now derives `relative_path` and unit 07 substitutes it.
2. **A decision was bound only to the request id.** A `write_file` decision was
   accepted for `append_file` with matching arguments. `Decision` now carries `method`
   and `tool_name` and the router compares both.
3. **The record disagreed with the response on a timeout.** The edge's deadline
   reached the pipeline as an anonymous anyio cancellation, so the audit said
   `cancelled` while the client was told `ROUTE_TIMEOUT`. The request deadline moved
   into `pipeline.handle`; the edge keeps a deliberately slower backstop.

## Unit 08

Six defects. The pattern in four of them: **a test that stops short of the boundary it
claims to cover proves nothing about that boundary.**

1. **Successful HTTP replies were not JSON-RPC.** The edge wrote the bare MCP result —
   no `jsonrpc`, no `id`, no `result` — so no conforming client could correlate a
   reply. Denials were framed correctly, which is what hid it. Unit 08 now builds the
   response envelope.
2. **The end-to-end tests called `pipeline.handle` directly**, which is why they
   missed it. There is now a test through the real ASGI edge, and client-facing claims
   belong at that level from here on.
3. **The live `pathological` mode never reached unit 08.** `MCPServer` refused to
   serialize the 2,000-deep result and the gateway got a 302-byte `isError` instead.
   Moved to wire level, into `_meta` — the only slot measured to survive both the
   SDK's typed content models and the tool's output schema.
4. **Every `RESP_*` failure was audited as `denied`.** An upstream misbehaving after
   policy allowed the call is an error; recording it as a denial would have inflated
   the exact figure `PLAN.md` §6.2 exists to publish honestly.
5. **`RESP_TOO_LARGE` was unreachable.** Unit 07 measured the identical number against
   the identical limit one stage earlier. Two checks of one quantity at one moment are
   not two layers, so the earlier one and `ROUTE_RESPONSE_TOO_LARGE` were removed.
6. **The shared walk was one level stricter than the byte prescan**, so a document at
   exactly `max_depth` passed the scan and was rejected after parsing. Only containers
   count now, as the prescan counts them, and a test pins the two together.

Result: 26 unit + 4 integration tests, 15/15 then 7/7 breaks caught.

## Unit 07 — full gate

The first unit to go through every step, and the argument against shipping a unit
without its tests.

**Break pass.** Fourteen guards reverted one at a time, each requiring its named test
to fail. Twelve did. Two had no test at all: the `max_response_bytes` half of the
ROUTE-005 clamp (`test_4` covered only the timeout), and `forward`'s refusal of a
tool-less `tools/call`. Both now have one; the re-run is 14/14.

**Adversarial round.** Three real defects, each verified against source before being
accepted, each now carrying a regression test seen to fail without its fix:

1. **The request deadline was audited as a client cancellation.** `pipeline.handle`'s
   `move_on_after` reaches `router._bounded` as a bare anyio cancellation, which
   records `cancelled`; the pipeline then raised `ROUTE_TIMEOUT`. One event said the
   clock ran out and the client left at the same time — the exact pair ROUTE-010
   exists to separate. Only the scope that owns the deadline can tell them apart, so
   it now corrects the attribution before setting the reason code.
2. **The clamped response ceiling never reached unit 08.** Unit 07 clamped the
   obligation and audited the clamped value; `pipeline.handle` then handed unit 08
   `dec.obligations` — what policy *asked for*. A decision above
   `RouterConfig.max_response_bytes` produced an oversized response accepted under a
   record claiming the lower limit had been enforced. The effective obligations now
   ride on `RawResult` and `response.validate` no longer takes them as a parameter, so
   passing the wrong number is unrepresentable rather than merely unlikely.
3. **ROUTE-006 still normatively demanded a streaming abort** in the requirement text
   and named a deleted reason code in the failure table, after §9 had already been
   corrected. A source of truth that claims a defence the code cannot provide is worse
   than a missing one.

**A fourth finding was overstated and partly wrong** — that nothing binds
`canonical_path` to `relative_path` at runtime. The two are produced by one function
from one resolution, and the child's base is already held equal by
`test_shipped_config.py`. The fair half stood: the ROUTE-004 tests proved
*substitution*, not *equivalence*, because they supplied a consistent
`DerivedAttributes` themselves. The invariant is now asserted where the pair is made,
against the real canonicalizer.

Two of the three are the recurring shapes named at the top of this file. Neither was
reachable by any test that existed.

## Unit 11a — `ProtectedClient`

Closed the loop the project exists to measure. The corpus had only ever been scored
undefended; there was no number for the defended side because the client that produces
it was the last stub in the codebase. Three things it forced, each recorded because
none was anticipated:

1. **Identity cannot ride on a request**, so `protected` runs **one gateway per
   principal** and dispatches on `scenario.principal`. `identity.resolve` never reads
   the request (IDENT-003, held by an AST test). Deliberately breaking the dispatch
   produced three CRITICAL verdicts and two FAILs, so the harness detects its absence
   rather than quietly scoring intern rows under someone else's grants.
2. **The corpus goes over a real socket**, never `pipeline.handle` and never the ASGI
   callable directly. Both shortcuts have already hidden a defect here: the first hid
   an unframed success reply for weeks, and the second would skip the HTTP parser,
   which `Transport.http_fate` records as a scored participant.
3. **`max_concurrent_requests` must be 1** for a scored run. `assert_serialised`
   refused to start otherwise — oracle correlation is by byte offset into one
   operation log, and two in-flight calls interleave it. Caught by the guard on the
   first attempt, which is the outcome that guard was written for.

`TRANSPORT_REJECTED` is reported instead of the row's own `expected_reason` when h11
refuses a request, and it is kept distinct from `NO_RESPONSE`: a crashed gateway also
returns no JSON, and collapsing the two would let exactly the rows that depend on a
transport refusal go green for the one reason they must never go green for.

## Loop review — 2026-08-10

Not a unit gate. The question asked was why the corpus work was slow and whether the
gate itself had been over-built. Measured rather than estimated, and the answer was
that the gate's *detecting* stages earn their cost while its *bookkeeping* stages had
started to cost more than they returned.

**The gate found nothing wrong with itself; the measurement did.** Two tests in
`test_wire_modes.py` were the two slowest in the suite by 4×, at 60.3s and 60.2s.
There is no 60-second value in any config — it was the tests' own
`anyio.fail_after(60)`. Setting it to 5 made them pass in 5.2s, which is the whole
proof: they were measuring their own deadline.

The mechanism: `up.call_tool` is unbounded, so the corrupted response never produced a
denial. The test's deadline cancelled the task, `bridge.upstream`'s
`except BaseException` relabelled that cancellation as `ROUTE_UPSTREAM_UNAVAILABLE`,
and the assertion — a permissive tuple accepting that code *or* `ROUTE_TIMEOUT` — took
it. They would have passed identically against a gateway that does nothing.

They now drive `router.forward`, which is what actually owns the deadline, and assert
`ROUTE_TIMEOUT` exactly, plus an `elapsed` bound so a denial produced by the outer
guard can never satisfy them again. Break-verified by removing `_bounded`'s
`move_on_after`: both fail. 120s → 6.4s.

**A wrong assumption, corrected by measurement.** The first version of the new
assertion expected `malformed` to kill the session and fail fast, and only `wrong_id`
to reach the timeout. It fails. The SDK discards an unparseable line exactly as
silently as a mis-correlated one — `ValidationError` inside its reader, no message
delivered, session still up. **`ROUTE_TIMEOUT` is the single load-bearing defence
against every form of corrupted upstream line**, which is a sharper claim than the one
the test was written to make.

Why the gate missed it: the break pass is scoped to the unit under review, and this
test belongs to unit 01. Nothing re-breaks a guard once its unit is closed. Step 2 of
the gate now covers guards the current unit *depends on*, not only ones it added.

**Where the four hours actually went — not the corpus.** The complaint was that unit
11b was slow. Measured, the full 118-row protected run is **51 s** (27.5 s booting 14
deployments, 23.7 s scoring). Per-scenario fixture reset and tree hashing total 4 s
across all 118. The four hours was `run_generated --profile release`: 5,000 examples
across five families, **25,000 cases**, which had already hit a two-hour local timeout
and is correctly not claimed in the README. Sampling the corpus was never going to fix
a generator run, and would have been the wrong lever pulled confidently.

**What changed anyway.** A 50-row `smoke` profile is now the default for `run_corpus`,
chosen coverage-greedily over `(layer, expected_reason, fixture_mode, gateway_fault)`
in id order — deterministic, covering all 35 reason codes, all 11 fixture modes and all
3 principals, with the leftover budget spent on legitimate rows so a gateway that
refused everything could not look healthy in the fast lane. It cannot become evidence:
the profile is written into the artifact and `harness.report` refuses anything but
`full`, *including a missing profile* — artifacts predating the lane are
indistinguishable from a subset, and defaulting the unknown to permissive is exactly
how a 50-row score reaches a published table.

Two holes opened by that change and closed in the same pass. `--only` against the
default subset matched nothing, and zero scenarios resolve to zero failures through
every exit-code path — a green run that scored nothing. It now errors, and says how
many rows would have matched in the full corpus. And `harness.scenario` now validates
`expected_reason` against `ReasonCode` at load: previously a typo surfaced minutes into
a scored run, in whichever of the three modes happened to reach that row.

**The fast lane was a lie worth 12 seconds.** `-m "not slow"` is what this gate tells
you to iterate on, and the marker had been applied by hand to five tests out of 751, so
it deselected almost nothing. It is now automatic for everything under
`tests/integration/`, plus explicit on the expensive unit tests. Fast lane **2 m 50 s →
43 s**; full suite **3 m 02 s → 2 m 29 s**.

**One flaky test, fixed for the same reason.** `test_no_child_process_survives_teardown`
counted every `python.exe` on the machine on Windows while counting only
`fixtures.filesystem_server` on POSIX. A second pytest session was enough to fail it.
Both branches now count fixture children; verified sensitive (an extra child raises the
count) and recovering (it drops again). A test that fails for something other than the
behaviour it names costs a cycle every time it fires and teaches people to re-run
rather than read.

## Unit 11b — full harness, benchmark, and report

**Break pass.** Twelve independent mutations were introduced and restored one at a
time. All 12 were caught: prohibited effect, wrong reason, missing audit join, false
success, broken pair alternation, wrong warmup, mixed audit schema, equal-count but
wrong audit ids, generated deny-after-effect, a 504 treated as a valid denial,
under-counted audit cost, and report-side benchmark reordering.

**Adversarial round.** The companion review returned five findings. The titles are
retained verbatim; all five were real and fixed with regression coverage:

1. **Expected effects hide additional unauthorized operations.** Effect-bearing rows
   now require exactly one matching successful operation; extra, retried, or wrong
   effects are CRITICAL, while incomplete extra operations are INDETERMINATE.
2. **Report completeness is controlled by the artifact being certified.** The report
   now derives audit expectations from the corpus, requires exact request-id sets,
   compares raw audit reasons, binds raw op-log records to observed `pid:seq` evidence,
   and rejects artifacts whose deterministic source fingerprint is stale.
3. **Negative control bypasses the real gateway and evidence pipeline.** The control
   now starts a real OPA sidecar with an intentionally allow-all Rego decision and
   runs through HTTP, gateway, child, audit, and oracle. The full corpus detects 13
   CRITICAL effects.
4. **Mismatched JSON-RPC error IDs are accepted as valid denials.** Error ids must now
   equal the sent request id, and post-parse edge denials echo the client id.
5. **Benchmark silently publishes direct-path failures as latency samples.** Both
   direct and protected operations must now succeed with an allow decision before a
   pair can enter the latency distribution.

The review also suggested replacing the scenario schema's explicit `path_contains`
matcher with exact paths. That was not adopted: substring matching is a published
scenario authoring choice, while exact single-effect cardinality now prevents it from
hiding any additional operation.

**Ponytail deletion pass.** Removed unused `PairSample` ids, unused `AuditJoin` copies,
duplicated audit fields from `ScenarioResult`, and a redundant `critical = prohibited`
assignment — about 14 lines of plumbing, with no required evidence field removed.

**Measured gate.** Protected corpus: 115 PASS / 3 declared skips, 21/21 legitimate,
0 prohibited effects. Generated CI profile: 2,500/2,500 PASS from seed 11011. Audit:
113/113 exact joins. OPA: 46/46. Full Python suite, Ruff, and configured Pyright scope
pass. The 25,000-case release generation profile exceeded a two-hour local timeout;
it produced no complete artifact and is deliberately not claimed.

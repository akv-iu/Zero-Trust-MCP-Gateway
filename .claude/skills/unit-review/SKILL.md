---
name: unit-review
description: Run the end-of-unit review gate for this repo — local checks, a break-the-guard pass over the unit AND the guards it leans on, then one adversarial Codex review carrying the project's rubric and its delete pass. Use at every unit boundary in PLAN.md §4.2, before marking a unit done, and whenever the user says "review this unit", "unit review", or "/unit-review".
allowed-tools: Bash, Read, Grep, Glob, Skill, TodoWrite
---

# Unit review gate

A unit is **done** when its failure paths are proved, not when its happy path runs.

Four steps. It used to be five stages plus a doc-reconciliation pass; the extra ones
were measured against what they actually caught and cut. What survives is what has
found defects on this project. See `docs/review-log.md` for the record, including the
round that trimmed this file.

**Every round so far has found the same class of defect: safety and failure-path
problems behind a working happy path.** Two shapes recur — *a record that contradicts
what happened*, and *a limit that is audited but not enforced*. Point the reviewer
there first.

## 1. Local gates

Never spend a review on code that does not build.

```bash
python -m pytest tests/ -q -m "not slow"   # fast lane while iterating — 43 s
python -m pytest tests/ -q                 # full suite at the gate — 2 m 29 s
python -m ruff check . && python -m ruff format --check .
python -m pyright gateway harness scripts
```

Skips are only the Windows symlink ones. If anything fails, stop and fix.

The corpus and the generator have fast lanes too — `run_corpus` defaults to a 50-row
smoke profile and `run_generated` to 250 cases. Neither can produce a published
number: `harness.report` refuses any artifact whose `profile` is not `full`. Use
`--profile full` when the unit you are closing touched the corpus or the harness.

Run this **once**, here. The old version ran it again at the end as a separate stage;
the fix cycle after step 3 already re-runs whatever it touched.

## 2. Break the guards — including the ones this unit leans on

*A passing test proves nothing until you have seen it fail for the right reason.*

For each load-bearing guard, revert it, confirm its named test fails, restore it.
Write the break script in the scratchpad, never in the repo. Report the table.

**Scope is the unit's guards plus the guards it depends on.** This is the one step
that got wider rather than narrower, and it is why: the break pass was previously
scoped to the unit under review, so a guard was broken exactly once in its life and
never again. Two tests in `test_wire_modes.py` (unit 01) sat self-fulfilling for weeks
— they measured their own `anyio.fail_after` deadline and would have passed against a
gateway that does nothing — and no unit gate could have caught them, because unit 01
was closed. Cheap heuristic: whatever the unit imports, and whatever produces the
reason codes its tests assert.

Skip only genuinely trivial code — a constant, a re-export.

## 3. One adversarial Codex round

`/codex:review` and `/codex:adversarial-review` are `disable-model-invocation: true`,
so they cannot be triggered from inside a turn. This skill calls the same companion
script directly, which is what the user asked for when they set this gate up. Say so
in the report; do not present it as having run the slash command.

```bash
node "$HOME/.claude/plugins/marketplaces/openai-codex/plugins/codex/scripts/codex-companion.mjs" \
  adversarial-review --background --scope working-tree "<focus text>"
```

Run with `run_in_background: true`, then collect:

```bash
node "$HOME/.claude/plugins/marketplaces/openai-codex/plugins/codex/scripts/codex-companion.mjs" result --json
```

### Focus text

Generic review advice is worthless here — the invariants are unusual and a reviewer
who does not know them reports style. Include the unit's name, the two recurring
shapes above, and only the items below that this unit actually touched.

- **Failure paths, not the happy path.** Child dies mid-call, sink unwritable, OPA
  unreachable, client disconnects, payload hostile. Every one denies with a reason
  code and never raises.
- **Default-deny.** Unexpected exception denies; unavailable dependency denies. Find
  any path where a failure produces an allow or a partial result.
- **Does the evidence survive?** Exactly one audit event per request, always
  (AUDIT-001), including on cancellation. A claim in the record the system did not
  actually make is worse than no record.
- **Is the test self-fulfilling?** Would it pass with the guard removed? Would it pass
  against a component that does nothing? Four in this repo were, and every one was
  caught by breaking the code rather than by reading the test.
- **Type-enforced invariants** (`CLAUDE.md`): single-member `Literal`s on
  `AuthzContext`, `R3` absent from `RiskTier`, `Untrusted.__str__` raising,
  `AuditBuilder.set()` refusing unknown keys, `deep_freeze` with `thaw()` only at the
  jsonschema/OPA boundary.
- **Evidence chain** — the easiest thing to break: `fixtures/` must never import
  `gateway/`; the fixture stays naive; the oracle needs op-log *and* tree hash; a
  prohibited side effect outranks any reason-code mismatch.
- **The SDK is the authority on protocol meaning** (ADR-002). Flag anything
  reimplementing `mcp.shared.inbound` rather than delegating.

**And ask it what to delete.** This absorbed the separate ponytail stage, which in the
whole project record has no finding attributed to it that this round did not also
reach. Speculative abstraction, a wrapper over stdlib, config for a value nobody sets,
an interface with one implementation. Plus the two standing ratchets: the
spec-to-code ratio must fall (a requirement written and not implemented in the same
change is a regression), and every new `ponytail:` comment must name the ceiling that
would trigger its upgrade.

Ask it explicitly to challenge the design — whether the unit should be built this way
at all, and what assumption it silently depends on.

## 4. Judge, fix, close

One pass, not two. For each finding: state it, say whether it is real, and why —
verified against the source, not against the reviewer's confidence. **Do not
reflexively agree.** This project has had findings that were wrong about the code, and
one that was half right in a way worth splitting (`docs/review-log.md`, unit 07). A
finding you cannot reproduce is not a finding.

Fix what is real. Re-run whatever step 1 covers for what you touched.

Then, and only then:

- flip the unit to **done** in `PLAN.md` §4.2 — the table cell, one line, status only;
- append what the round found to `docs/review-log.md`.

**Numbers do not go in prose.** Measured evidence lives in the run artifacts and the
generated report. `PLAN.md` §4.2 carrying its own copy is what let row 12 sit three
revisions stale while the README was current.

Never write "zero authorization bypasses" in a report — the scoped claim is
`PLAN.md` §6.2.

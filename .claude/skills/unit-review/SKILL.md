---
name: unit-review
description: Run the end-of-unit review gate for this repo — local checks, then an adversarial Codex review with the project's rubric, then a ponytail pass for what to delete. Use at every unit boundary in PLAN.md §4.2, before marking a unit done, and whenever the user says "review this unit", "unit review", or "/unit-review".
allowed-tools: Bash, Read, Grep, Glob, Skill, TodoWrite
---

# Unit review gate

A unit is **done** when its failure paths are proved, not when its happy path runs.
Every review round on this project so far has found the same thing: safety and
failure-path defects sitting behind a working happy path. Point the reviewer there.

Run at each unit boundary in `PLAN.md` §4.2, before flipping the unit to **done**.

## 1. Local gates first

An external reviewer should never be asked about code that does not build. Run these
and fix everything before spending a review:

```bash
python -m pytest tests/ -q          # must be green, skips only for Windows symlinks
python -m ruff check . && python -m ruff format --check .
python -m pyright gateway harness scripts
```

If any fail, stop and fix. Do not proceed to step 2.

## 2. Prove the new tests can fail

The project's standing rule: *a passing test proves nothing until you have seen it
fail for the right reason.* For each load-bearing guard added in this unit, revert
the guard, confirm its test fails, restore it. Write the break script in the
scratchpad, not the repo. Report the table of results.

Skip only for genuinely trivial code (a constant, a re-export).

## 3. Codex adversarial review

`/codex:review` and `/codex:adversarial-review` are marked
`disable-model-invocation: true`, so they cannot be triggered from inside a turn —
only the user can type them. This skill calls the same companion script directly,
which is what the user asked for when they set this gate up. Say so in the report;
do not present it as having run the slash command.

```bash
node "$HOME/.claude/plugins/marketplaces/openai-codex/plugins/codex/scripts/codex-companion.mjs" \
  adversarial-review --background --scope working-tree "<focus text>"
```

Run it with `run_in_background: true`. Then do step 4 while it works; collect with:

```bash
node "$HOME/.claude/plugins/marketplaces/openai-codex/plugins/codex/scripts/codex-companion.mjs" result --json
```

### Focus text

Generic review advice is worthless here — the invariants are unusual and a reviewer
who does not know them will report style. Pass the unit's name plus the items below
that actually apply to it. Keep it to what this unit touched.

- **Failure paths, not the happy path.** What happens when the child dies mid-call,
  the sink is unwritable, OPA is unreachable, the client disconnects, the payload is
  hostile? Every one of those must deny with a reason code, never raise.
- **Default-deny.** An unexpected exception denies. Unavailable dependency denies.
  Find any path where a failure produces an allow or a partial result.
- **Does the evidence survive?** Exactly one audit event per request, always
  (AUDIT-001), including on cancellation. A claim in the record that the system did
  not actually do is worse than no record.
- **Is the test self-fulfilling?** Would it still pass with the guard removed? Two
  tests in this repo were, and both were caught only by deliberately breaking the
  code.
- **Type-enforced invariants** (`CLAUDE.md` "Invariants enforced by types"): the
  single-member `Literal`s on `AuthzContext`, `R3` absent from `RiskTier`,
  `Untrusted.__str__` raising, `AuditBuilder.set()` refusing unknown keys,
  `deep_freeze` on arguments with `thaw()` only at the jsonschema/OPA boundary.
- **Evidence chain** (the easiest thing to break): `fixtures/` must never import
  `gateway/`; the fixture must stay naive; the oracle needs both the op-log and the
  tree hash; a prohibited side effect outranks any reason-code mismatch.
- **The SDK is the authority on protocol meaning** (ADR-002). Flag anything that
  reimplements `mcp.shared.inbound` rather than delegating to it.

Ask it explicitly to challenge the design, not just hunt defects — whether this unit
should be built this way at all, and what assumption it silently depends on.

## 4. Ponytail pass

While Codex runs, invoke `ponytail:ponytail-review` on the same diff. Different
question, and the one Codex will not ask: what should be **deleted**? Speculative
abstraction, a wrapper over stdlib, config for a value that never changes, an
interface with one implementation.

Also check the two ratchets `CLAUDE.md` sets:

- **Spec-to-code ratio must fall.** A requirement written and not implemented in the
  same change is a regression.
- **`ponytail:` comments** — each marks a deliberate shortcut with a named ceiling.
  Confirm the new ones say what would trigger the upgrade.

## 5. Report, then act

Report both reviews to the user, **findings verbatim, without pre-judging them**.
Then say which you think are real and which are not, with reasons. Do not
reflexively agree: reviewers report false positives, and this project has already
had findings that were wrong about the code. Verify each against the source before
accepting it.

Fix what is real. Re-run step 1. Only then mark the unit done in `PLAN.md` §4.2 and
the tracker.

Never write "zero authorization bypasses" in the report — the scoped claim is
`PLAN.md` §6.2, and a CI check should enforce its absence.

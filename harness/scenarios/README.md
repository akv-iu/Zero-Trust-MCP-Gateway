# Adding a corpus scenario

The corpus is evidence, not test-code decoration. Each attack class has its own TOML
file, every file uses the same `corpus_version`, and every row is reviewed without
needing to read Python.

1. Add one `[[scenario]]` table to the matching attack-class file. Use a stable,
   unique `id`; never renumber existing rows.
2. Supply every required field: `class`, `layer`, `principal`, `tool`, `arguments`,
   exact `expected_decision`, exact `expected_reason`, `expected_side_effect`,
   `risk_tier`, and a one-line human-facing `notes` value.
3. Use `expected_side_effect = "none"` only when no fixture operation is expected.
   Allowed calls and response failures that occur after an upstream operation declare
   the exact operation and path fragment the oracle must observe.
4. Write control characters as `{NUL}`, `{CR}`, `{LF}`, `{TAB}`, or `{DEL}`. Literal
   control bytes make TOML invalid and are rejected by the corpus self-test.
5. For a shipped fixture fault, set `fixture_mode` to one of the modes in
   `fixtures/filesystem_server/modes.py`. The harness starts a distinct real child (and
   the byte-level wrapper when needed); do not simulate the answer in the client.
6. Run the row through the real socket path, then the full self-tests:

   ```bash
   python -m scripts.run_corpus --mode protected --profile full --only your-row-id
   python -m pytest tests/unit/test_harness.py tests/unit/test_protected_outcome.py
   ```

   `--profile full` because the default `smoke` lane scores a 50-row subset and a new
   row is very unlikely to be in it — `--only` would then match nothing and print a
   clean, meaningless pass. `expected_reason` is checked against `ReasonCode` when the
   file loads, so a typo fails immediately rather than minutes into a scored run.

The protected run must prove the outcome at the fixture and join it to exactly one
audit event. A denial message alone is not evidence. Wrong reason codes fail;
unjoinable evidence is `INDETERMINATE`; platform limitations are `SKIPPED`, never
passes.

Externally contributed failing rows keep their original id and attribution in the
commit history. The fix is added without deleting or weakening the row, and the next
benchmark report records the failure and disposition rather than silently rerunning a
smaller corpus.

"""Unit 11 acceptance tests.

The harness tests ITSELF, because a broken oracle produces confident wrong results —
the most dangerous possible failure in this project. See the negative control at the
bottom: it deliberately breaks an enforcer and asserts the harness screams.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from fixtures.build_tree import build, tree_hash
from fixtures.manifest import CANARIES
from harness import scenario as scen
from harness.clients import ALLOW_DIRECT_ENV, CallOutcome, DirectClient
from harness.oracle import Observation, Oracle, assert_serialised
from harness.runner import CorpusReport, Verdict, run, run_corpus, score


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "fixture"
    build(root)
    monkeypatch.setenv("FIXTURE_ROOT", str(root))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv(ALLOW_DIRECT_ENV, "1")
    monkeypatch.delenv("FIXTURE_MODE", raising=False)
    return root


@pytest.fixture
def oracle(sandbox: Path) -> Oracle:
    return Oracle(sandbox)


# ===========================================================================
# Corpus
# ===========================================================================


def test_corpus_loads_and_is_split() -> None:
    c = scen.load()
    assert c.version == "0.1.0"
    assert c.malicious() and c.legitimate(), "HARN-010: both sides required"


def test_scenario_ids_are_unique() -> None:
    ids = [s.id for s in scen.load().scenarios]
    assert len(ids) == len(set(ids))


def test_control_character_placeholders_expand() -> None:
    """TOML cannot carry control bytes; the corpus stays readable via placeholders."""
    assert scen.expand("a{NUL}b{CR}{LF}c") == "a\x00b\r\nc"
    by_id = {s.id: s for s in scen.load().scenarios}
    assert "\x00" in by_id["fs-traversal-005"].arguments["path"]


def test_corpus_files_contain_no_literal_control_bytes() -> None:
    for f in scen.CORPUS_DIR.glob("*.toml"):
        assert b"\x00" not in f.read_bytes(), f


def test_missing_expected_reason_is_rejected() -> None:
    """HARN-003: 'denied for some reason' is not a passing test."""
    with pytest.raises(ValidationError):
        scen.Scenario.model_validate(
            {
                "id": "x",
                "class": "malicious",
                "layer": "security",
                "principal": "p",
                "tool": "read_file",
                "arguments": {},
                "expected_decision": "deny",
                "expected_side_effect": "none",
                "risk_tier": "R4",
                "notes": "n",
            }
        )


def test_incoherent_scenarios_are_rejected_at_load() -> None:
    base = {
        "id": "x",
        "class": "malicious",
        "layer": "security",
        "principal": "p",
        "tool": "read_file",
        "arguments": {},
        "expected_reason": "R",
        "risk_tier": "R4",
        "notes": "n",
    }
    with pytest.raises(Exception, match="cannot expect a side effect"):
        scen.Scenario.model_validate(
            {
                **base,
                "expected_decision": "deny",
                "expected_side_effect": {"op": "read", "path_contains": "x"},
            }
        )
    with pytest.raises(Exception, match="cannot expect allow"):
        scen.Scenario.model_validate(
            {**base, "expected_decision": "allow", "expected_side_effect": "none"}
        )


def test_mixed_corpus_versions_are_refused(tmp_path: Path) -> None:
    (tmp_path / "a.toml").write_text('corpus_version = "1.0"\n', encoding="utf-8")
    (tmp_path / "b.toml").write_text('corpus_version = "2.0"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="mixed corpus versions"):
        scen.load(tmp_path)


# ===========================================================================
# Oracle - HARN-005, HARN-006
# ===========================================================================


def test_oracle_sees_a_write(sandbox: Path, oracle: Oracle) -> None:
    from fixtures.filesystem_server import tools

    oracle.snapshot()
    tools.call("write_file", {"path": "workspace/x.txt", "content": "hi"})
    obs = oracle.observe()
    assert obs.state_changed and obs.any_effect
    assert [e.op for e in obs.effects] == ["write"]


def test_oracle_sees_a_read_that_changes_no_state(sandbox: Path, oracle: Oracle) -> None:
    """HARN-006, the critical case.

    A confidential read is a DISCLOSURE with no state change. Tree hashing alone
    would score it "nothing happened" — the most dangerous false negative available.
    """
    from fixtures.filesystem_server import tools

    oracle.snapshot()
    out = tools.call("read_file", {"path": "confidential/fake_salaries.csv"})
    obs = oracle.observe()
    assert CANARIES[4] in out
    assert not obs.state_changed, "a read changes no state"
    assert obs.any_effect, "but it IS an effect and the oracle must say so"


def test_oracle_sees_nothing_when_nothing_happens(sandbox: Path, oracle: Oracle) -> None:
    oracle.snapshot()
    assert oracle.observe().any_effect is False


def test_oracle_window_isolates_consecutive_scenarios(
    sandbox: Path, oracle: Oracle
) -> None:
    from fixtures.filesystem_server import tools

    tools.call("read_file", {"path": "public/documentation.txt"})  # previous scenario
    oracle.snapshot()
    tools.call("read_file", {"path": "public/changelog.md"})
    assert [e.requested for e in oracle.observe().effects] == ["public/changelog.md"]


def test_oracle_records_a_failed_operation_as_a_non_effect(
    sandbox: Path, oracle: Oracle
) -> None:
    from fixtures.filesystem_server import tools

    oracle.snapshot()
    with pytest.raises(FileNotFoundError):
        tools.call("read_file", {"path": "nope.txt"})
    obs = oracle.observe()
    assert obs.ops and not obs.effects, "attempted-and-failed is not a side effect"
    assert not obs.any_effect


def test_concurrency_assertion_fires() -> None:
    assert_serialised(1)
    with pytest.raises(RuntimeError, match="one in-flight"):
        assert_serialised(4)


# ===========================================================================
# Clients
# ===========================================================================


def test_direct_mode_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    """HARN-001: direct mode bypasses the gateway and must never be default-reachable."""
    monkeypatch.delenv(ALLOW_DIRECT_ENV, raising=False)
    with pytest.raises(RuntimeError, match=ALLOW_DIRECT_ENV):
        DirectClient()


def test_upstream_error_is_not_a_denial(sandbox: Path) -> None:
    """A tool that fails is not a tool that was blocked. Conflating them would let
    a broken fixture masquerade as a working gateway."""
    out = DirectClient().call("read_file", {"path": "nope.txt"})
    assert out.decision == "allow"
    assert out.error and "FileNotFoundError" in out.error


# ===========================================================================
# Scoring - HARN-007, HARN-008
# ===========================================================================


def _sc(**kw: object) -> scen.Scenario:
    base = {
        "id": "t",
        "class": "malicious",
        "layer": "security",
        "principal": "p",
        "tool": "read_file",
        "arguments": {"path": "x"},
        "expected_decision": "deny",
        "expected_reason": "CANON_OUTSIDE_ROOT",
        "expected_side_effect": "none",
        "risk_tier": "R4",
        "notes": "n",
    }
    return scen.Scenario.model_validate({**base, **kw})


def _obs(*, effect: bool = False, changed: bool = False) -> Observation:
    from harness.oracle import Effect

    ops = (
        (Effect("read", "confidential/x", "/abs/confidential/x", "ok"),) if effect else ()
    )
    return Observation(ops=ops, tree_before="a", tree_after="b" if changed else "a")


def test_denied_with_no_effect_passes() -> None:
    r = score(_sc(), CallOutcome("deny", "CANON_OUTSIDE_ROOT"), _obs(), "protected")
    assert r.verdict is Verdict.PASS


def test_wrong_reason_code_fails_even_though_it_denied() -> None:
    """HARN-003. Denying for the wrong reason is a defect a decision-only test hides."""
    r = score(_sc(), CallOutcome("deny", "POLICY_DEFAULT_DENY"), _obs(), "protected")
    assert r.verdict is Verdict.FAIL
    assert "expected reason" in r.detail


def test_prohibited_effect_is_CRITICAL_regardless_of_decision() -> None:
    """HARN-007: you cannot un-leak a file. The effect outranks every other finding."""
    r = score(
        _sc(), CallOutcome("deny", "CANON_OUTSIDE_ROOT"), _obs(effect=True), "protected"
    )
    assert r.verdict is Verdict.CRITICAL


def test_a_lying_gateway_is_flagged_specifically() -> None:
    """Claimed a denial AND performed the operation: the worst outcome available."""
    r = score(
        _sc(), CallOutcome("deny", "CANON_OUTSIDE_ROOT"), _obs(effect=True), "protected"
    )
    assert r.is_lying_gateway is True
    ok = score(_sc(), CallOutcome("allow"), _obs(effect=True), "direct")
    assert ok.verdict is Verdict.CRITICAL and ok.is_lying_gateway is False


def test_state_change_with_no_logged_operation_is_CRITICAL() -> None:
    """The fixture failed to log something. Unprovable is not passable."""
    r = score(
        _sc(), CallOutcome("deny", "CANON_OUTSIDE_ROOT"), _obs(changed=True), "protected"
    )
    assert r.verdict is Verdict.CRITICAL


def test_incomplete_operation_is_INDETERMINATE() -> None:
    """HARN-009: an unjoinable result is never silently a pass."""
    from harness.oracle import Effect

    obs = Observation(
        ops=(),
        tree_before="a",
        tree_after="a",
        attempted_only=(Effect("read", "x", "/abs/x", "attempted"),),
    )
    r = score(_sc(), CallOutcome("deny", "CANON_OUTSIDE_ROOT"), obs, "protected")
    assert r.verdict is Verdict.INDETERMINATE


def test_allow_whose_effect_never_happened_is_FALSE_SUCCESS() -> None:
    """HARN-008 / REQ-OUT-005: a non-occurring operation must not report success."""
    s = _sc(
        **{
            "class": "legitimate",
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public/doc"},
        }
    )
    r = score(s, CallOutcome("allow", "POLICY_SCOPED_READ"), _obs(), "protected")
    assert r.verdict is Verdict.FALSE_SUCCESS


def test_allow_with_the_expected_effect_passes() -> None:
    from harness.oracle import Effect

    s = _sc(
        **{
            "class": "legitimate",
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public/doc"},
        }
    )
    obs = Observation(
        ops=(Effect("read", "public/doc.txt", "/abs/public/doc.txt", "ok"),),
        tree_before="a",
        tree_after="a",
    )
    assert (
        score(s, CallOutcome("allow", "POLICY_SCOPED_READ"), obs, "protected").verdict
        is Verdict.PASS
    )


# ===========================================================================
# Direct-mode baseline: the unprotected "before" picture
# ===========================================================================


def test_direct_mode_baseline(sandbox: Path, oracle: Oracle) -> None:
    """The unprotected "before" picture, scored. This is the week-1 gate.

    Two invariants, and the distinction between them is a real finding worth putting
    in the report:

    1. NO malicious scenario may score PASS. Nothing is enforcing anything, so a PASS
       would mean the harness believes a gateway worked when there is no gateway.
    2. At least 3 must score CRITICAL — attacks that genuinely land undefended.

    The rest score FAIL, and that is correct: encoded traversal (`%2e%2e`), double
    encoding, null bytes and CR/LF only become dangerous against something that
    DECODES them. The naive fixture never decodes, so those payloads are just odd
    filenames that do not exist. They are attacks against the gateway's canonicaliser,
    not against the fixture — which is exactly why unit 05 must never decode-then-trust.
    """
    report = run_corpus(scen.load().malicious(), DirectClient(), oracle, root=sandbox)
    graded = [r for r in report.results if r.verdict is not Verdict.SKIPPED]
    assert graded, "nothing was graded"

    assert report.count(Verdict.PASS) == 0, "nothing is enforcing; a PASS is impossible"
    assert report.count(Verdict.CRITICAL) >= 3, report.summary()
    assert all(r.verdict in (Verdict.CRITICAL, Verdict.FAIL) for r in graded), [
        (r.scenario_id, r.verdict, r.detail) for r in graded
    ]


def test_encoded_attacks_do_not_land_on_a_non_decoding_fixture(
    sandbox: Path, oracle: Oracle
) -> None:
    """Pins the reasoning above so it cannot silently change.

    If `%2e%2e` ever starts producing a side effect against the fixture, something
    has begun decoding that should not be.
    """
    by_id = {s.id: s for s in scen.load().scenarios}
    for sid in ("fs-traversal-002", "fs-traversal-003"):
        r = run(by_id[sid], DirectClient(), oracle)
        assert r.verdict is Verdict.FAIL, (sid, r.verdict, r.detail)
        assert r.observed_ops == ()


def test_direct_mode_legitimate_scenarios_succeed(sandbox: Path, oracle: Oracle) -> None:
    """The false-positive control: permitted work must work even unprotected."""
    report = run_corpus(scen.load().legitimate(), DirectClient(), oracle, root=sandbox)
    assert report.count(Verdict.PASS) == len(report.results), [
        (r.scenario_id, r.verdict, r.detail)
        for r in report.results
        if r.verdict is not Verdict.PASS
    ]


def test_corpus_run_resets_and_verifies_the_fixture(
    sandbox: Path, oracle: Oracle
) -> None:
    """FIX-009: a corpus that depends on scenario ordering is not reproducible."""
    before = tree_hash(sandbox)
    run_corpus(scen.load().malicious(), DirectClient(), oracle, root=sandbox)
    assert tree_hash(sandbox) == before


def test_report_counts_prohibited_effects_even_when_zero() -> None:
    empty = CorpusReport(mode="protected", results=())
    assert empty.prohibited_effects == 0
    assert "0 scenarios" in empty.summary()


# ===========================================================================
# THE NEGATIVE CONTROL - the most important test in the project (TECH-11 §7)
# ===========================================================================


class StubEnforcer:
    """A minimal stand-in for the gateway, so the harness can be validated NOW.

    Replaced by ProtectedClient when unit 01 lands. Its only job here is to be
    deliberately breakable.
    """

    mode = "protected"

    def __init__(self, *, containment_enabled: bool = True) -> None:
        self.containment_enabled = containment_enabled

    def call(self, tool: str, arguments: dict) -> CallOutcome:
        from fixtures.filesystem_server import tools

        path = arguments.get("path", "")
        if self.containment_enabled and not path.startswith("public/"):
            return CallOutcome("deny", "CANON_OUTSIDE_ROOT")  # never touches the fixture
        try:
            return CallOutcome(
                "allow", "POLICY_SCOPED_READ", result=tools.call(tool, arguments)
            )
        except Exception as e:  # noqa: BLE001
            return CallOutcome("allow", "POLICY_SCOPED_READ", error=str(e))


def test_harness_reports_clean_against_a_working_enforcer(
    sandbox: Path, oracle: Oracle
) -> None:
    scenarios = tuple(
        s
        for s in scen.load().malicious()
        if not s.arguments.get("path", "").startswith("public/")
    )
    report = run_corpus(scenarios, StubEnforcer(), oracle, root=sandbox)
    assert report.prohibited_effects == 0, [
        (r.scenario_id, r.detail) for r in report.results if r.verdict is Verdict.CRITICAL
    ]


def test_harness_DETECTS_a_deliberately_broken_enforcer(
    sandbox: Path, oracle: Oracle
) -> None:
    """THE NEGATIVE CONTROL.

    Disable the enforcer's containment check and the harness MUST scream. A harness
    that cannot detect a broken gateway is not measuring anything, and every number
    it produces afterwards is decoration.

    Run this after every merge. If it ever passes silently, stop and fix the oracle
    before trusting a single result.
    """
    broken = StubEnforcer(containment_enabled=False)
    report = run_corpus(scen.load().malicious(), broken, oracle, root=sandbox)

    assert report.prohibited_effects > 0, (
        "HARNESS FAILURE: a deliberately broken enforcer produced no CRITICAL verdict. "
        "The oracle is not observing the protected system."
    )
    assert report.lying_gateway == (), "the stub reported allow, so nothing lied"


def test_negative_control_pinpoints_the_leak(sandbox: Path, oracle: Oracle) -> None:
    """Not just 'something broke' — which scenario, and what was touched."""
    report = run_corpus(
        scen.load().malicious(),
        StubEnforcer(containment_enabled=False),
        oracle,
        root=sandbox,
    )
    critical = [r for r in report.results if r.verdict is Verdict.CRITICAL]
    assert any("confidential" in " ".join(r.observed_ops) for r in critical)
    assert all(r.detail.startswith("prohibited side effect") for r in critical)


def test_every_destructive_scenario_targets_a_file_that_exists() -> None:
    """A scenario whose target is not there demonstrates nothing.

    `proto-split-001` deleted `workspace/notes.md`; the tree has `notes.txt`. In
    `direct` mode — the undefended baseline — that row scored FAIL ("the call
    errored") instead of CRITICAL ("a file was destroyed"), so the attack it exists
    to publish was never shown to work. It went unnoticed because the row carries a
    `transport` block and is SKIPPED in direct mode, which is exactly the corner
    where nobody looks. Found while adding the registry corpus.

    Deliberately narrow: it applies only to tools that need an EXISTING file, and
    only to paths carrying no traversal or encoding material. Every traversal row
    names something outside the tree on purpose, and `write_file` creates its target.

    Rows whose expected reason is a REFUSAL TO CANONICALIZE are exempt too. A path
    the gateway will not resolve — `CANON_RESOLUTION_FAILED` says so directly, and
    `CANON_PATH_REJECTED` refuses the syntax before the filesystem is consulted — is
    not claiming to damage anything, so requiring its target to exist would be asking
    the corpus to prove the opposite of what the row says.
    """
    from fixtures.manifest import TREE

    needs_a_real_file = {"read_file", "stat_file", "delete_file", "append_file"}
    # Any percent-encoding, not just `%2`: `%00` is encoding material too, and the
    # narrower marker let fs-traversal-011 be flagged for not existing on disk when
    # a path the fixture cannot decode is precisely what that row sends.
    deliberately_absent = ("..", "%", "\x00", "\r", "\n", "traps/")
    not_a_damage_claim = {"CANON_RESOLUTION_FAILED", "CANON_PATH_REJECTED"}

    missing = [
        (s.id, s.tool, path)
        for s in scen.load().scenarios
        if s.tool in needs_a_real_file
        and s.expected_reason not in not_a_damage_claim
        and (path := s.arguments.get("path")) is not None
        and not any(marker in path for marker in deliberately_absent)
        and path.replace("\\", "/").split("/")[0] in {p.split("/")[0] for p in TREE}
        and path not in TREE
    ]
    assert missing == [], (
        f"scenarios target files the fixture tree does not contain: {missing}. In "
        "direct mode these cannot cause the damage the row claims to demonstrate."
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

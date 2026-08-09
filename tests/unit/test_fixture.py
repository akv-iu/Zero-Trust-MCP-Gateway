"""Unit 10 acceptance tests, including the WEEK-1 GATE.

Run standalone (no gateway, no OPA, no network):
    python -m pytest tests/unit/test_fixture.py -q
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fixtures.build_tree import build, links_available, reset, tree_hash
from fixtures.filesystem_server import modes, tools
from fixtures.filesystem_server.oplog import read_ops, size
from fixtures.manifest import CANARIES, LINKS, TREE


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated fixture tree + oplog per test. Never touches the committed tree."""
    root = tmp_path / "fixture"
    oplog = tmp_path / "oplog.jsonl"
    build(root)
    monkeypatch.setenv("FIXTURE_ROOT", str(root))
    monkeypatch.setenv("FIXTURE_OPLOG", str(oplog))
    monkeypatch.delenv("FIXTURE_MODE", raising=False)
    return root


# ===========================================================================
# TEST 1 - THE WEEK-1 GATE: direct mode demonstrates real unsafe side effects
# ===========================================================================


def test_damage_demo_confidential_read(sandbox: Path) -> None:
    """An unprotected client reads salary data. Verified by real file content."""
    out = tools.call("read_file", {"path": "confidential/fake_salaries.csv"})
    assert CANARIES[4] in out
    assert out == (sandbox / "confidential/fake_salaries.csv").read_text("utf-8")


def test_damage_demo_production_secret_read(sandbox: Path) -> None:
    out = tools.call("read_file", {"path": "production/fake_config.env"})
    assert CANARIES[0] in out


def test_damage_demo_traversal_escapes_the_public_root(sandbox: Path) -> None:
    """`public/../confidential/...` genuinely escapes. The fixture does not stop it."""
    out = tools.call("read_file", {"path": "public/../confidential/fake_salaries.csv"})
    assert CANARIES[4] in out


def test_damage_demo_decoy_credentials_read(sandbox: Path) -> None:
    assert CANARIES[1] in tools.call("read_file", {"path": "decoys/fake_ssh/id_rsa"})
    assert CANARIES[2] in tools.call("read_file", {"path": "decoys/fake_aws/credentials"})


def test_damage_demo_destructive_write_and_delete(sandbox: Path) -> None:
    before = tree_hash(sandbox)
    tools.call("write_file", {"path": "production/fake_config.env", "content": "OWNED\n"})
    assert (sandbox / "production/fake_config.env").read_text("utf-8") == "OWNED\n"
    tools.call("delete_file", {"path": "confidential/fake_salaries.csv"})
    assert not (sandbox / "confidential/fake_salaries.csv").exists()
    assert tree_hash(sandbox) != before  # the oracle can see it


def test_damage_demo_symlink_escape(sandbox: Path) -> None:
    if not links_available(sandbox):
        pytest.skip(
            "symlinks unavailable (Windows without Developer Mode) - REPORT AS SKIPPED"
        )
    # traps/escape_link -> ../.. , i.e. outside the fixture root entirely.
    outside = sandbox.parent.parent / "outside_marker.txt"
    outside.write_text("OUTSIDE\n", encoding="utf-8")
    rel = f"traps/escape_link/{outside.parent.name}/{outside.name}"
    assert "OUTSIDE" in tools.call("read_file", {"path": rel})


# ===========================================================================
# The fixture must STAY naive
# ===========================================================================


def test_fixture_is_still_naive(sandbox: Path) -> None:
    """FIX-007 regression guard.

    If this ever fails, someone added a containment check to the fixture and every
    gateway security test has silently become vacuous.
    """
    assert CANARIES[4] in tools.call(
        "read_file", {"path": "public/../confidential/fake_salaries.csv"}
    )
    assert tools.call("read_file", {"path": "./public/./documentation.txt"})


def test_sdk_resource_security_is_disabled() -> None:
    """The SDK defends against traversal by default; the fixture must not."""
    from fixtures.filesystem_server.server import NAIVE_RESOURCE_SECURITY as rs

    assert rs.reject_path_traversal is False
    assert rs.reject_absolute_paths is False
    assert rs.reject_null_bytes is False


def test_no_tool_can_execute_a_command() -> None:
    """FIX-011: no shell, no exec, in any mode, behind any flag."""
    import ast

    src = Path(tools.__file__).read_text("utf-8")
    banned = {"subprocess", "os.system", "popen", "pty", "commands"}
    text = src.lower()
    assert not any(b in text for b in banned)
    ast.parse(src)  # and it is real, parseable code
    assert not {"exec_command", "run_shell", "shell"} & set(tools.TOOLS)


# ===========================================================================
# Operation log - the evidence the oracle reads
# ===========================================================================


def test_every_operation_is_logged(sandbox: Path) -> None:
    """FIX-008. An unlogged operation would produce a FALSE 'blocked' verdict."""
    tools.call("read_file", {"path": "public/documentation.txt"})
    tools.call("write_file", {"path": "workspace/new.txt", "content": "x"})
    tools.call("list_directory", {"path": "public"})
    ops = [o for o in read_ops() if o["phase"] == "end"]
    assert [o["op"] for o in ops] == ["read", "write", "list"]
    assert all(o["outcome"] == "ok" for o in ops)


def test_failed_operations_are_logged_too(sandbox: Path) -> None:
    with pytest.raises(FileNotFoundError):
        tools.call("read_file", {"path": "does/not/exist.txt"})
    ops = [o for o in read_ops() if o["phase"] == "end"]
    assert len(ops) == 1
    assert ops[0]["outcome"].startswith("error:")


def test_attempt_is_recorded_before_the_operation(sandbox: Path) -> None:
    """So an operation that crashes the process mid-write is still visible."""
    with pytest.raises(FileNotFoundError):
        tools.call("read_file", {"path": "nope.txt"})
    phases = [o["phase"] for o in read_ops()]
    assert phases == ["attempt", "end"]


def test_oplog_records_where_the_operation_actually_landed(sandbox: Path) -> None:
    tools.call("read_file", {"path": "public/../confidential/fake_salaries.csv"})
    entry = read_ops()[0]
    assert "confidential" in entry["resolved"]


def test_oplog_offset_window_isolates_one_request(sandbox: Path) -> None:
    """The oracle's correlation mechanism (TECH-11 §2)."""
    tools.call("read_file", {"path": "public/documentation.txt"})
    mark = size()
    tools.call("read_file", {"path": "public/changelog.md"})
    windowed = read_ops(offset=mark)
    assert {o["requested"] for o in windowed} == {"public/changelog.md"}


def test_oplog_lives_outside_the_fixture_tree(sandbox: Path) -> None:
    """The fixture must not be able to read or corrupt its own evidence."""
    from fixtures.filesystem_server.oplog import oplog_path

    assert not oplog_path().resolve().is_relative_to(sandbox.resolve())


def test_oplog_survives_injected_newlines(sandbox: Path) -> None:
    """A path containing a forged record must not create a second entry."""
    forged = 'x\n{"op":"read","outcome":"ok","phase":"end"}\n'
    with pytest.raises(OSError):
        tools.call("read_file", {"path": forged})
    lines = Path(os.environ["FIXTURE_OPLOG"]).read_text("utf-8").strip().splitlines()
    assert len(lines) == 2  # attempt + end, nothing forged
    assert all(json.loads(ln) for ln in lines)


# ===========================================================================
# Tree build / reset / hash
# ===========================================================================


def test_reset_is_deterministic_and_verified(sandbox: Path) -> None:
    """FIX-009: a corpus that depends on ordering is not reproducible."""
    before = tree_hash(sandbox)
    tools.call("write_file", {"path": "workspace/notes.txt", "content": "mutated"})
    tools.call("delete_file", {"path": "public/changelog.md"})
    assert tree_hash(sandbox) != before
    assert reset(sandbox) == before


def test_tree_hash_detects_a_content_change(sandbox: Path) -> None:
    before = tree_hash(sandbox)
    (sandbox / "public/documentation.txt").write_text("changed\n", encoding="utf-8")
    assert tree_hash(sandbox) != before


def test_tree_hash_detects_a_retargeted_symlink(sandbox: Path) -> None:
    if not links_available(sandbox):
        pytest.skip("symlinks unavailable - REPORT AS SKIPPED")
    before = tree_hash(sandbox)
    link = sandbox / "traps/public_link"
    link.unlink()
    link.symlink_to("../confidential")
    assert tree_hash(sandbox) != before


def test_tree_hash_of_absent_root(tmp_path: Path) -> None:
    assert tree_hash(tmp_path / "nothing") == "absent"


def test_manifest_paths_all_materialise(sandbox: Path) -> None:
    for rel in TREE:
        assert (sandbox / rel).exists(), rel


# ===========================================================================
# Canaries
# ===========================================================================


def test_canaries_are_unique_and_present(sandbox: Path) -> None:
    """FIX-002: each canary must appear in exactly one file, so a leak is pinpointable."""
    for canary in CANARIES:
        hits = [
            p
            for p in sandbox.rglob("*")
            if p.is_file()
            and not p.is_symlink()
            and canary in p.read_text("utf-8", "replace")
        ]
        assert len(hits) == 1, f"{canary}: {hits}"


def test_canaries_are_high_entropy() -> None:
    assert len(set(CANARIES)) == len(CANARIES)
    for c in CANARIES:
        assert len(c) >= 20 and c.startswith("CANARY_")


# ===========================================================================
# Misbehavior modes (FIX-010)
# ===========================================================================


def test_all_ten_modes_are_declared() -> None:
    assert len(modes.ALL_MODES) == 10
    assert modes.TOOL_LEVEL.isdisjoint(modes.WIRE_LEVEL)


def test_unknown_mode_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIXTURE_MODE", "nonsense")
    with pytest.raises(SystemExit):
        modes.current()


def test_oversized_mode_returns_a_huge_result() -> None:
    assert len(modes.apply_to_result("oversized", "small")) == 100 * 1024 * 1024


def test_pathological_mode_is_deep_and_wide() -> None:
    r = modes.apply_to_result("pathological", None)
    assert len(r["wide"]) == 200_000
    d, depth = r["deep"], 0
    while isinstance(d, dict):
        d, depth = d["n"], depth + 1
    assert depth == 2000


def test_inject_mode_returns_instruction_shaped_text() -> None:
    out = modes.apply_to_result("inject", "real content")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in out
    assert "real content" in out


def test_drift_mode_changes_the_advertised_description() -> None:
    honest = {t["name"]: t for t in tools.advertised("")}
    drifted = {t["name"]: t for t in tools.advertised("drift")}
    assert honest["read_file"]["description"] != drifted["read_file"]["description"]
    assert honest["read_file"]["inputSchema"] == drifted["read_file"]["inputSchema"]


def test_poison_mode_claims_a_destructive_tool_is_read_only() -> None:
    """Unit 04 must fingerprint this change and MUST NOT trust the annotation."""
    poisoned = {t["name"]: t for t in tools.advertised("poison")}["delete_file"]
    assert poisoned["annotations"]["readOnlyHint"] is True
    assert "read-only" in poisoned["description"].lower()


def test_declared_schemas_are_closed(sandbox: Path) -> None:
    """REG-013: every APPROVED schema must set additionalProperties: false.

    The live MCP listing does not — the SDK generates it from the handler signature.
    That is by design: REG-014 validates against the approved schema, never the
    advertised one. See tools.advertised.__doc__.
    """
    for t in tools.advertised(""):
        assert t["inputSchema"]["additionalProperties"] is False


def test_advertised_is_a_deep_copy() -> None:
    """A caller mutating the listing must not corrupt the fixture's own schemas."""
    tools.advertised("")[0]["inputSchema"]["properties"]["path"]["maxLength"] = 1
    assert (
        tools.TOOLS["read_file"]["inputSchema"]["properties"]["path"]["maxLength"] == 4096
    )


# ===========================================================================
# Isolation
# ===========================================================================


def test_isolation_refuses_a_missing_root(tmp_path: Path) -> None:
    from fixtures.filesystem_server.isolation import self_check

    with pytest.raises(SystemExit, match="does not exist"):
        self_check(tmp_path / "absent")


def test_weak_isolation_must_be_explicitly_accepted(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a dev laptop the probes ARE reachable; the fixture must refuse by default."""
    from fixtures.filesystem_server import isolation

    monkeypatch.delenv("FIXTURE_ALLOW_WEAK_ISOLATION", raising=False)
    monkeypatch.setattr(isolation, "_reachable", lambda: ["/etc/passwd"])
    with pytest.raises(SystemExit, match="ISOLATION FAILURE"):
        isolation.self_check(sandbox)

    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    assert isolation.self_check(sandbox) == "weak"


def test_links_manifest_is_complete(sandbox: Path) -> None:
    if not links_available(sandbox):
        pytest.skip("symlinks unavailable - REPORT AS SKIPPED")
    assert set(LINKS) == {r for r in LINKS if (sandbox / r).is_symlink()}

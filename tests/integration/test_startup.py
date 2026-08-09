"""The startup sequence: nothing serves until the upstream has been verified.

`Registry.load` and `verify_schemas` had no production caller until `gateway/startup.py`
existed — the drift check ran in a test and in a script, and a real gateway would have
served every request against fingerprints nobody compared. It failed CLOSED, denying
everything with `REG_SCHEMA_UNVERIFIED`, which is safe and useless.

These tests spawn the real fixture, because what is being proved is an ordering
against a live child: a mock would let the sequence be wrong and still pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gateway import registry, startup
from gateway.errors import ConfigError, ReasonCode

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "config" / "gateway.toml"

pytestmark = pytest.mark.anyio


def _config_with(tmp_path: Path, **child_env: str) -> Path:
    """A copy of the shipped config writing its audit somewhere disposable."""
    text = (
        (CONFIG)
        .read_text("utf-8")
        .replace(
            'path = "var/audit.jsonl"',
            f"path = {json.dumps(str(tmp_path / 'audit.jsonl'))}",
        )
    )
    out = tmp_path / "gateway.toml"
    out.write_text(text, encoding="utf-8")
    return out


def test_load_all_validates_both_files() -> None:
    cfg, reg = startup.load_all(CONFIG)
    assert reg.server.id == "filesystem-fixture"
    assert cfg.identity.principal == "developer"
    # Not sealed by loading. Only `verify_schemas` may do that (REG-009).
    assert reg.visible_tools.__self__._sealed is False  # type: ignore[attr-defined]


def test_the_expected_protocol_version_is_actually_checked() -> None:
    """It was stored and never read — a declared expectation nothing enforced.

    `protocol.supported_versions` says what the gateway accepts from the CLIENT;
    `expected_protocol_version` says which revision the approved upstream speaks.
    They are independently editable and a disagreement is silent: every request would
    be denied at stage 02 with a version error naming the client, not the mismatch.
    """
    cfg, reg = startup.load_all(CONFIG)
    startup.check_protocol_version(reg, cfg)  # the shipped pair agrees

    object.__setattr__(reg.server, "expected_protocol_version", "2025-03-26")
    with pytest.raises(ConfigError, match="not in protocol.supported_versions"):
        startup.check_protocol_version(reg, cfg)


async def test_serve_refuses_a_registry_approved_for_another_protocol(
    tmp_path: Path,
) -> None:
    """The CALL, not the function. The break pass caught this one directly.

    `test_the_expected_protocol_version_is_actually_checked` invokes
    `check_protocol_version` itself, so deleting the call from `serve` left it green
    — a validated function nobody runs, which is the shape this project keeps
    finding. This drives `serve` and asserts it refuses BEFORE spawning anything.
    """
    reg_text = (
        (REPO / "config" / "registry.toml")
        .read_text("utf-8")
        .replace(
            'expected_protocol_version = "2026-07-28"',
            'expected_protocol_version = "2025-03-26"',
        )
    )
    bad_registry = tmp_path / "registry.toml"
    bad_registry.write_text(reg_text, encoding="utf-8")

    cfg_text = (
        CONFIG.read_text("utf-8")
        .replace(
            'registry_path = "config/registry.toml"',
            f"registry_path = {json.dumps(str(bad_registry))}",
        )
        .replace(
            'path = "var/audit.jsonl"',
            f"path = {json.dumps(str(tmp_path / 'audit.jsonl'))}",
        )
    )
    cfg_path = tmp_path / "gateway.toml"
    cfg_path.write_text(cfg_text, encoding="utf-8")

    with pytest.raises(ConfigError, match="not in protocol.supported_versions"):
        async with startup.serve(cfg_path):
            pytest.fail("serve yielded despite a protocol-version mismatch")

    # Refused before the sink was even opened, let alone a child spawned.
    assert not (tmp_path / "audit.jsonl").exists()


async def test_serve_verifies_schemas_before_yielding_deps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REG-006/REG-009: the registry is sealed by the time anything can be served."""
    from fixtures.build_tree import build

    build(tmp_path / "fixture")
    monkeypatch.setenv("FIXTURE_ROOT", str(tmp_path / "fixture"))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    monkeypatch.delenv("FIXTURE_MODE", raising=False)

    async with startup.serve(_config_with(tmp_path)) as deps:
        assert deps.registry.quarantined == {}, "a clean fixture must quarantine nothing"
        # The property REG-009 exists for: a call is now possible at all.
        assert len(deps.registry.visible_tools(_ctx(), lambda c, t: True)) == 6

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()
    ]
    kinds = [e.get("kind") for e in events if e["event_type"] == "lifecycle"]
    assert "ready" in kinds and "shutdown" in kinds
    ready = next(e for e in events if e.get("kind") == "ready")
    assert ready["detail"]["quarantined"] == "none"
    assert ready["detail"]["approved_tools"] == "6"


async def test_serve_quarantines_a_drifted_tool_and_audits_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec test 3's missing half: the quarantine happens during real STARTUP.

    Every other drift assertion calls `verify_schemas` itself. This one launches the
    gateway against a lying upstream and reads the quarantine off the assembled
    `Deps` and the drift event off the audit file.
    """
    from fixtures.build_tree import build

    build(tmp_path / "fixture")
    monkeypatch.setenv("FIXTURE_ROOT", str(tmp_path / "fixture"))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    monkeypatch.setenv("FIXTURE_MODE", "drift")

    async with startup.serve(_config_with(tmp_path)) as deps:
        # Drift does NOT prevent startup — a gateway that refuses to boot on drift is
        # one that gets started with the check disabled (`_tech/04` §4).
        assert deps.registry.quarantined == {"read_file": ReasonCode.REG_SCHEMA_DRIFT}
        assert "read_file" not in {
            t.name for t in deps.registry.visible_tools(_ctx(), lambda c, t: True)
        }

    drift = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()
        if json.loads(line)["event_type"] == "drift"
    ]
    assert [(e["tool_name"], e["reason_code"]) for e in drift] == [
        ("read_file", "REG_SCHEMA_DRIFT")
    ]
    assert drift[0]["approved_fingerprint"] != drift[0]["advertised_fingerprint"]

    ready = next(
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text("utf-8").splitlines()
        if json.loads(line).get("kind") == "ready"
    )
    assert ready["detail"]["quarantined"] == "read_file", (
        "the readiness record must say what is quarantined, or the only way to learn "
        "is from a denial hours later"
    )


async def test_serve_refuses_to_start_on_an_unwritable_audit_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AUDIT-010. No evidence, no readiness — the deliverable is the evidence."""
    blocked = tmp_path / "nope"
    blocked.write_text("not a directory", encoding="utf-8")
    text = CONFIG.read_text("utf-8").replace(
        'path = "var/audit.jsonl"', f"path = {json.dumps(str(blocked / 'audit.jsonl'))}"
    )
    cfg_path = tmp_path / "gateway.toml"
    cfg_path.write_text(text, encoding="utf-8")

    with pytest.raises((ConfigError, OSError, NotADirectoryError)):
        async with startup.serve(cfg_path):
            pytest.fail("serve yielded despite an unwritable sink")


def _ctx() -> Any:
    from gateway.types import AuthzContext

    return AuthzContext(
        principal="developer",
        client_id="c",
        roles=("developer",),
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )


def test_registry_load_and_verify_have_a_production_caller() -> None:
    """The finding this module exists to close, asserted so it cannot reopen.

    A drift check with no production caller is a drift check that never runs. The
    assertion is on the AST of `startup.py` rather than on behaviour because the
    failure is an absence — no test of a request can notice a startup step that
    stopped happening.
    """
    import ast

    source = Path(startup.__file__).read_text("utf-8")
    called = {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "verify_schemas" in called, "startup no longer verifies schemas"
    assert "load" in called, "startup no longer loads the registry"
    assert hasattr(registry.Registry, "verify_schemas")

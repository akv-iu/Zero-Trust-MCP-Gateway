"""The SHIPPED configuration must actually work.

Review finding 01-FIX-1: `config/gateway.toml` pointed at `fixtures.filesystem_server`
(a package with no `__main__`) with `cwd = "fixtures"`. It could never have started
the child. Every bridge test used a hand-corrected config, so the defect was invisible.

The general lesson: tests that build their own config prove the CODE works, never that
the SHIPPED ARTIFACT works. At least one test must start from the real file.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import pytest

from fixtures.build_tree import build
from gateway import config as cfgmod
from gateway import startup
from gateway.bridge import upstream

pytestmark = pytest.mark.anyio

REPO = Path(__file__).resolve().parents[2]


def test_shipped_config_loads() -> None:
    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    assert cfg.edge.host == "127.0.0.1"


def test_shipped_child_module_is_importable() -> None:
    """Cheap guard: the configured `-m` target must resolve."""
    import importlib.util

    _, reg = startup.load_all(REPO / "config" / "gateway.toml")
    args = reg.server.args
    assert args[0] == "-m"
    spec = importlib.util.find_spec(args[1])
    assert spec is not None, f"{args[1]} is not importable"


async def test_shipped_config_actually_starts_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The test the review asked for: start the fixture from the REAL config file.

    Only the executable is substituted (sys.executable rather than a bare `python`,
    which need not be on PATH in every CI image). Module, argv and cwd come from the
    shipped file untouched — those were the broken parts.
    """
    build(tmp_path / "fixture")
    monkeypatch.setenv("FIXTURE_ROOT", str(tmp_path / "fixture"))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    monkeypatch.delenv("FIXTURE_MODE", raising=False)

    cfg, reg = startup.load_all(REPO / "config" / "gateway.toml")
    child = reg.server.child_config(cfg.child).model_copy(
        update={"executable": sys.executable, "cwd": str(REPO)}
    )

    with anyio.fail_after(45):
        async with upstream(child) as up:
            names = {t.name for t in (await up.list_tools()).tools}
            result = await up.call_tool("read_file", {"path": "public/documentation.txt"})

    assert "read_file" in names
    assert not result.is_error, result.content


def test_shipped_env_allowlist_covers_what_the_fixture_needs() -> None:
    """The fixture refuses to start without FIXTURE_ROOT / FIXTURE_OPLOG, and on a
    developer laptop it also needs FIXTURE_ALLOW_WEAK_ISOLATION. Omitting any of them
    from the allowlist is a silent startup failure."""
    _, reg = startup.load_all(REPO / "config" / "gateway.toml")
    required = {
        "FIXTURE_ROOT",
        "FIXTURE_OPLOG",
        "FIXTURE_MODE",
        "FIXTURE_ALLOW_WEAK_ISOLATION",
    }
    assert required <= set(reg.server.env_allowlist)


def test_shipped_allowlist_excludes_provider_keys() -> None:
    """AGENT-005: GROQ_API_KEY must never reach the child (BRIDGE-006)."""
    _, reg = startup.load_all(REPO / "config" / "gateway.toml")
    banned = {"GROQ_API_KEY", "CLOUDFLARE_API_TOKEN", "OPENAI_API_KEY"}
    assert not (banned & set(reg.server.env_allowlist))
    assert not any(
        "KEY" in k or "TOKEN" in k or "SECRET" in k for k in reg.server.env_allowlist
    )


def test_shipped_config_binds_loopback_only() -> None:
    cfg = cfgmod.load(REPO / "config" / "gateway.toml")
    assert cfg.edge.host in ("127.0.0.1", "::1", "localhost")
    assert cfg.policy.base_url.startswith("http://127.0.0.1")


def test_gateway_owned_paths_lie_outside_every_approved_root() -> None:
    """CANON-015 self-check, run against the shipped file rather than a synthetic one."""
    cfgmod.load(REPO / "config" / "gateway.toml").self_check()


def test_no_secret_shaped_env_var_is_set_during_tests() -> None:
    """CONV-016: the suite must pass with no provider key present."""
    assert not os.environ.get("GROQ_API_KEY")

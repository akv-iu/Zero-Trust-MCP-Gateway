"""Unit 01b acceptance tests - the stdio child leg.

These spawn the REAL fixture MCP server as a subprocess. They are the first tests in
the project with a moving part outside the process, so they are also the first that
can hang: every one is bounded by a deadline.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import anyio
import pytest

from fixtures.build_tree import build
from gateway.bridge import _child_env, upstream
from gateway.config import ChildConfig
from gateway.errors import GatewayDenial, ReasonCode, RouteDenial

pytestmark = pytest.mark.anyio

REPO = Path(__file__).resolve().parents[2]


def child_cfg(root: Path, oplog: Path, *, mode: str = "", **kw) -> ChildConfig:
    os.environ["FIXTURE_ROOT"] = str(root)
    os.environ["FIXTURE_OPLOG"] = str(oplog)
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ["FIXTURE_MODE"] = mode
    return ChildConfig(
        executable=sys.executable,
        args=("-m", "fixtures.filesystem_server.server"),
        cwd=str(REPO),
        env_allowlist=(
            "PATH", "PYTHONPATH", "SYSTEMROOT", "FIXTURE_ROOT",
            "FIXTURE_OPLOG", "FIXTURE_MODE", "FIXTURE_ALLOW_WEAK_ISOLATION",
        ),
        **kw,
    )


@pytest.fixture
def cfg(tmp_path: Path) -> ChildConfig:
    build(tmp_path / "fixture")
    return child_cfg(tmp_path / "fixture", tmp_path / "oplog.jsonl")


# ===========================================================================
# Handshake and calls
# ===========================================================================


async def test_child_starts_and_advertises_tools(cfg: ChildConfig) -> None:
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            names = {t.name for t in (await up.list_tools()).tools}
    assert "read_file" in names and "delete_file" in names


async def test_tool_call_reaches_the_fixture(cfg: ChildConfig, tmp_path: Path) -> None:
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            result = await up.call_tool("read_file", {"path": "public/documentation.txt"})
    assert not result.is_error, result.content
    assert "Public documentation" in result.content[0].text
    # The oracle's evidence: the fixture logged it at the far end.
    assert "public/documentation.txt" in (tmp_path / "oplog.jsonl").read_text("utf-8")


# ===========================================================================
# Launch parameters come from config and ONLY from config (BRIDGE-005 .. 007)
# ===========================================================================


def test_environment_is_allowlisted_not_inherited() -> None:
    """BRIDGE-006. With env=None the SDK inherits everything, which would leak
    GROQ_API_KEY to the child in v1.1."""
    os.environ["ZTMG_TEST_SECRET"] = "must-not-propagate"
    try:
        env = _child_env(ChildConfig(executable="x", cwd=".", env_allowlist=("PATH",)))
        assert "ZTMG_TEST_SECRET" not in env
        assert set(env) <= {"PATH"}
    finally:
        del os.environ["ZTMG_TEST_SECRET"]


async def test_shell_metacharacters_are_inert(cfg: ChildConfig, tmp_path: Path) -> None:
    """BRIDGE-005: an argv list performs no shell interpolation. The test guards a
    future refactor to a joined command string."""
    marker = tmp_path / "pwned.txt"
    payload = f"public/x.txt; touch {marker}; #"
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            # MCP returns tool failures as is_error results, not exceptions.
            result = await up.call_tool("read_file", {"path": payload})
    assert result.is_error, "the payload should fail as a filename, not succeed"
    assert not marker.exists(), "shell interpolation occurred - argv is being joined"


async def test_argv_is_exactly_what_was_configured(cfg: ChildConfig) -> None:
    """No client-supplied value can reach a launch parameter (REG-002)."""
    assert cfg.args == ("-m", "fixtures.filesystem_server.server")
    assert isinstance(cfg.args, tuple)


# ===========================================================================
# Failure behaviour
# ===========================================================================


async def test_missing_executable_denies_rather_than_hanging(tmp_path: Path) -> None:
    bad = ChildConfig(
        executable=str(tmp_path / "does-not-exist"),
        cwd=str(REPO),
        startup_timeout_s=5.0,
    )
    with anyio.fail_after(30):
        with pytest.raises(RouteDenial) as exc:
            async with upstream(bad):
                pass
    assert exc.value.reason_code is ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE


async def test_crashing_child_denies_and_is_not_retried(
    tmp_path: Path, cfg: ChildConfig
) -> None:
    """BRIDGE-011: a dead child is a denial. It is never restarted mid-request and
    completed as though nothing happened."""
    build(tmp_path / "fixture2")
    crash = child_cfg(tmp_path / "fixture2", tmp_path / "oplog2.jsonl", mode="crash")
    with anyio.fail_after(60):
        with pytest.raises(RouteDenial) as exc:
            async with upstream(crash) as up:
                await up.call_tool("read_file", {"path": "public/documentation.txt"})
    assert exc.value.reason_code is ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE
    # The child died before performing anything: no successful operation logged.
    log = tmp_path / "oplog2.jsonl"
    assert '"outcome": "ok"' not in (log.read_text("utf-8") if log.exists() else "")


async def test_calls_after_teardown_are_denied(cfg: ChildConfig) -> None:
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            pass
        with pytest.raises(RouteDenial):
            await up.call_tool("read_file", {"path": "public/documentation.txt"})


async def test_no_child_process_survives_teardown(cfg: ChildConfig) -> None:
    """BRIDGE-009. A leaked child outliving the gateway is a real operational hazard."""
    before = _python_child_count()
    with anyio.fail_after(30):
        async with upstream(cfg):
            pass
    await anyio.sleep(0.5)
    assert _python_child_count() <= before


def _python_child_count() -> int:
    if os.name == "nt":
        out = os.popen('tasklist /FI "IMAGENAME eq python.exe" /NH').read()
        return out.count("python.exe")
    return int(os.popen("pgrep -c -f fixtures.filesystem_server || true").read() or 0)


# ===========================================================================
# Serialisation - the oracle's correlation depends on it
# ===========================================================================


async def test_upstream_calls_are_serialised(cfg: ChildConfig, tmp_path: Path) -> None:
    """Offset-window correlation in harness.oracle is only valid while one upstream
    call is in flight at a time."""
    with anyio.fail_after(60):
        async with upstream(cfg) as up:
            async with anyio.create_task_group() as tg:
                for _ in range(5):
                    tg.start_soon(up.call_tool, "read_file", {"path": "public/changelog.md"})
    assert (tmp_path / "oplog.jsonl").exists(), "no operation reached the fixture"

    ops = [
        ln for ln in (tmp_path / "oplog.jsonl").read_text("utf-8").splitlines() if ln.strip()
    ]
    # attempt+end pairs must not interleave: every attempt is immediately followed
    # by its own end record.
    import json

    phases = [json.loads(ln)["phase"] for ln in ops]
    assert phases == ["attempt", "end"] * 5, phases


# ===========================================================================
# Review follow-ups: stderr capture, cancellation, caller-exception passthrough
# ===========================================================================


async def test_child_stderr_is_captured_and_bounded(cfg: ChildConfig) -> None:
    """BRIDGE-010. An undrained stderr pipe fills its OS buffer and deadlocks the
    child; an unbounded one lets a looping child exhaust memory."""
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            await up.list_tools()
            diags = up.diagnostics()
    assert diags, "child stderr was not captured at all"
    assert any("filesystem-fixture" in line for line in diags)
    assert len(diags) <= cfg.stderr_capture_lines


def test_stderr_ring_is_bounded() -> None:
    from collections import deque

    from gateway.bridge import MAX_STDERR_LINE, append_line

    ring: deque[str] = deque(maxlen=4)
    for i in range(100):
        append_line(ring, "line %d\n" % i)
    assert len(ring) == 4 and ring[-1] == "line 99"
    append_line(ring, "x" * 5000)  # a child emitting one endless line
    assert all(len(line) <= MAX_STDERR_LINE for line in ring)


def test_a_child_emitting_no_newline_at_all_cannot_exhaust_memory() -> None:
    """Review finding: `append_line` bounds what is STORED; nothing bounded what was
    BUFFERED while waiting for a newline. Line-iterating a stream accumulates until
    one arrives, so a child looping on `write("x")` grew the reader without limit and
    the ring stayed empty the whole time — the bound that existed never engaged.

    The assertion that matters is the one on TIMING, not on the contents at the end.
    A test that writes a flood, then a newline, then inspects the ring passes on the
    leaking implementation too: it eventually emits the same truncated line, having
    held the whole flood in memory to get there. So this waits for the cut to happen
    while the line is still open, which only a bounded reader can do.
    """
    import os
    import threading
    import time
    from collections import deque

    from gateway.bridge import MAX_STDERR_LINE, TRUNCATED, _drain_stderr

    read_fd, write_fd = os.pipe()
    ring: deque[str] = deque(maxlen=8)
    drainer = threading.Thread(target=_drain_stderr, args=(read_fd, ring), daemon=True)
    drainer.start()

    w = os.fdopen(write_fd, "wb")
    try:
        blob = b"x" * 65536  # 8 MiB, without a single newline in it
        for _ in range(128):
            w.write(blob)
        w.flush()

        deadline = time.monotonic() + 10
        while not ring and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ring, "8 MiB buffered with nothing emitted: the reader is unbounded"
        assert ring[0].endswith(TRUNCATED)

        w.write(b"\nrecovered\n")  # the runaway line finally ends
        w.flush()
    finally:
        w.close()
    drainer.join(timeout=10)

    assert not drainer.is_alive()
    assert ring[-1] == "recovered", "the drainer never resynchronised after the flood"
    assert len(ring) == 2, f"one flood should cost one ring entry, got {list(ring)}"
    assert all(len(line) <= MAX_STDERR_LINE for line in ring)


async def test_a_crashed_child_denies_at_the_call_site(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cfg: ChildConfig
) -> None:
    """BRIDGE-011, and the review's sharpest finding.

    The child dies mid-call. The SDK reports that as `MCPError(CONNECTION_CLOSED)`,
    which is neither a broken anyio stream nor an OSError — so it flew straight past
    the handler and reached the caller as a raw MCP error. The clean denial only
    appeared later, when the whole child context unwound. By then the caller has
    already been handed the thing it was promised it would never see.

    The assertion is on the exception RAISED BY `call_tool`, not on what escapes the
    `async with`: that distinction IS the finding.
    """
    monkeypatch.setenv("FIXTURE_MODE", "crash")
    with anyio.fail_after(45):
        async with upstream(cfg) as up:
            with pytest.raises(RouteDenial) as caught:
                await up.call_tool("read_file", {"path": "public/documentation.txt"})
            assert caught.value.reason_code is ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE
            assert up.alive is False, "a dead child must not be offered for reuse"


async def test_cancellation_notification_is_accepted_by_the_child(
    cfg: ChildConfig,
) -> None:
    """The notification must be a real typed ClientNotification.

    A malformed dict was previously sent inside a bare `except Exception: pass`, so
    it failed silently and the audit trail would have claimed an upstream
    cancellation that never happened.
    """
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            assert await up.cancel(request_id=1, reason="test") is True


async def test_cancel_reports_failure_when_the_child_is_gone(cfg: ChildConfig) -> None:
    with anyio.fail_after(30):
        async with upstream(cfg) as up:
            pass
        assert await up.cancel(request_id=1) is False


async def test_a_caller_denial_survives_the_context_manager(cfg: ChildConfig) -> None:
    """Unwrapping ExceptionGroups must not swallow the caller's own GatewayDenial."""
    sentinel = GatewayDenial(ReasonCode.CANON_OUTSIDE_ROOT)
    with anyio.fail_after(30):
        with pytest.raises(GatewayDenial) as exc:
            async with upstream(cfg):
                raise sentinel
    assert exc.value.reason_code is ReasonCode.CANON_OUTSIDE_ROOT

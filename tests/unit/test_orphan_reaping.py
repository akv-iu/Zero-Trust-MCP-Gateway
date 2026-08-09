"""BRIDGE-009: no child process may outlive the gateway, INCLUDING on abnormal exit.

Review finding 01-FIX-7: the previous test only covered a clean `async with` exit,
which proves nothing interesting. The case that matters is the gateway being killed
outright — `atexit` and signal handlers do not run, so only OS-level process-group or
job-object semantics save you.

A leaked child is a real hazard here: it keeps the fixture sandbox open and keeps
writing to the operation log the oracle reads, which would corrupt later evidence.

WHY IT CURRENTLY PASSES, stated plainly: reaping works because the child honours
stdin EOF. When the gateway dies its pipes close, the child reads EOF and exits —
the portable mechanism the stdio spec calls "the primary graceful-shutdown signal
and the only portable one". It is NOT a process group or a Windows Job Object.

That means the guarantee is only as strong as the upstream server's manners. A child
that ignores EOF (or blocks before reading it) WOULD leak, and this test would catch
it. If a real upstream ever does that, implement the Job Object / process-group path
from _tech/01 §3 rather than weakening this test.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fixtures.build_tree import build

REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "tests" / "helpers" / "orphan_parent.py"


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, check=False,
        ).stdout
        return str(pid) in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for(predicate, timeout: float = 15.0, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.slow
def test_child_does_not_survive_an_abnormal_gateway_death(tmp_path: Path) -> None:
    build(tmp_path / "fixture")
    pidfile = tmp_path / "child.pid"

    env = {
        **os.environ,
        "FIXTURE_ROOT": str(tmp_path / "fixture"),
        "FIXTURE_OPLOG": str(tmp_path / "oplog.jsonl"),
        "FIXTURE_PIDFILE": str(pidfile),
        "FIXTURE_ALLOW_WEAK_ISOLATION": "1",
        "FIXTURE_MODE": "",
        "PYTHONPATH": str(REPO),
    }

    parent = subprocess.Popen(
        [sys.executable, str(HELPER)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    try:
        assert wait_for(lambda: pidfile.exists()), "child never started"
        child_pid = int(pidfile.read_text(encoding="utf-8").strip())
        assert pid_alive(child_pid), "child was not running before the kill"

        # Kill the PARENT ONLY - hard, no cleanup handlers. Do not use taskkill /T
        # or killpg here: those would kill the tree and prove nothing.
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(parent.pid)],
                           capture_output=True, check=False)
        else:
            os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=15)

        reaped = wait_for(lambda: not pid_alive(child_pid), timeout=20.0)
        if not reaped:
            _force_kill(child_pid)
            pytest.fail(
                f"ORPHAN: child pid {child_pid} outlived an abnormally killed gateway. "
                "BRIDGE-009 requires OS-level reaping (POSIX process group, or a "
                "Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)."
            )
    finally:
        if parent.poll() is None:
            parent.kill()
        if pidfile.exists():
            _force_kill(int(pidfile.read_text(encoding="utf-8").strip()))


def _force_kill(pid: int) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, check=False)
        else:
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass

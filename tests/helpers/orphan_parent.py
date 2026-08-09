"""Holds a live child, then waits to be killed. Used by the orphan-reaping test.

Run as a subprocess so the test can terminate it ABNORMALLY (SIGKILL / taskkill /F),
which is the case BRIDGE-009 actually cares about: atexit handlers and signal
handlers do not run, so only OS-level process-group or job-object semantics save you.
"""

import os
import sys
from pathlib import Path

import anyio

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gateway.bridge import upstream  # noqa: E402
from gateway.config import ChildConfig  # noqa: E402


async def main() -> None:
    cfg = ChildConfig(
        executable=sys.executable,
        args=("-m", "fixtures.filesystem_server.server"),
        cwd=str(Path(__file__).resolve().parents[2]),
        env_allowlist=(
            "PATH",
            "PYTHONPATH",
            "SYSTEMROOT",
            "FIXTURE_ROOT",
            "FIXTURE_OPLOG",
            "FIXTURE_MODE",
            "FIXTURE_ALLOW_WEAK_ISOLATION",
            "FIXTURE_PIDFILE",
        ),
    )
    async with upstream(cfg) as up:
        await up.list_tools()
        print("READY", flush=True)
        await anyio.sleep(300)


if __name__ == "__main__":
    os.environ.setdefault("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    anyio.run(main)

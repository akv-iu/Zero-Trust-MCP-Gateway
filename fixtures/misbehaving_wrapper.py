"""Wire-level misbehaviour: the three modes that must corrupt bytes (FIX-010).

`malformed`, `wrong_id` and `unsolicited` cannot be produced from inside the fixture.
The SDK owns JSON-RPC framing and correlation, and it will not emit an unparseable
line, a mismatched id, or a message nobody asked for. So this process sits between
the gateway and the honest fixture and edits the stream:

    gateway <--stdio--> misbehaving_wrapper <--stdio--> filesystem_server

Spawn it INSTEAD of the server, with the same environment:

    [child]
    args = ["-m", "fixtures.misbehaving_wrapper"]

Only responses to `tools/call` are corrupted. The handshake and `tools/list` pass
through untouched, or the gateway never gets far enough to reach the code under test.

Imports nothing from `gateway/` — the evidence chain forbids it (FIX-002).
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from contextlib import suppress
from typing import Any

from fixtures.filesystem_server import modes

CHILD_ARGV = [sys.executable, "-m", "fixtures.filesystem_server.server"]


def _pump_requests(stdin: Any, child_stdin: Any, targets: set[Any]) -> None:
    """Gateway -> fixture, unmodified, noting which ids are `tools/call`."""
    try:
        for line in stdin:
            try:
                msg = json.loads(line)
                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    targets.add(msg.get("id"))
            except (ValueError, UnicodeDecodeError):
                pass  # not our problem: forward whatever the gateway sent
            child_stdin.write(line)
            child_stdin.flush()
    except (OSError, ValueError):
        pass
    finally:
        # EOF upward must become EOF downward, or the child never exits (BRIDGE-009).
        with suppress(OSError, ValueError):
            child_stdin.close()


def main() -> None:
    mode = modes.current()
    if mode not in modes.WIRE_LEVEL:
        raise SystemExit(
            f"misbehaving_wrapper is only for {sorted(modes.WIRE_LEVEL)}; "
            f"FIXTURE_MODE={mode!r} runs inside the server itself"
        )

    child = subprocess.Popen(
        CHILD_ARGV,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # the child's stderr is already the gateway's captured pipe
    )
    assert child.stdin is not None and child.stdout is not None

    targets: set[Any] = set()
    threading.Thread(
        target=_pump_requests,
        args=(sys.stdin.buffer, child.stdin, targets),
        daemon=True,
        name="wrapper-up",
    ).start()

    out = sys.stdout.buffer
    for line in child.stdout:
        for emitted in modes.apply_to_wire(mode, line.rstrip(b"\r\n"), targets):
            out.write(emitted + b"\n")
            out.flush()

    raise SystemExit(child.wait())


if __name__ == "__main__":
    main()

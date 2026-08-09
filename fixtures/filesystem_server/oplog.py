"""The operation log — the fixture's own record of what it actually did.

FIX-008. This is the highest-stakes component in the fixture, and arguably in the
project. Every "the gateway blocked it" verdict is proven by the ABSENCE of an entry
here. An operation performed but not logged produces a false "blocked" result, which
is the worst failure this project can have.

Two defences against that:
  1. Logging wraps the syscall itself, so there is no code path that performs an
     operation without logging it.
  2. An "attempted" record is written BEFORE the operation. If the process dies
     mid-write, the attempt is still on disk.

Written outside the fixture tree so the fixture cannot read or corrupt its own
evidence, and fsynced per record so `crash` mode (os._exit) cannot lose one.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def oplog_path() -> Path:
    return Path(os.environ.get("FIXTURE_OPLOG", "var/oplog.jsonl"))


def _append(entry: dict[str, Any]) -> None:
    p = oplog_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


@contextmanager
def oplog(operation: str, requested: str, root: Path) -> Iterator[dict[str, Any]]:
    """Record one operation. Yields the entry so the body can add detail."""
    seq = _next_seq()
    base = {
        "seq": seq,
        "op": operation,
        "requested": requested,
        "pid": os.getpid(),
        # What the naive fixture will actually touch — the escape, if there is one.
        "resolved": _naive_resolve(root, requested),
    }
    _append({**base, "phase": "attempt", "ts": _now(), "outcome": "attempted"})
    entry: dict[str, Any] = dict(base)
    try:
        yield entry
        entry["outcome"] = "ok"
    except Exception as e:
        entry["outcome"] = f"error:{type(e).__name__}"
        raise
    finally:
        _append({**entry, "phase": "end", "ts": _now()})


def _naive_resolve(root: Path, requested: str) -> str:
    """Where the fixture's own naive join lands. NOT a security check (FIX-007)."""
    try:
        return str((root / requested).absolute())
    except (OSError, ValueError):
        return "<unresolvable>"


_seq = 0


def _next_seq() -> int:
    global _seq
    _seq += 1
    return _seq


def _now() -> str:
    return datetime.now(UTC).isoformat()


# -- reader, for the oracle ------------------------------------------------


def read_ops(path: Path | None = None, *, offset: int = 0) -> list[dict[str, Any]]:
    """Entries appended after byte `offset`. The oracle's correlation window."""
    p = Path(path) if path else oplog_path()
    if not p.exists():
        return []
    with p.open("rb") as fh:
        fh.seek(offset)
        raw = fh.read().decode("utf-8")
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def size(path: Path | None = None) -> int:
    p = Path(path) if path else oplog_path()
    return p.stat().st_size if p.exists() else 0

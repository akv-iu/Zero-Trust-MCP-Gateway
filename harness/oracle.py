"""The side-effect oracle. The most important component in the project.

HARN-005 / CONV-018: a denial is proven by observing the PROTECTED SYSTEM, never by
the gateway's own output. A gateway that says "denied" while quietly performing the
operation is the exact failure this project exists to catch, and only the oracle can
see it.

HARN-006: two independent sources, both required.
  - Tree hashing alone misses READS. A confidential file read changes no state, and
    reads are the most common expected violation in this corpus.
  - The operation log alone misses an operation the fixture failed to log.
Together they cover both.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fixtures.build_tree import tree_hash
from fixtures.filesystem_server.oplog import read_ops, size


@dataclass(frozen=True)
class Effect:
    """One observed operation at the protected system."""

    op: str
    requested: str
    resolved: str
    outcome: str

    @property
    def succeeded(self) -> bool:
        return self.outcome == "ok"


@dataclass
class Observation:
    ops: tuple[Effect, ...] = ()
    tree_before: str = ""
    tree_after: str = ""
    attempted_only: tuple[Effect, ...] = field(default_factory=tuple)

    @property
    def state_changed(self) -> bool:
        return self.tree_before != self.tree_after

    @property
    def effects(self) -> tuple[Effect, ...]:
        """Operations that actually succeeded — disclosures included."""
        return tuple(e for e in self.ops if e.succeeded)

    @property
    def any_effect(self) -> bool:
        """True if the protected system was read OR modified.

        A read is an effect. `state_changed` alone would score a confidential-file
        disclosure as "nothing happened", which is the single most dangerous possible
        false negative in this harness.
        """
        return bool(self.effects) or self.state_changed


class Oracle:
    """Snapshot before a scenario, observe after."""

    def __init__(self, root: Path, oplog: Path | None = None) -> None:
        self.root = Path(root)
        self.oplog = Path(oplog) if oplog else Path(os.environ["FIXTURE_OPLOG"])
        self._tree_before = ""
        self._offset = 0

    def snapshot(self) -> None:
        self._tree_before = tree_hash(self.root)
        self._offset = size(self.oplog)

    def observe(self) -> Observation:
        """Everything the fixture did since `snapshot()`.

        Correlation is by byte offset into the operation log, which is valid only
        while upstream calls are serialised (TECH-01 §5). `assert_serialised()`
        enforces that rather than trusting it.
        """
        raw = read_ops(self.oplog, offset=self._offset)
        ended = [o for o in raw if o.get("phase") == "end"]
        attempted = [o for o in raw if o.get("phase") == "attempt"]
        return Observation(
            ops=tuple(_effect(o) for o in ended),
            tree_before=self._tree_before,
            tree_after=tree_hash(self.root),
            attempted_only=tuple(
                _effect(o) for o in attempted if o["seq"] not in {e["seq"] for e in ended}
            ),
        )


def _effect(o: dict[str, Any]) -> Effect:
    return Effect(
        op=o["op"],
        requested=o["requested"],
        resolved=o.get("resolved", ""),
        outcome=o.get("outcome", "attempted"),
    )


def assert_serialised(max_concurrent: int) -> None:
    """Offset-window correlation breaks under concurrency. Fail loudly, not subtly."""
    if max_concurrent != 1:
        raise RuntimeError(
            "oracle correlation assumes one in-flight upstream call; "
            f"max_concurrent_requests={max_concurrent}. Security scenarios must run "
            "with concurrency 1 (performance scenarios assert no side effects "
            "and are exempt)."
        )

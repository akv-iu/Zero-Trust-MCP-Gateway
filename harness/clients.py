"""Execution modes. Two implementations of one protocol.

This is the one place in the project where a Protocol with two implementations is
justified: the same scenario body must run against either path, and the paired
benchmark alternates between them within a single run (HARN-014).

HARN-001: `direct` exists only to demonstrate the unsafe baseline against synthetic
fixtures. It MUST NOT be reachable from any protected client configuration, so its
constructor refuses unless the harness explicitly enables it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from fixtures.filesystem_server import tools

ALLOW_DIRECT_ENV = "ZTMG_ALLOW_DIRECT"


@dataclass(frozen=True)
class CallOutcome:
    """What the client observed. Deliberately NOT evidence of a side effect."""

    decision: str  # "allow" | "deny"
    reason_code: str | None = None
    result: Any = None
    error: str | None = None


@runtime_checkable
class Client(Protocol):
    mode: str

    def call(self, tool: str, arguments: dict[str, Any]) -> CallOutcome: ...


class DirectClient:
    """Test driver straight to the fixture. No gateway, no policy, no protection.

    Every call reports `allow` because nothing is deciding anything. That is not a
    bug — scoring a malicious scenario against this client is what produces the
    unprotected baseline.
    """

    mode = "direct"

    def __init__(self) -> None:
        if os.environ.get(ALLOW_DIRECT_ENV) != "1":
            raise RuntimeError(
                f"direct mode requires {ALLOW_DIRECT_ENV}=1. It bypasses the gateway "
                "entirely and must never be reachable from a protected configuration."
            )

    def call(self, tool: str, arguments: dict[str, Any]) -> CallOutcome:
        try:
            return CallOutcome(decision="allow", result=tools.call(tool, arguments))
        except Exception as e:  # noqa: BLE001 - the fixture's failure is data
            # NOTE: an upstream error is NOT a denial. Nothing authorised anything;
            # the operation was attempted and failed. The oracle still sees the attempt.
            return CallOutcome(decision="allow", error=f"{type(e).__name__}: {e}")


class ProtectedClient:
    """Test driver -> gateway -> fixture. The system under test.

    Implemented when unit 01 lands. Until then the harness runs `direct` only, which
    is exactly the week-1 gate: establish the baseline before building the guard.
    """

    mode = "protected"

    def call(self, tool: str, arguments: dict[str, Any]) -> CallOutcome:
        raise NotImplementedError("ProtectedClient requires unit 01 (transport edge)")

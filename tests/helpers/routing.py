"""Request/decision factories shared by every test that drives unit 07.

These lived in `test_router.py` alone until `test_wire_modes.py` needed to drive a
corrupted child through the REAL router rather than through the bridge. Copying them
would have let the two files disagree about what a valid `Decision` looks like — and
a stale copy here is exactly the shape that makes a routing test pass against a
binding the production code no longer accepts.

`helpers` is importable from any test module: pytest puts `tests/` on `sys.path`
because `tests/conftest.py` sits there with no `__init__.py`.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

from gateway import hashing
from gateway.context import current_audit
from gateway.errors import ReasonCode
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    Decision,
    DerivedAttributes,
    Obligations,
)


class AuditProbe:
    """Stands in for the AuditBuilder so a stage's writes can be read back.

    `gateway.context.audit()` raises `LookupError` outside a request, deliberately —
    so any test driving a stage directly must install one of these or the stage
    cannot run at all.
    """

    def __init__(self) -> None:
        self.fields: dict[str, Any] = {}

    def set(self, **values: Any) -> None:
        self.fields.update(values)


@pytest.fixture
def audit_probe() -> Generator[AuditProbe]:
    probe = AuditProbe()
    token = current_audit.set(probe)
    try:
        yield probe
    finally:
        current_audit.reset(token)


def request(
    *,
    request_id: str = "route-1",
    method: str = "tools/call",
    tool: str | None = "read_file",
    arguments: dict[str, Any] | None = None,
) -> CanonicalRequest:
    return CanonicalRequest(
        request_id=request_id,
        protocol_version="2026-07-28",
        method=method,
        jsonrpc_id=1,
        tool_name=tool,
        arguments=(
            arguments if arguments is not None else {"path": "%70ublic/documentation.txt"}
        ),
        body_hash="body",
    )


def derived(req: CanonicalRequest) -> DerivedAttributes:
    canonical = "C:/fixture/public/documentation.txt" if req.tool_name else ""
    return DerivedAttributes(
        canonical_path=canonical,
        root="public" if req.tool_name else "",
        operation="read",
        classification="public",
        exists=True,
        arg_hash=hashing.argument_hash(req.arguments, canonical),
        raw_hash="raw",
        path_argument="path" if req.tool_name else "",
        relative_path="public/documentation.txt" if req.tool_name else "",
    )


def decision(
    req: CanonicalRequest,
    drv: DerivedAttributes,
    *,
    request_id: str | None = None,
    method: str | None = None,
    tool: str | None = None,
    timeout_ms: int = 1_000,
    max_response_bytes: int = 1_048_576,
) -> Decision:
    return Decision(
        request_id=request_id or req.request_id,
        method=method or req.method,
        tool_name=req.tool_name if tool is None else tool,
        decision="allow",
        reason_code=ReasonCode.POLICY_SCOPED_READ.value,
        risk_tier="R1",
        policy_revision="policy-test",
        obligations=Obligations(
            timeout_ms=timeout_ms, max_response_bytes=max_response_bytes
        ),
        arg_hash=drv.arg_hash,
    )


def context() -> AuthzContext:
    return AuthzContext(
        principal="developer",
        client_id="router-tests",
        roles=("developer",),
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )


class Upstream:
    def __init__(self, result: Any | None = None) -> None:
        self.result: Any = result if result is not None else {"content": []}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((tool, arguments))
        return self.result

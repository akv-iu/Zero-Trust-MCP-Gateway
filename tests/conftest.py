"""Shared test setup and suite-wide invariants.

The invariants below are autouse rather than individual tests on purpose: each one
guards against a mistake that could be introduced by ANY module, so checking them
once per run beats hoping the right unit test exists.
"""

from __future__ import annotations

from typing import Any

import pytest

from gateway.audit import AuditSink
from gateway.audit_schema import AuditRecord, RequestEvent


@pytest.fixture
def anyio_backend() -> str:
    """Pin to asyncio. Do not parametrise over trio — the MCP SDK targets asyncio."""
    return "asyncio"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Everything under `tests/integration/` is `slow` by definition.

    The marker existed but had been applied by hand to five tests, so
    `-m "not slow"` — the fast lane the review gate tells you to iterate on — saved
    twelve seconds out of three minutes. A marker that has to be remembered is a
    marker that stops being true, and this one had.

    Directory rather than per-test, because "integration" already means "spawns a
    gateway, a child, or OPA". Expensive UNIT tests still need the explicit marker:
    they sit beside fast ones in the same module, so nothing structural distinguishes
    them.
    """
    for item in items:
        if "integration" in item.path.parts:
            item.add_marker(pytest.mark.slow)


# ===========================================================================
# IDENT-002 / spec-03 test 2 — the gateway never claims verified identity
# ===========================================================================
#
# Scanning EVERY record the whole session emits, not one test's output. The failure
# this guards is a single code path in some other module inventing a value: a
# per-test assertion would only cover the events that test happened to look at, and
# an audit record labelling a locally configured principal as authenticated is a lie
# that invalidates every downstream evidence claim in the project.
#
# Implemented by teeing the sink rather than by reading files: most tests write to a
# `tmp_path` that pytest deletes, so a `pytest_sessionfinish` file scan would silently
# check almost nothing — passing not because identity is honest but because there was
# nothing left to read.

_EMITTED: list[AuditRecord] = []

VERIFICATION_WORDS = frozenset(
    {"oidc", "authenticated", "verified", "jwt", "bearer", "mtls", "saml"}
)
"""Values that would imply cryptographic verification. v1 can produce none of them —
`AuthzContext` makes them unrepresentable — so this is a tripwire on the schema
being widened without the claim being re-examined (IDENT-002)."""


@pytest.fixture(autouse=True, scope="session")
def audit_events() -> Any:
    """Tee every written record, then assert the identity invariant over all of them.

    YIELDS the list rather than exposing the module global. pytest imports this file
    as top-level module `conftest`, so a test doing `from tests.conftest import
    _EMITTED` gets a SECOND module object with its own empty list — the tee looks
    broken while working perfectly. Requesting the fixture is the only way to reach
    the instance pytest is actually using.
    """
    original = AuditSink.write_sync

    def tee(self: AuditSink, event: AuditRecord) -> None:
        _EMITTED.append(event)
        return original(self, event)

    AuditSink.write_sync = tee  # type: ignore[method-assign]
    try:
        yield _EMITTED
    finally:
        AuditSink.write_sync = original  # type: ignore[method-assign]

    # No emptiness guard here: running one test file is normal, and a file that
    # emits no request events would then fail for a reason that has nothing to do
    # with it. That the tee actually captures records is proved by
    # `test_identity.py::test_the_session_invariant_sees_written_records`, which is
    # an ordinary test and therefore fails loudly if the mechanism breaks.
    for event in (e for e in _EMITTED if isinstance(e, RequestEvent)):
        # Checked INDEPENDENTLY, not gated on auth_method being present. Skipping
        # the whole record when `auth_method is None` (Codex review finding) let an
        # assurance-only claim through unexamined, and would have hidden a record
        # that named an assurance while omitting the method that produced it.
        if event.auth_method is not None:
            assert event.auth_method == "local_config", (
                f"{event.request_id}: auth_method={event.auth_method!r} — the "
                "gateway claimed an identity it cannot verify (IDENT-002)"
            )
            assert event.auth_method.lower() not in VERIFICATION_WORDS
        if event.assurance is not None:
            assert event.assurance == "unverified_local", (
                f"{event.request_id}: assurance={event.assurance!r} (IDENT-002)"
            )
            assert event.assurance.lower() not in VERIFICATION_WORDS

        # If stage 03 ran at all, every field it owns must be on the record. The
        # earlier version let a half-labelled event pass by treating an absent
        # auth_method as "identity never resolved" — which is indistinguishable, from
        # the record alone, from "identity resolved and the wiring dropped it".
        if "identity" in event.stage_latency_ms:
            missing = [
                f
                for f in ("principal", "client_id", "auth_method", "assurance")
                if getattr(event, f) is None
            ]
            assert not missing, (
                f"{event.request_id}: stage 03 ran but the record is missing "
                f"{missing} — the pipeline is not persisting what identity resolved"
            )

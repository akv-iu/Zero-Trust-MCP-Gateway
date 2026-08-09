"""Shared test setup and suite-wide invariants.

The invariants below are autouse rather than individual tests on purpose: each one
guards against a mistake that could be introduced by ANY module, so checking them
once per run beats hoping the right unit test exists.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def anyio_backend() -> str:
    """Pin to asyncio. Do not parametrise over trio — the MCP SDK targets asyncio."""
    return "asyncio"

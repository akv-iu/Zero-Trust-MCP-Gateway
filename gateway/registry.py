"""04 - Approved servers, tools, schema fingerprints, drift.

Spec: _specs/04-svc-registry.md   Tech: _tech/04-svc-registry.md
Owner: wave 2, agent E.
"""

from __future__ import annotations

from typing import Any

from gateway.types import AuthzContext, CanonicalRequest, ResolvedTarget


class Registry:
    """Loaded once at startup into a frozen structure. Restart is the reload."""

    def resolve(
        self, req: CanonicalRequest, ctx: AuthzContext
    ) -> ResolvedTarget:  # pragma: no cover
        raise NotImplementedError("wave 2, agent E")

    def visible_tools(self, ctx: AuthzContext) -> list[Any]:  # pragma: no cover
        """tools/list filtering. MUST share its predicate with resolve (REG-011)."""
        raise NotImplementedError("wave 2, agent E")


def resolve(
    req: CanonicalRequest, ctx: AuthzContext, reg: Registry
) -> ResolvedTarget:
    raise NotImplementedError("wave 2, agent E")

"""Per-request context, carried by contextvar so stage signatures stay clean.

`_tech/00-conventions.md` §5. Unit 09 sets `current_audit`; every stage reads it.

WAVE-0 FILE — shared spine. Parallel agents MUST NOT edit this.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid importing unit 09 at module load
    from gateway.audit import AuditBuilder

current_audit: ContextVar[Any] = ContextVar("current_audit")
"""The request's AuditBuilder. Typed Any to keep the spine free of unit imports;
consumers annotate locally as `AuditBuilder`."""


def audit() -> AuditBuilder:
    """The current request's audit builder.

    Raises LookupError outside a request — deliberately. A stage running with no
    audit builder would produce an unrecorded decision (AUDIT-001).
    """
    return current_audit.get()

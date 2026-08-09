"""Emit policies/reason_codes.json from the ReasonCode enum.

The enum is the single source of truth; Rego loads the JSON as data.reason_codes.
tests/unit/test_foundation.py fails if they drift.

Run: python -m scripts.sync_reason_codes
"""

from __future__ import annotations

import json
from pathlib import Path

from gateway.errors import ADVISORY_CODES, ALLOW_CODES, ReasonCode

OUT = Path(__file__).resolve().parents[1] / "policies" / "reason_codes.json"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "codes": sorted(c.value for c in ReasonCode),
                "allow": sorted(c.value for c in ALLOW_CODES),
                "advisory": sorted(c.value for c in ADVISORY_CODES),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT} ({len(ReasonCode)} codes)")


if __name__ == "__main__":
    main()

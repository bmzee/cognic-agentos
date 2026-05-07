"""Sprint-7A T11 — ADR-014 risk-tier consistency validator.

T6 ships this as a stub returning ``[]``. T11 replaces the stub
body with the risk-tier-vs-data-classes consistency check.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T11 wires the ADR-014 risk-tier consistency check."""
    del data, pack_path  # placeholders until T11
    return []


__all__ = ["validate"]

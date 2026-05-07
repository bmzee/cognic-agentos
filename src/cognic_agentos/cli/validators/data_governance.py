"""Sprint-7A T10 — ADR-017 data-governance validator (CRITICAL CONTROLS).

T6 ships this as a stub returning ``[]``. T10 replaces the stub
body with the ADR-017 contract checks (data_classes / purpose /
retention / egress_allowlist; cross-checks with risk_tier + mcp
caching).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T10 wires the ADR-017 data-governance contract checks."""
    del data, pack_path  # placeholders until T10
    return []


__all__ = ["validate"]

"""Sprint-7A T9 — MCP conformance validator.

T6 ships this as a stub returning ``[]``. T9 replaces the stub body
with Wave-1 MCP checks (Wave-2 features, caching/elicitation_form
on restricted data classes).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T9 wires Wave-1 MCP conformance checks."""
    del data, pack_path  # placeholders until T9
    return []


__all__ = ["validate"]

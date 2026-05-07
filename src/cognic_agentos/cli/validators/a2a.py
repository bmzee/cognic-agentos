"""Sprint-7A T8 — A2A conformance validator.

T6 ships this as a stub returning ``[]``. T8 replaces the stub body
with Wave-1 A2A capability checks (Wave-2 features in a Wave-1
manifest trip ``a2a_wave2_feature_in_wave1_manifest``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T8 wires Wave-1 A2A conformance checks."""
    del data, pack_path  # placeholders until T8
    return []


__all__ = ["validate"]

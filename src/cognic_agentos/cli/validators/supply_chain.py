"""Sprint-7A T12 — ADR-016 supply-chain validator (CRITICAL CONTROLS).

T6 ships this as a stub returning ``[]``. T12 replaces the stub
body with the attestation-paths existence checks.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T12 wires the ADR-016 attestation-paths existence checks."""
    del data, pack_path  # placeholders until T12
    return []


__all__ = ["validate"]

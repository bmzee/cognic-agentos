"""Sprint-7A T7 — AGNTCY/OASF identity validator.

T6 ships this as a stub returning ``[]``. T7 replaces the stub body
with the real Wave-1 identity-matrix checks (agent_id /
display_name / provider_organization / provider_url /
agent_card_url / agent_card_jws_path; capability_set as a warning).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Stub — T7 wires the real Wave-1 identity-matrix checks."""
    del data, pack_path  # placeholders until T7
    return []


__all__ = ["validate"]

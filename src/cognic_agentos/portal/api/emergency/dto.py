"""Sprint 13.6 T6 — emergency portal DTOs (ADR-018 §Portal API).

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED per the
standing FastAPI route/DTO module convention. The wire field for the switch
class is ``class`` (matching the chain payload key); the Python attribute is
``class_`` via alias.
"""

import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cognic_agentos.core.emergency.kill_switches import (
    EnforcementStatus,
    KillSwitchCategory,
    KillSwitchClass,
)

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class KillSwitchFlipRequest(BaseModel):
    """POST /kill-switches body — the mandatory categorised reason per
    ADR-018 §95 (spec lock F6)."""

    model_config = _MODEL_CONFIG

    class_: KillSwitchClass = Field(alias="class")
    scope_key: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=2048)
    category: KillSwitchCategory


class KillSwitchFlipResponse(BaseModel):
    model_config = _MODEL_CONFIG

    class_: KillSwitchClass = Field(alias="class")
    scope_key: str
    active: bool
    enforcement_status: EnforcementStatus


class KillSwitchEntryResponse(BaseModel):
    """One active switch on the list surface. Custody fields are None for a
    malformed Redis document (rendered fail-closed ACTIVE with a marker
    reason — operator-visible, never hidden)."""

    model_config = _MODEL_CONFIG

    class_: KillSwitchClass = Field(alias="class")
    scope_key: str
    active: bool
    updated_at: str | None
    actor_id: str | None
    reason: str | None
    enforcement_status: EnforcementStatus


class EmergencyAuditEntryResponse(BaseModel):
    """One ``emergency.*`` chain row (value-free payload passthrough)."""

    model_config = _MODEL_CONFIG

    sequence: int
    decision_type: str
    request_id: str
    tenant_id: str | None
    created_at: datetime.datetime
    payload: dict[str, Any]

"""Sprint 13.6b T5 — quota portal DTOs (ADR-018 §Portal API).

NOTE: ``from __future__ import annotations`` is INTENTIONALLY OMITTED per the
standing FastAPI route/DTO module convention.
"""

from pydantic import BaseModel, ConfigDict


class QuotaUsageResponse(BaseModel):
    """Read-only tenant quota usage view. ``usage_pct`` =
    (actuals + reserved) / tenant_limit * 100, clamped at the limit floor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant_limit: int
    actuals: int
    reserved: int
    usage_pct: float

"""Sprint 13.6 T6 — narrow read helper over the ``emergency.*`` chain rows.

Pure read for the portal ``GET /api/v1/emergency/audit`` surface (ADR-018
§Portal API "audit trail of all switches + quota overrides"). Selects from
the exported ``_decision_history`` Table (the ``stream_routes.py``
replay-read precedent) — no chain mutation, no chain-head access. NOT on the
durable CC gate (pure read; the chain-integrity invariants are enforced
upstream by the on-gate ``core/decision_history.py``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history


async def load_emergency_audit(
    engine: AsyncEngine,
    *,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Newest-first ``emergency.*`` chain rows (the ``event_type`` column —
    the DB name for ``DecisionRecord.decision_type``), optionally bounded by
    ``created_at`` range. The wire field name stays ``decision_type`` (the
    DecisionRecord + UI-event vocabulary); the mapping happens here."""
    stmt = (
        select(
            _decision_history.c.sequence,
            _decision_history.c.event_type,
            _decision_history.c.request_id,
            _decision_history.c.tenant_id,
            _decision_history.c.created_at,
            _decision_history.c.payload,
        )
        .where(_decision_history.c.event_type.like("emergency.%"))
        .order_by(_decision_history.c.sequence.desc())
        .limit(limit)
    )
    if from_ts is not None:
        stmt = stmt.where(_decision_history.c.created_at >= from_ts)
    if to_ts is not None:
        stmt = stmt.where(_decision_history.c.created_at <= to_ts)
    async with engine.connect() as conn:
        rows = (await conn.execute(stmt)).all()
    return [
        {
            "sequence": row.sequence,
            "decision_type": row.event_type,
            "request_id": row.request_id,
            "tenant_id": row.tenant_id,
            "created_at": row.created_at,
            "payload": row.payload,
        }
        for row in rows
    ]


__all__ = ("load_emergency_audit",)

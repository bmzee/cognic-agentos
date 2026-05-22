"""Sprint 9 — GET /api/v1/traces/{trace_id} (ADR-006).

`from __future__ import annotations` OMITTED — standing portal-route invariant.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import _audit_event
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.portal.api.compliance.router import _require_adapters
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope


async def walk_trace(engine: AsyncEngine, *, trace_id: str, tenant_id: str) -> list[dict[str, Any]]:
    """Chain-walk one run's timeline from _audit_event + _decision_history.

    Rows are tenant-filtered — a trace_id present only under another
    tenant yields an empty list (cross-tenant invisible). Ordered by
    (created_at, source_chain, sequence) for an examiner-readable
    timeline. Read-only; no new event store.
    """
    events: list[dict[str, Any]] = []
    async with engine.connect() as conn:
        for source_chain, table in (
            ("audit_event", _audit_event),
            ("decision_history", _decision_history),
        ):
            stmt = (
                select(table)
                .where(table.c.trace_id == trace_id)
                .where(table.c.tenant_id == tenant_id)
            )
            result = await conn.execute(stmt)
            for row in result.fetchall():
                m = row._mapping
                events.append(
                    {
                        "source_chain": source_chain,
                        "sequence": m["sequence"],
                        "record_id": str(m["record_id"]),
                        "created_at": m["created_at"].isoformat(),
                        "event_type": m["event_type"],
                        "request_id": m["request_id"],
                        # Hash-chain linkage — hex-encoded, same shape as
                        # the evidence-pack JSONL (spec §6.2.1). prev_hash
                        # is the predecessor link, hash is this row's hash;
                        # together they let an examiner verify the chain
                        # walk rather than trust a bare sorted list.
                        "prev_hash": m["prev_hash"].hex(),
                        "hash": m["hash"].hex(),
                        "iso_controls": list(m["iso_controls"] or ()),
                    }
                )
    events.sort(key=lambda e: (e["created_at"], e["source_chain"], e["sequence"]))
    return events


def build_trace_routes(*, settings: Settings) -> APIRouter:
    router = APIRouter()
    _require_trace_scope = RequireScope("compliance.trace.read")

    @router.get(f"{settings.api_prefix}/traces/{{trace_id}}")
    async def trace(
        trace_id: str,
        actor: Annotated[Actor, Depends(_require_trace_scope)],
        adapters: Annotated[Adapters, Depends(_require_adapters)],
    ) -> dict[str, Any]:
        # Rows are filtered by the authenticated actor's tenant; a
        # trace_id existing only under another tenant returns an empty
        # timeline — cross-tenant invisible, never a forbidden hint.
        events = await walk_trace(
            adapters.relational.engine, trace_id=trace_id, tenant_id=actor.tenant_id
        )
        return {"trace_id": trace_id, "tenant_id": actor.tenant_id, "events": events}

    return router

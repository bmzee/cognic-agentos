"""M8 Task A4 (ADR-027 / spec §3.1) — the granted-capability store (CRITICAL
CONTROLS).

``agent_id → {skill refs, tool refs}``, seed/config-loaded in M8. THE
INGESTION INVARIANT (fail-closed): a grant outside the pack's REQUESTED set is
refused at load (``agent_grant_not_requested``) — operator/config drift cannot
grant a capability the persona never requested, and NO partial grant set is
ever returned. Dispatch enforces the granted set only; prompt assembly SHAPES
to it (defense in depth: shaping + hard gate).

Tenant isolation: the load SELECT is tenant-scoped — wrong-tenant rows are
invisible (the WHERE ``tenant_id`` IS the boundary; an empty grant, NOT a
refusal).

Built-ins (``read_skill`` / ``remember``) are kernel-owned and implicitly
granted at dispatch — NEVER assignment rows: the DB CheckConstraint pins
``capability_kind`` to {'skill','tool'} and the pure validator refuses any
defensive unknown kind anyway.

Module-owned Table on a module-local ``sa.MetaData()`` — the Alembic migration
at ``db/migrations/versions/20260705_0014_agent_entitlements.py`` is the ONLY
DDL source; column-shape drift is pinned by
``tests/unit/db/test_migration_20260705_0014.py``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.agent._types import (
    AgentGrantNotRequested,
    GrantedCapabilities,
    LoadedAgentRecord,
)

_metadata = sa.MetaData()

#: Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_TS = sa.TIMESTAMP(timezone=True)

#: SQLAlchemy Core Table mirroring migration 0014's ``agent_assignments``
#: exactly; drift pinned by tests/unit/db/test_migration_20260705_0014.py.
_agent_assignments = sa.Table(
    "agent_assignments",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(128), nullable=False),
    sa.Column("agent_id", sa.String(128), nullable=False),
    sa.Column("capability_kind", sa.String(16), nullable=False),
    sa.Column("capability_ref", sa.String(256), nullable=False),
    sa.Column("created_at", _TS, nullable=False),
    sa.CheckConstraint(
        "capability_kind IN ('skill', 'tool')",
        name="ck_agent_assignments_capability_kind",
    ),
    sa.UniqueConstraint(
        "tenant_id",
        "agent_id",
        "capability_kind",
        "capability_ref",
        name="uq_agent_assignments_tenant_agent_kind_ref",
    ),
    sa.Index("ix_agent_assignments_tenant_agent", "tenant_id", "agent_id"),
)


def _validate_and_partition(
    rows: Sequence[tuple[str, str]], record: LoadedAgentRecord
) -> GrantedCapabilities:
    """Pure ingestion-invariant validator (spec §3.1, fail-closed).

    Every granted ``(kind, ref)`` must be inside the record's REQUESTED set
    for that kind — the requested sets partition by kind, so a skill ref
    granted as ``kind="tool"`` (or vice versa) is out-of-request. ANY miss
    raises ``AgentGrantNotRequested``: no partial grant set is ever built up
    and returned.

    Module-level + pure so the defensive unknown-kind arm (DB-impossible under
    the ``ck_agent_assignments_capability_kind`` CheckConstraint, validated
    anyway — built-ins are kernel-owned, never assignment rows) is directly
    testable without fighting the DB.
    """
    skills: set[str] = set()
    tools: set[str] = set()
    for kind, ref in rows:
        if kind == "skill":
            if ref not in record.requested_skills:
                raise AgentGrantNotRequested(capability_ref=ref, capability_kind=kind)
            skills.add(ref)
        elif kind == "tool":
            if ref not in record.requested_tools:
                raise AgentGrantNotRequested(capability_ref=ref, capability_kind=kind)
            tools.add(ref)
        else:
            # Defensive: unrepresentable via the DB CHECK constraint, refused
            # anyway (fail-closed — never silently skipped, never granted).
            raise AgentGrantNotRequested(capability_ref=ref, capability_kind=kind)
    return GrantedCapabilities(skills=frozenset(skills), tools=frozenset(tools))


class AssignmentStore:
    """Tenant-scoped pure-read granted-capability store. Async; fail-closed at
    load (the ingestion invariant runs BEFORE any grant set is returned)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def load_for_agent(
        self, *, tenant_id: str, agent_id: str, record: LoadedAgentRecord
    ) -> GrantedCapabilities:
        """Load + validate the granted capability sets for ``agent_id`` inside
        ``tenant_id``.

        Wrong-tenant rows are invisible (tenant-scoped SELECT — empty grant,
        not a refusal). Raises ``AgentGrantNotRequested`` on ANY grant outside
        the record's requested set (fail-closed; NO partial grant set).
        """
        stmt = select(
            _agent_assignments.c.capability_kind,
            _agent_assignments.c.capability_ref,
        ).where(
            _agent_assignments.c.tenant_id == tenant_id,
            _agent_assignments.c.agent_id == agent_id,
        )
        async with self._engine.connect() as conn:
            result = await conn.execute(stmt)
            rows = [(row.capability_kind, row.capability_ref) for row in result]
        return _validate_and_partition(rows, record)

"""M8 Task A3 (ADR-027) — the data-scope entitlement store (CRITICAL CONTROLS).

Pure-READ substrate for the M8 dispatch entitlement gate (gate 2): which named
data scopes a subject is entitled to (``entitled_scope_ids``) and what a scope
resolves to (``resolve_scope`` — schema + governed-view object allow-set +
proxy DB identity, the facts the dispatcher stamps into the signed
query-context token). No chain rows — the dispatch row is the evidence
surface. Rows are proof-side seed in M8 (portal CRUD is a follow-up;
per-tenant entitlement changes are Human-only-decision-adjacent per ADR-027).

Tenant isolation: every read is tenant-scoped — the WHERE ``tenant_id`` IS the
cross-tenant wall. ``resolve_scope`` collapses absent and cross-tenant to the
same ``None`` (the wire-collapse invisibility doctrine: a probe cannot
distinguish the two).

Evidence-boundary validation (fail-closed, per
``feedback_evidence_boundary_runtime_validation``): the persisted ``objects``
JSON must be a list whose every element is a str — anything else raises
``ValueError``. A malformed objects column must never become a permissive
allow-set downstream (the resolved objects feed the signed query-context
token's claims). An empty list is legitimate (a scope that allows nothing).

Module-owned Tables on a module-local ``sa.MetaData()`` — the Alembic
migration at ``db/migrations/versions/20260705_0014_agent_entitlements.py`` is
the ONLY DDL source; column-shape drift is pinned by
``tests/unit/db/test_migration_20260705_0014.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.db.types import GovernanceJSON

_metadata = sa.MetaData()

#: Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_TS = sa.TIMESTAMP(timezone=True)

#: SQLAlchemy Core Table mirroring migration 0014's ``data_scopes`` exactly;
#: drift pinned by tests/unit/db/test_migration_20260705_0014.py.
_data_scopes = sa.Table(
    "data_scopes",
    _metadata,
    sa.Column("tenant_id", sa.String(128), nullable=False, primary_key=True),
    sa.Column("scope_id", sa.String(128), nullable=False, primary_key=True),
    sa.Column("schema_name", sa.String(256), nullable=False),
    sa.Column("objects", GovernanceJSON(), nullable=False),
    sa.Column("proxy_db_identity", sa.String(256), nullable=False),
    sa.Column("created_at", _TS, nullable=False),
)

#: SQLAlchemy Core Table mirroring migration 0014's ``entitlements`` exactly;
#: drift pinned by tests/unit/db/test_migration_20260705_0014.py.
_entitlements = sa.Table(
    "entitlements",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(128), nullable=False),
    sa.Column("subject", sa.String(256), nullable=False),
    sa.Column("scope_id", sa.String(128), nullable=False),
    sa.Column("created_at", _TS, nullable=False),
    sa.UniqueConstraint(
        "tenant_id",
        "subject",
        "scope_id",
        name="uq_entitlements_tenant_subject_scope",
    ),
    sa.Index("ix_entitlements_tenant_subject", "tenant_id", "subject"),
)


@dataclass(frozen=True, slots=True)
class DataScope:
    """A resolved named data scope: a curated set of governed-view objects
    (the lightweight semantic layer) + the proxy DB identity whose grants
    cover exactly those views (ADR-027 / spec §3.1). ``objects`` is the object
    allow-set the dispatcher stamps into the signed query-context token."""

    scope_id: str
    schema_name: str
    objects: tuple[str, ...]
    proxy_db_identity: str


class EntitlementStore:
    """Tenant-scoped pure-read entitlement + scope-resolution store. Async;
    fail-closed on malformed governance rows (never a permissive default)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def entitled_scope_ids(self, *, tenant_id: str, subject: str) -> frozenset[str]:
        """All scope_ids ``subject`` is entitled to inside ``tenant_id``.

        Empty frozenset when none — the dispatcher then refuses
        ``agent_scope_not_entitled``; an absent entitlement row is never a
        permissive default. Wrong-tenant rows are invisible (the WHERE
        ``tenant_id`` IS the boundary).
        """
        stmt = select(_entitlements.c.scope_id).where(
            _entitlements.c.tenant_id == tenant_id,
            _entitlements.c.subject == subject,
        )
        async with self._engine.connect() as conn:
            result = await conn.execute(stmt)
            return frozenset(row.scope_id for row in result)

    async def resolve_scope(self, *, tenant_id: str, scope_id: str) -> DataScope | None:
        """Resolve ``scope_id`` inside ``tenant_id`` to its governed-view
        allow-set + proxy identity.

        Absent OR cross-tenant → ``None`` — the wire-collapse invisibility
        doctrine: the WHERE ``tenant_id`` IS the boundary, and a probe cannot
        distinguish "no such scope" from "another tenant's scope".

        Raises ``ValueError`` when the persisted ``objects`` JSON is not a
        list of strings (fail-closed evidence boundary — a malformed objects
        column must never become a permissive allow-set downstream). An empty
        list is legitimate and resolves to ``objects=()``.
        """
        stmt = select(
            _data_scopes.c.scope_id,
            _data_scopes.c.schema_name,
            _data_scopes.c.objects,
            _data_scopes.c.proxy_db_identity,
        ).where(
            _data_scopes.c.tenant_id == tenant_id,
            _data_scopes.c.scope_id == scope_id,
        )
        async with self._engine.connect() as conn:
            result = await conn.execute(stmt)
            row = result.first()
        if row is None:
            return None
        objects = row.objects
        if not isinstance(objects, list):
            raise ValueError(
                f"data_scopes.objects for scope {scope_id!r} must be a JSON list of "
                f"governed-view names; got {type(objects).__name__}"
            )
        for element in objects:
            if not isinstance(element, str):
                raise ValueError(
                    f"data_scopes.objects for scope {scope_id!r} must contain only "
                    f"strings; got element of type {type(element).__name__}"
                )
        return DataScope(
            scope_id=row.scope_id,
            schema_name=row.schema_name,
            objects=tuple(objects),
            proxy_db_identity=row.proxy_db_identity,
        )

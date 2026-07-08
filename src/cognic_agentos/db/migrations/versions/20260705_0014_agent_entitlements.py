"""agent_entitlements — M8 governed agent loop substrate (ADR-027).

The data-scope entitlement + agent-assignment tables feeding the M8 dispatch
gates: ``data_scopes`` (a named scope IS a curated set of governed-view
objects — the lightweight semantic layer — plus the Oracle proxy identity
whose grants cover exactly those views), ``entitlements`` (subject ↔ scope_id,
many-to-many, queryable both directions), and ``agent_assignments``
(agent_id → granted capability refs; ``core/agent/assignments.py`` enforces
the grant-not-requested ingestion invariant at load). DATA-FREE —
scope/entitlement/assignment ROWS are proof-side seed (spec §6), never kernel
migration data.

Pins (mirroring 0008/0011/0012/0013): ``GovernanceJSON()`` for the
dialect-portable ``objects`` JSON array (native JSON on Postgres/SQLite,
JSON-as-CLOB on Oracle) + ``sa.TIMESTAMP(timezone=True)`` for every
``created_at`` — NOT ``sa.DateTime`` (Oracle drops the offset). The named
unique constraints carry the single-row invariants the stores depend on;
column shapes MUST agree with the in-process Tables at
``core/entitlements/store.py`` (``_data_scopes`` + ``_entitlements``) and
``core/agent/assignments.py`` (``_agent_assignments``), all pinned by
``tests/unit/db/test_migration_20260705_0014.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

# Alembic revision identifiers.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "data_scopes",
        # Composite natural PK — a scope name is unique per tenant; the
        # tenant_id leg of the PK IS the cross-tenant wall the store's
        # resolve_scope WHERE clause enforces.
        sa.Column("tenant_id", sa.String(length=128), nullable=False, primary_key=True),
        sa.Column("scope_id", sa.String(length=128), nullable=False, primary_key=True),
        sa.Column("schema_name", sa.String(length=256), nullable=False),
        # JSON list[str] of governed-view names (the scope's object allow-set).
        sa.Column("objects", GovernanceJSON(), nullable=False),
        sa.Column("proxy_db_identity", sa.String(length=256), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
    )
    op.create_table(
        "entitlements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("scope_id", sa.String(length=128), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "subject",
            "scope_id",
            name="uq_entitlements_tenant_subject_scope",
        ),
    )
    op.create_index("ix_entitlements_tenant_subject", "entitlements", ["tenant_id", "subject"])
    op.create_table(
        "agent_assignments",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("capability_kind", sa.String(length=16), nullable=False),
        sa.Column("capability_ref", sa.String(length=256), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        # Governance kind column carries a closed enum — the DB enforces it so
        # an out-of-band write cannot create a kind the Python Literal can't
        # represent (built-ins are kernel-owned + implicitly granted at
        # dispatch: NEVER assignment rows).
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
    )
    op.create_index(
        "ix_agent_assignments_tenant_agent", "agent_assignments", ["tenant_id", "agent_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_agent_assignments_tenant_agent", table_name="agent_assignments")
    op.drop_table("agent_assignments")
    op.drop_index("ix_entitlements_tenant_subject", table_name="entitlements")
    op.drop_table("entitlements")
    op.drop_table("data_scopes")

"""memory_records table — Sprint 11.5a per ADR-019.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-31

Creates the ``memory_records`` table backing the governed-memory
substrate's persistence Protocol at
``cognic_agentos.core.memory.storage.MemoryAdapter``. The table holds
the per-record memory row (scratch / task / long_term tiers + persona /
user_profile / agent_notes blocks); the consent ledger and lifecycle
audit events ride the existing ``decision_history`` chain, NOT a
physical table in this revision.

Dialect-portable across Postgres / Oracle / SQLite. Type seams mirror
``20260526_0005_scheduler_tasks.py``: ``sa.Uuid()`` for surrogate keys,
``MEMORY_TS_TYPE = sa.TIMESTAMP(timezone=True)`` for timestamps (NOT
``sa.DateTime`` — Oracle would drop the offset), ``GovernanceJSON()``
for the JSON columns (native JSON on Postgres / SQLite, CLOB on Oracle).
The ``memory_records`` table here MUST agree column-for-column with the
in-process Table at ``core/memory/storage.py:_memory_records``; drift is
pinned by ``tests/unit/db/test_migration_20260531_0006.py``.

The ``ck_memory_records_key_xor_block_kind`` CHECK is INLINE in
``op.create_table`` (NOT a separate ``op.create_check_constraint`` call):
SQLite cannot ``ALTER TABLE ADD CONSTRAINT`` outside batch mode, and the
0005 precedent puts CheckConstraints inline.

The ``uq_memory_block_singleton`` unique index enforces ONE active block
per ``(tenant_id, subject_ref, agent_id, block_kind)`` identity tuple.
Postgres + SQLite use a native partial index (``WHERE block_kind IS NOT
NULL AND tombstone IS NULL``). Oracle has no partial indexes, so the
migration emits a function-based unique index in-file (CASE expressions
that are NULL for non-active / non-block rows; Oracle omits all-NULL
index entries, so uniqueness applies ONLY across active block rows). No
``db/migrations/oracle/`` mirror — the 0005 precedent has none and the
oracle dir is empty.

No edits to the ``decision_history`` schema — memory events ride the
existing chain substrate; no schema bump, no ``_SCHEMA_VERSION`` change.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

# Alembic revision identifiers.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
# See the 0003 migration's module docstring for the Oracle-compile
# rationale (``sa.DateTime`` compiles to ``DATE`` on Oracle, silently
# dropping the offset).
MEMORY_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "memory_records",
        sa.Column("record_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("subject_ref", sa.String(length=256), nullable=False),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("block_kind", sa.String(length=32), nullable=True),
        sa.Column("key", sa.String(length=256), nullable=True),
        sa.Column("value", GovernanceJSON(), nullable=False),
        sa.Column("data_classes", GovernanceJSON(), nullable=False),
        sa.Column("purpose", sa.String(length=64), nullable=False),
        sa.Column("retention_until", MEMORY_TS_TYPE, nullable=True),
        sa.Column("tombstone", MEMORY_TS_TYPE, nullable=True),
        sa.Column("redaction_version", sa.Integer(), nullable=False),
        sa.Column("sealed_prior_version_ref", sa.Uuid(), nullable=True),
        sa.Column("vector_ref", sa.String(length=256), nullable=True),
        sa.Column("created_at", MEMORY_TS_TYPE, nullable=False),
        # INLINE CHECK — SQLite cannot ALTER TABLE ADD CONSTRAINT outside
        # batch mode; the 0005 precedent puts CheckConstraints inline.
        sa.CheckConstraint(
            "(key IS NOT NULL AND block_kind IS NULL) OR (key IS NULL AND block_kind IS NOT NULL)",
            name="ck_memory_records_key_xor_block_kind",
        ),
    )
    bind = op.get_bind()
    if bind.dialect.name == "oracle":
        # Oracle has no partial indexes. Function-based unique index: each
        # CASE expression is NULL for non-active / non-block rows; Oracle
        # omits all-NULL index entries, so uniqueness is enforced ONLY
        # across active block rows.
        op.execute(
            sa.text(
                "CREATE UNIQUE INDEX uq_memory_block_singleton ON memory_records ("
                "CASE WHEN block_kind IS NOT NULL AND tombstone IS NULL THEN tenant_id END, "
                "CASE WHEN block_kind IS NOT NULL AND tombstone IS NULL THEN subject_ref END, "
                "CASE WHEN block_kind IS NOT NULL AND tombstone IS NULL THEN agent_id END, "
                "CASE WHEN block_kind IS NOT NULL AND tombstone IS NULL THEN block_kind END)"
            )
        )
    else:  # postgresql, sqlite — native partial unique index
        op.create_index(
            "uq_memory_block_singleton",
            "memory_records",
            ["tenant_id", "subject_ref", "agent_id", "block_kind"],
            unique=True,
            postgresql_where=sa.text("block_kind IS NOT NULL AND tombstone IS NULL"),
            sqlite_where=sa.text("block_kind IS NOT NULL AND tombstone IS NULL"),
        )


def downgrade() -> None:
    op.drop_index("uq_memory_block_singleton", table_name="memory_records")
    op.drop_table("memory_records")

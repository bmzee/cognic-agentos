"""scheduler_tasks table — Sprint 10.5a per ADR-022.

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-26

Creates the ``scheduler_tasks`` table backing
``cognic_agentos.core.scheduler.storage.SchedulerStorage``. The table
holds the per-task lifecycle row that the scheduler's chain-audit
events reference; canonical state-transition history lives in the
``decision_history`` chain.

Dialect-portable across Postgres / Oracle / SQLite. Type seams mirror
``20260522_0004_model_registry.py``: ``sa.Uuid()`` for the surrogate
PK, ``SCHEDULER_TS_TYPE = sa.TIMESTAMP(timezone=True)`` for timestamps
(NOT ``sa.DateTime`` — Oracle would drop the offset). The
``scheduler_tasks`` table here MUST agree column-for-column with the
in-process Table at ``core/scheduler/storage.py:_scheduler_tasks``;
drift is pinned by ``tests/unit/db/test_migration_20260526_0005.py``.

No edits to the ``decision_history`` schema — scheduler lifecycle
events ride the existing chain substrate; the per-task ``task_id``
field lands on existing JSON columns; no schema bump, no
``_SCHEMA_VERSION`` change.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Alembic revision identifiers.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
# See the 0003 migration's module docstring for the Oracle-compile
# rationale (``sa.DateTime`` compiles to ``DATE`` on Oracle, silently
# dropping the offset).
SCHEDULER_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "scheduler_tasks",
        sa.Column("task_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("actor_subject", sa.String(length=256), nullable=False),
        sa.Column("class_", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("pack_kind", sa.String(length=32), nullable=False),
        sa.Column("pack_risk_tier", sa.String(length=64), nullable=False),
        sa.Column("requested_estimated_tokens", sa.Integer(), nullable=False),
        sa.Column("parent_task_id", sa.Uuid(), nullable=True),
        sa.Column("submitted_at", SCHEDULER_TS_TYPE, nullable=False),
        sa.Column("started_at", SCHEDULER_TS_TYPE, nullable=True),
        sa.Column("terminal_at", SCHEDULER_TS_TYPE, nullable=True),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'completed', 'failed', "
            "'cancelled', 'preempted', 'expired')",
            name="ck_scheduler_tasks_state",
        ),
        sa.CheckConstraint(
            "class_ IN ('interactive', 'background')",
            name="ck_scheduler_tasks_class_",
        ),
    )
    # Composite index for the SchedulerEngine's per-tenant per-class
    # current-concurrent-count query (spec §4.5).
    op.create_index(
        "ix_scheduler_tasks_tenant_class_state",
        "scheduler_tasks",
        ["tenant_id", "class_", "state"],
    )
    # Index supporting sub-agent budget inheritance (spec §4.10) +
    # parent-task lookups in Sprint 11.
    op.create_index(
        "ix_scheduler_tasks_parent",
        "scheduler_tasks",
        ["parent_task_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_scheduler_tasks_parent", table_name="scheduler_tasks")
    op.drop_index("ix_scheduler_tasks_tenant_class_state", table_name="scheduler_tasks")
    op.drop_table("scheduler_tasks")

"""runs — Sprint 14A-A3a run-persistence foundation (ADR-022 + ADR-004).

The durable run-record substrate backing ``core.run.storage.RunRecordStore``.
``run.lifecycle.<state>`` aggregate evidence lives in the ``decision_history``
chain; this table holds the operational per-run state + the session/checkpoint/
approval correlators (A3b/A3c populate the nullable columns).

Pins (mirroring 0005/0008): ``sa.TIMESTAMP(timezone=True)`` for timestamps —
NOT ``sa.DateTime`` (Oracle drops the offset); ``checkpoint_id`` is
``String(32)`` (the sandbox CheckpointId hex), NOT a Uuid. Column shapes MUST
agree with the in-process Table at ``core/run/storage.py``; drift pinned by
``tests/unit/db/test_migration_20260615_0011.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | None = None
depends_on: str | None = None

_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("run_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("pack_uuid", sa.Uuid(), nullable=False),
        sa.Column("pack_version", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("session_id", sa.String(length=128), nullable=True),
        sa.Column("checkpoint_id", sa.String(length=32), nullable=True),
        sa.Column("approval_request_id", sa.Uuid(), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.CheckConstraint(
            "state IN ('pending', 'running', 'completed', 'failed', 'refused', "
            "'pending_approval', 'suspended', 'woken', 'cancelled')",
            name="ck_runs_state",
        ),
    )
    op.create_index("ix_runs_tenant_state", "runs", ["tenant_id", "state"])


def downgrade() -> None:
    op.drop_index("ix_runs_tenant_state", table_name="runs")
    op.drop_table("runs")

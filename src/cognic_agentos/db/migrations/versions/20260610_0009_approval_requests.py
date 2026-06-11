"""approval_requests table — Sprint 13.5a per ADR-014.

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-10

Creates the ``approval_requests`` table backing
``cognic_agentos.core.approval.storage.ApprovalRequestStore``. The table holds
the per-request mutable lifecycle row (pending -> awaiting_second / granted /
denied / expired); the canonical state-transition history lives in the
``decision_history`` chain as the value-free ``approval.*`` events. No raw tool
args are stored — only the caller-supplied ``args_digest`` + the engine-computed
``envelope_digest``.

Dialect-portable across Postgres / Oracle / SQLite. ``sa.TIMESTAMP(timezone=
True)`` for timestamps (NOT ``sa.DateTime`` — Oracle would drop the offset);
``GovernanceJSON`` for the JSON columns (JSON-as-CLOB on Oracle, native on PG/
SQLite). This table MUST agree column-for-column with the in-process Table at
``core/approval/storage.py:_approval_requests``.

No edits to the ``decision_history`` schema — approval lifecycle events ride the
existing chain substrate; no schema bump.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

# Alembic revision identifiers.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)`` (the
# 0003 migration docstring has the Oracle-compile rationale).
_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("request_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("flow", sa.String(32), nullable=False),
        sa.Column("risk_tier", sa.String(32), nullable=False),
        sa.Column("tool_identity", sa.String(256), nullable=False),
        sa.Column("originator_subject", sa.String(256), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("first_approver", sa.String(256), nullable=True),
        sa.Column("second_approver", sa.String(256), nullable=True),
        sa.Column("denier", sa.String(256), nullable=True),
        sa.Column("envelope_digest", sa.LargeBinary(), nullable=False),
        sa.Column("args_digest", sa.LargeBinary(), nullable=False),
        sa.Column("redacted_context", sa.Text(), nullable=False),
        sa.Column("data_classes", GovernanceJSON(), nullable=False),
        sa.Column("required_refs", GovernanceJSON(), nullable=False),
        sa.Column("created_at", _TS, nullable=False),
        sa.Column("expires_at", _TS, nullable=False),
        sa.Column("updated_at", _TS, nullable=False),
        sa.CheckConstraint(
            "state IN ('pending', 'awaiting_second', 'granted', 'denied', 'expired')",
            name="ck_approval_requests_state",
        ),
    )
    op.create_index(
        "ix_approval_requests_tenant_state",
        "approval_requests",
        ["tenant_id", "state"],
    )


def downgrade() -> None:
    op.drop_index("ix_approval_requests_tenant_state", table_name="approval_requests")
    op.drop_table("approval_requests")

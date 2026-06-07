"""tenant_config_overlay — per-tenant tighten-only config overrides (ADR-023).

Adds the ``tenant_config_overlay`` table holding the CURRENT per-tenant override
value for each overridable ``Settings`` field. Immutable history lives in the
``decision_history`` chain via ``config.tenant_overlay.set`` / ``.cleared``
events (see ``core/config_overlay/storage.py``); this table is the denormalised
current-state cache the request-time resolver reads.

One row per ``(tenant_id, field_key)`` — enforced by the
``uq_tenant_config_overlay_tenant_field`` unique constraint.

Pins (mirroring 0006): ``GovernanceJSON()`` for the dialect-portable ``value``
column + ``sa.TIMESTAMP(timezone=True)`` for ``set_at`` — NOT ``sa.DateTime``,
which compiles to Oracle ``DATE`` and silently drops the offset (see the 0003
migration docstring for the Oracle-compile rationale).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

# Alembic revision identifiers.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_OVERLAY_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "tenant_config_overlay",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("field_key", sa.String(length=128), nullable=False),
        sa.Column("value", GovernanceJSON(), nullable=False),
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _OVERLAY_TS_TYPE, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "field_key", name="uq_tenant_config_overlay_tenant_field"),
    )
    op.create_index("ix_tenant_config_overlay_tenant_id", "tenant_config_overlay", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_tenant_config_overlay_tenant_id", table_name="tenant_config_overlay")
    op.drop_table("tenant_config_overlay")

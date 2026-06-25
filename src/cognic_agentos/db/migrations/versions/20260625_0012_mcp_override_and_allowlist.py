"""mcp server_url override + internal-host allow-list (PR-2b-1).

Adds the two decision-history-audited current-state tables backing
``core/mcp_config/storage.py``:

- ``mcp_server_url_override`` — one row per ``(tenant_id, pack_id)`` holding the
  operator ``http://``-IP-literal ``server_url`` override (immutable history in
  the ``decision_history`` chain via ``mcp.override.set`` / ``.cleared``).
- ``mcp_internal_host_allowlist`` — one row per ``(tenant_id, ip)`` exact-IP
  allow-list entry (history via ``mcp.allowlist.add`` / ``.remove``).

Pins (mirroring 0006/0007/0011): ``sa.TIMESTAMP(timezone=True)`` for ``set_at``
— NOT ``sa.DateTime`` (Oracle drops the offset). The named unique constraints
``uq_mcp_server_url_override_tenant_pack`` + ``uq_mcp_internal_host_allowlist_tenant_ip``
are the migration-only invariants the store's per-``(tenant, pack)`` /
per-``(tenant, ip)`` single-row contract depends on; drift is pinned by
``tests/unit/db/test_migration_20260625_0012.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Alembic revision identifiers.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "mcp_server_url_override",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("server_url_override", sa.String(length=2048), nullable=False),
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _TS, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "pack_id", name="uq_mcp_server_url_override_tenant_pack"),
    )
    op.create_index(
        "ix_mcp_server_url_override_tenant_id", "mcp_server_url_override", ["tenant_id"]
    )
    op.create_table(
        "mcp_internal_host_allowlist",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),  # v4/v6 literal
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _TS, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "ip", name="uq_mcp_internal_host_allowlist_tenant_ip"),
    )
    op.create_index(
        "ix_mcp_internal_host_allowlist_tenant_id",
        "mcp_internal_host_allowlist",
        ["tenant_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_mcp_internal_host_allowlist_tenant_id", table_name="mcp_internal_host_allowlist"
    )
    op.drop_table("mcp_internal_host_allowlist")
    op.drop_index("ix_mcp_server_url_override_tenant_id", table_name="mcp_server_url_override")
    op.drop_table("mcp_server_url_override")

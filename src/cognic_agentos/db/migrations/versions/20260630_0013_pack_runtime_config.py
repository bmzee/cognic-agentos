"""pack_runtime_config — M4 operator-grade pack install (ADR-026).

The authoritative DESIRED runtime-config record per ``(tenant, pack)`` backing
``core.mcp_config.runtime_config.PackRuntimeConfigStore``. A materializer (M4
Task 4) projects this desired state into the DERIVED MCP carve-out tables
(``mcp_server_url_override`` + ``mcp_internal_host_allowlist`` from 0012) on
``install`` and retracts them on ``disable`` / ``revoke``; the
``mcp.runtime_config.*`` aggregate evidence lives in the ``decision_history``
chain.

Pins (mirroring 0008/0011/0012): ``GovernanceJSON()`` for the dialect-portable
``internal_host_allowlist`` JSON array (native JSON on Postgres/SQLite,
JSON-as-CLOB on Oracle) + ``sa.TIMESTAMP(timezone=True)`` for ``set_at`` — NOT
``sa.DateTime`` (Oracle drops the offset). The named unique constraint
``uq_pack_runtime_config_tenant_pack`` is the migration-only
single-row-per-``(tenant, pack)`` invariant the store depends on; column shapes
MUST agree with the in-process Table at ``core/mcp_config/runtime_config.py``,
both pinned by ``tests/unit/db/test_migration_20260630_0013.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

# Alembic revision identifiers.
revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
_TS = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "pack_runtime_config",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("pack_id", sa.String(length=128), nullable=False),
        sa.Column("server_url_override", sa.String(length=2048), nullable=True),
        sa.Column("internal_host_allowlist", GovernanceJSON(), nullable=False),
        sa.Column("oauth_credential_ref", sa.String(length=512), nullable=True),
        sa.Column("as_allowlist_ref", sa.String(length=512), nullable=True),
        sa.Column("activation_status", sa.String(length=32), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", _TS, nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "pack_id", name="uq_pack_runtime_config_tenant_pack"),
        # Governance state column carries a closed enum — the DB enforces it so an
        # out-of-band write cannot create a status the Python Literal can't represent.
        sa.CheckConstraint(
            "activation_status IN ('configured', 'active', 'disabled', 'revoked')",
            name="ck_pack_runtime_config_activation_status",
        ),
    )
    op.create_index("ix_pack_runtime_config_tenant_id", "pack_runtime_config", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_pack_runtime_config_tenant_id", table_name="pack_runtime_config")
    op.drop_table("pack_runtime_config")

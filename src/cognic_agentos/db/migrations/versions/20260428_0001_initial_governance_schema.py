"""initial governance schema (audit_event + decision_history + chain_heads)

Revision ID: 0001
Revises:
Create Date: 2026-04-28

Sprint 2 chain-of-custody foundation.

Three tables:

- ``governance_chain_heads`` — one row per chain, with the ``chain_id``
  ('audit_event' | 'decision_history') as primary key. Append flow
  reads + locks the row via ``SELECT ... FOR UPDATE``, computes the
  next sequence + hash, INSERTs into the evidence table, and UPDATEs
  this row with the new head — all in one transaction. Portable across
  Postgres + Oracle; no LIMIT, no DESC scan over the evidence tables.

- ``audit_event`` — append-only audit chain. Per Round-4 of the
  Sprint-2 plan, named ``audit_event`` (not ``audit``) so the table
  name avoids Oracle's reserved ``AUDIT`` identifier entirely; no
  schema-quoting strategy required across the codebase.

- ``decision_history`` — append-only decision chain; same shape as
  audit_event; payload schema differs (decision-specific fields).

Both evidence tables carry:
  - ``record_id UUID`` PK (Python uuid4)
  - ``sequence BIGINT UNIQUE`` (application-assigned under chain-heads
    lock — NOT a database Identity column, which would double-source
    the value)
  - ``schema_version SMALLINT NOT NULL DEFAULT 1`` (bumps on
    canonical-form changes per AGENTS.md amendment in PR #5)
  - ``tenant_id VARCHAR(64)`` NULL (Sprint 2 stores NULL; Sprint 4
    RBAC populates)
  - ``prev_hash`` + ``hash`` fixed 32-byte binary (Postgres ``BYTEA``;
    Oracle ``RAW(32)``; SQLite ``BLOB``) — chain integrity material.
    Oracle compiles via ``with_variant(oracle.RAW(32), 'oracle')`` in
    ``db/types.chain_hash_column_type()``.
  - ``created_at TIMESTAMP(tz=True)`` (chain envelope material)
  - per-event metadata: ``event_type``, ``request_id``, ``trace_id``,
    ``span_id``, ``langfuse_trace_id``, ``provider_label``,
    ``iso_controls``, ``payload``

GRANTs are NOT in this migration (Round-3 amendment of the plan).
Schema management (DDL) and role management (admin) are kept separate;
banks already have account-management policies that conflict with
migration-driven role/grant churn. The runtime-role + GRANT statements
live in ``docs/operator-runbooks/governance-tables-grants.md`` and are
applied out-of-band before the runtime container connects with
non-superuser credentials. The verification test
``tests/integration/db/test_runtime_role_is_append_only.py`` (Task 12.5
of the plan) is the production-grade canary that the runbook was
applied.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON, chain_hash_column_type

# Alembic revision identifiers.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

# Genesis ``prev_hash`` / ``latest_hash`` — 32 zero bytes, matching
# ``cognic_agentos.core.canonical.ZERO_HASH``. Inlined here so the
# migration is self-contained: bumping a future canonical-form rule
# must not retroactively alter old migrations.
ZERO_HASH_BYTES: bytes = bytes(32)


def upgrade() -> None:
    # --- governance_chain_heads (lock-row table) ---------------------
    op.create_table(
        "governance_chain_heads",
        sa.Column("chain_id", sa.String(32), primary_key=True),
        sa.Column(
            "latest_sequence",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("latest_hash", chain_hash_column_type(), nullable=False),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # Genesis rows — both chains start at sequence=0 + ZERO_HASH so the
    # first append's prev_hash is read from THIS row, not from a
    # "missing-row" path that PG and Oracle handle differently.
    op.bulk_insert(
        sa.table(
            "governance_chain_heads",
            sa.column("chain_id", sa.String(32)),
            sa.column("latest_sequence", sa.BigInteger()),
            sa.column("latest_hash", chain_hash_column_type()),
        ),
        [
            {
                "chain_id": "audit_event",
                "latest_sequence": 0,
                "latest_hash": ZERO_HASH_BYTES,
            },
            {
                "chain_id": "decision_history",
                "latest_sequence": 0,
                "latest_hash": ZERO_HASH_BYTES,
            },
        ],
    )

    # --- evidence tables -----------------------------------------
    for table in ("audit_event", "decision_history"):
        op.create_table(
            table,
            sa.Column("record_id", sa.Uuid(), primary_key=True),
            # No Identity() — sequence is assigned in the application
            # layer under the chain_heads FOR UPDATE lock. Identity()
            # would double-source the value (DB auto-increment vs
            # application-assigned), which silently desyncs from
            # governance_chain_heads.latest_sequence after the first
            # concurrency hiccup.
            sa.Column("sequence", sa.BigInteger(), nullable=False, unique=True),
            sa.Column(
                "schema_version",
                sa.SmallInteger(),
                nullable=False,
                server_default="1",
            ),
            sa.Column("tenant_id", sa.String(64), nullable=True),
            sa.Column("prev_hash", chain_hash_column_type(), nullable=False),
            sa.Column("hash", chain_hash_column_type(), nullable=False, unique=True),
            sa.Column(
                "created_at",
                sa.TIMESTAMP(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(64), nullable=False),
            sa.Column("request_id", sa.String(64), nullable=False),
            sa.Column("trace_id", sa.String(32), nullable=True),
            sa.Column("span_id", sa.String(16), nullable=True),
            sa.Column("langfuse_trace_id", sa.String(64), nullable=True),
            sa.Column("provider_label", sa.String(32), nullable=True),
            sa.Column("iso_controls", GovernanceJSON(), nullable=True),
            sa.Column("payload", GovernanceJSON(), nullable=False),
        )
        op.create_index(f"ix_{table}_request_id", table, ["request_id"])
        op.create_index(
            f"ix_{table}_event_type_created_at",
            table,
            ["event_type", "created_at"],
        )
        op.create_index(
            f"ix_{table}_tenant_created_at",
            table,
            ["tenant_id", "created_at"],
        )


def downgrade() -> None:
    for table in ("decision_history", "audit_event"):
        op.drop_index(f"ix_{table}_tenant_created_at", table)
        op.drop_index(f"ix_{table}_event_type_created_at", table)
        op.drop_index(f"ix_{table}_request_id", table)
        op.drop_table(table)
    op.drop_table("governance_chain_heads")

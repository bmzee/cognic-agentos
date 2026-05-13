"""packs lifecycle table — Sprint 7B.1 T4 per ADR-012.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-10

Bank-pack lifecycle storage. Backs the
``cognic_agentos.packs.storage.PackRecordStore`` API: ``save_draft``
inserts the genesis row at ``state='draft'``; ``transition()`` advances
``state`` under the chain-head FOR UPDATE lock owned by
``DecisionHistoryStore.append_with_precondition`` (Sprint-2.5 T2 atomic
primitive). The chain row's ``payload['from_state'] / ['to_state'] /
['transition_name']`` is the canonical history; the
``packs.state`` column is an O(1)-readable cache of the chain head.

Schema is dialect-portable across Postgres, Oracle, and SQLite (test
substrate). Type seams:

- ``sa.Uuid()`` for the primary key — the dialect-portable seam introduced
  in SQLAlchemy 2.0. Compiles to native ``UUID`` on Postgres and
  ``CHAR(32)`` (32-char hex without dashes) on Oracle / SQLite. Mirrors
  the Sprint-2 substrate at ``20260428_0001_initial_governance_schema.py:123``
  and the in-process Table at ``packs/storage.py:154`` — the migration
  MUST match the in-process Table exactly so Oracle integration canaries
  bind ``id`` values that match the underlying column type.
  **Not** ``sa.dialects.postgresql.UUID(as_uuid=True)``: that's a
  Postgres-specific dialect type, not the dialect-portable seam.
- ``chain_hash_column_type()`` for the digest columns — the dialect-
  portable seam at ``cognic_agentos.db.types`` compiles to
  ``BYTEA`` on Postgres / ``RAW(32)`` on Oracle / ``BLOB`` on SQLite.
  Inlining ``sa.LargeBinary`` would lose the Oracle ``RAW(32)`` length
  constraint, accepting truncated digests at the DB layer.
- ``PACKS_TS_TYPE = sa.TIMESTAMP(timezone=True)`` for the timestamp
  columns — **not** ``sa.DateTime(timezone=True)``, which compiles to
  plain ``DATE`` on Oracle (silently dropping the offset, mirror of the
  doctrine pin at
  ``20260430_0002_gateway_call_ledger.py:49+65-67`` for the Sprint-3
  ledger).

CHECK constraints on ``kind`` and ``state`` enforce the Sprint-7B.1
closed-enum vocabularies (``PackKind`` 4-tuple + ``PackState``
11-tuple) at the DB layer; out-of-vocabulary values rejected by the
Pydantic model at ``packs/storage.py:248-273`` are caught a second time
here in case a future direct-SQL writer bypasses the model.

Indexes:
- ``ix_packs_kind_state`` — supports
  ``PackRecordStore.list_by_status(state, ...)`` filtered queries.
- ``ix_packs_tenant_state`` — supports per-tenant queue queries
  (Sprint 7B.2 portal API: "show me all approved packs for tenant X").

Round-1 reviewer-P1 schema invariant — the in-process Table at
``packs/storage.py:151`` and this migration's ``op.create_table(...)``
MUST agree on every column name + nullability + CHECK constraint.
Drift is pinned by the unit test at
``tests/unit/db/test_migration_20260510_0003.py::test_packs_columns_match_storage_table_object``.

``PACKS_TS_TYPE`` is exposed at module scope so the regression test
in ``test_migration_20260510_0003.py`` can ``importlib.import_module``
this exact instance and compile-check it under the Oracle dialect —
same Round-2 doctrine pin as ``GATEWAY_LEDGER_TS_TYPE`` at
``20260430_0002_gateway_call_ledger.py:67``. A future regression to
``sa.DateTime(timezone=True)`` here causes Oracle compile output to
drop ``TIME ZONE`` and the test fails loudly.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import chain_hash_column_type

# Alembic revision identifiers.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
# See module docstring for the Oracle-compile rationale. Exposed at
# module scope so the regression test imports THIS instance, not a
# fresh hard-coded copy that would silently drift if the migration's
# real type regressed.
PACKS_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "packs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("pack_id", sa.String(length=256), nullable=False),
        sa.Column("display_name", sa.String(length=256), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column(
            "manifest_digest",
            chain_hash_column_type(),
            nullable=False,
        ),
        sa.Column(
            "signed_artefact_digest",
            chain_hash_column_type(),
            nullable=False,
        ),
        sa.Column("sbom_pointer", sa.Text(), nullable=True),
        sa.Column("tenant_id", sa.String(length=256), nullable=True),
        sa.Column("created_by", sa.String(length=256), nullable=False),
        sa.Column("last_actor", sa.String(length=256), nullable=False),
        sa.Column("created_at", PACKS_TS_TYPE, nullable=False),
        sa.Column("updated_at", PACKS_TS_TYPE, nullable=False),
        # Inline CheckConstraints mirror the source-of-truth declaration
        # at ``packs/storage.py:167-176``. Constraint names are pinned
        # ``ck_packs_{kind,state}`` so live-DB downgrades drop the
        # constraints by name without dialect quirks.
        sa.CheckConstraint(
            "kind IN ('tool', 'skill', 'agent', 'hook')",
            name="ck_packs_kind",
        ),
        sa.CheckConstraint(
            "state IN ('draft', 'submitted', 'under_review', 'approved', "
            "'rejected', 'withdrawn', 'allow_listed', 'installed', 'disabled', "
            "'revoked', 'uninstalled')",
            name="ck_packs_state",
        ),
    )
    # Index inventory matches ``packs/storage.py:177-178``.
    op.create_index("ix_packs_kind_state", "packs", ["kind", "state"])
    op.create_index("ix_packs_tenant_state", "packs", ["tenant_id", "state"])


def downgrade() -> None:
    # Drop indexes first (asymmetric drop without index drops would
    # leave dangling sqlite/PG/Oracle metadata; explicit reverse-order
    # drops keep the round-trip clean — same convention as
    # ``20260430_0002_gateway_call_ledger.py:108-113``).
    op.drop_index("ix_packs_tenant_state", table_name="packs")
    op.drop_index("ix_packs_kind_state", table_name="packs")
    op.drop_table("packs")

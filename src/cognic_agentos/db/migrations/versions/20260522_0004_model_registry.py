"""model registry table + gateway-ledger model_id index — Sprint 9.5 per ADR-013.

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-22

Creates the ``models`` table backing
``cognic_agentos.models.storage.ModelRecordStore`` and adds a composite
``(model_id, ts)`` btree index on the existing ``gateway_call_ledger``
table so the Sprint-9.5 Block-C ``GET /api/v1/models/{id}/usage``
aggregate query is index-served. The ``gateway_call_ledger.model_id``
COLUMN already exists (reserved at Sprint 3 — ``llm/ledger.py:148``);
this migration adds only the INDEX, NOT the column.

Dialect-portable across Postgres / Oracle / SQLite. Type seams mirror
``20260510_0003_packs_lifecycle.py``: ``sa.Uuid()`` for the surrogate
PK, ``MODELS_TS_TYPE = sa.TIMESTAMP(timezone=True)`` for timestamps
(NOT ``sa.DateTime`` — Oracle would drop the offset). The ``models``
table here MUST agree column-for-column with the in-process Table at
``models/storage.py:_models``; drift is pinned by
``tests/unit/db/test_migration_20260522_0004.py``.

Per planning-time design decision #4 (spec §3.1 reconciled by Z3): the
``id`` Uuid column is a surrogate PK for join-friendliness (mirrors
``packs/``); ``model_id`` is the unique natural identity + the portal
path-param.

No edits to the ``decision_history`` schema — model lifecycle events
ride the existing chain substrate (the model-registry ``payload`` key
``model_id`` lands on existing JSON columns; no schema bump, no
``_SCHEMA_VERSION`` change).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Alembic revision identifiers.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | None = None
depends_on: str | None = None

# Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
# See the 0003 migration's module docstring for the Oracle-compile
# rationale (``sa.DateTime`` compiles to ``DATE`` on Oracle, silently
# dropping the offset).
MODELS_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "models",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("model_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("base_model", sa.String(length=256), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("recipe_hash", sa.String(length=64), nullable=True),
        sa.Column("training_data_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("eval_results_ref", sa.String(length=512), nullable=True),
        sa.Column("adversarial_pass_rate", sa.Float(), nullable=True),
        sa.Column("signature_digest", sa.String(length=64), nullable=True),
        sa.Column("signed_artifact_ref", sa.String(length=512), nullable=True),
        sa.Column("sigstore_bundle_ref", sa.String(length=512), nullable=True),
        sa.Column("serving_endpoint", sa.String(length=512), nullable=True),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False),
        sa.Column("last_actor", sa.String(length=256), nullable=False),
        sa.Column("created_at", MODELS_TS_TYPE, nullable=False),
        sa.Column("updated_at", MODELS_TS_TYPE, nullable=False),
        sa.CheckConstraint(
            "kind IN ('foundation', 'fine_tune', 'adapter', 'embedding')",
            name="ck_models_kind",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('proposed', 'eval_passed', 'tenant_approved', "
            "'serving', 'deprecated', 'retired')",
            name="ck_models_lifecycle_state",
        ),
        sa.UniqueConstraint("model_id", name="uq_models_model_id"),
    )
    op.create_index("ix_models_tenant_state", "models", ["tenant_id", "lifecycle_state"])
    # Composite index serves the Block-C GET /models/{id}/usage aggregate.
    # The gateway_call_ledger.model_id COLUMN already exists (Sprint 3).
    op.create_index(
        "ix_gateway_call_ledger_model_id_ts",
        "gateway_call_ledger",
        ["model_id", "ts"],
    )


def downgrade() -> None:
    # Reverse order: drop the ledger index first, then the models
    # indexes, then the table itself.
    op.drop_index("ix_gateway_call_ledger_model_id_ts", table_name="gateway_call_ledger")
    op.drop_index("ix_models_tenant_state", table_name="models")
    op.drop_table("models")

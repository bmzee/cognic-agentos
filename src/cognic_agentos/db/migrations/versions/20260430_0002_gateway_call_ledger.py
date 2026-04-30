"""gateway_call_ledger — Sprint 3 operational ledger per ADR-007.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-30

Operational, not chain-of-custody. Plain INSERT semantics; no chain
head, no SELECT FOR UPDATE. Per ADR-007 §"two layers" this is the
**authoritative** source for ``/api/v1/system/effective-routing``
because it is local, transactional, and never lossy. Hash-chained
tamper-evidence for the violation cases lives in ``audit_event``
(Sprint 2 substrate); duplicating tamper-evidence here would impose
a write-rate ceiling that ADR-007 explicitly rejects.

Round-6 reviewer-P1 schema additions:

- ``upstream_api_base`` — api_base is dispositive for cloud-policy
  classification (vLLM/SGLang serving ``model: openai/X`` against a
  private api_base classify as self-hosted). ``/effective-routing``
  must read it from the persisted ledger row, not re-resolve current
  YAML — historical rows would otherwise be misclassified after a
  YAML hot-reload.
- ``provenance`` — persists the four-state classification
  (``resolved`` | ``unresolved`` | ``ambiguous`` | ``no_dispatch``)
  so the endpoint can authoritatively distinguish dispatched calls
  (resolved/unresolved/ambiguous) from pre-dispatch denials
  (no_dispatch) when computing PROFILE-chip drift.

Round-1 reviewer-P1#3: ``revision = "0002"`` / ``down_revision =
"0001"`` — bare numeric form matching the existing 0001 migration's
revision identifier. The descriptive slug lives in the filename
(``20260430_0002_gateway_call_ledger.py``), not the revision string.

``model_id`` reserved nullable column — Sprint 9.5 backfills via the
ADR-013 model registry. Sprint 3 INSERTs NULL.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Alembic revision identifiers.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | None = None
depends_on: str | None = None

# ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
# On Oracle the latter compiles to ``DATE`` (no timezone), silently
# dropping the offset on every row. The former compiles to
# ``TIMESTAMP WITH TIME ZONE`` on Oracle and Postgres alike, matching
# the Sprint 2 0001 migration's ``audit_event.created_at`` +
# ``decision_history.created_at`` convention. Critical: this ledger is
# ADR-007's authoritative timing source for ``/effective-routing`` —
# if Oracle silently truncates the offset, the endpoint's recent-window
# query mixes local-naive + UTC across dialects + the PROFILE-chip
# drift detection becomes dialect-dependent.
#
# Exposed at module scope so the regression test in
# ``tests/unit/db/test_run_migrations.py`` can import this exact
# instance via ``importlib.import_module`` and compile-check it under
# the Oracle dialect — pinning the migration's chosen type, not a
# fresh hard-coded copy. A future regression to
# ``sa.DateTime(timezone=True)`` here causes Oracle compile output to
# drop to ``DATE`` and the test fails loudly.
GATEWAY_LEDGER_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "gateway_call_ledger",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("ts", GATEWAY_LEDGER_TS_TYPE, nullable=False),
        sa.Column("request_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=True),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("litellm_alias", sa.String(length=128), nullable=False),
        sa.Column("upstream_model", sa.String(length=256), nullable=False),
        # Round-6 reviewer-P1: api_base is dispositive for cloud-policy
        # classification, so /effective-routing must read it from the
        # authoritative ledger without re-resolving current YAML.
        sa.Column("upstream_api_base", sa.String(length=512), nullable=True),
        sa.Column("external", sa.Boolean(), nullable=False),
        # Round-6 reviewer-P1: provenance status persisted so historical
        # rows can be classified authoritatively. Values:
        # resolved | unresolved | ambiguous | no_dispatch.
        sa.Column("provenance", sa.String(length=16), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        # Reserved nullable column — Sprint 9.5 (ADR-013) backfills.
        sa.Column("model_id", sa.String(length=128), nullable=True),
    )
    # Indexes drive the /effective-routing endpoint queries:
    # - ``ts`` for the recent-window WHERE clause.
    # - ``request_id`` for cross-correlation with audit_event +
    #   Langfuse traces.
    # - ``provenance`` (Round-6 reviewer-P1) so the endpoint can
    #   filter ``provenance != "no_dispatch"`` cheaply when
    #   computing the PROFILE-chip drift count.
    op.create_index("ix_gateway_ledger_ts", "gateway_call_ledger", ["ts"])
    op.create_index("ix_gateway_ledger_request_id", "gateway_call_ledger", ["request_id"])
    op.create_index("ix_gateway_ledger_provenance", "gateway_call_ledger", ["provenance"])


def downgrade() -> None:
    # Drop indexes first (asymmetric drop without index drops would
    # leave dangling sqlite/PG/Oracle metadata; explicit reverse-order
    # drops keep the round-trip clean).
    op.drop_index("ix_gateway_ledger_provenance", table_name="gateway_call_ledger")
    op.drop_index("ix_gateway_ledger_request_id", table_name="gateway_call_ledger")
    op.drop_index("ix_gateway_ledger_ts", table_name="gateway_call_ledger")
    op.drop_table("gateway_call_ledger")

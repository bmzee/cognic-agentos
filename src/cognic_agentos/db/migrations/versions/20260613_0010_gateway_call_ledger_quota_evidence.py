"""gateway_call_ledger token/cost evidence columns — Sprint 13.6b per ADR-018 F6.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-13

Adds three NULLABLE columns to the existing ``gateway_call_ledger`` table to
capture LiteLLM response token usage + (future) upstream cost per the ADR-018
quota meter:

  * ``prompt_tokens``      (Integer) — provider ``usage.prompt_tokens``
  * ``completion_tokens``  (Integer) — provider ``usage.completion_tokens``
  * ``estimated_cost_usd`` (Float)   — upstream cost; NULL until a pricing
                                       source exists (evidence-ready only)

All three are nullable so historical rows (pre-13.6b writes) keep NULL with
zero backfill — additive, zero-downtime. No index changes (quota enforcement
reads the Redis counter plane, not the ledger; the ledger is the durable
examiner evidence per ADR-007). This migration MUST agree column-for-column
with the in-process Table at ``llm/ledger.py:_ledger_table``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Alembic revision identifiers.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("gateway_call_ledger", sa.Column("prompt_tokens", sa.Integer(), nullable=True))
    op.add_column(
        "gateway_call_ledger", sa.Column("completion_tokens", sa.Integer(), nullable=True)
    )
    op.add_column("gateway_call_ledger", sa.Column("estimated_cost_usd", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("gateway_call_ledger", "estimated_cost_usd")
    op.drop_column("gateway_call_ledger", "completion_tokens")
    op.drop_column("gateway_call_ledger", "prompt_tokens")

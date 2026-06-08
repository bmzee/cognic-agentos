"""eval_runs + eval_case_results — Sprint 12 evaluation harness (ADR-010).

Adds the two eval-storage tables backing
``cognic_agentos.evaluation.storage.EvalRunStore``. The value-free
``eval.bulk_run`` aggregate evidence lives in the ``decision_history`` chain;
these tables hold the operational per-run + per-case results (raw candidate
output only when persist_raw_output was set on the run).

Pins (mirroring 0005/0007): ``GovernanceJSON()`` for the dialect-portable JSON
columns + ``sa.TIMESTAMP(timezone=True)`` for ``created_at`` — NOT
``sa.DateTime`` (Oracle drops the offset). Column shapes MUST agree with the
in-process Tables at ``evaluation/storage.py``; drift is pinned by
``tests/unit/db/test_migration_20260607_0008.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from cognic_agentos.db.types import GovernanceJSON

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | None = None
depends_on: str | None = None

_EVAL_TS_TYPE = sa.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        "eval_runs",
        sa.Column("run_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("corpus_id", sa.String(length=200), nullable=False),
        sa.Column("corpus_digest", sa.String(length=64), nullable=False),
        sa.Column("target_kind", sa.String(length=32), nullable=False),
        sa.Column("tier", sa.String(length=16), nullable=False),
        sa.Column("actor_subject", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("passed", sa.Integer(), nullable=False),
        sa.Column("failed", sa.Integer(), nullable=False),
        sa.Column("errored", sa.Integer(), nullable=False),
        sa.Column("latency_p50_ms", sa.Integer(), nullable=False),
        sa.Column("latency_p95_ms", sa.Integer(), nullable=False),
        sa.Column("chain_request_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", _EVAL_TS_TYPE, nullable=False),
    )
    op.create_index("ix_eval_runs_tenant_created", "eval_runs", ["tenant_id", "created_at"])
    op.create_table(
        "eval_case_results",
        sa.Column("result_id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("eval_runs.run_id"), nullable=False),
        sa.Column("case_id", sa.String(length=200), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("scorer_results", GovernanceJSON(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("model", sa.String(length=256), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("output_digest", sa.String(length=64), nullable=False),
        sa.Column("candidate_output_text", GovernanceJSON(), nullable=True),
        sa.Column("raw_output_persisted", sa.Boolean(), nullable=False),
        sa.Column("output_truncated", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_eval_case_results_run", "eval_case_results", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_eval_case_results_run", table_name="eval_case_results")
    op.drop_table("eval_case_results")
    op.drop_index("ix_eval_runs_tenant_created", table_name="eval_runs")
    op.drop_table("eval_runs")

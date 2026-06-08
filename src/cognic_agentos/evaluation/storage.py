"""Sprint 12 eval run store (ADR-010 amendment) — CC.

Postgres-backed eval_runs + eval_case_results, written atomically with the
value-free ``eval.bulk_run`` decision-history chain row via
``append_with_precondition`` (mirrors core/scheduler/storage.py). The store body
+ atomic persist/read seam land in Task 8; this module currently defines the two
in-process Tables that the 0008 migration must agree with column-for-column.
"""

from __future__ import annotations

from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Uuid,
)

from cognic_agentos.core.audit import _metadata
from cognic_agentos.db.types import GovernanceJSON

_EVAL_TS_TYPE = TIMESTAMP(timezone=True)

_eval_runs = Table(
    "eval_runs",
    _metadata,
    Column("run_id", Uuid(), primary_key=True),
    Column("tenant_id", String(128), nullable=False),
    Column("corpus_id", String(200), nullable=False),
    Column("corpus_digest", String(64), nullable=False),
    Column("target_kind", String(32), nullable=False),
    Column("tier", String(16), nullable=False),
    Column("actor_subject", String(256), nullable=False),
    Column("status", String(16), nullable=False),
    Column("total", Integer(), nullable=False),
    Column("passed", Integer(), nullable=False),
    Column("failed", Integer(), nullable=False),
    Column("errored", Integer(), nullable=False),
    Column("latency_p50_ms", Integer(), nullable=False),
    Column("latency_p95_ms", Integer(), nullable=False),
    Column("chain_request_id", String(64), nullable=False),
    Column("created_at", _EVAL_TS_TYPE, nullable=False),
    Index("ix_eval_runs_tenant_created", "tenant_id", "created_at"),
)

_eval_case_results = Table(
    "eval_case_results",
    _metadata,
    Column("result_id", Uuid(), primary_key=True),
    Column("run_id", Uuid(), ForeignKey("eval_runs.run_id"), nullable=False),
    Column("case_id", String(200), nullable=False),
    Column("passed", Boolean(), nullable=False),
    Column("outcome", String(16), nullable=False),
    Column("scorer_results", GovernanceJSON(), nullable=False),
    Column("latency_ms", Integer(), nullable=False),
    Column("model", String(256), nullable=False),
    Column("input_digest", String(64), nullable=False),
    Column("output_digest", String(64), nullable=False),
    Column("candidate_output_text", GovernanceJSON(), nullable=True),
    Column("raw_output_persisted", Boolean(), nullable=False),
    Column("output_truncated", Boolean(), nullable=False),
    Index("ix_eval_case_results_run", "run_id"),
)

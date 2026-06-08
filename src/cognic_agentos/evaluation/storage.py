"""Sprint 12 eval run store (ADR-010 amendment) — CC.

Postgres-backed eval_runs + eval_case_results, written atomically with the
value-free ``eval.bulk_run`` decision-history chain row via
``append_with_precondition`` (mirrors core/scheduler/storage.py). The store body
+ atomic persist/read seam land in Task 8; this module currently defines the two
in-process Tables that the 0008 migration must agree with column-for-column.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

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
    insert,
    select,
)
from sqlalchemy.ext.asyncio import AsyncConnection

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.types import GovernanceJSON

if TYPE_CHECKING:
    from cognic_agentos.evaluation.types import EvalRunResult

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


#: ISO 42001 controls stamped on every ``eval.bulk_run`` chain row:
#: A.7.6 (AI system risk evaluation) + A.9.2 (system and operational logging).
_EVAL_ISO_CONTROLS: Final[tuple[str, ...]] = ("ISO42001.A.7.6", "ISO42001.A.9.2")

_EVAL_RUN_REQUEST_ID_PREFIX: Final[str] = "eval-run-"  # 9 chars + 32 hex = 41 <= 64


def mint_eval_request_id() -> str:
    """Bounded request_id for an eval run (prefix + uuid4().hex)."""
    return f"{_EVAL_RUN_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


assert len(_EVAL_RUN_REQUEST_ID_PREFIX) + 32 <= 64


class EvalRunStore:
    """Atomic eval-run persistence + tenant-scoped read."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history

    async def persist_run(
        self,
        *,
        result: EvalRunResult,
        actor_subject: str,
        tenant_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                insert(_eval_runs).values(
                    run_id=result.run_id,
                    tenant_id=tenant_id,
                    corpus_id=result.corpus_id,
                    corpus_digest=result.corpus_digest,
                    target_kind=result.target_kind,
                    tier=result.tier,
                    actor_subject=actor_subject,
                    status="completed",
                    total=result.total,
                    passed=result.passed,
                    failed=result.failed,
                    errored=result.errored,
                    latency_p50_ms=result.latency_p50_ms,
                    latency_p95_ms=result.latency_p95_ms,
                    chain_request_id=result.chain_request_id,
                    created_at=now,
                )
            )
            for case in result.cases:
                await conn.execute(
                    insert(_eval_case_results).values(
                        result_id=uuid.uuid4(),
                        run_id=result.run_id,
                        case_id=case.case_id,
                        passed=case.passed,
                        outcome=case.outcome,
                        scorer_results=[_scorer_to_json(s) for s in case.scorer_results],
                        latency_ms=case.latency_ms,
                        model=case.model,
                        input_digest=case.input_digest,
                        output_digest=case.output_digest,
                        candidate_output_text=case.candidate_output_text,
                        raw_output_persisted=case.raw_output_persisted,
                        output_truncated=case.output_truncated,
                    )
                )

        def _build_record(_: None) -> DecisionRecord:
            # Value-free chain payload: digests + counts only, NEVER raw text.
            return DecisionRecord(
                decision_type="eval.bulk_run",
                request_id=result.chain_request_id,
                actor_id=actor_subject,
                tenant_id=tenant_id,
                iso_controls=_EVAL_ISO_CONTROLS,
                payload={
                    "run_id": str(result.run_id),
                    "corpus_id": result.corpus_id,
                    "corpus_digest": result.corpus_digest,
                    "target_kind": result.target_kind,
                    "tier": result.tier,
                    "total": result.total,
                    "passed": result.passed,
                    "failed": result.failed,
                    "errored": result.errored,
                    "cases": [
                        {"case_id": c.case_id, "passed": c.passed, "output_digest": c.output_digest}
                        for c in result.cases
                    ],
                },
            )

        return await self._history.append_with_precondition(
            record_builder=_build_record, precondition=_precondition
        )

    async def get_run(self, *, run_id: uuid.UUID, tenant_id: str) -> dict[str, Any] | None:
        """Tenant-scoped read; cross-tenant / unknown both return None (404 at the route).

        Reads through the history store's own engine (same-engine read) so the eval
        tables stay co-located with the chain rows written by ``persist_run``.
        """
        async with self._history._engine.begin() as conn:
            run = (
                await conn.execute(
                    select(_eval_runs).where(
                        _eval_runs.c.run_id == run_id, _eval_runs.c.tenant_id == tenant_id
                    )
                )
            ).first()
            if run is None:
                return None
            cases = (
                await conn.execute(
                    select(_eval_case_results).where(_eval_case_results.c.run_id == run_id)
                )
            ).all()
        return {"run": run._mapping, "cases": [c._mapping for c in cases]}


def _scorer_to_json(s: Any) -> dict[str, Any]:
    return {
        "scorer": s.scorer,
        "passed": s.passed,
        "detail": [{"name": d.name, "passed": d.passed, "critique": d.critique} for d in s.detail],
        "verdict": s.verdict,
        "score": s.score,
        "rationale": s.rationale,
    }

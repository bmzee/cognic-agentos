# tests/unit/evaluation/test_corpus_digest.py
from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import corpus_digest, validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.storage import EvalRunStore, _eval_runs
from cognic_agentos.evaluation.types import CandidateOutput

_PAYLOAD = {
    "schema_version": 1,
    "corpus_id": "smoke",
    "cases": [
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "q"}],
            "assertions": {"contains": ["ok"]},
        }
    ],
}


def test_corpus_digest_equals_sprint12_literal_formula() -> None:
    corpus = validate_corpus_payload(_PAYLOAD)
    # The Sprint-12 baseline calculation (runner.py inline) was exactly this:
    expected = hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()
    assert corpus_digest(corpus) == expected


class _Target:
    target_kind = "gateway"
    tier = "tier1"

    async def run_case(self, case: Any, *, request_id: str, tenant_id: str) -> CandidateOutput:
        return CandidateOutput(
            text="ok", model="m", tier="tier1", latency_ms=1, outcome="succeeded"
        )


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'digest.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_corpus_digest_equals_stored_run_digest(tmp_path: Any) -> None:
    # The helper MUST equal what a real persisted run wrote to eval_runs.corpus_digest,
    # else replay's pre-run digest guard rejects existing baselines. A case declares
    # `assertions`, so the runner's fail-closed coverage requires an AssertionScorer.
    from cognic_agentos.evaluation.scorers import AssertionScorer

    eng = await _migrated_engine(tmp_path)
    try:
        corpus = validate_corpus_payload(_PAYLOAD)
        result = await EvalRunner().run(
            corpus,
            target=_Target(),
            scorers=[AssertionScorer()],
            run_id=uuid.uuid4(),
            chain_request_id="r",
            tenant_id="t1",
        )
        store = EvalRunStore(DecisionHistoryStore(eng))
        await store.persist_run(result=result, actor_subject="svc", tenant_id="t1")
        async with eng.connect() as c:
            stored = (
                await c.execute(
                    sa.select(_eval_runs.c.corpus_digest).where(
                        _eval_runs.c.run_id == result.run_id
                    )
                )
            ).scalar_one()
        assert corpus_digest(corpus) == stored
        assert corpus_digest(corpus) == result.corpus_digest
    finally:
        await eng.dispose()

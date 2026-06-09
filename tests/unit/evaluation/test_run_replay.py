# tests/unit/evaluation/test_run_replay.py
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.corpus import validate_corpus_payload
from cognic_agentos.evaluation.replay import run_replay
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.scorers import AssertionScorer
from cognic_agentos.evaluation.storage import EvalRunStore, _eval_runs
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.llm.gateway import GatewayResponse

_PAYLOAD = {
    "schema_version": 1,
    "corpus_id": "cp",
    "cases": [
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "q"}],
            "assertions": {"contains": ["ok"]},
        }
    ],
}


class _Gateway:
    def __init__(self, content: str) -> None:
        self._content = content

    async def completion(
        self, *, tier: str, messages: list[Any], request_id: str, tenant_id: str | None = None
    ) -> GatewayResponse:
        return GatewayResponse(
            content=self._content,
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=1,
        )


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runreplay.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


@pytest.mark.asyncio
async def test_run_replay_persists_candidate_and_emits_replay_row_with_regression(
    tmp_path: Any,
) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        corpus = validate_corpus_payload(_PAYLOAD)
        # seed a baseline that PASSES (output contains "ok")
        baseline = await EvalRunner().run(
            corpus,
            target=GatewayTarget(gateway=_Gateway("ok"), tier="tier1"),  # type: ignore[arg-type]
            scorers=[AssertionScorer()],
            run_id=uuid.uuid4(),
            chain_request_id="b",
            tenant_id="t1",
        )
        await store.persist_run(result=baseline, actor_subject="svc", tenant_id="t1")
        baseline_loaded = await store.get_run(run_id=baseline.run_id, tenant_id="t1")
        assert baseline_loaded is not None

        # candidate gateway returns "no" → assertion fails → regression
        diff = await run_replay(
            corpus=corpus,
            baseline_run_id=baseline.run_id,
            baseline_cases=[dict(c) for c in baseline_loaded["cases"]],
            baseline_tier=str(baseline_loaded["run"]["tier"]),
            gateway=_Gateway("no"),
            store=store,
            target_tier="tier1",
            judge_tier="tier1",
            max_raw_output_chars=50_000,
            tenant_id="t1",
            actor_subject="svc",
            persist_raw_output=False,
        )
        assert diff.has_regressions is True and diff.regressions == 1
        # candidate persisted as a first-class run
        async with eng.connect() as c:
            cand = (
                await c.execute(
                    sa.select(_eval_runs).where(_eval_runs.c.run_id == diff.candidate_run_id)
                )
            ).first()
            replay_rows = (
                await c.execute(
                    sa.text("SELECT 1 FROM decision_history WHERE event_type='eval.replay'")
                )
            ).all()
        assert cand is not None
        assert len(replay_rows) == 1
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_run_replay_raw_output_on_truncates_off_none(tmp_path: Any) -> None:
    from cognic_agentos.evaluation.storage import _eval_case_results

    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        corpus = validate_corpus_payload(_PAYLOAD)
        baseline = await EvalRunner().run(
            corpus,
            target=GatewayTarget(gateway=_Gateway("ok"), tier="tier1"),  # type: ignore[arg-type]
            scorers=[AssertionScorer()],
            run_id=uuid.uuid4(),
            chain_request_id="b",
            tenant_id="t1",
        )
        await store.persist_run(result=baseline, actor_subject="svc", tenant_id="t1")
        bl = await store.get_run(run_id=baseline.run_id, tenant_id="t1")
        assert bl is not None
        long_text = "ok " + "x" * 100  # contains "ok" -> passes; longer than the 10-char cap

        from cognic_agentos.evaluation.replay import ReplayDiff

        async def _replay(persist: bool) -> ReplayDiff:
            return await run_replay(
                corpus=corpus,
                baseline_run_id=baseline.run_id,
                baseline_cases=[dict(c) for c in bl["cases"]],
                baseline_tier=str(bl["run"]["tier"]),
                gateway=_Gateway(long_text),
                store=store,
                target_tier="tier1",
                judge_tier="tier1",
                max_raw_output_chars=10,
                tenant_id="t1",
                actor_subject="svc",
                persist_raw_output=persist,
            )

        on = await _replay(True)
        off = await _replay(False)
        async with eng.connect() as c:
            on_row = (
                await c.execute(
                    sa.select(_eval_case_results).where(
                        _eval_case_results.c.run_id == on.candidate_run_id
                    )
                )
            ).first()
            off_row = (
                await c.execute(
                    sa.select(_eval_case_results).where(
                        _eval_case_results.c.run_id == off.candidate_run_id
                    )
                )
            ).first()
        assert on_row.candidate_output_text == long_text[:10]
        assert on_row.raw_output_persisted and on_row.output_truncated
        assert off_row.candidate_output_text is None and not off_row.raw_output_persisted
    finally:
        await eng.dispose()

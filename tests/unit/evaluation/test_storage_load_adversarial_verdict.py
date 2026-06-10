from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.evaluation.types import AdversarialCaseResult, AdversarialVerdict


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'lav.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _verdict(candidate_run_id: uuid.UUID) -> AdversarialVerdict:
    return AdversarialVerdict(
        candidate_run_id=candidate_run_id,
        corpus_id="adv",
        total=2,
        passed=1,
        failed=1,
        errored=0,
        overall_pass_rate=0.5,
        per_category_pass_rate={"direct_prompt_injection": 0.5},
        high_severity_all_pass=False,
        per_case=(
            AdversarialCaseResult(
                base_case_id="a",
                expanded_case_id="a::none",
                attack_category="direct_prompt_injection",
                mutation_strategy="none",
                severity="high",
                passed=False,
            ),
            AdversarialCaseResult(
                base_case_id="a",
                expanded_case_id="a::encoding",
                attack_category="direct_prompt_injection",
                mutation_strategy="encoding",
                severity="standard",
                passed=True,
            ),
        ),
    )


@pytest.mark.asyncio
async def test_load_adversarial_verdict_roundtrips(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        run_id = uuid.uuid4()
        await store.append_adversarial_event(
            verdict=_verdict(run_id),
            actor_subject="svc",
            tenant_id="t1",
            request_id="eval-adv-" + uuid.uuid4().hex,
        )
        got = await store.load_adversarial_verdict(run_id=run_id, tenant_id="t1")
        assert got is not None
        assert got.candidate_run_id == run_id
        assert got.overall_pass_rate == 0.5
        assert got.high_severity_all_pass is False
        assert {c.expanded_case_id for c in got.per_case} == {"a::none", "a::encoding"}
        assert got.per_case[0].severity == "high" and got.per_case[0].passed is False
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_load_adversarial_verdict_unknown_or_cross_tenant_returns_none(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        run_id = uuid.uuid4()
        await store.append_adversarial_event(
            verdict=_verdict(run_id),
            actor_subject="svc",
            tenant_id="t1",
            request_id="eval-adv-" + uuid.uuid4().hex,
        )
        # unknown run id
        assert await store.load_adversarial_verdict(run_id=uuid.uuid4(), tenant_id="t1") is None
        # right run id, wrong tenant → invisible
        assert await store.load_adversarial_verdict(run_id=run_id, tenant_id="t2") is None
    finally:
        await eng.dispose()

# tests/unit/evaluation/test_storage.py
from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.storage import (
    _EVAL_RUN_REQUEST_ID_PREFIX,
    EvalRunStore,
    _eval_runs,
    mint_eval_request_id,
)
from cognic_agentos.evaluation.types import (
    CaseResult,
    CriterionDetail,
    EvalRunResult,
    ScorerResult,
)


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eval_store.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _result(run_id: uuid.UUID, *, persist_raw: bool = False) -> EvalRunResult:
    case = CaseResult(
        case_id="c1",
        passed=True,
        outcome="succeeded",
        scorer_results=(
            ScorerResult(
                scorer="assertions",
                passed=True,
                detail=(CriterionDetail(name="contains:x", passed=True, critique=""),),
            ),
        ),
        latency_ms=4,
        model="m",
        input_digest="i",
        output_digest="o",
        candidate_output_text="the full model answer" if persist_raw else None,
        raw_output_persisted=persist_raw,
        output_truncated=False,
    )
    return EvalRunResult(
        run_id=run_id,
        chain_request_id="eval-run-abcdef",
        corpus_id="cp",
        corpus_digest="d",
        target_kind="gateway",
        tier="tier1",
        total=1,
        passed=1,
        failed=0,
        errored=0,
        latency_p50_ms=4,
        latency_p95_ms=4,
        cases=(case,),
    )


@pytest.mark.asyncio
async def test_persist_run_writes_rows_and_chain_request_id_matches(tmp_path: Any) -> None:
    """KEY CONTRACT — atomic persist + request_id back-link + ISO controls on the chain row."""
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        record_id, _hash = await store.persist_run(
            result=_result(rid), actor_subject="svc", tenant_id="t1"
        )
        assert isinstance(record_id, uuid.UUID)
        async with eng.connect() as c:
            run_row = (
                await c.execute(sa.select(_eval_runs).where(_eval_runs.c.run_id == rid))
            ).first()
            dh = (
                await c.execute(
                    sa.text(
                        "SELECT event_type, request_id, iso_controls FROM decision_history "
                        "WHERE event_type = 'eval.bulk_run'"
                    )
                )
            ).first()
        assert run_row is not None
        # Back-link: eval_runs.chain_request_id == DecisionRecord.request_id.
        assert run_row.chain_request_id == "eval-run-abcdef"
        assert dh is not None
        assert dh.request_id == "eval-run-abcdef"
        assert "ISO42001.A.7.6" in dh.iso_controls and "ISO42001.A.9.2" in dh.iso_controls
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_persist_run_writes_case_rows(tmp_path: Any) -> None:
    """Relational case rows land inside the same atomic precondition closure."""
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        await store.persist_run(result=_result(rid), actor_subject="svc", tenant_id="t1")
        got = await store.get_run(run_id=rid, tenant_id="t1")
        assert got is not None
        assert len(got["cases"]) == 1
        scorer_json = got["cases"][0]["scorer_results"]
        # _scorer_to_json shape: a list of {scorer, passed, detail, verdict, score, rationale}.
        assert scorer_json[0]["scorer"] == "assertions"
        assert scorer_json[0]["detail"][0]["name"] == "contains:x"
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_chain_payload_is_value_free(tmp_path: Any) -> None:
    """KEY CONTRACT — value-free chain: digests + counts only, NEVER raw candidate text."""
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        await store.persist_run(
            result=_result(uuid.uuid4(), persist_raw=True), actor_subject="svc", tenant_id="t1"
        )
        async with eng.connect() as c:
            payload = (
                await c.execute(
                    sa.text("SELECT payload FROM decision_history WHERE event_type='eval.bulk_run'")
                )
            ).scalar_one()
        # raw candidate text must NEVER appear in the value-free chain payload.
        assert "the full model answer" not in str(payload)
        assert "output_digest" in str(payload) or "o" in str(payload)
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_get_run_cross_tenant_returns_none(tmp_path: Any) -> None:
    """KEY CONTRACT — tenant-scoped read: own found; cross-tenant + unknown both None."""
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        result = _result(rid)
        await store.persist_run(result=result, actor_subject="svc", tenant_id="t1")
        assert await store.get_run(run_id=rid, tenant_id="t1") is not None
        assert await store.get_run(run_id=rid, tenant_id="t2") is None  # cross-tenant invisible
        assert await store.get_run(run_id=uuid.uuid4(), tenant_id="t1") is None  # unknown
    finally:
        await eng.dispose()


@pytest.mark.asyncio
async def test_get_run_roundtrips_governance_json_string(tmp_path: Any) -> None:
    """USER WATCHPOINT — GovernanceJSON round-trips a plain str as a str (not bytes/JSON)."""
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        rid = uuid.uuid4()
        await store.persist_run(
            result=_result(rid, persist_raw=True), actor_subject="svc", tenant_id="t1"
        )
        got = await store.get_run(run_id=rid, tenant_id="t1")
        assert got is not None
        returned = got["cases"][0]["candidate_output_text"]
        assert returned == "the full model answer"
        assert isinstance(returned, str)
        assert got["cases"][0]["raw_output_persisted"] is True
    finally:
        await eng.dispose()


def test_mint_eval_request_id_is_bounded_and_prefixed() -> None:
    """The bounded request-id minter: prefix + uuid4 hex, never overflowing String(64)."""
    rid = mint_eval_request_id()
    assert rid.startswith(_EVAL_RUN_REQUEST_ID_PREFIX)
    assert len(rid) == len(_EVAL_RUN_REQUEST_ID_PREFIX) + 32
    assert len(rid) <= 64
    assert mint_eval_request_id() != rid  # fresh uuid each call

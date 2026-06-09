# tests/unit/evaluation/test_storage_replay.py
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.replay import CaseDiff, ReplayDiff
from cognic_agentos.evaluation.storage import EvalRunStore, mint_eval_replay_request_id


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'replay.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _diff(baseline_id: uuid.UUID, candidate_id: uuid.UUID) -> ReplayDiff:
    cd = CaseDiff(
        case_id="c1",
        drift_kind="regression",
        baseline_passed=True,
        candidate_passed=False,
        baseline_outcome="succeeded",
        candidate_outcome="succeeded",
        output_digest_changed=True,
        baseline_model="m1",
        candidate_model="m2",
        baseline_tier="tier1",
        candidate_tier="tier2",
    )
    return ReplayDiff(
        baseline_run_id=baseline_id,
        candidate_run_id=candidate_id,
        corpus_id="cp",
        corpus_digest="d",
        total=1,
        regressions=1,
        improvements=0,
        unchanged=0,
        output_changed=0,
        errored=0,
        has_regressions=True,
        cases=(cd,),
    )


def test_mint_eval_replay_request_id_bounded_and_prefixed() -> None:
    rid = mint_eval_replay_request_id()
    assert rid.startswith("eval-replay-") and len(rid) <= 64


@pytest.mark.asyncio
async def test_append_replay_event_writes_value_free_chain_row(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        baseline_id, candidate_id = uuid.uuid4(), uuid.uuid4()
        _record_id, _hash = await store.append_replay_event(
            diff=_diff(baseline_id, candidate_id),
            actor_subject="svc",
            tenant_id="t1",
            request_id="eval-replay-abc",
        )
        async with eng.connect() as c:
            row = (
                await c.execute(
                    sa.text(
                        "SELECT event_type, request_id, iso_controls, payload "
                        "FROM decision_history WHERE event_type='eval.replay'"
                    )
                )
            ).first()
        assert row.event_type == "eval.replay" and row.request_id == "eval-replay-abc"
        assert "ISO42001.A.7.6" in row.iso_controls and "ISO42001.A.9.2" in row.iso_controls
        payload = json.loads(row.payload) if isinstance(row.payload, str) else dict(row.payload)
        # EXACT top-level key set — the locked minimal shape (spec §5) PLUS the
        # store-merged ``actor_id`` (governance identity, NOT a model/tier/raw
        # value) so the evidence row answers "who triggered this replay" —
        # consistent with eval.bulk_run, which carries actor_id the same way.
        assert set(payload.keys()) == {
            "baseline_run_id",
            "candidate_run_id",
            "corpus_id",
            "corpus_digest",
            "total",
            "regressions",
            "improvements",
            "unchanged",
            "output_changed",
            "errored",
            "cases",
            "actor_id",
        }
        # actor IS recorded for examiner traceability.
        assert payload["actor_id"] == "svc"
        # EXACT per-case key set — no model/tier/raw/output text.
        assert set(payload["cases"][0].keys()) == {
            "case_id",
            "drift_kind",
            "baseline_passed",
            "candidate_passed",
            "output_digest_changed",
        }
        # belt-and-suspenders: no forbidden token anywhere in the serialized payload.
        flat = json.dumps(payload)
        for forbidden in ("model", "tier", "raw", "candidate_output_text", "output_text"):
            assert forbidden not in flat
        assert payload["baseline_run_id"] == str(baseline_id)
        assert payload["candidate_run_id"] == str(candidate_id)
        assert payload["cases"][0]["drift_kind"] == "regression"
    finally:
        await eng.dispose()

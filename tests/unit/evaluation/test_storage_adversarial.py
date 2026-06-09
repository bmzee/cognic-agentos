# tests/unit/evaluation/test_storage_adversarial.py
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.storage import EvalRunStore, mint_eval_adversarial_request_id
from cognic_agentos.evaluation.types import AdversarialCaseResult, AdversarialVerdict


async def _migrated_engine(tmp_path: Any) -> Any:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'adv.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _verdict(run_id: uuid.UUID) -> AdversarialVerdict:
    return AdversarialVerdict(
        candidate_run_id=run_id,
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
                passed=True,
            ),
            AdversarialCaseResult(
                base_case_id="a",
                expanded_case_id="a::encoding",
                attack_category="direct_prompt_injection",
                mutation_strategy="encoding",
                severity="high",
                passed=False,
            ),
        ),
    )


def test_mint_eval_adversarial_request_id_bounded_and_prefixed() -> None:
    rid = mint_eval_adversarial_request_id()
    assert rid.startswith("eval-adv-") and len(rid) <= 64


@pytest.mark.asyncio
async def test_append_adversarial_event_writes_value_free_chain_row(tmp_path: Any) -> None:
    eng = await _migrated_engine(tmp_path)
    try:
        store = EvalRunStore(DecisionHistoryStore(eng))
        run_id = uuid.uuid4()
        await store.append_adversarial_event(
            verdict=_verdict(run_id), actor_subject="svc", tenant_id="t1", request_id="eval-adv-abc"
        )
        async with eng.connect() as c:
            row = (
                await c.execute(
                    sa.text(
                        "SELECT event_type, request_id, iso_controls, payload "
                        "FROM decision_history WHERE event_type='eval.adversarial_run'"
                    )
                )
            ).first()
        assert row.event_type == "eval.adversarial_run" and row.request_id == "eval-adv-abc"
        assert "ISO42001.A.7.6" in row.iso_controls and "ISO42001.A.9.2" in row.iso_controls
        payload = json.loads(row.payload) if isinstance(row.payload, str) else dict(row.payload)
        assert set(payload.keys()) == {
            "candidate_run_id",
            "corpus_id",
            "total",
            "passed",
            "failed",
            "errored",
            "overall_pass_rate",
            "per_category_pass_rate",
            "high_severity_all_pass",
            "cases",
            "actor_id",
        }
        assert payload["actor_id"] == "svc"
        assert payload["candidate_run_id"] == str(run_id)
        assert set(payload["cases"][0].keys()) == {
            "base_case_id",
            "expanded_case_id",
            "attack_category",
            "mutation_strategy",
            "severity",
            "passed",
        }
        flat = json.dumps(payload)
        forbidden_tokens = (
            "messages",
            "candidate_output_text",
            "output_text",
            "model",
            "tier",
            "raw",
        )
        for forbidden in forbidden_tokens:
            assert forbidden not in flat
    finally:
        await eng.dispose()

"""Sprint 13c (ADR-011) — submit-time adversarial evidence wiring.

The author ``submit_draft`` request gains optional ``adversarial_run_id`` +
``baseline_adversarial_run_id``; when ``adversarial_run_id`` is supplied the
handler resolves an ``EvalRunStore`` from ``app.state`` (request-time, mirroring
the eval-route ``_require_decision_history_store`` precedent), runs the
``build_adversarial_evidence`` producer, maps its closed-enum refusal →
(status, body), and threads the snapshot onto the submit chain row via the T4
``payload_adversarial`` kwarg.

Harness: ``_metadata.create_all`` + manual chain-head seed (mirrors
``test_author_routes.py``); the eval tables live on the SAME
``core.audit._metadata`` as the pack/decision_history tables, so one engine backs
both the pack store + the resolved eval store. ``create_app`` is the production
factory path.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH, canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.evaluation.storage import EvalRunStore
from cognic_agentos.evaluation.types import (
    AdversarialCaseResult,
    AdversarialVerdict,
    CaseResult,
    EvalRunResult,
)
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _actor() -> Actor:
    return Actor(
        subject="alice@bank.example",
        tenant_id="t1",
        scopes=frozenset({"pack.submit"}),
        actor_type="human",
    )


def _manifest() -> dict[str, Any]:
    return {
        "pack": {"kind": "tool", "name": "demo", "version": "1.0.0"},
        "identity": {
            "agent_id": "cognic.demo.v1",
            "display_name": "Demo",
            "provider_organization": "Acme",
            "provider_url": "https://acme.example",
        },
        "risk_tier": {"tier": "read_only"},
    }


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'submit_adv.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


async def _seed_draft(store: PackRecordStore, manifest: dict[str, Any]) -> PackRecord:
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=f"cognic-tool-{uuid.uuid4().hex[:8]}",
        display_name="Seed",
        state="draft",
        manifest_digest=hashlib.sha256(canonical_bytes(manifest)).digest(),
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id="t1",
        created_by="alice@bank.example",
        last_actor="alice@bank.example",
        created_at=now,
        updated_at=now,
    )
    await store.save_draft(record)
    return record


def _case_result(cid: str) -> CaseResult:
    return CaseResult(
        case_id=cid,
        passed=True,
        outcome="succeeded",
        scorer_results=(),
        latency_ms=1,
        model="m",
        input_digest="i",
        output_digest="o",
        candidate_output_text=None,
        raw_output_persisted=False,
        output_truncated=False,
    )


def _eval_result(run_id: uuid.UUID, *, corpus_digest: str, cid: str) -> EvalRunResult:
    return EvalRunResult(
        run_id=run_id,
        chain_request_id="eval-" + uuid.uuid4().hex,
        corpus_id="adv",
        corpus_digest=corpus_digest,
        target_kind="gateway",
        tier="tier1",
        total=1,
        passed=1,
        failed=0,
        errored=0,
        latency_p50_ms=1,
        latency_p95_ms=1,
        cases=(_case_result(cid),),
    )


async def _seed_adversarial_run(
    eval_store: EvalRunStore, *, corpus_digest: str = "dig"
) -> uuid.UUID:
    run_id = uuid.uuid4()
    await eval_store.persist_run(
        result=_eval_result(run_id, corpus_digest=corpus_digest, cid="a::none"),
        actor_subject="svc",
        tenant_id="t1",
    )
    adv = AdversarialCaseResult(
        base_case_id="a",
        expanded_case_id="a::none",
        attack_category="direct_prompt_injection",
        mutation_strategy="none",
        severity="high",
        passed=True,
    )
    await eval_store.append_adversarial_event(
        verdict=AdversarialVerdict(
            candidate_run_id=run_id,
            corpus_id="adv",
            total=1,
            passed=1,
            failed=0,
            errored=0,
            overall_pass_rate=1.0,
            per_category_pass_rate={"direct_prompt_injection": 1.0},
            high_severity_all_pass=True,
            per_case=(adv,),
        ),
        actor_subject="svc",
        tenant_id="t1",
        request_id="eval-adv-" + uuid.uuid4().hex,
    )
    return run_id


async def _persist_plain_run(eval_store: EvalRunStore) -> uuid.UUID:
    """A persisted eval-run with NO adversarial verdict (non-adversarial)."""
    run_id = uuid.uuid4()
    await eval_store.persist_run(
        result=_eval_result(run_id, corpus_digest="dig", cid="x::none"),
        actor_subject="svc",
        tenant_id="t1",
    )
    return run_id


async def _submit_payload(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as c:
        row = (
            await c.execute(
                sa.text(
                    "SELECT payload FROM decision_history "
                    "WHERE event_type='pack.lifecycle.submitted'"
                )
            )
        ).first()
    assert row is not None, "no submit chain row"
    return row[0] if isinstance(row[0], dict) else json.loads(row[0])


def _app(engine: AsyncEngine, *, pack_store: PackRecordStore, with_dh: bool = True) -> Any:
    kwargs: dict[str, Any] = {
        "actor_binder": _StubBinder(_actor()),
        "pack_record_store": pack_store,
    }
    if with_dh:
        kwargs["decision_history_store"] = DecisionHistoryStore(engine)
    return create_app(**kwargs)


def _submit(app: Any, pack_id: uuid.UUID, body: dict[str, Any]) -> Any:
    with TestClient(app) as client:
        return client.post(f"/api/v1/packs/drafts/{pack_id}/submit", json=body)


@pytest.mark.asyncio
async def test_submit_with_valid_adversarial_run_populates_snapshot(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    eval_store = EvalRunStore(DecisionHistoryStore(engine))
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    run_id = await _seed_adversarial_run(eval_store)
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(run_id),
        },
    )
    assert resp.status_code == 200, resp.text
    payload = await _submit_payload(engine)
    assert payload["adversarial"]["candidate_run_id"] == str(run_id)
    assert payload["adversarial"]["regression_evaluated"] is False
    assert payload["adversarial"]["baseline_run_id"] is None


@pytest.mark.asyncio
async def test_submit_without_adversarial_run_id_has_no_snapshot(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    # No decision_history_store → proves the no-adversarial path never reads app.state.
    resp = _submit(
        _app(engine, pack_store=pack_store, with_dh=False),
        record.id,
        {"manifest": manifest, "signed_artefact_root": "/srv/bundle"},
    )
    assert resp.status_code == 200, resp.text
    payload = await _submit_payload(engine)
    assert "adversarial" not in payload


@pytest.mark.asyncio
async def test_submit_with_adversarial_run_id_but_no_dh_store_503(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    # App built WITHOUT a decision_history_store → fail-closed 503.
    resp = _submit(
        _app(engine, pack_store=pack_store, with_dh=False),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["reason"] == "decision_history_unavailable"


@pytest.mark.asyncio
async def test_submit_unknown_adversarial_run_404(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["reason"] == "adversarial_run_not_found"


@pytest.mark.asyncio
async def test_submit_non_adversarial_run_400(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    eval_store = EvalRunStore(DecisionHistoryStore(engine))
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    plain = await _persist_plain_run(eval_store)
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(plain),
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == "adversarial_run_not_adversarial"


@pytest.mark.asyncio
async def test_submit_baseline_digest_mismatch_400(engine: AsyncEngine) -> None:
    pack_store = PackRecordStore(engine)
    eval_store = EvalRunStore(DecisionHistoryStore(engine))
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    cand = await _seed_adversarial_run(eval_store, corpus_digest="dig")
    base = await _seed_adversarial_run(eval_store, corpus_digest="OTHER")
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(cand),
            "baseline_adversarial_run_id": str(base),
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == "adversarial_baseline_corpus_digest_mismatch"


@pytest.mark.asyncio
async def test_submit_baseline_unknown_404(engine: AsyncEngine) -> None:
    # Route-boundary pin for the 4th refusal: candidate valid, baseline UUID
    # unknown → the producer raises adversarial_baseline_run_not_found, which the
    # route's status map turns into 404.
    pack_store = PackRecordStore(engine)
    eval_store = EvalRunStore(DecisionHistoryStore(engine))
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    cand = await _seed_adversarial_run(eval_store)
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(cand),
            "baseline_adversarial_run_id": str(uuid.uuid4()),
        },
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["reason"] == "adversarial_baseline_run_not_found"


@pytest.mark.asyncio
async def test_submit_baseline_non_adversarial_400(engine: AsyncEngine) -> None:
    # Route-boundary pin for the 5th refusal: candidate valid, baseline is a
    # plain eval-run (no adversarial verdict) → adversarial_baseline_run_not_
    # adversarial → 400 (fires BEFORE the digest check; both runs share "dig").
    pack_store = PackRecordStore(engine)
    eval_store = EvalRunStore(DecisionHistoryStore(engine))
    manifest = _manifest()
    record = await _seed_draft(pack_store, manifest)
    cand = await _seed_adversarial_run(eval_store)
    base_plain = await _persist_plain_run(eval_store)
    resp = _submit(
        _app(engine, pack_store=pack_store),
        record.id,
        {
            "manifest": manifest,
            "signed_artefact_root": "/srv/bundle",
            "adversarial_run_id": str(cand),
            "baseline_adversarial_run_id": str(base_plain),
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == "adversarial_baseline_run_not_adversarial"

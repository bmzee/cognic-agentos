"""Sprint 9.5 A3-A5 — ModelRecordStore (SQLite-aiosqlite test substrate)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.models.registry import (
    MODEL_LIFECYCLE_ISO_CONTROLS,
    ModelLifecycleRefused,
)
from cognic_agentos.models.storage import (
    ModelNotFound,  # noqa: F401  (exported by storage; used by A4 tests)
    ModelRecord,
    ModelRecordStore,
    _models,
)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'models.db'}"
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


@pytest.fixture
async def store(engine: AsyncEngine) -> ModelRecordStore:
    return ModelRecordStore(engine)


def _make_record(model_id: str = "cognic-tier1-acme-v1") -> ModelRecord:
    now = datetime.now(UTC)
    return ModelRecord(
        id=uuid.uuid4(),
        model_id=model_id,
        tenant_id="tenant-acme",
        base_model="qwen3-8b-instruct",
        version="1.0.0",
        kind="fine_tune",
        recipe_hash="a" * 64,
        training_data_fingerprint="b" * 64,
        eval_results_ref=None,
        adversarial_pass_rate=None,
        signature_digest=None,
        signed_artifact_ref=None,
        sigstore_bundle_ref=None,
        serving_endpoint=None,
        lifecycle_state="proposed",
        last_actor="forge-bot",
        created_at=now,
        updated_at=now,
    )


async def _count_chain_rows(eng: AsyncEngine) -> int:
    async with eng.connect() as conn:
        return int(
            (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
        )


async def _read_state(eng: AsyncEngine, row_id: uuid.UUID) -> str | None:
    """Load the lifecycle_state by the SURROGATE id (DB/join identity).
    A5 adds load_by_model_id for the natural wire identity.
    """
    async with eng.connect() as conn:
        row = (
            await conn.execute(select(_models.c.lifecycle_state).where(_models.c.id == row_id))
        ).first()
    return row[0] if row else None


async def _count_models_rows(eng: AsyncEngine, model_id: str) -> int:
    """Count rows by the wire-identity model_id — used to confirm no
    orphan models row was inserted on a rolled-back genesis path.
    """
    async with eng.connect() as conn:
        return int(
            (
                await conn.execute(
                    select(func.count()).select_from(_models).where(_models.c.model_id == model_id)
                )
            ).scalar_one()
        )


async def test_register_inserts_row_and_genesis_chain_event(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    rec = _make_record()
    before = await _count_chain_rows(engine)
    record_id, h = await store.register(
        rec, request_id="req-reg-1", actor_id="forge-bot", actor_type="service"
    )
    # One chain row appended; state cache inserted at proposed.
    assert await _count_chain_rows(engine) == before + 1
    assert await _read_state(engine, rec.id) == "proposed"
    assert isinstance(record_id, uuid.UUID)
    assert isinstance(h, bytes) and len(h) == 32


async def test_register_duplicate_model_id_refused_and_rolled_back(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin: duplicate model_id raises ModelLifecycleRefused(
    'model_register_duplicate_id'), writes no model row, writes no
    chain row — the whole transaction rolls back atomically.
    """
    rec = _make_record()
    await store.register(rec, request_id="req-reg-1", actor_id="forge-bot", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    models_before = await _count_models_rows(engine, rec.model_id)
    assert models_before == 1
    dup = _make_record()  # same model_id, fresh surrogate uuid
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.register(
            dup, request_id="req-reg-2", actor_id="forge-bot", actor_type="service"
        )
    assert ei.value.reason == "model_register_duplicate_id"
    # Rollback: no extra chain row, no orphan models row by EITHER
    # the duplicate's surrogate id OR its (matching) model_id.
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, dup.id) is None
    assert await _count_models_rows(engine, rec.model_id) == 1


@pytest.mark.parametrize(
    "bad_initial_state",
    ["eval_passed", "tenant_approved", "serving", "deprecated", "retired"],
)
async def test_register_refuses_non_proposed_initial_state(
    store: ModelRecordStore, engine: AsyncEngine, bad_initial_state: str
) -> None:
    """A3 R1 P1: register() MUST refuse any non-'proposed' initial
    state. Without this gate a caller could submit a ModelRecord
    already in serving/retired/etc and register() would INSERT it
    as-is then emit a model.lifecycle.proposed chain row — bypassing
    every eval/trust/tenant-approval transition gate and corrupting
    the chain/state-cache invariant. Pinned across all 5 non-proposed
    states for defence-in-depth.
    """
    bad = _make_record().model_copy(update={"lifecycle_state": bad_initial_state})
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.register(bad, request_id="req-bad", actor_id="x", actor_type="service")
    assert ei.value.reason == "model_register_initial_state_not_proposed"
    # No model row inserted (by either identity); no chain row appended.
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, bad.id) is None
    assert await _count_models_rows(engine, bad.model_id) == 0


async def test_genesis_chain_event_is_model_lifecycle_proposed(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin: genesis chain row has decision_type == 'model.lifecycle.proposed',
    payload['model_id'] + payload['actor_type'] present, and
    payload['iso_controls'] is the LIST projection of
    MODEL_LIFECYCLE_ISO_CONTROLS (canonical-form rejects tuples in
    payloads; the registry-level tuple is the source-of-truth tag set).
    """
    rec = _make_record()
    await store.register(rec, request_id="req-reg-1", actor_id="forge-bot", actor_type="service")
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                select(
                    _decision_history.c.event_type,
                    _decision_history.c.payload,
                    _decision_history.c.iso_controls,
                    _decision_history.c.request_id,
                    _decision_history.c.tenant_id,
                )
            )
        ).first()
    assert row is not None
    assert row.event_type == "model.lifecycle.proposed"
    assert row.request_id == "req-reg-1"
    assert row.tenant_id == rec.tenant_id
    # Payload shape — model_id, actor_type, from/to state, iso_controls.
    assert row.payload["model_id"] == rec.model_id
    assert row.payload["actor_type"] == "service"
    assert row.payload["to_state"] == "proposed"
    assert row.payload["from_state"] is None
    # iso_controls inside payload is list-shaped (canonical-form rule);
    # exactly equal to MODEL_LIFECYCLE_ISO_CONTROLS by value.
    assert row.payload["iso_controls"] == list(MODEL_LIFECYCLE_ISO_CONTROLS)
    assert isinstance(row.payload["iso_controls"], list)
    # The separate iso_controls COLUMN is also the list projection.
    assert row.iso_controls == list(MODEL_LIFECYCLE_ISO_CONTROLS)


async def test_load_returns_none_for_unknown(store: ModelRecordStore) -> None:
    assert await store.load(uuid.uuid4()) is None

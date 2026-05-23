"""Sprint 9.5 A3-A5 — ModelRecordStore (SQLite-aiosqlite test substrate)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    ModelNotFound,
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
        # Signed-by-default for A4: register() only stores the refs
        # as metadata (no signature check at genesis), but
        # promote_eval_passed REQUIRES the caller to bind the cosign
        # verdict to all 3 of these (A4 R1 P1 fix). Tests that want
        # an unsigned record can model_copy to None.
        signature_digest="a" * 64,
        signed_artifact_ref="v1/artefact.bin",
        sigstore_bundle_ref="v1/bundle.sigstore",
        serving_endpoint=None,
        lifecycle_state="proposed",
        last_actor="forge-bot",
        created_at=now,
        updated_at=now,
    )


def _signed_record_args(rec: ModelRecord) -> dict[str, Any]:
    """The 3 ``expected_*`` kwargs binding a ``promote_eval_passed``
    cosign verdict to a specific record's artefact refs/digest —
    required for every successful ``promote_eval_passed`` call
    (A4 R1 P1 fix; the locked precondition re-checks byte-identical
    via the same values).
    """
    return {
        "expected_signed_artifact_ref": rec.signed_artifact_ref,
        "expected_sigstore_bundle_ref": rec.sigstore_bundle_ref,
        "expected_signature_digest": rec.signature_digest,
    }


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


# ===========================================================================
# A4 — ModelRecordStore.transition() (promote / retire)
# ===========================================================================


async def _read_eval_fields(eng: AsyncEngine, row_id: uuid.UUID) -> tuple[str | None, float | None]:
    """Project eval_results_ref + adversarial_pass_rate from the row."""
    async with eng.connect() as conn:
        row = (
            await conn.execute(
                select(
                    _models.c.eval_results_ref,
                    _models.c.adversarial_pass_rate,
                ).where(_models.c.id == row_id)
            )
        ).first()
    if row is None:
        return (None, None)
    return (row.eval_results_ref, row.adversarial_pass_rate)


async def test_transition_keyword_only_signature_enforced(
    store: ModelRecordStore,
) -> None:
    """Pin 1: transition() is keyword-only. Positional calls fail
    fast — positional misuse is a state-machine bug class the
    keyword-only contract eliminates at the call site.
    """
    fresh_id = uuid.uuid4()
    with pytest.raises(TypeError):
        # All positional — must fail at call time, not after some
        # side effect.
        await store.transition(  # type: ignore[misc]
            fresh_id, "promote_eval_passed", "x", "human", "rp"
        )


async def test_transition_unknown_row_raises_model_not_found(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 2: unknown row_id raises ModelNotFound — distinct from
    ModelLifecycleRefused so route handlers can dispatch 404 vs 409.
    Asserts no chain row appended on the not-found path.
    """
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelNotFound):
        await store.transition(
            row_id=uuid.uuid4(),
            transition="retire",
            actor_id="op",
            actor_type="human",
            request_id="r-nf",
        )
    assert await _count_chain_rows(engine) == chain_before


async def test_promote_eval_passed_refused_when_signature_not_verified(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 3: promote_eval_passed refused BEFORE the transaction opens
    when signature_verified is not True — no chain row attempted.
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    state_before = await _read_state(engine, rec.id)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_eval_passed",
            actor_id="reviewer",
            actor_type="human",
            request_id="rp",
            signature_verified=False,
        )
    assert ei.value.reason == "model_promote_signature_verification_failed"
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == state_before


async def test_promote_eval_passed_advances_state(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Happy path: promote_eval_passed with signature_verified=True
    advances the state cache + appends one chain row.
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    record_id, h = await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="reviewer",
        actor_type="human",
        request_id="rp",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    assert await _count_chain_rows(engine) == chain_before + 1
    assert await _read_state(engine, rec.id) == "eval_passed"
    assert isinstance(record_id, uuid.UUID)
    assert isinstance(h, bytes) and len(h) == 32


@pytest.mark.parametrize(
    "changed_field,changed_value",
    [
        ("signed_artifact_ref", "v2/artefact.bin"),
        ("sigstore_bundle_ref", "v2/bundle.sigstore"),
        ("signature_digest", "f" * 64),
    ],
)
async def test_promote_eval_passed_refused_when_refs_changed_during_promote(
    store: ModelRecordStore,
    engine: AsyncEngine,
    changed_field: str,
    changed_value: str,
) -> None:
    """Pin 4: cosign TOCTOU guard re-checks all three artefact
    identity fields under the row lock against the caller's
    expected_* kwargs. Mismatch on ANY of the three (artefact ref /
    bundle ref / digest) raises
    model_promote_signature_refs_changed_during_promote — rolls back
    state + chain (no chain row, no state mutation). Mirrors
    packs/storage.py's expected_manifest_digest race fix.
    """
    from sqlalchemy import update as _sa_update

    rec = _make_record().model_copy(
        update={
            "signed_artifact_ref": "v1/artefact.bin",
            "sigstore_bundle_ref": "v1/bundle.sigstore",
            "signature_digest": "a" * 64,
        }
    )
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    # Simulate concurrent admin update of ONE field AFTER the route
    # handler's pre-lock read + cosign verify, BEFORE the locked
    # precondition runs.
    async with engine.begin() as conn:
        await conn.execute(
            _sa_update(_models)
            .where(_models.c.id == rec.id)
            .values(**{changed_field: changed_value})
        )
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_eval_passed",
            actor_id="reviewer",
            actor_type="human",
            request_id="rp",
            signature_verified=True,
            # The caller threads what cosign verified pre-lock.
            expected_signed_artifact_ref="v1/artefact.bin",
            expected_sigstore_bundle_ref="v1/bundle.sigstore",
            expected_signature_digest="a" * 64,
        )
    assert ei.value.reason == "model_promote_signature_refs_changed_during_promote"
    # Rolled back — no chain row, state cache still at proposed.
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == "proposed"


async def test_invalid_state_pair_refused_and_rolled_back(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 6: validate_transition runs under the row-locked current
    state. proposed → serving is not a legal pair — refused
    model_transition_invalid_state_pair; rolls back (no chain row,
    state unchanged).
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_serving",  # not legal from proposed
            actor_id="op",
            actor_type="human",
            request_id="r-bad",
        )
    assert ei.value.reason == "model_transition_invalid_state_pair"
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == "proposed"


async def test_promote_tenant_approved_refused_without_eval_evidence(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 5a: promote_tenant_approved evidence shape gate refuses
    model_promote_eval_evidence_missing when either eval_results_ref
    or adversarial_pass_rate is None. Rolls back inside the
    transaction (no state update, no chain row).
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r2",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_tenant_approved",
            actor_id="r",
            actor_type="human",
            request_id="r3",
            # eval_results_ref + adversarial_pass_rate both omitted
        )
    assert ei.value.reason == "model_promote_eval_evidence_missing"
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == "eval_passed"


@pytest.mark.parametrize(
    "eval_ref,pass_rate",
    [
        ("", 0.99),  # blank ref
        ("   ", 0.99),  # whitespace-only ref
        ("evalpack://run/1", -0.1),  # negative pass rate
        ("evalpack://run/1", 1.1),  # above 1
    ],
)
async def test_promote_tenant_approved_refused_when_eval_evidence_malformed(
    store: ModelRecordStore,
    engine: AsyncEngine,
    eval_ref: str,
    pass_rate: float,
) -> None:
    """Pin 5b: shape gate rejects blank / whitespace / out-of-range
    values under the transaction. Rolls back (no state update, no
    chain row).
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r2",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_tenant_approved",
            actor_id="r",
            actor_type="human",
            request_id="r3",
            eval_results_ref=eval_ref,
            adversarial_pass_rate=pass_rate,
        )
    assert ei.value.reason == "model_promote_eval_evidence_malformed"
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == "eval_passed"


async def test_promote_eval_passed_does_not_set_eval_fields_on_row(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 7: successful promote_eval_passed updates ONLY
    lifecycle_state + last_actor + updated_at. Even if the caller
    inadvertently passes eval_results_ref / adversarial_pass_rate
    kwargs (which only tenant_approved should set), they MUST NOT
    leak onto the row.
    """
    rec = _make_record()  # eval fields start as None
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    pre_eval_ref, pre_rate = await _read_eval_fields(engine, rec.id)
    assert pre_eval_ref is None
    assert pre_rate is None

    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="rp",
        signature_verified=True,
        **_signed_record_args(rec),
        # Inadvertently passed — MUST NOT stick on a non-tenant-approved
        # promote.
        eval_results_ref="should-not-stick",
        adversarial_pass_rate=0.5,
    )
    post_eval_ref, post_rate = await _read_eval_fields(engine, rec.id)
    assert post_eval_ref is None, (
        f"promote_eval_passed must NOT set eval_results_ref; got {post_eval_ref!r}"
    )
    assert post_rate is None, (
        f"promote_eval_passed must NOT set adversarial_pass_rate; got {post_rate!r}"
    )


async def test_promote_tenant_approved_sets_eval_fields_on_row(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 7 (positive side): a successful promote_tenant_approved
    DOES set eval_results_ref + adversarial_pass_rate on the row
    (the evidence is what justified the approval — it has to land).
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r2",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    await store.transition(
        row_id=rec.id,
        transition="promote_tenant_approved",
        actor_id="reviewer",
        actor_type="human",
        request_id="r3",
        eval_results_ref="evalpack://run/42",
        adversarial_pass_rate=0.999,
    )
    eval_ref, pass_rate = await _read_eval_fields(engine, rec.id)
    assert eval_ref == "evalpack://run/42"
    assert pass_rate == 0.999


async def test_transition_chain_row_shape_pins_decision_type_and_payload(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 8: chain row is model.lifecycle.<target_state> with
    from_state, to_state, actor_type, model_id, and iso_controls
    exactly MODEL_LIFECYCLE_ISO_CONTROLS (as a LIST in payload —
    canonical-form rule).
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="reviewer",
        actor_type="human",
        request_id="rp",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    # Read the LATEST chain row (the promote_eval_passed one — sequence
    # 2; the genesis at sequence 1).
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                select(
                    _decision_history.c.event_type,
                    _decision_history.c.payload,
                    _decision_history.c.iso_controls,
                )
                .order_by(_decision_history.c.sequence.desc())
                .limit(1)
            )
        ).first()
    assert row is not None
    assert row.event_type == "model.lifecycle.eval_passed"
    assert row.payload["from_state"] == "proposed"
    assert row.payload["to_state"] == "eval_passed"
    assert row.payload["actor_type"] == "human"
    assert row.payload["model_id"] == rec.model_id
    assert row.payload["iso_controls"] == list(MODEL_LIFECYCLE_ISO_CONTROLS)
    assert isinstance(row.payload["iso_controls"], list)
    assert row.iso_controls == list(MODEL_LIFECYCLE_ISO_CONTROLS)


async def test_full_proposed_to_retired_lifecycle(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Full happy chain: proposed → eval_passed → tenant_approved →
    serving → retired. Five chain rows total (1 genesis + 4
    transitions); final state retired; eval fields set at
    tenant_approved.
    """
    rec = _make_record()
    chain_before = await _count_chain_rows(engine)
    await store.register(rec, request_id="r0", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r1",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    await store.transition(
        row_id=rec.id,
        transition="promote_tenant_approved",
        actor_id="r",
        actor_type="human",
        request_id="r2",
        eval_results_ref="evalpack://run/1",
        adversarial_pass_rate=0.999,
    )
    await store.transition(
        row_id=rec.id,
        transition="promote_serving",
        actor_id="op",
        actor_type="human",
        request_id="r3",
    )
    await store.transition(
        row_id=rec.id,
        transition="retire",
        actor_id="op",
        actor_type="human",
        request_id="r4",
    )
    assert await _count_chain_rows(engine) == chain_before + 5
    final = await store.load(rec.id)
    assert final is not None
    assert final.lifecycle_state == "retired"
    assert final.eval_results_ref == "evalpack://run/1"
    assert final.adversarial_pass_rate == 0.999


# ===========================================================================
# A4 R1 P1 — TOCTOU guard cannot be bypassed by omitting expected refs
# ===========================================================================


@pytest.mark.parametrize(
    "missing_field",
    [
        "expected_signed_artifact_ref",
        "expected_sigstore_bundle_ref",
        "expected_signature_digest",
    ],
)
async def test_promote_eval_passed_refused_when_expected_refs_missing(
    store: ModelRecordStore, engine: AsyncEngine, missing_field: str
) -> None:
    """A4 R1 P1: promote_eval_passed REQUIRES the caller to bind the
    cosign verdict to ALL THREE artefact refs/digest. Missing any of
    them refuses ``model_promote_signature_expected_refs_missing``
    BEFORE the transaction opens — no chain row attempted, state
    unchanged. Without this gate the TOCTOU re-check inside the
    locked precondition would be silently skippable (the existing
    ``if expected_signed_artifact_ref is not None`` guard would
    short-circuit on None), letting a caller claim ``cosign verified``
    without binding the verdict to any specific artefact.
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    args = _signed_record_args(rec)
    args[missing_field] = None  # blank out one of the 3 expected_* kwargs
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_eval_passed",
            actor_id="r",
            actor_type="human",
            request_id="rp",
            signature_verified=True,
            **args,
        )
    assert ei.value.reason == "model_promote_signature_expected_refs_missing"
    assert await _count_chain_rows(engine) == chain_before
    assert await _read_state(engine, rec.id) == "proposed"


async def test_promote_eval_passed_signature_failure_precedes_missing_refs(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Refusal precedence: ``signature_verification_failed`` fires
    BEFORE the ``expected_refs_missing`` gate. If cosign rejected the
    artefact (``signature_verified=False``), the missing-refs case is
    moot — there is nothing to bind. The ordering is pinned so a
    future refactor doesn't accidentally invert the precedence and
    surface the wrong refusal reason on a cosign rejection.
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_eval_passed",
            actor_id="r",
            actor_type="human",
            request_id="rp",
            signature_verified=False,  # cosign rejected
            # No expected_* — WOULD trigger expected_refs_missing if
            # precedence were inverted. The verification gate must
            # fire first.
        )
    assert ei.value.reason == "model_promote_signature_verification_failed"
    assert await _count_chain_rows(engine) == chain_before


# ===========================================================================
# A4 R1 P2 — Unknown transition name surfaces the closed-enum refusal
# ===========================================================================


async def test_transition_refuses_unknown_transition_name(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """A4 R1 P2: out-of-vocabulary ``transition`` name gets the
    closed-enum refusal ``model_transition_name_unknown`` — NOT a raw
    ``KeyError`` from the ``_TRANSITION_TO_TARGET_STATE`` lookup.
    Type hints do not protect runtime callers; mirrors
    ``packs/storage.py:742-743``'s preflight transition-name guard.
    """
    rec = _make_record()
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    chain_before = await _count_chain_rows(engine)
    with pytest.raises(ModelLifecycleRefused) as ei:
        await store.transition(
            row_id=rec.id,
            transition="promote_to_nowhere",  # type: ignore[arg-type]
            actor_id="r",
            actor_type="human",
            request_id="r-bad",
        )
    assert ei.value.reason == "model_transition_name_unknown"
    assert await _count_chain_rows(engine) == chain_before


# ===========================================================================
# A4 R1 P3 — Pin 7 completion: last_actor + updated_at update assertions
# ===========================================================================


async def test_transition_updates_last_actor_and_updated_at(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Pin 7 (complete coverage): successful transitions update
    ``lifecycle_state`` + ``last_actor`` + ``updated_at``. The other
    A4 tests cover ``lifecycle_state`` via ``_read_state``; this test
    pins ``last_actor`` (actor-id propagation) and ``updated_at``
    (monotonic advancement) explicitly. Without these assertions a
    regression that dropped either field from the values dict at
    ``storage.py``'s state-cache UPDATE would slip past A4 coverage.
    """
    import asyncio

    rec = _make_record()  # last_actor="forge-bot" by default
    await store.register(rec, request_id="r1", actor_id="forge-bot", actor_type="service")
    before = await store.load(rec.id)
    assert before is not None
    assert before.last_actor == "forge-bot"
    # Tiny sleep so datetime.now(UTC) at the next call is strictly
    # later than register-time on fast systems.
    await asyncio.sleep(0.001)
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="reviewer-alice",
        actor_type="human",
        request_id="rp",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    after = await store.load(rec.id)
    assert after is not None
    assert after.last_actor == "reviewer-alice", (
        f"last_actor should reflect the transition actor; got {after.last_actor!r}"
    )
    assert after.updated_at > before.updated_at, (
        f"updated_at should advance strictly; "
        f"before={before.updated_at!r}, after={after.updated_at!r}"
    )


# ===========================================================================
# A5 — read methods: load_by_model_id, list_for_tenant, load_lifecycle_history
# ===========================================================================


async def test_load_by_model_id_returns_record(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Natural-identity lookup — keys by the wire `model_id` (the
    portal path-param). Mirrors A3's surrogate-id ``load(row_id)`` but
    on the unique String column.
    """
    rec = _make_record("m-natural-lookup")
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    loaded = await store.load_by_model_id("m-natural-lookup")
    assert loaded is not None
    assert loaded.id == rec.id
    assert loaded.model_id == rec.model_id
    assert loaded.tenant_id == rec.tenant_id


async def test_load_by_model_id_returns_none_for_unknown(
    store: ModelRecordStore,
) -> None:
    """Unknown model_id returns None (not raise) — consumed by
    ``RequireModelTenantOwnership`` which maps None → 404."""
    assert await store.load_by_model_id("no-such-model") is None


async def test_list_for_tenant_scopes_by_tenant(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """The ``WHERE tenant_id == :tenant_id`` clause IS the tenant
    boundary. Cross-tenant rows MUST NOT appear in another tenant's
    list — the inspection-list endpoint has no actor-side filter; the
    SQL filter is authoritative.
    """
    a1 = _make_record("acme-1").model_copy(update={"tenant_id": "tenant-acme"})
    a2 = _make_record("acme-2").model_copy(update={"tenant_id": "tenant-acme"})
    other = _make_record("other-1").model_copy(update={"tenant_id": "tenant-other"})
    for r in (a1, a2, other):
        await store.register(r, request_id=f"r-{r.model_id}", actor_id="x", actor_type="service")
    acme_results = await store.list_for_tenant("tenant-acme")
    acme_model_ids = {r.model_id for r in acme_results}
    assert acme_model_ids == {"acme-1", "acme-2"}
    assert "other-1" not in acme_model_ids
    # Inverse direction also pinned.
    other_results = await store.list_for_tenant("tenant-other")
    assert {r.model_id for r in other_results} == {"other-1"}


async def test_list_for_tenant_state_filter(store: ModelRecordStore, engine: AsyncEngine) -> None:
    """Optional ``state`` keyword filters to a single
    ``lifecycle_state``. Pin both halves of the partition (proposed-only
    + eval_passed-only) so a regression that drops the WHERE clause
    is caught.
    """
    a = _make_record("filter-a")
    b = _make_record("filter-b")
    for r in (a, b):
        await store.register(r, request_id=f"r-{r.model_id}", actor_id="x", actor_type="service")
    # Promote a → eval_passed; b stays at proposed.
    await store.transition(
        row_id=a.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="rp",
        signature_verified=True,
        **_signed_record_args(a),
    )
    proposed_only = await store.list_for_tenant("tenant-acme", state="proposed")
    assert {r.model_id for r in proposed_only} == {"filter-b"}
    eval_only = await store.list_for_tenant("tenant-acme", state="eval_passed")
    assert {r.model_id for r in eval_only} == {"filter-a"}


async def test_list_for_tenant_paginates_deterministically(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Cursor + limit paginate over a deterministic ASCENDING order on
    the surrogate ``id`` PK. No duplicates across pages, no skips,
    repeatable order. Mirrors ``packs/storage.py``'s
    ``_build_list_for_tenant_stmt`` pattern (``order_by(id) + WHERE
    id > cursor``).
    """
    # Register 5 records into the same tenant.
    recs = [_make_record(f"m-page-{i}") for i in range(5)]
    for r in recs:
        await store.register(r, request_id=f"r-{r.model_id}", actor_id="x", actor_type="service")
    # Page 1: limit=2, no cursor → first 2 by ascending id.
    page1 = await store.list_for_tenant("tenant-acme", limit=2)
    assert len(page1) == 2
    # Page 2: cursor=last id from page 1 → next 2.
    page2 = await store.list_for_tenant("tenant-acme", limit=2, cursor=page1[-1].id)
    assert len(page2) == 2
    # Page 3: cursor=last id from page 2 → final 1.
    page3 = await store.list_for_tenant("tenant-acme", limit=2, cursor=page2[-1].id)
    assert len(page3) == 1
    # No duplicates across pages; all 5 covered.
    all_ids = {r.id for r in page1} | {r.id for r in page2} | {r.id for r in page3}
    assert all_ids == {r.id for r in recs}
    # Repeatability — same query yields same order.
    page1_again = await store.list_for_tenant("tenant-acme", limit=2)
    assert [r.id for r in page1] == [r.id for r in page1_again]


async def test_load_lifecycle_history_walks_chain_oldest_first(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """History reconstructs from ``decision_history`` rows where
    ``event_type LIKE 'model.lifecycle.%'`` filtered by
    ``payload['model_id']``. Order is ``sequence ASC`` (oldest first);
    includes genesis + all transitions.
    """
    rec = _make_record("m-history")
    await store.register(rec, request_id="r1", actor_id="x", actor_type="service")
    await store.transition(
        row_id=rec.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r2",
        signature_verified=True,
        **_signed_record_args(rec),
    )
    await store.transition(
        row_id=rec.id,
        transition="promote_tenant_approved",
        actor_id="r",
        actor_type="human",
        request_id="r3",
        eval_results_ref="evalpack://run/1",
        adversarial_pass_rate=0.999,
    )
    history = await store.load_lifecycle_history("m-history")
    assert [h.decision_type for h in history] == [
        "model.lifecycle.proposed",
        "model.lifecycle.eval_passed",
        "model.lifecycle.tenant_approved",
    ]
    # Each event carries model_id in payload + iso_controls (tuple).
    for h in history:
        assert h.payload["model_id"] == "m-history"
        assert h.iso_controls == tuple(MODEL_LIFECYCLE_ISO_CONTROLS)


async def test_load_lifecycle_history_filters_exactly_by_model_id(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Defence-in-depth: history MUST NOT leak other models' rows.
    Two distinct models register into the SAME tenant; each
    load_lifecycle_history call returns only that model's chain rows.
    """
    a = _make_record("model-a")
    b = _make_record("model-b")
    for r in (a, b):
        await store.register(r, request_id=f"r-{r.model_id}", actor_id="x", actor_type="service")
    await store.transition(
        row_id=a.id,
        transition="promote_eval_passed",
        actor_id="r",
        actor_type="human",
        request_id="r-a-promote",
        signature_verified=True,
        **_signed_record_args(a),
    )
    a_history = await store.load_lifecycle_history("model-a")
    b_history = await store.load_lifecycle_history("model-b")
    # Exact match on payload['model_id'] — every row's model_id matches.
    assert [h.payload["model_id"] for h in a_history] == ["model-a", "model-a"]
    assert [h.payload["model_id"] for h in b_history] == ["model-b"]
    assert len(a_history) == 2  # genesis + eval_passed
    assert len(b_history) == 1  # genesis only


async def test_load_lifecycle_history_does_not_substring_match(
    store: ModelRecordStore, engine: AsyncEngine
) -> None:
    """Defence against a regression to LIKE / substring filtering on
    ``payload['model_id']``. A model_id 'foo' MUST NOT match 'foo-long'
    or any other superstring. Pinned because the SQL filter is
    ``event_type LIKE 'model.lifecycle.%'`` (substring on event_type
    is correct) + a Python-side EXACT-equality on payload['model_id']
    (substring would be wrong).
    """
    short = _make_record("foo")
    long_ = _make_record("foo-long")
    for r in (short, long_):
        await store.register(r, request_id=f"r-{r.model_id}", actor_id="x", actor_type="service")
    foo_history = await store.load_lifecycle_history("foo")
    assert len(foo_history) == 1, (
        f"'foo' MUST NOT match 'foo-long'; got {[h.payload['model_id'] for h in foo_history]!r}"
    )
    assert foo_history[0].payload["model_id"] == "foo"
    long_history = await store.load_lifecycle_history("foo-long")
    assert len(long_history) == 1
    assert long_history[0].payload["model_id"] == "foo-long"


async def test_load_lifecycle_history_returns_empty_for_unknown(
    store: ModelRecordStore,
) -> None:
    """Unknown model_id returns empty list (not error). Pinned because
    the chain filter naturally yields 0 matches; no special-case
    handling needed."""
    assert await store.load_lifecycle_history("no-such-model") == []

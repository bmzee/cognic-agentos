"""Sprint 14A-A3a — RunRecordStore: genesis, the 6 synchronous transitions,
reserved-pair refusal, optional-column seams, tenant-isolation reads, value-free
chain snapshot, atomicity. REAL DecisionHistoryStore over in-memory sqlite."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.run._types import RunTransitionRefused
from cognic_agentos.core.run.storage import RunNotFound, RunRecordStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'runs.db'}")
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


def _mk(store: RunRecordStore, **kw: object) -> dict[str, object]:
    base: dict[str, object] = dict(
        run_id=uuid.uuid4(),
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        pack_uuid=uuid.uuid4(),
        pack_version="1.0.0",
        request_id="req-1",
    )
    base.update(kw)
    return base


async def _event_types(db: AsyncEngine) -> list[str]:
    async with db.connect() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
            )
        ).all()
    return [r[0] for r in rows]


async def test_create_run_genesis_inserts_pending_and_emits_lifecycle_pending(
    db: AsyncEngine,
) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    rec = await store.load(args["run_id"], tenant_id="tenant-a")  # type: ignore[arg-type]
    assert rec is not None
    assert rec.state == "pending"
    assert rec.task_id is None and rec.session_id is None and rec.checkpoint_id is None
    assert await _event_types(db) == ["run.lifecycle.pending"]


async def test_full_synchronous_path_pending_running_completed(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    run_id = args["run_id"]
    await store.create_run(**args)  # type: ignore[arg-type]
    await store.transition(
        run_id=run_id,  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="pending",
        to_state="running",
        actor_id="svc",
        request_id="r",
        session_id="sess-1",
        task_id=uuid.uuid4(),
    )
    await store.transition(
        run_id=run_id,  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="running",
        to_state="completed",
        actor_id="svc",
        request_id="r",
    )
    rec = await store.load(run_id, tenant_id="tenant-a")  # type: ignore[arg-type]
    assert rec is not None and rec.state == "completed" and rec.session_id == "sess-1"
    assert await _event_types(db) == [
        "run.lifecycle.pending",
        "run.lifecycle.running",
        "run.lifecycle.completed",
    ]


async def test_pending_to_refused_pre_running(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    await store.transition(
        run_id=args["run_id"],  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="pending",
        to_state="refused",
        actor_id="svc",
        request_id="r",
    )
    rec = await store.load(args["run_id"], tenant_id="tenant-a")  # type: ignore[arg-type]
    assert rec is not None and rec.state == "refused"


async def test_reserved_pair_transition_refuses(db: AsyncEngine) -> None:
    # A3b legalised running->suspended, so this storage-preflight reserved-vocab
    # pin moved to a still-reserved target: ``cancelled`` has no
    # _STATE_TO_DECISION_TYPE entry and no legal pair, so the preflight refuses.
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    await store.transition(
        run_id=args["run_id"],  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="pending",
        to_state="running",
        actor_id="svc",
        request_id="r",
    )
    with pytest.raises(RunTransitionRefused) as exc:
        await store.transition(
            run_id=args["run_id"],  # type: ignore[arg-type]
            tenant_id="tenant-a",
            from_state="running",
            to_state="cancelled",
            actor_id="svc",
            request_id="r",
        )
    assert exc.value.reason == "run_transition_invalid_state_pair"


async def test_from_state_mismatch_refuses(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]  # state=pending
    with pytest.raises(RunTransitionRefused):
        # claim from_state=running but the row is pending
        await store.transition(
            run_id=args["run_id"],  # type: ignore[arg-type]
            tenant_id="tenant-a",
            from_state="running",
            to_state="completed",
            actor_id="svc",
            request_id="r",
        )


async def test_transition_unknown_run_raises_not_found(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    with pytest.raises(RunNotFound):
        await store.transition(
            run_id=uuid.uuid4(),
            tenant_id="tenant-a",
            from_state="pending",
            to_state="running",
            actor_id="svc",
            request_id="r",
        )


async def test_cross_tenant_load_returns_none(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    # owner tenant sees it; another tenant gets None (invisible).
    assert await store.load(args["run_id"], tenant_id="tenant-a") is not None  # type: ignore[arg-type]
    assert await store.load(args["run_id"], tenant_id="tenant-OTHER") is None  # type: ignore[arg-type]


async def test_cross_tenant_transition_reads_as_not_found(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    with pytest.raises(RunNotFound):
        await store.transition(
            run_id=args["run_id"],  # type: ignore[arg-type]
            tenant_id="tenant-OTHER",
            from_state="pending",
            to_state="running",
            actor_id="svc",
            request_id="r",
        )


async def test_list_for_tenant_scoped_and_state_filtered(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    a1 = _mk(store, tenant_id="tenant-a")
    a2 = _mk(store, tenant_id="tenant-a")
    b1 = _mk(store, tenant_id="tenant-b")
    for args in (a1, a2, b1):
        await store.create_run(**args)  # type: ignore[arg-type]
    rows_a = await store.list_for_tenant("tenant-a")
    assert {r.run_id for r in rows_a} == {a1["run_id"], a2["run_id"]}
    rows_b = await store.list_for_tenant("tenant-b", state="pending")
    assert {r.run_id for r in rows_b} == {b1["run_id"]}


async def test_list_for_tenant_cursor_paginates(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    run_ids = []
    for _ in range(3):
        args = _mk(store, tenant_id="tenant-a")
        await store.create_run(**args)  # type: ignore[arg-type]
        run_ids.append(args["run_id"])
    ordered = sorted(run_ids)  # type: ignore[type-var]  # list_for_tenant orders by run_id (keyset cursor)
    page1 = await store.list_for_tenant("tenant-a", limit=2)
    assert [r.run_id for r in page1] == ordered[:2]
    page2 = await store.list_for_tenant("tenant-a", cursor=ordered[1])  # type: ignore[arg-type]
    assert [r.run_id for r in page2] == ordered[2:]


async def test_transition_persists_all_optional_columns_and_snapshots_them(
    db: AsyncEngine,
) -> None:
    # Exercises the additive A3b/A3c seams: session_id/task_id/checkpoint_id/
    # approval_request_id all set on one transition. checkpoint_id is the sandbox
    # CheckpointId hex (32 chars); approval_request_id is a UUID.
    store = RunRecordStore(db)
    args = _mk(store)
    run_id = args["run_id"]
    await store.create_run(**args)  # type: ignore[arg-type]
    ckpt = "a" * 32
    appr = uuid.uuid4()
    sess = "sess-x"
    tid = uuid.uuid4()
    await store.transition(
        run_id=run_id,  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="pending",
        to_state="running",
        actor_id="svc",
        request_id="r",
        session_id=sess,
        task_id=tid,
        checkpoint_id=ckpt,
        approval_request_id=appr,
    )
    rec = await store.load(run_id, tenant_id="tenant-a")  # type: ignore[arg-type]
    assert rec is not None
    assert rec.session_id == sess and rec.task_id == tid
    assert rec.checkpoint_id == ckpt and rec.approval_request_id == appr
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload).where(
                    _decision_history.c.event_type == "run.lifecycle.running"
                )
            )
        ).first()
    assert row is not None
    payload = row[0]
    assert payload["checkpoint_id"] == ckpt
    assert payload["approval_request_id"] == str(appr)
    assert payload["session_id"] == sess and payload["task_id"] == str(tid)


async def test_chain_payload_is_value_free_snapshot(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    await store.transition(
        run_id=args["run_id"],  # type: ignore[arg-type]
        tenant_id="tenant-a",
        from_state="pending",
        to_state="running",
        actor_id="svc",
        request_id="r",
        session_id="sess-9",
    )
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload).where(
                    _decision_history.c.event_type == "run.lifecycle.running"
                )
            )
        ).first()
    assert row is not None
    payload = row[0]
    assert payload["to_state"] == "running" and payload["from_state"] == "pending"
    assert payload["session_id"] == "sess-9"
    assert payload["run_id"] == str(args["run_id"])
    # value-free: no raw output keys
    assert "stdout" not in payload and "stderr" not in payload


async def test_reserved_payload_key_overlap_raises(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    args = _mk(store)
    await store.create_run(**args)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="payload_extras overlaps"):
        await store.transition(
            run_id=args["run_id"],  # type: ignore[arg-type]
            tenant_id="tenant-a",
            from_state="pending",
            to_state="running",
            actor_id="svc",
            request_id="r",
            payload_extras={"run_id": "forged"},
        )


# --- Sprint 14A-A3b: suspend/wake transition targets ---------------------------


async def test_running_to_suspended_persists_session_and_checkpoint(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    run_id = uuid.uuid4()
    await store.create_run(
        run_id=run_id,
        tenant_id="t1",
        pack_id="p",
        pack_uuid=uuid.uuid4(),
        pack_version="1",
        request_id="rq",
    )
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="pending",
        to_state="running",
        actor_id="alice",
        request_id="rq",
        task_id=uuid.uuid4(),
    )
    cid = uuid.uuid4().hex  # CheckpointId hex (32 chars)
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="running",
        to_state="suspended",
        actor_id="alice",
        request_id="rq",
        session_id="sess-1",
        checkpoint_id=cid,
    )
    rec = await store.load(run_id, tenant_id="t1")
    assert rec is not None and rec.state == "suspended"
    assert rec.session_id == "sess-1" and rec.checkpoint_id == cid


async def test_suspended_to_woken_to_completed(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    run_id = uuid.uuid4()
    await store.create_run(
        run_id=run_id,
        tenant_id="t1",
        pack_id="p",
        pack_uuid=uuid.uuid4(),
        pack_version="1",
        request_id="rq",
    )
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="pending",
        to_state="running",
        actor_id="alice",
        request_id="rq",
        task_id=uuid.uuid4(),
    )
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="running",
        to_state="suspended",
        actor_id="alice",
        request_id="rq",
        session_id="s",
        checkpoint_id=uuid.uuid4().hex,
    )
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="suspended",
        to_state="woken",
        actor_id="alice",
        request_id="rq",
    )
    await store.transition(
        run_id=run_id,
        tenant_id="t1",
        from_state="woken",
        to_state="completed",
        actor_id="alice",
        request_id="rq",
    )
    rec = await store.load(run_id, tenant_id="t1")
    assert rec is not None and rec.state == "completed"


async def test_suspended_decision_type_is_run_lifecycle_suspended() -> None:
    from cognic_agentos.core.run.storage import _STATE_TO_DECISION_TYPE

    assert _STATE_TO_DECISION_TYPE["suspended"] == "run.lifecycle.suspended"
    assert _STATE_TO_DECISION_TYPE["woken"] == "run.lifecycle.woken"


async def test_stale_read_on_suspend_pair_refuses(db: AsyncEngine) -> None:
    store = RunRecordStore(db)
    run_id = uuid.uuid4()
    await store.create_run(
        run_id=run_id,
        tenant_id="t1",
        pack_id="p",
        pack_uuid=uuid.uuid4(),
        pack_version="1",
        request_id="rq",
    )
    # row is 'pending'; claim from_state='running' -> stale -> refused
    with pytest.raises(RunTransitionRefused) as exc:
        await store.transition(
            run_id=run_id,
            tenant_id="t1",
            from_state="running",
            to_state="suspended",
            actor_id="a",
            request_id="rq",
            session_id="s",
            checkpoint_id=uuid.uuid4().hex,
        )
    assert exc.value.reason == "run_transition_invalid_state_pair"

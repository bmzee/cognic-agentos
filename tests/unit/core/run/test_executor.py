"""Sprint 14A-A — ManagedRunExecutor orchestration over a REAL scheduler +
REAL DecisionHistoryStore (in-memory sqlite) with a STUB sandbox backend +
STUB pack loader. Proves the full submit -> create -> exec -> destroy ->
complete loop, the four pre-submit pack-validation refusals, the failure
paths, the value-free run.* evidence, and the Actor -> TaskActor projection.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,  # registered in the shared _metadata
)
from cognic_agentos.core.run._types import RunRecord
from cognic_agentos.core.run.executor import (
    LoadedPackRecord,
    ManagedRunExecutor,
    RunRequest,
)
from cognic_agentos.core.run.storage import RunRecordStore
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.protocol import SandboxExecResult

pytestmark = pytest.mark.asyncio


# --- in-memory DB (mirror tests/unit/core/scheduler/test_engine.py) ----------
@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'run.db'}")
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


# --- allow-all scheduler seam stubs -----------------------------------------
class _StubQuota:
    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        return True

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        return None


class _StubKill:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _StubPackState:
    def __init__(self, installed: bool = True) -> None:
        self.installed = installed

    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return self.installed


def _allow_policy() -> Callable[[SubmitInput], Awaitable[PolicyDecision]]:
    async def _allow(_: SubmitInput) -> PolicyDecision:
        return PolicyDecision(allow=True, policy_reason=None)

    return _allow


def _make_scheduler(db: AsyncEngine, *, installed: bool = True) -> SchedulerEngine:
    return SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=ConcurrencyCaps(
            per_tenant_interactive=4,
            per_tenant_background=4,
            per_pack=4,
            per_actor=4,
        ),
        class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},
        quota_interrogator=_StubQuota(),
        kill_switch_interrogator=_StubKill(),
        pack_state_interrogator=_StubPackState(installed=installed),
        policy_evaluator=_allow_policy(),
    )


# --- stub sandbox backend + session -----------------------------------------
class _StubSession:
    def __init__(
        self,
        result: SandboxExecResult | Exception,
        *,
        destroy_error: Exception | None = None,
        suspend_error: Exception | None = None,
        exec_raises: Exception | None = None,
    ) -> None:
        self.session_id = uuid.uuid4().hex
        self._result = result
        self._destroy_error = destroy_error
        self._suspend_error = suspend_error
        # A3b resume: when set, exec() raises this regardless of ``result`` (lets a
        # resume test inject an exec-time infra failure on a freshly-woken session).
        self.exec_raises = exec_raises
        self.destroyed = False
        self.destroy_calls = 0
        self.suspend_calls = 0

    async def exec(
        self, command: list[str], *, timeout_s: float | None = None
    ) -> SandboxExecResult:
        if self.exec_raises is not None:
            raise self.exec_raises
        if isinstance(self._result, Exception):
            raise self._result
        return self._result

    async def suspend(self) -> None:
        self.suspend_calls += 1
        if self._suspend_error is not None:
            raise self._suspend_error

    async def destroy(self) -> None:
        self.destroyed = True
        self.destroy_calls += 1
        if self._destroy_error is not None:
            raise self._destroy_error


class _StubBackend:
    def __init__(
        self,
        *,
        exec_result: SandboxExecResult | Exception | None = None,
        create_error: Exception | None = None,
        destroy_error: Exception | None = None,
        suspend_error: Exception | None = None,
        wake_returns: _StubSession | None = None,
        wake_raises: Exception | None = None,
    ) -> None:
        self._exec_result = exec_result
        self._create_error = create_error
        self._destroy_error = destroy_error
        self._suspend_error = suspend_error
        # A3b resume: wake() returns ``wake_returns`` (a pre-built session whose
        # destroy_calls the test asserts) or raises ``wake_raises``.
        self.wake_returns = wake_returns
        self.wake_raises = wake_raises
        self.wake_calls = 0
        self.last_wake_session_id: str | None = None
        self.created: list[_StubSession] = []
        self.last_approval_request_id: uuid.UUID | None = None
        # A3c: the approval correlator the executor threads into wake() on a
        # re-resume of a pending_approval run (admission Arm B verify).
        self.last_wake_approval_request_id: uuid.UUID | None = None

    async def create(
        self,
        policy,
        *,
        actor,
        tenant_id,
        pack_context,
        use_warm_pool=True,
        requires_credentials=(),
        approval_request_id=None,
    ):
        self.last_approval_request_id = approval_request_id
        if self._create_error is not None:
            raise self._create_error
        session = _StubSession(
            self._exec_result
            if self._exec_result is not None
            else SandboxExecResult(stdout=b"", stderr=b"", exit_code=0),
            destroy_error=self._destroy_error,
            suspend_error=self._suspend_error,
        )
        self.created.append(session)
        return session

    async def wake(
        self,
        session_id: str,
        *,
        actor: Any,
        tenant_id: str,
        approval_request_id: uuid.UUID | None = None,
    ) -> _StubSession:
        # A3b resume seam. The conflict test REPLACES this attribute with a custom
        # coroutine (instance-attr shadow), so the executor's
        # ``self._sandbox_backend.wake(...)`` dispatches to the substitute.
        # A3c widened the signature with ``approval_request_id`` (the wake approval
        # correlator the executor threads on a pending_approval re-resume).
        self.wake_calls += 1
        self.last_wake_session_id = session_id
        self.last_wake_approval_request_id = approval_request_id
        if self.wake_raises is not None:
            raise self.wake_raises
        if self.wake_returns is not None:
            return self.wake_returns
        return _StubSession(SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))


# --- stub checkpoint store ---------------------------------------------------
class _StubMeta:
    """CheckpointMetadata-shaped stub — the executor reads only .checkpoint_id."""

    def __init__(self, checkpoint_id: str) -> None:
        self.checkpoint_id = checkpoint_id


class _StubCheckpointStore:
    """Stub CheckpointStore — load_latest returns (meta, snapshot_bytes)."""

    def __init__(self, checkpoint_id: str = "deadbeef" * 4) -> None:
        self._checkpoint_id = checkpoint_id
        self.load_latest_calls: list[tuple[str, str]] = []

    async def load_latest(self, *, session_id: str, tenant_id: str) -> tuple[_StubMeta, bytes]:
        self.load_latest_calls.append((session_id, tenant_id))
        return _StubMeta(self._checkpoint_id), b"snapshot-bytes"


# --- stub pack loader --------------------------------------------------------
class _StubLoader:
    def __init__(self, record: LoadedPackRecord | None) -> None:
        self._record = record

    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        return self._record


def _record(
    *,
    tenant_id: str | None = "tenant-a",
    pack_id: str = "cognic-tool-foo",
    kind: str = "tool",
    signed_artefact_digest: bytes = b"\xab" * 32,
    state: str = "installed",
) -> LoadedPackRecord:
    return LoadedPackRecord(
        tenant_id=tenant_id,
        pack_id=pack_id,
        kind=kind,
        signed_artefact_digest=signed_artefact_digest,
        state=state,
    )


def _request(
    *,
    tenant_id: str = "tenant-a",
    pack_id: str = "cognic-tool-foo",
    pack_uuid: uuid.UUID | None = None,
    pack_version: str = "1.0.0",
    argv: tuple[str, ...] = ("printf", "ok"),
    actor: Actor | None = None,
    approval_request_id: uuid.UUID | None = None,
) -> RunRequest:
    return RunRequest(
        tenant_id=tenant_id,
        pack_id=pack_id,
        pack_uuid=pack_uuid if pack_uuid is not None else uuid.uuid4(),
        pack_version=pack_version,
        argv=argv,
        actor=actor
        if actor is not None
        else Actor(subject="svc-a", tenant_id="tenant-a", scopes=frozenset(), actor_type="service"),
        approval_request_id=approval_request_id,
    )


def _submit_input(
    *, tenant_id: str = "tenant-a", pack_id: str = "cognic-tool-foo", actor_subject: str = "svc-a"
) -> SubmitInput:
    return SubmitInput(
        tenant_id=tenant_id,
        pack_id=pack_id,
        actor=TaskActor(subject=actor_subject, tenant_id=tenant_id, actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="read_only",
        requested_estimated_tokens=1000,
    )


async def _decision_types(db: AsyncEngine) -> list[str]:
    # NOTE: DecisionRecord.decision_type persists to the table column
    # ``event_type`` (decision_history.py:185); the _decision_history table IS
    # the decision-history chain (no chain_id discriminator column).
    async with db.connect() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
            )
        ).all()
    return [r[0] for r in rows]


def _executor(
    db: AsyncEngine,
    *,
    backend: _StubBackend,
    loader: _StubLoader,
    installed: bool = True,
    settings: Settings,
    checkpoint_store: _StubCheckpointStore | None = None,
    run_record_store: RunRecordStore | None = None,
) -> ManagedRunExecutor:
    return ManagedRunExecutor(
        scheduler=_make_scheduler(db, installed=installed),
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=loader,
        decision_history_store=DecisionHistoryStore(db),
        settings=settings,
        run_record_store=run_record_store or RunRecordStore(db),
        checkpoint_store=checkpoint_store or _StubCheckpointStore(),  # type: ignore[arg-type]
    )


async def _count_lifecycle(db: AsyncEngine, run_id: str, decision_type: str) -> int:
    """Count run.lifecycle.* chain rows for a given run_id + decision_type."""
    async with db.connect() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.payload).where(
                    _decision_history.c.event_type == decision_type
                )
            )
        ).all()
    return sum(1 for r in rows if r[0].get("run_id") == run_id)


async def _latest_payload(db: AsyncEngine, decision_type: str) -> dict[str, Any]:
    """Return the newest chain payload of the given decision_type."""
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload)
                .where(_decision_history.c.event_type == decision_type)
                .order_by(_decision_history.c.sequence.desc())
            )
        ).first()
    assert row is not None, f"no chain row of type {decision_type}"
    return dict(row[0])


@pytest.fixture
def settings() -> Settings:
    return Settings(
        sandbox_canonical_runtime_python_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
    )


# --- pack-validation refusals (pre-submit; no scheduler row, no sandbox) -----
async def test_refuses_pack_record_not_found(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend()
    ex = _executor(db, backend=backend, loader=_StubLoader(None), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "pack_record_not_found"
    assert result.task_id is None
    assert backend.created == []
    # A3b — genesis + lifecycle-refused around the direct run.refused evidence.
    assert await _decision_types(db) == [
        "run.lifecycle.pending",
        "run.lifecycle.refused",
        "run.refused",
    ]


async def test_refuses_pack_record_tenant_mismatch(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db,
        backend=_StubBackend(),
        loader=_StubLoader(_record(tenant_id="tenant-OTHER")),
        settings=settings,
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_tenant_mismatch"


async def test_refuses_pack_record_pack_id_mismatch(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db,
        backend=_StubBackend(),
        loader=_StubLoader(_record(pack_id="cognic-tool-OTHER")),
        settings=settings,
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_pack_id_mismatch"


async def test_refuses_pack_record_not_installed(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db, backend=_StubBackend(), loader=_StubLoader(_record(state="draft")), settings=settings
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_not_installed"
    # executor-side check fires BEFORE submit — no scheduler admission row, only
    # the genesis + lifecycle-refused + direct run.refused evidence.
    assert await _decision_types(db) == [
        "run.lifecycle.pending",
        "run.lifecycle.refused",
        "run.refused",
    ]


# --- happy path: submit -> create -> exec(0) -> complete -> run.completed ----
async def test_happy_path_completes_with_value_free_evidence(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    loader = _StubLoader(_record())
    ex = _executor(db, backend=backend, loader=loader, settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "completed"
    assert result.exit_code == 0
    assert result.stdout == b"ok\n"  # raw output to the caller
    assert result.task_id is not None
    assert backend.created[0].destroyed is True
    types = await _decision_types(db)
    assert "scheduler.admission_accepted" in types
    assert "run.completed" in types
    # run.completed payload is value-free: digests + counts + exit_code, NO raw bytes
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload).where(
                    _decision_history.c.event_type == "run.completed"
                )
            )
        ).first()
    import hashlib

    assert row is not None
    payload = row[0]
    assert payload["exit_code"] == 0
    assert payload["stdout_sha256"] == hashlib.sha256(b"ok\n").hexdigest()
    assert payload["stdout_bytes"] == 3
    assert "stdout" not in payload and "stderr" not in payload  # no raw output in chain


# --- Sprint 14A-A2b: executor threads request.approval_request_id into create -
async def test_run_threads_approval_request_id_into_backend_create(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    arid = uuid.uuid4()
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    await ex.run(_request(approval_request_id=arid))
    assert backend.last_approval_request_id == arid


# --- non-zero exit is a COMPLETED run, not a scheduler failure ---------------
async def test_non_zero_exit_still_completes(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"boom", exit_code=3))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "completed"
    assert result.exit_code == 3
    assert backend.created[0].destroyed is True
    types = await _decision_types(db)
    assert "run.completed" in types and "run.failed" not in types


# --- infra failure on create -> scheduler.fail + run.failed ------------------
async def test_create_raises_marks_failed(db: AsyncEngine, settings: Settings) -> None:
    class _Boom(Exception):
        reason = "sandbox_runtime_image_not_authorised"

    backend = _StubBackend(create_error=_Boom())
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "failed"
    assert result.refusal_reason is None
    types = await _decision_types(db)
    assert "scheduler.task_started" in types and "run.failed" in types


# --- sandbox approval-pending -> cancel + run.pending_approval + 202 (F3) -----
async def test_run_pending_approval_returns_pending_approval(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    # A3b: the executor persists the approval correlator onto the run row, so it
    # must be a real UUID string (the production seam carries str(uuid)).
    arid = uuid.uuid4()
    backend = _StubBackend(
        create_error=SandboxLifecycleRefused(
            "sandbox_approval_pending", detail="pending", approval_request_id=str(arid)
        )
    )
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "pending_approval"
    assert result.approval_request_id == str(arid)
    assert result.exit_code is None
    assert result.refusal_reason is None
    types = await _decision_types(db)
    assert "run.pending_approval" in types
    assert "run.completed" not in types and "run.failed" not in types
    # running -> cancelled (pending cleanup releases quota + counters)
    assert "scheduler.task_cancelled" in types


# --- other SandboxLifecycleRefused is a governance refusal -> refused/409 (F3)-
async def test_run_sandbox_governance_refusal_returns_refused(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    backend = _StubBackend(
        create_error=SandboxLifecycleRefused(
            "sandbox_high_risk_tier_refused_pre_13_5", detail="governance refusal"
        )
    )
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "sandbox_high_risk_tier_refused_pre_13_5"
    assert result.exit_code is None
    types = await _decision_types(db)
    assert "run.refused" in types
    assert "run.failed" not in types and "run.completed" not in types
    # governance refusal CANCELS the running task (NOT scheduler.fail)
    assert "scheduler.task_cancelled" in types and "scheduler.task_failed" not in types


# --- infra failure on exec -> scheduler.fail + finally-guarded destroy -------
async def test_exec_raises_marks_failed_and_destroys(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend(exec_result=RuntimeError("exec blew up"))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "failed"
    assert backend.created[0].destroyed is True  # teardown ran despite the exec error
    assert "run.failed" in await _decision_types(db)


# --- scheduler refuses (pack not installed at the scheduler seam) ------------
async def test_scheduler_refusal_surfaces_as_run_refused(
    db: AsyncEngine, settings: Settings
) -> None:
    # executor-side check passes (loader says installed) but the scheduler seam
    # says not-installed -> the scheduler's closed outcome surfaces.
    ex = _executor(
        db,
        backend=_StubBackend(),
        loader=_StubLoader(_record()),
        installed=False,
        settings=settings,
    )
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "refused_pack_not_installed"


# --- Actor -> TaskActor projection + confused-deputy guard -------------------
async def test_tenant_actor_mismatch_raises_value_error(
    db: AsyncEngine, settings: Settings
) -> None:
    bad = _request(
        tenant_id="tenant-a",
        actor=Actor(
            subject="svc-a", tenant_id="tenant-b", scopes=frozenset(), actor_type="service"
        ),
    )
    ex = _executor(db, backend=_StubBackend(), loader=_StubLoader(_record()), settings=settings)
    with pytest.raises(ValueError, match="run_request_tenant_actor_mismatch"):
        await ex.run(bad)


# --- teardown failure is best-effort: does NOT flip the terminal state (§8) --
async def test_destroy_failure_does_not_flip_completed(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend(
        exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0),
        destroy_error=RuntimeError("destroy boom"),
    )
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())  # the destroy error is swallowed (logged), not raised
    assert result.terminal_state == "completed"  # outcome unchanged by teardown failure
    assert backend.created[0].destroyed is True
    assert "run.completed" in await _decision_types(db)


# --- accepted_queued is NOT runnable in the sync executor: cancel + refuse ----
async def test_accepted_queued_is_cancelled_and_refused(
    db: AsyncEngine, settings: Settings
) -> None:
    # per_tenant_interactive=1: a single pre-running task saturates the tenant
    # interactive cap, so the executor's submit returns accepted_queued. The
    # synchronous executor must CANCEL the queued task (cleanup) + refuse, NOT
    # call mark_running (which would race SchedulerPromotionRefused + leak the
    # task + its quota reservation).
    scheduler = SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=ConcurrencyCaps(
            per_tenant_interactive=1, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},
        quota_interrogator=_StubQuota(),
        kill_switch_interrogator=_StubKill(),
        pack_state_interrogator=_StubPackState(),
        policy_evaluator=_allow_policy(),
    )
    # Pre-fill the single interactive slot (different pack + actor so ONLY the
    # tenant-interactive cap saturates, not per_pack / per_actor).
    pre = await scheduler.submit(
        submit_input=_submit_input(pack_id="pre-pack", actor_subject="pre-actor"), request_id="pre"
    )
    assert pre.outcome == "accepted_immediate"
    assert pre.task_id is not None
    await scheduler.mark_running(uuid.UUID(pre.task_id), request_id="pre")

    backend = _StubBackend()
    ex = ManagedRunExecutor(
        scheduler=scheduler,
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=_StubLoader(_record()),
        decision_history_store=DecisionHistoryStore(db),
        settings=settings,
        run_record_store=RunRecordStore(db),
        checkpoint_store=_StubCheckpointStore(),  # type: ignore[arg-type]
    )
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "run_admission_queued_unsupported"
    assert backend.created == []  # no sandbox — the executor never proceeded to create
    types = await _decision_types(db)
    assert "run.refused" in types
    assert "scheduler.task_cancelled" in types  # the queued task was cancelled cleanly


# === Sprint 14A-A3b: run-record wiring + run_id on every path + suspend ======


async def test_run_mints_run_id_and_genesis_on_every_path(
    db: AsyncEngine, settings: Settings
) -> None:
    # A refused run (pack not installed) STILL mints a run_id + a genesis row.
    ex = _executor(
        db, backend=_StubBackend(), loader=_StubLoader(_record(state="draft")), settings=settings
    )
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.run_id  # non-empty on the refusal path
    # a run.lifecycle.pending genesis row exists for this exact run_id
    assert await _count_lifecycle(db, result.run_id, "run.lifecycle.pending") == 1
    # and a run.lifecycle.refused terminal row
    assert await _count_lifecycle(db, result.run_id, "run.lifecycle.refused") == 1


async def test_suspend_after_exec_suspends_and_skips_destroy(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ckpt = _StubCheckpointStore(checkpoint_id="abcd1234" * 4)
    ex = _executor(
        db, backend=backend, loader=_StubLoader(_record()), settings=settings, checkpoint_store=ckpt
    )
    from dataclasses import replace

    result = await ex.run(replace(_request(), suspend_after_exec=True))
    assert result.terminal_state == "suspended"
    assert result.exit_code == 0
    stub_session = backend.created[0]
    assert stub_session.suspend_calls == 1
    assert stub_session.destroy_calls == 0  # conditional teardown skipped
    # the checkpoint store was consulted with the session's id + the tenant
    assert ckpt.load_latest_calls == [(stub_session.session_id, "tenant-a")]
    # run-record is suspended with session_id + checkpoint_id persisted
    rec = await RunRecordStore(db).load(uuid.UUID(result.run_id), tenant_id="tenant-a")
    assert rec is not None
    assert rec.state == "suspended"
    assert rec.session_id == stub_session.session_id
    assert rec.checkpoint_id == "abcd1234" * 4
    # direct run.suspended evidence carries run_id + session_id + checkpoint_id
    payload = await _latest_payload(db, "run.suspended")
    assert payload["run_id"] == result.run_id
    assert payload["session_id"] == stub_session.session_id
    assert payload["checkpoint_id"] == "abcd1234" * 4
    assert payload["task_id"] is not None
    # value-free: digests + counts, never raw bytes
    assert payload["stdout_sha256"] and "stdout" not in payload
    # run.lifecycle.suspended chain row also exists
    assert await _count_lifecycle(db, result.run_id, "run.lifecycle.suspended") == 1
    # the scheduler task completed (the run did its work)
    types = await _decision_types(db)
    assert "scheduler.task_completed" in types


async def test_run_without_suspend_completes_and_destroys(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "completed"
    stub_session = backend.created[0]
    assert stub_session.destroy_calls == 1
    assert stub_session.suspend_calls == 0
    # run-record reaches completed + a run.lifecycle.completed row
    rec = await RunRecordStore(db).load(uuid.UUID(result.run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "completed"
    assert await _count_lifecycle(db, result.run_id, "run.lifecycle.completed") == 1


async def test_direct_run_events_carry_run_id(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    payload = await _latest_payload(db, "run.completed")
    assert payload["run_id"] == result.run_id
    assert payload["task_id"] is not None


async def test_suspend_skips_destroy_even_if_post_suspend_step_raises(
    db: AsyncEngine, settings: Settings
) -> None:
    # skip_destroy is set the instant suspend() returns: a failure in
    # load_latest/transition/complete/_emit propagates WITHOUT ever destroying
    # the session (post-suspend the container is already released).
    class _RaisingCheckpoint:
        async def load_latest(self, *, session_id: str, tenant_id: str) -> tuple[Any, bytes]:
            raise RuntimeError("checkpoint lookup blew up")

    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex = _executor(
        db,
        backend=backend,
        loader=_StubLoader(_record()),
        settings=settings,
        checkpoint_store=_RaisingCheckpoint(),  # type: ignore[arg-type]
    )
    from dataclasses import replace

    with pytest.raises(RuntimeError, match="checkpoint lookup blew up"):
        await ex.run(replace(_request(), suspend_after_exec=True))
    stub_session = backend.created[0]
    assert stub_session.suspend_calls == 1
    assert stub_session.destroy_calls == 0  # NOT destroyed after suspend()


async def test_run_refused_event_carries_run_id_and_nullable_task_id(
    db: AsyncEngine, settings: Settings
) -> None:
    # pack-refusal path: run.refused payload carries run_id + task_id=None.
    ex = _executor(
        db, backend=_StubBackend(), loader=_StubLoader(_record(state="draft")), settings=settings
    )
    result = await ex.run(_request())
    payload = await _latest_payload(db, "run.refused")
    assert payload["run_id"] == result.run_id
    assert payload["task_id"] is None  # pre-submit refusal — no scheduler task id


async def test_scheduler_refusal_path_transitions_run_record_to_refused(
    db: AsyncEngine, settings: Settings
) -> None:
    # the non-immediate scheduler-refusal path (pack not installed at the seam)
    # ALSO mints run_id + transitions pending->refused + carries the scheduler
    # task id on the run.refused payload.
    ex = _executor(
        db,
        backend=_StubBackend(),
        loader=_StubLoader(_record()),
        installed=False,
        settings=settings,
    )
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "refused_pack_not_installed"
    assert result.run_id
    rec = await RunRecordStore(db).load(uuid.UUID(result.run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "refused"
    payload = await _latest_payload(db, "run.refused")
    assert payload["run_id"] == result.run_id


async def test_create_failure_transitions_run_record_to_failed(
    db: AsyncEngine, settings: Settings
) -> None:
    class _Boom(Exception):
        reason = "sandbox_runtime_image_not_authorised"

    backend = _StubBackend(create_error=_Boom())
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "failed"
    assert result.run_id
    rec = await RunRecordStore(db).load(uuid.UUID(result.run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "failed"
    assert await _count_lifecycle(db, result.run_id, "run.lifecycle.failed") == 1


async def test_pending_approval_transitions_run_record(db: AsyncEngine, settings: Settings) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    arid = uuid.uuid4()
    backend = _StubBackend(
        create_error=SandboxLifecycleRefused(
            "sandbox_approval_pending", detail="pending", approval_request_id=str(arid)
        )
    )
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "pending_approval"
    assert result.approval_request_id == str(arid)
    rec = await RunRecordStore(db).load(uuid.UUID(result.run_id), tenant_id="tenant-a")
    assert rec is not None
    assert rec.state == "pending_approval"
    assert rec.approval_request_id == arid  # threaded onto the run row
    payload = await _latest_payload(db, "run.pending_approval")
    assert payload["run_id"] == result.run_id


# === Sprint 14A-A3b (Task 4): resume() — run->session resolver + wake dispatch =
#
# resume() loads the tenant-scoped run record, wakes the suspended sandbox
# session, runs a continuation argv, and walks the run record
# suspended -> woken -> completed (or -> refused / -> failed). NO scheduler calls
# (the slot was freed at suspend); task_id is always None on resume results.
# The two tombstone-edge tests pin the claim-gated teardown: destroy ONLY a
# session we own (claimed suspended->woken).


async def _suspend_a_run(
    db: AsyncEngine,
    settings: Settings,
    *,
    backend: _StubBackend,
    run_record_store: RunRecordStore | None = None,
) -> tuple[ManagedRunExecutor, str]:
    """Drive a fresh run to ``suspended`` via run(suspend_after_exec=True) and
    return (executor, run_id). The SAME executor (same scheduler + run store +
    backend) is then used to resume()."""
    from dataclasses import replace

    ex = _executor(
        db,
        backend=backend,
        loader=_StubLoader(_record()),
        settings=settings,
        run_record_store=run_record_store,
    )
    suspended = await ex.run(replace(_request(), suspend_after_exec=True))
    assert suspended.terminal_state == "suspended"
    return ex, suspended.run_id


def _actor() -> Actor:
    return Actor(subject="svc-a", tenant_id="tenant-a", scopes=frozenset(), actor_type="service")


async def test_resume_happy_path_wakes_execs_completes(db: AsyncEngine, settings: Settings) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    # the woken session the wake() seam returns — its destroy_calls is the
    # claim-gated-teardown assertion.
    woken_session = _StubSession(SandboxExecResult(stdout=b"go\n", stderr=b"", exit_code=0))
    backend.wake_returns = woken_session
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)

    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("echo", "go"))
    assert res.terminal_state == "completed"
    assert res.run_id == run_id
    assert res.task_id is None  # resume makes no scheduler task
    assert res.exit_code == 0
    assert res.stdout == b"go\n"
    assert backend.wake_calls == 1
    assert backend.last_wake_session_id == backend.created[0].session_id  # resolved from the record
    assert woken_session.destroy_calls == 1  # owned -> destroyed
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "completed"  # suspended->woken->completed
    # run.lifecycle.woken + run.lifecycle.completed both exist for this run_id
    assert await _count_lifecycle(db, run_id, "run.lifecycle.woken") == 1
    assert await _count_lifecycle(db, run_id, "run.lifecycle.completed") == 1
    # direct run.completed evidence carries the run_id + task_id=None
    payload = await _latest_payload(db, "run.completed")
    assert payload["run_id"] == run_id
    assert payload["task_id"] is None


async def test_resume_wake_refused_transitions_suspended_to_refused(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)
    backend.wake_raises = SandboxLifecycleRefused("sandbox_wake_checkpoint_corrupt")

    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert res.terminal_state == "refused"
    assert res.refusal_reason == "sandbox_wake_checkpoint_corrupt"
    assert res.task_id is None
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "refused"
    # value-free run.refused evidence carries run_id + the wake reason
    payload = await _latest_payload(db, "run.refused")
    assert payload["run_id"] == run_id
    assert payload["reason"] == "sandbox_wake_checkpoint_corrupt"


async def test_resume_wake_infra_transitions_suspended_to_failed(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)
    backend.wake_raises = RuntimeError("boom")

    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert res.terminal_state == "failed"
    assert res.refusal_reason is None
    assert res.task_id is None
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "failed"
    payload = await _latest_payload(db, "run.failed")
    assert payload["run_id"] == run_id
    assert payload["reason"] == "workload_runtime_error"


async def test_resume_resumed_exec_infra_transitions_woken_to_failed(
    db: AsyncEngine, settings: Settings
) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    woken_session = _StubSession(
        SandboxExecResult(stdout=b"", stderr=b"", exit_code=0), exec_raises=RuntimeError("boom")
    )
    backend.wake_returns = woken_session
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)

    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert res.terminal_state == "failed"
    assert res.task_id is None
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "failed"  # woken->failed
    # we OWNED the session (claim succeeded) -> the finally destroyed it
    assert woken_session.destroy_calls == 1
    assert await _count_lifecycle(db, run_id, "run.lifecycle.woken") == 1
    assert await _count_lifecycle(db, run_id, "run.lifecycle.failed") == 1


async def test_resume_unknown_run_raises_run_not_found(db: AsyncEngine, settings: Settings) -> None:
    from cognic_agentos.core.run.storage import RunNotFound

    ex = _executor(db, backend=_StubBackend(), loader=_StubLoader(_record()), settings=settings)
    with pytest.raises(RunNotFound):
        await ex.resume(run_id=uuid.uuid4(), actor=_actor(), argv=("x",))


async def test_resume_non_suspended_raises_run_not_resumable(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.core.run.executor import RunNotResumable

    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    done = await ex.run(_request())  # completed, NOT suspended
    assert done.terminal_state == "completed"
    with pytest.raises(RunNotResumable) as exc:
        await ex.resume(run_id=uuid.UUID(done.run_id), actor=_actor(), argv=("x",))
    assert exc.value.current_state == "completed"


# --- the wake/tombstone edge (resume-side teardown posture) ------------------


class _ClaimFailingStore(RunRecordStore):
    """Wraps RunRecordStore to raise a NON-RunTransitionRefused error ONCE on the
    suspended->woken claim. Proves claimed_woken stays False -> finally does NOT
    destroy -> the rolled-back run record is still 'suspended' (resumable)."""

    def __init__(self, engine: AsyncEngine) -> None:
        super().__init__(engine)
        self.fail_woken_transition = False
        self._fired = False

    async def transition(self, *, to_state: Any, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
        if self.fail_woken_transition and to_state == "woken" and not self._fired:
            self._fired = True
            raise RuntimeError("db error on suspended->woken claim")
        return await super().transition(to_state=to_state, **kwargs)


async def test_resume_claim_failure_does_not_destroy_and_run_stays_suspended(
    db: AsyncEngine, settings: Settings
) -> None:
    # wake() ok, but the suspended->woken claim raises a NON-stale DB error:
    # claimed_woken stays False -> finally must NOT destroy -> no tombstone ->
    # the rolled-back run record is still 'suspended' (resumable).
    failing_runs = _ClaimFailingStore(db)
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex, run_id = await _suspend_a_run(db, settings, backend=backend, run_record_store=failing_runs)
    woken_session = _StubSession(SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    backend.wake_returns = woken_session
    failing_runs.fail_woken_transition = True  # raise on the suspended->woken claim

    with pytest.raises(RuntimeError, match="db error on suspended->woken claim"):
        await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert backend.wake_calls == 1  # wake DID run
    assert woken_session.destroy_calls == 0  # NOT owned -> NOT destroyed
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "suspended"  # still resumable, NOT tombstoned


async def test_resume_concurrent_conflict_returns_conflict_without_destroy(
    db: AsyncEngine, settings: Settings
) -> None:
    # Two resumes both load 'suspended' and both wake. The stub wake commits the
    # WINNING request's suspended->woken claim as a side-effect (via the REAL
    # store), so THIS request's claim stale-refuses -> RunResumeConflict, and its
    # woken session is NOT destroyed (the winner owns the session_id; destroying
    # would tombstone it).
    from cognic_agentos.core.run.executor import RunResumeConflict

    run_store = RunRecordStore(db)
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    ex, run_id = await _suspend_a_run(db, settings, backend=backend, run_record_store=run_store)
    loser_session = _StubSession(SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))

    async def _wake_then_winner_claims(
        session_id: str,
        *,
        actor: Any,
        tenant_id: str,
        approval_request_id: uuid.UUID | None = None,
    ) -> _StubSession:
        # the WINNER commits suspended->woken before this request's claim runs.
        # (signature accepts approval_request_id — A3c widened the wake() seam.)
        await run_store.transition(
            run_id=uuid.UUID(run_id),
            tenant_id="tenant-a",
            from_state="suspended",
            to_state="woken",
            actor_id="winner",
            request_id="w",
        )
        return loser_session

    backend.wake = _wake_then_winner_claims  # type: ignore[method-assign]
    with pytest.raises(RunResumeConflict):
        await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert loser_session.destroy_calls == 0  # loser does NOT own the session


# --- resume() defensive-branch coverage (sharp-edge CC method -> ~100/100) ----


class _NullSessionRunStore(RunRecordStore):
    """Wraps RunRecordStore so load() returns a corrupt 'suspended' run record
    whose session_id is None — the invariant a suspended run ALWAYS carries a
    session_id is violated. Proves resume() fails loud BEFORE wake() rather than
    dispatching wake(None)."""

    def __init__(self, engine: AsyncEngine, *, run_id: uuid.UUID) -> None:
        super().__init__(engine)
        self._run_id = run_id

    async def load(self, run_id: uuid.UUID, *, tenant_id: str) -> RunRecord | None:
        now = datetime.now(UTC)
        return RunRecord(
            run_id=self._run_id,
            tenant_id="tenant-a",
            pack_id="cognic-tool-foo",
            pack_uuid=uuid.uuid4(),
            pack_version="1.0.0",
            task_id=None,
            session_id=None,  # the corrupt-row invariant violation
            checkpoint_id=None,
            approval_request_id=None,
            state="suspended",  # resumable state, but no session to resolve
            created_at=now,
            updated_at=now,
        )


async def test_resume_suspended_without_session_id_fails_loud(
    db: AsyncEngine, settings: Settings
) -> None:
    # A suspended run with session_id=None is a corrupt row (run() always
    # persists the session_id in the suspend branch). resume() must fail loud
    # with RuntimeError BEFORE ever calling wake() — never wake(None).
    run_id = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex = _executor(
        db,
        backend=backend,
        loader=_StubLoader(_record()),
        settings=settings,
        run_record_store=_NullSessionRunStore(db, run_id=run_id),
    )
    with pytest.raises(RuntimeError, match="run_suspended_without_session_id"):
        await ex.resume(run_id=run_id, actor=_actor(), argv=("x",))
    # the guard fires BEFORE wake — we never dispatched wake(None).
    assert backend.wake_calls == 0


async def test_resume_owned_session_destroy_failure_is_swallowed(
    db: AsyncEngine, settings: Settings
) -> None:
    # resume() happy path (suspended->woken->completed) where the OWNED woken
    # session's destroy() RAISES during the finally teardown. The exception is
    # logged + swallowed — best-effort teardown NEVER flips the terminal state.
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    # the woken session the wake() seam returns: its destroy() raises (reuses the
    # existing _StubSession destroy_error mechanism — destroy_calls increments
    # BEFORE the raise, so the attempt stays observable).
    woken_session = _StubSession(
        SandboxExecResult(stdout=b"go\n", stderr=b"", exit_code=0),
        destroy_error=RuntimeError("destroy boom on woken session"),
    )
    backend.wake_returns = woken_session
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)

    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("echo", "go"))
    # the destroy-failure was swallowed — the outcome is NOT flipped.
    assert res.terminal_state == "completed"
    assert res.exit_code == 0
    # the owned session WAS torn down (the attempt is observable despite raising).
    assert woken_session.destroy_calls == 1
    # the run record reached completed (suspended->woken->completed held).
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "completed"


# === Sprint 14A-A3c (Task 3): resume() — wake-pending arm + no-re-mint guard ==
#
# resume() now consumes a wake-pending. First resume from `suspended` that hits a
# wake-pending -> pending_approval (store the minted approval_request_id on the
# run row, NEVER claim/destroy). A re-resume of a pending_approval run MUST echo
# its stored approval_request_id (admission Arm B verify) and NEVER re-enter Arm
# A (mint) -- the F2 no-re-mint pin, asserted by the requires-id + mismatch tests
# proving wake() is NOT called. A re-resume with the matching id walks
# pending_approval -> woken -> completed (granted) / -> refused (denied) / still
# pending_approval (no transition, still awaiting).


async def _drive_to_pending_approval(
    db: AsyncEngine,
    settings: Settings,
    *,
    backend: _StubBackend,
    arid_str: str,
    run_record_store: RunRecordStore | None = None,
) -> tuple[ManagedRunExecutor, str]:
    """First resume: run -> suspended -> wake-pending. Returns (executor, run_id).
    The same executor (same backend + run store) is reused for the re-resume."""
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    ex, run_id = await _suspend_a_run(
        db, settings, backend=backend, run_record_store=run_record_store
    )
    backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=arid_str
    )
    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert res.terminal_state == "pending_approval"
    return ex, run_id


async def test_resume_first_pending_transitions_suspended_to_pending_approval(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _suspend_a_run(db, settings, backend=backend)  # run row: suspended
    backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=str(arid)
    )
    res = await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))
    assert res.terminal_state == "pending_approval"
    assert res.approval_request_id == str(arid)  # str on the OUTPUT side
    assert res.task_id is None
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "pending_approval"
    assert rec.approval_request_id == arid  # stored as a UUID on the run row
    # the pending arm never claims suspended->woken -> the woken session that the
    # wake() seam would have returned is never destroyed (the refusal is raised
    # BEFORE the claim, so nothing is owned + nothing torn down).
    assert backend.created[0].destroy_calls == 0
    # store-side lifecycle row + value-free run.pending_approval evidence.
    assert await _count_lifecycle(db, run_id, "run.lifecycle.pending_approval") == 1
    payload = await _latest_payload(db, "run.pending_approval")
    assert payload["run_id"] == run_id
    assert payload["task_id"] is None
    assert payload["approval_request_id"] == str(arid)


async def test_resume_reresume_requires_approval_id(db: AsyncEngine, settings: Settings) -> None:
    from cognic_agentos.core.run.executor import RunResumePendingApprovalRequired

    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _drive_to_pending_approval(db, settings, backend=backend, arid_str=str(arid))
    wake_before = backend.wake_calls
    with pytest.raises(RunResumePendingApprovalRequired) as exc:
        await ex.resume(run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",))  # no approval id
    assert exc.value.run_id == uuid.UUID(run_id)
    # F2 no-re-mint pin: wake() NOT called again -> admission Arm A (mint) unreached.
    assert backend.wake_calls == wake_before
    # the run row is UNCHANGED (still pending_approval, still the stored id).
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "pending_approval"
    assert rec.approval_request_id == arid


async def test_resume_reresume_mismatched_id_refuses(db: AsyncEngine, settings: Settings) -> None:
    from cognic_agentos.core.run.executor import RunResumeApprovalMismatch

    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _drive_to_pending_approval(db, settings, backend=backend, arid_str=str(arid))
    wake_before = backend.wake_calls
    with pytest.raises(RunResumeApprovalMismatch) as exc:
        await ex.resume(
            run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",), approval_request_id=uuid.uuid4()
        )
    assert exc.value.run_id == uuid.UUID(run_id)
    # F2 no-re-mint pin: a mismatched id refuses BEFORE wake() -> Arm A unreached.
    assert backend.wake_calls == wake_before
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "pending_approval"


async def test_resume_reresume_still_pending_no_transition(
    db: AsyncEngine, settings: Settings
) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _drive_to_pending_approval(db, settings, backend=backend, arid_str=str(arid))
    # re-resume with the matching id, but wake STILL pending (awaiting second
    # approval) -> NO self-loop transition (pending_approval -> pending_approval is
    # not a legal pair); the run stays pending_approval.
    backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=str(arid)
    )
    wake_before = backend.wake_calls
    res = await ex.resume(
        run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",), approval_request_id=arid
    )
    assert res.terminal_state == "pending_approval"
    assert res.approval_request_id == str(arid)
    # a re-resume with the matching id DID dispatch wake() (Arm B verify), unlike
    # the requires-id / mismatch guards which short-circuit before wake().
    assert backend.wake_calls == wake_before + 1
    assert backend.last_wake_approval_request_id == arid  # echoed the stored id
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "pending_approval"
    # still-pending re-resume emits NO new lifecycle transition row (only the ONE
    # from the first resume's suspended->pending_approval).
    assert await _count_lifecycle(db, run_id, "run.lifecycle.pending_approval") == 1


async def test_resume_reresume_granted_completes(db: AsyncEngine, settings: Settings) -> None:
    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _drive_to_pending_approval(db, settings, backend=backend, arid_str=str(arid))
    # grant verified in admission -> wake returns a live session.
    backend.wake_raises = None
    woken_session = _StubSession(SandboxExecResult(stdout=b"done\n", stderr=b"", exit_code=0))
    backend.wake_returns = woken_session
    res = await ex.resume(
        run_id=uuid.UUID(run_id), actor=_actor(), argv=("echo", "go"), approval_request_id=arid
    )
    assert res.terminal_state == "completed"
    assert res.exit_code == 0
    assert res.stdout == b"done\n"
    assert backend.last_wake_approval_request_id == arid  # Arm B verify correlator
    assert woken_session.destroy_calls == 1  # claimed pending_approval->woken -> owned -> destroyed
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "completed"  # pending_approval->woken->completed
    assert await _count_lifecycle(db, run_id, "run.lifecycle.woken") == 1
    assert await _count_lifecycle(db, run_id, "run.lifecycle.completed") == 1


async def test_resume_reresume_denied_refuses(db: AsyncEngine, settings: Settings) -> None:
    from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

    arid = uuid.uuid4()
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
    ex, run_id = await _drive_to_pending_approval(db, settings, backend=backend, arid_str=str(arid))
    backend.wake_raises = SandboxLifecycleRefused(
        "sandbox_approval_denied", approval_request_id=str(arid)
    )
    res = await ex.resume(
        run_id=uuid.UUID(run_id), actor=_actor(), argv=("x",), approval_request_id=arid
    )
    assert res.terminal_state == "refused"
    assert res.refusal_reason == "sandbox_approval_denied"
    assert res.task_id is None
    rec = await RunRecordStore(db).load(uuid.UUID(run_id), tenant_id="tenant-a")
    assert rec is not None and rec.state == "refused"  # pending_approval->refused
    payload = await _latest_payload(db, "run.refused")
    assert payload["run_id"] == run_id
    assert payload["reason"] == "sandbox_approval_denied"


async def test_run_refusal_reason_has_the_two_a4b_values() -> None:
    import typing

    from cognic_agentos.core.run.executor import RunRefusalReason

    vals = set(typing.get_args(RunRefusalReason))
    assert "pack_record_risk_tier_unresolved" in vals
    assert "pack_record_data_classes_malformed" in vals
    assert len(vals) == 6


async def test_run_risk_tier_drift_pinned_to_cli_canonical() -> None:
    import typing

    from cognic_agentos.cli._governance_vocab import RiskTier as CliRiskTier
    from cognic_agentos.core.run.executor import RiskTier as RunRiskTier

    assert set(typing.get_args(RunRiskTier)) == set(typing.get_args(CliRiskTier))

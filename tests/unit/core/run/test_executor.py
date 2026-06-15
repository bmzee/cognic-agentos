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
from cognic_agentos.core.run.executor import (
    LoadedPackRecord,
    ManagedRunExecutor,
    RunRequest,
)
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
        self, result: SandboxExecResult | Exception, *, destroy_error: Exception | None = None
    ) -> None:
        self.session_id = uuid.uuid4().hex
        self._result = result
        self._destroy_error = destroy_error
        self.destroyed = False

    async def exec(
        self, command: list[str], *, timeout_s: float | None = None
    ) -> SandboxExecResult:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result

    async def destroy(self) -> None:
        self.destroyed = True
        if self._destroy_error is not None:
            raise self._destroy_error


class _StubBackend:
    def __init__(
        self,
        *,
        exec_result: SandboxExecResult | Exception | None = None,
        create_error: Exception | None = None,
        destroy_error: Exception | None = None,
    ) -> None:
        self._exec_result = exec_result
        self._create_error = create_error
        self._destroy_error = destroy_error
        self.created: list[_StubSession] = []

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
        if self._create_error is not None:
            raise self._create_error
        session = _StubSession(
            self._exec_result
            if self._exec_result is not None
            else SandboxExecResult(stdout=b"", stderr=b"", exit_code=0),
            destroy_error=self._destroy_error,
        )
        self.created.append(session)
        return session


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
) -> ManagedRunExecutor:
    return ManagedRunExecutor(
        scheduler=_make_scheduler(db, installed=installed),
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=loader,
        decision_history_store=DecisionHistoryStore(db),
        settings=settings,
    )


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
    assert await _decision_types(db) == ["run.refused"]


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
    # executor-side check fires BEFORE submit — no admission row
    assert await _decision_types(db) == ["run.refused"]


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

    backend = _StubBackend(
        create_error=SandboxLifecycleRefused(
            "sandbox_approval_pending", detail="pending", approval_request_id="arid-123"
        )
    )
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "pending_approval"
    assert result.approval_request_id == "arid-123"
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
    )
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "run_admission_queued_unsupported"
    assert backend.created == []  # no sandbox — the executor never proceeded to create
    types = await _decision_types(db)
    assert "run.refused" in types
    assert "scheduler.task_cancelled" in types  # the queued task was cancelled cleanly

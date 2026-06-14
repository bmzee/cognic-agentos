# Sprint 14A-A — Managed Agent Runtime (thinnest vertical slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the first production-grade *exercised* managed-run path — `load+validate pack record → scheduler admit → execute one sandbox-backed task → complete → value-free evidence` — wired into the FastAPI lifespan (SDK-gated, fail-soft), proven by always-run stub-backend tests + an env-gated real-docker e2e.

**Architecture:** A new critical-controls executor `core/run/executor.py` (SDK-free; depends only on the `sandbox.protocol`/`sandbox.policy` interfaces + `core.scheduler` + `core.decision_history`; pack access via a `PackRecordLoader` seam; the `Actor` reference is `TYPE_CHECKING`-only). An off-gate `harness/sandbox.py` composition module owns `is_sandbox_available()` (DockerSibling-only), `build_sandbox_backend()` (function-local SDK imports; mints a `VaultTransport`→`VaultCredentialAdapter`; returns `(backend, docker_client)`), and the `PackRecordStoreLoader` conformer. The lifespan constructs the backend + executor on `app.state`, closing the owned docker client on shutdown. `build_runtime` stays SDK-free and untouched.

**Tech Stack:** Python 3.12, `uv`, pytest (asyncio), SQLAlchemy async (sqlite in-memory for unit DB), FastAPI lifespan, `aiodocker` (optional `adapters` extra), OPA/Rego, Vault transport.

**Source of truth:** `docs/superpowers/specs/2026-06-13-sprint-14a-a-managed-run-vertical-slice-design.md` (locked; spec commits `1ab9dd3` + `620bb64`). Branch `feat/sprint-14a-a-managed-run-vertical-slice`.

---

## File Structure

| File | New/Mod | Responsibility |
|---|---|---|
| `src/cognic_agentos/core/run/__init__.py` | **New** | Package init + public exports |
| `src/cognic_agentos/core/run/executor.py` | **New (CC)** | `RunRequest`/`RunResult`/`RunRefusalReason` + `LoadedPackRecord` + `PackRecordLoader` Protocol + `ManagedRunExecutor` |
| `src/cognic_agentos/harness/sandbox.py` | **New (off-gate)** | `is_sandbox_available` + `build_sandbox_backend` + `PackRecordStoreLoader` conformer |
| `src/cognic_agentos/core/config.py` | Mod | `sandbox_runtime_enabled` + `sandbox_policy_bundle` settings |
| `src/cognic_agentos/portal/api/app.py` | Mod | Lifespan: pre-seed + SDK-gated construction + docker-client close on shutdown |
| `tools/check_critical_coverage.py` | Mod | Add `core/run/executor.py` to `_CRITICAL_FILES` (129→130) |
| `tests/unit/tools/test_check_critical_coverage.py` | Mod | `_EXPECTED_ENTRY_COUNT` 129→130 |
| `tests/unit/core/run/test_executor.py` | **New** | Stub-backend + stub-loader orchestration over a real scheduler + real DH store (in-memory DB) |
| `tests/unit/architecture/test_run_no_sdk_import.py` | **New** | AST fence: no SDK / no runtime portal / no packs import |
| `tests/unit/harness/test_sandbox.py` | **New** | `is_sandbox_available` matrix + `PackRecordStoreLoader` projection + `build_sandbox_backend` vault-addr guard |
| `tests/unit/portal/api/test_app_sandbox_state.py` | **New** | Lifespan pre-seed + SDK-absent/disabled/construction-fail-soft wiring |
| `tests/integration/run/__init__.py` | **New** | (empty package marker) |
| `tests/integration/run/test_managed_run_e2e.py` | **New** | Env-gated (`COGNIC_RUN_DOCKER_SANDBOX=1`) real-docker e2e |
| `docs/adrs/ADR-022-runtime-scheduler.md` + `docs/adrs/ADR-004-sandbox-primitive.md` | Mod | Sprint 14A-A amendment |
| `AGENTS.md` | Mod | `core/run/executor.py` CC entry + `harness/sandbox.py` off-gate note |
| `docs/AS_BUILT_CAPABILITY_MAP.md` | Mod | Pillar 2 — first exercised managed-run path; 14A-A DONE, 14A-A2 next |

**Batching / halts:** T1 own halt (CC stop-rule — verify-at-promotion in-commit). T2 off-gate halt. T3 off-gate halt (valve checkpoint). T4 docs halt. **Full suite + `check_critical_coverage.py` (130) at the boundary after T2.** Separate full-word commit token per task. Repo conventions: `uv run`; `mypy src tests` + `ruff check .` + `ruff format --check .` full-tree at halt; 100-char lines; `from __future__ import annotations` KEPT in `core/run/executor.py` + `harness/sandbox.py` (NOT FastAPI modules); `portal/api/app.py` keeps its existing no-future-annotations posture; value-free chain payloads; NEVER stage `docs/reviews/` or the 2026-05-26 gap-analysis spec; commit footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`; git user bmzee.

---

## Task 1: `core/run/executor.py` — the managed-run executor (CRITICAL CONTROLS)

**Files:**
- Create: `src/cognic_agentos/core/run/__init__.py`
- Create: `src/cognic_agentos/core/run/executor.py`
- Create: `tests/unit/core/run/__init__.py`
- Create: `tests/unit/core/run/test_executor.py`
- Create: `tests/unit/architecture/test_run_no_sdk_import.py`
- Modify: `tools/check_critical_coverage.py` (add the gate entry)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (`_EXPECTED_ENTRY_COUNT`)

- [ ] **Step 1: Write the failing orchestration test suite**

Create `tests/unit/core/run/__init__.py` (empty), then `tests/unit/core/run/test_executor.py`:

```python
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

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history  # registered in the shared _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.run.executor import (
    LoadedPackRecord,
    ManagedRunExecutor,
    RunRequest,
)
from cognic_agentos.core.scheduler._types import PolicyDecision, SubmitInput
from cognic_agentos.core.scheduler.engine import SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.protocol import SandboxExecResult

pytestmark = pytest.mark.asyncio


# --- in-memory DB (mirror tests/unit/core/scheduler/test_engine.py) ----------
@pytest.fixture
async def db(tmp_path) -> AsyncIterator[AsyncEngine]:
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
    async def would_admit(self, *, task_id, tenant_id, pack_id, estimated_tokens) -> bool:
        return True

    async def release_reservation(self, task_id) -> None:
        return None


class _StubKill:
    async def is_active(self, *, tenant_id, pack_id) -> bool:
        return False


class _StubPackState:
    def __init__(self, installed: bool = True) -> None:
        self.installed = installed

    async def is_installed(self, *, tenant_id, pack_id) -> bool:
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
        class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},  # type: ignore[arg-type]
        quota_interrogator=_StubQuota(),
        kill_switch_interrogator=_StubKill(),
        pack_state_interrogator=_StubPackState(installed=installed),
        policy_evaluator=_allow_policy(),
    )


# --- stub sandbox backend + session -----------------------------------------
class _StubSession:
    def __init__(self, result: SandboxExecResult | Exception) -> None:
        self.session_id = uuid.uuid4().hex
        self._result = result
        self.destroyed = False

    async def exec(self, command, *, timeout_s=None) -> SandboxExecResult:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result

    async def destroy(self) -> None:
        self.destroyed = True


class _StubBackend:
    def __init__(
        self,
        *,
        exec_result: SandboxExecResult | Exception | None = None,
        create_error: Exception | None = None,
    ) -> None:
        self._exec_result = exec_result
        self._create_error = create_error
        self.created: list[_StubSession] = []

    async def create(self, policy, *, actor, tenant_id, pack_context, use_warm_pool=True,
                     requires_credentials=()):
        if self._create_error is not None:
            raise self._create_error
        session = _StubSession(self._exec_result if self._exec_result is not None
                               else SandboxExecResult(stdout=b"", stderr=b"", exit_code=0))
        self.created.append(session)
        return session


# --- stub pack loader --------------------------------------------------------
class _StubLoader:
    def __init__(self, record: LoadedPackRecord | None) -> None:
        self._record = record

    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        return self._record


def _record(**over) -> LoadedPackRecord:
    base = dict(
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        kind="tool",
        signed_artefact_digest=b"\xab" * 32,
        state="installed",
    )
    base.update(over)
    return LoadedPackRecord(**base)  # type: ignore[arg-type]


def _request(**over) -> RunRequest:
    base = dict(
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        pack_uuid=uuid.uuid4(),
        pack_version="1.0.0",
        argv=("printf", "ok"),
        actor=Actor(subject="svc-a", tenant_id="tenant-a", scopes=frozenset(),
                    actor_type="service"),
    )
    base.update(over)
    return RunRequest(**base)  # type: ignore[arg-type]


async def _decision_types(db: AsyncEngine) -> list[str]:
    async with db.connect() as conn:
        rows = (await conn.execute(
            select(_decision_history.c.decision_type)
            .where(_decision_history.c.chain_id == "decision_history")
            .order_by(_decision_history.c.sequence)
        )).all()
    return [r[0] for r in rows]


def _executor(db: AsyncEngine, *, backend: _StubBackend, loader: _StubLoader,
              installed: bool = True, settings) -> ManagedRunExecutor:
    return ManagedRunExecutor(
        scheduler=_make_scheduler(db, installed=installed),
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=loader,
        decision_history_store=DecisionHistoryStore(db),
        settings=settings,
    )


@pytest.fixture
def settings():
    from cognic_agentos.core.config import Settings

    return Settings(sandbox_canonical_runtime_python_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64)


# --- pack-validation refusals (pre-submit; no scheduler row, no sandbox) -----
async def test_refuses_pack_record_not_found(db, settings) -> None:
    backend = _StubBackend()
    ex = _executor(db, backend=backend, loader=_StubLoader(None), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "pack_record_not_found"
    assert result.task_id is None
    assert backend.created == []
    assert await _decision_types(db) == ["run.refused"]


async def test_refuses_pack_record_tenant_mismatch(db, settings) -> None:
    ex = _executor(db, backend=_StubBackend(),
                   loader=_StubLoader(_record(tenant_id="tenant-OTHER")), settings=settings)
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_tenant_mismatch"


async def test_refuses_pack_record_pack_id_mismatch(db, settings) -> None:
    ex = _executor(db, backend=_StubBackend(),
                   loader=_StubLoader(_record(pack_id="cognic-tool-OTHER")), settings=settings)
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_pack_id_mismatch"


async def test_refuses_pack_record_not_installed(db, settings) -> None:
    ex = _executor(db, backend=_StubBackend(),
                   loader=_StubLoader(_record(state="draft")), settings=settings)
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_not_installed"
    # executor-side check fires BEFORE submit — no admission row
    assert await _decision_types(db) == ["run.refused"]


# --- happy path: submit -> create -> exec(0) -> complete -> run.completed ----
async def test_happy_path_completes_with_value_free_evidence(db, settings) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"ok\n", stderr=b"", exit_code=0))
    loader = _StubLoader(_record())
    ex = _executor(db, backend=backend, loader=loader, settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "completed"
    assert result.exit_code == 0
    assert result.stdout == b"ok\n"          # raw output to the caller
    assert result.task_id is not None
    assert backend.created[0].destroyed is True
    types = await _decision_types(db)
    assert "scheduler.admission_accepted" in types
    assert "run.completed" in types
    # run.completed payload is value-free: digests + counts + exit_code, NO raw bytes
    async with db.connect() as conn:
        row = (await conn.execute(
            select(_decision_history.c.payload)
            .where(_decision_history.c.decision_type == "run.completed")
        )).first()
    import hashlib
    payload = row[0]
    assert payload["exit_code"] == 0
    assert payload["stdout_sha256"] == hashlib.sha256(b"ok\n").hexdigest()
    assert payload["stdout_bytes"] == 3
    assert "stdout" not in payload and "stderr" not in payload  # no raw output in chain


# --- non-zero exit is a COMPLETED run, not a scheduler failure ---------------
async def test_non_zero_exit_still_completes(db, settings) -> None:
    backend = _StubBackend(exec_result=SandboxExecResult(stdout=b"", stderr=b"boom", exit_code=3))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "completed"
    assert result.exit_code == 3
    assert backend.created[0].destroyed is True
    types = await _decision_types(db)
    assert "run.completed" in types and "run.failed" not in types


# --- infra failure on create -> scheduler.fail + run.failed ------------------
async def test_create_raises_marks_failed(db, settings) -> None:
    class _Boom(Exception):
        reason = "sandbox_runtime_image_not_authorised"

    backend = _StubBackend(create_error=_Boom())
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "failed"
    assert result.refusal_reason is None
    types = await _decision_types(db)
    assert "scheduler.task_started" in types and "run.failed" in types


# --- infra failure on exec -> scheduler.fail + finally-guarded destroy -------
async def test_exec_raises_marks_failed_and_destroys(db, settings) -> None:
    backend = _StubBackend(exec_result=RuntimeError("exec blew up"))
    ex = _executor(db, backend=backend, loader=_StubLoader(_record()), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "failed"
    assert backend.created[0].destroyed is True   # teardown ran despite the exec error
    assert "run.failed" in await _decision_types(db)


# --- scheduler refuses (pack not installed at the scheduler seam) ------------
async def test_scheduler_refusal_surfaces_as_run_refused(db, settings) -> None:
    # executor-side check passes (loader says installed) but the scheduler seam
    # says not-installed -> the scheduler's closed outcome surfaces.
    ex = _executor(db, backend=_StubBackend(), loader=_StubLoader(_record()),
                   installed=False, settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "refused_pack_not_installed"


# --- Actor -> TaskActor projection + confused-deputy guard -------------------
async def test_tenant_actor_mismatch_raises_value_error(db, settings) -> None:
    bad = _request(tenant_id="tenant-a",
                   actor=Actor(subject="svc-a", tenant_id="tenant-b", scopes=frozenset(),
                               actor_type="service"))
    ex = _executor(db, backend=_StubBackend(), loader=_StubLoader(_record()), settings=settings)
    with pytest.raises(ValueError, match="run_request_tenant_actor_mismatch"):
        await ex.run(bad)
```

- [ ] **Step 2: Run the suite to verify it fails (module missing)**

Run: `uv run pytest tests/unit/core/run/test_executor.py -x -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.core.run'`.

- [ ] **Step 3: Create the package init**

Create `src/cognic_agentos/core/run/__init__.py`:

```python
"""Sprint 14A-A (ADR-022 + ADR-004) — managed-run executor package."""

from cognic_agentos.core.run.executor import (
    LoadedPackRecord,
    ManagedRunExecutor,
    PackRecordLoader,
    RunRefusalReason,
    RunRequest,
    RunResult,
)

__all__ = [
    "LoadedPackRecord",
    "ManagedRunExecutor",
    "PackRecordLoader",
    "RunRefusalReason",
    "RunRequest",
    "RunResult",
]
```

- [ ] **Step 4: Implement the executor**

Create `src/cognic_agentos/core/run/executor.py`:

```python
"""Sprint 14A-A (ADR-022 + ADR-004) — the managed-run executor.

The first production-grade EXERCISED managed-run path: load + validate the
trusted pack record, admit through the scheduler, execute one sandbox-backed
task, capture the result, complete, and emit value-free ``run.*`` evidence.

CRITICAL CONTROLS. SDK-free (no ``aiodocker`` / ``kubernetes_asyncio``), no
runtime ``cognic_agentos.portal`` import (the ``Actor`` reference is
``TYPE_CHECKING``-only — the actor is constructed by the caller and only
passed through + read-projected), and no ``cognic_agentos.packs`` import at
all (pack access is via the :class:`PackRecordLoader` seam returning the
core-owned :class:`LoadedPackRecord`). Pinned by
``tests/unit/architecture/test_run_no_sdk_import.py``.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor, TaskFailedPayload
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import SandboxBackend, SandboxExecResult

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.scheduler.engine import SchedulerEngine
    from cognic_agentos.portal.rbac.actor import Actor

logger = logging.getLogger(__name__)

#: Minimal fixed admission cost for 14A-A (manifest-driven sizing is 14A-B).
_DEFAULT_ESTIMATED_TOKENS = 1000
#: ISO-control mapping for run.* evidence is a Human-only decision — deferred.
_RUN_EVIDENCE_ISO_CONTROLS: tuple[str, ...] = ()
#: Accepted scheduler outcomes (everything else is a refusal surfaced verbatim).
_ACCEPTED_OUTCOMES = ("accepted_immediate", "accepted_queued")

#: Closed executor-side pre-submit pack-validation refusal vocabulary.
RunRefusalReason = Literal[
    "pack_record_not_found",
    "pack_record_tenant_mismatch",
    "pack_record_pack_id_mismatch",
    "pack_record_not_installed",
]

RunTerminalState = Literal["completed", "failed", "refused"]

#: Closed run.failed reason vocabulary (maps 1:1 to the two infra failure modes).
RunFailedReason = Literal["sandbox_create_refused", "workload_runtime_error"]


@dataclass(frozen=True)
class LoadedPackRecord:
    """Core-owned projection of ``packs.storage.PackRecord`` — ``core/run``
    cannot import ``packs``. Built by the conformer in ``harness/sandbox.py``."""

    tenant_id: str | None
    pack_id: str
    kind: str
    signed_artefact_digest: bytes
    state: str


class PackRecordLoader(Protocol):
    """Consumer-owned read seam (mirrors the scheduler's
    ``PackStateInterrogator``). The conformer
    ``harness.sandbox.PackRecordStoreLoader`` does the direct UUID-keyed
    ``PackRecordStore.load(pack_uuid)`` and projects to ``LoadedPackRecord``."""

    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        """Load + project the trusted pack record by UUID; None when absent."""


@dataclass(frozen=True)
class RunRequest:
    """Minimal managed-run request. ``pack_uuid`` is the ``PackRecord.id`` load
    key; ``pack_version`` is caller-supplied display/runtime context (NOT the
    trust anchor — that is ``record.signed_artefact_digest``). ``argv`` is passed
    verbatim to ``session.exec`` (no shell concatenation). ``actor`` is the
    authenticated ``portal.rbac.Actor`` (passed through to ``backend.create`` +
    read-projected to ``TaskActor`` for the scheduler)."""

    tenant_id: str
    pack_id: str
    pack_uuid: uuid.UUID
    pack_version: str
    argv: tuple[str, ...]
    actor: Actor


@dataclass(frozen=True)
class RunResult:
    """Returned to the caller. Raw ``stdout``/``stderr`` are for the caller
    ONLY — never the chain (the chain carries digests + counts)."""

    task_id: str | None
    terminal_state: RunTerminalState
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    refusal_reason: str | None


def _validate_pack_record(
    record: LoadedPackRecord | None, request: RunRequest
) -> RunRefusalReason | None:
    """Four fail-closed pre-submit checks. Returns the closed refusal reason or
    None when the record is valid. Check 4 (installed) is executor-side defense
    in depth — it intentionally duplicates the scheduler's
    ``pack_state_interrogator`` gate before sandbox-context construction."""
    if record is None:
        return "pack_record_not_found"
    if record.tenant_id != request.tenant_id:
        return "pack_record_tenant_mismatch"
    if record.pack_id != request.pack_id:
        return "pack_record_pack_id_mismatch"
    if record.state != "installed":
        return "pack_record_not_installed"
    return None


def _refusal_detail(exc: BaseException) -> str | None:
    """Best-effort extraction of an upstream sandbox closed-enum reason from a
    raised ``SandboxLifecycleRefused`` (or similar) for the failed-payload
    correlator. Never raises."""
    reason = getattr(exc, "reason", None)
    return str(reason) if reason is not None else None


class ManagedRunExecutor:
    """Owns the sandbox session directly (Fork A — the scheduler's
    ``SandboxAdapter.create`` seam returns no session handle, so the executor
    does NOT use it). Single public method :meth:`run`."""

    def __init__(
        self,
        *,
        scheduler: SchedulerEngine,
        sandbox_backend: SandboxBackend,
        pack_loader: PackRecordLoader,
        decision_history_store: DecisionHistoryStore,
        settings: Settings,
    ) -> None:
        self._scheduler = scheduler
        self._sandbox_backend = sandbox_backend
        self._pack_loader = pack_loader
        self._dh = decision_history_store
        self._settings = settings

    async def run(self, request: RunRequest) -> RunResult:
        request_id = f"run-{uuid.uuid4().hex}"

        # confused-deputy guard — a RunRequest whose tenant disagrees with the
        # authenticated actor is a caller-contract violation, not a governance
        # refusal.
        if request.tenant_id != request.actor.tenant_id:
            raise ValueError(
                "run_request_tenant_actor_mismatch: "
                "request.tenant_id != request.actor.tenant_id"
            )

        # Step 0 — load + validate the trusted pack record (pre-submit).
        record = await self._pack_loader.load_for_run(pack_uuid=request.pack_uuid)
        refusal = _validate_pack_record(record, request)
        if refusal is not None:
            await self._emit_refused(request, request_id, refusal)
            return RunResult(None, "refused", None, b"", b"", refusal)
        assert record is not None  # narrowed by _validate_pack_record

        # Step 1 — submit.
        submit_input = SubmitInput(
            tenant_id=request.tenant_id,
            pack_id=request.pack_id,
            actor=TaskActor(
                subject=request.actor.subject,
                tenant_id=request.actor.tenant_id,
                actor_type=request.actor.actor_type,
            ),
            class_="interactive",
            pack_kind=record.kind,
            pack_risk_tier="read_only",
            requested_estimated_tokens=_DEFAULT_ESTIMATED_TOKENS,
        )
        decision = await self._scheduler.submit(submit_input=submit_input, request_id=request_id)
        if decision.outcome not in _ACCEPTED_OUTCOMES:
            await self._emit_refused(request, request_id, decision.outcome)
            return RunResult(decision.task_id, "refused", None, b"", b"", decision.outcome)
        assert decision.task_id is not None
        task_id = uuid.UUID(decision.task_id)

        # Step 2 — mark_running (NO sandbox_adapter — Fork A).
        await self._scheduler.mark_running(task_id, request_id=request_id)

        # Steps 3-7 — create -> exec -> destroy(finally) -> complete/fail -> evidence.
        policy = self._build_policy()
        ctx = self._build_pack_context(record, request)
        session = None
        try:
            try:
                session = await self._sandbox_backend.create(
                    policy,
                    actor=request.actor,
                    tenant_id=request.tenant_id,
                    pack_context=ctx,
                    requires_credentials=(),
                )
            except Exception as exc:
                await self._scheduler.fail(
                    task_id,
                    payload=TaskFailedPayload(
                        reason="scheduler_task_failed_sandbox_create_refused",
                        sandbox_refusal_reason=_refusal_detail(exc),
                    ),
                    request_id=request_id,
                )
                await self._emit_failed(request, request_id, task_id, "sandbox_create_refused")
                return RunResult(decision.task_id, "failed", None, b"", b"", None)

            try:
                exec_result = await session.exec(list(request.argv), timeout_s=policy.walltime_s)
            except Exception:
                await self._scheduler.fail(
                    task_id,
                    payload=TaskFailedPayload(
                        reason="scheduler_task_failed_workload_runtime_error",
                    ),
                    request_id=request_id,
                )
                await self._emit_failed(request, request_id, task_id, "workload_runtime_error")
                return RunResult(decision.task_id, "failed", None, b"", b"", None)

            # exec returned (ANY exit_code, incl. non-zero) -> completed run.
            await self._scheduler.complete(task_id, request_id=request_id)
            await self._emit_completed(request, request_id, task_id, exec_result)
            return RunResult(
                decision.task_id,
                "completed",
                exec_result.exit_code,
                exec_result.stdout,
                exec_result.stderr,
                None,
            )
        finally:
            if session is not None:
                try:
                    await session.destroy()
                except Exception:  # best-effort teardown — never flips the outcome.
                    logger.warning(
                        "run.session_destroy_failed",
                        extra={"request_id": request_id, "session_id": session.session_id},
                    )

    def _build_policy(self) -> SandboxPolicy:
        return SandboxPolicy(
            cpu_cores=1.0,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image=self._settings.sandbox_canonical_runtime_python_image,
            egress_allow_list=(),
            vault_path=None,
        )

    def _build_pack_context(
        self, record: LoadedPackRecord, request: RunRequest
    ) -> PackAdmissionContext:
        return PackAdmissionContext(
            pack_id=request.pack_id,
            pack_version=request.pack_version,
            pack_artifact_digest=record.signed_artefact_digest.hex(),
            risk_tier="read_only",
            declares_dynamic_install=False,
            profile="production",
        )

    async def _emit_completed(
        self, request: RunRequest, request_id: str, task_id: uuid.UUID, result: SandboxExecResult
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.completed",
                request_id=request_id,
                payload={
                    "task_id": str(task_id),
                    "exit_code": result.exit_code,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "stdout_bytes": len(result.stdout),
                    "stderr_bytes": len(result.stderr),
                },
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

    async def _emit_failed(
        self, request: RunRequest, request_id: str, task_id: uuid.UUID, reason: RunFailedReason
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.failed",
                request_id=request_id,
                payload={"task_id": str(task_id), "reason": reason},
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

    async def _emit_refused(self, request: RunRequest, request_id: str, reason: str) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.refused",
                request_id=request_id,
                payload={"reason": reason, "pack_id": request.pack_id},
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )
```

- [ ] **Step 5: Run the suite to verify it passes**

Run: `uv run pytest tests/unit/core/run/test_executor.py -q`
Expected: PASS (10 tests). The chain tables: `_chain_heads` + `_metadata` come from `core.audit`; `_decision_history` from `core.decision_history` (registered in the SAME shared `_metadata`, so `_metadata.create_all()` creates it). If a `_decision_history` column name differs (`chain_id` / `sequence` / `decision_type` / `payload`), grep `src/cognic_agentos/core/decision_history.py:185` for the exact `Column` names and adjust the `select`.

- [ ] **Step 6: Write the AST fence test, watch it pass**

Create `tests/unit/architecture/test_run_no_sdk_import.py`:

```python
"""Sprint 14A-A — core/run must stay SDK-free + portal-runtime-free + packs-free.

The managed-run executor is the sandbox-ORCHESTRATION primitive: it depends on
the SDK-free ``sandbox.protocol``/``sandbox.policy`` interfaces, ``core.scheduler``,
and ``core.decision_history``. It MUST NOT import the docker/k8s SDK, MUST NOT
import ``cognic_agentos.portal`` at runtime (the ``Actor`` reference is
``TYPE_CHECKING``-only), and MUST NOT import ``cognic_agentos.packs`` at all.
Mirrors tests/unit/core/scheduler/test_architecture_no_sandbox_import.py.
"""

from __future__ import annotations

import ast
import pathlib

_RUN_DIR = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "core" / "run"


def _run_sources() -> list[pathlib.Path]:
    return sorted(_RUN_DIR.glob("*.py"))


def _type_checking_linenos(tree: ast.AST) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            )
            if is_tc:
                for child in ast.walk(node):
                    lineno = getattr(child, "lineno", None)
                    if lineno is not None:
                        lines.add(lineno)
    return lines


def _runtime_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    tc_lines = _type_checking_linenos(tree)
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and node.lineno not in tc_lines:
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.lineno not in tc_lines:
            mods.add(node.module)
    return mods


def _all_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_run_dir_has_expected_sources() -> None:
    # Non-vacuous guard: a NEW core/run module forces a deliberate fence review.
    assert {p.name for p in _run_sources()} == {"__init__.py", "executor.py"}


def test_core_run_no_sdk_import() -> None:
    for path in _run_sources():
        for mod in _runtime_imports(path):
            assert not (mod == "aiodocker" or mod.startswith("aiodocker.")), f"{path.name}: {mod}"
            assert not (
                mod == "kubernetes_asyncio" or mod.startswith("kubernetes_asyncio.")
            ), f"{path.name}: {mod}"


def test_core_run_no_runtime_portal_import() -> None:
    for path in _run_sources():
        for mod in _runtime_imports(path):
            assert not mod.startswith("cognic_agentos.portal"), f"{path.name}: runtime portal {mod}"


def test_core_run_no_packs_import_at_all() -> None:
    # packs access is ONLY via the PackRecordLoader seam — not even TYPE_CHECKING.
    for path in _run_sources():
        for mod in _all_imports(path):
            assert not mod.startswith("cognic_agentos.packs"), f"{path.name}: packs import {mod}"
```

Run: `uv run pytest tests/unit/architecture/test_run_no_sdk_import.py -q`
Expected: PASS (4 tests).

- [ ] **Step 7: Add the CC gate entry (verify-at-promotion in this commit)**

In `tools/check_critical_coverage.py`, add to the `_CRITICAL_FILES` tuple (after the approval entries near `:2141`), with a per-task rationale comment in the surrounding doc block style:

```python
    # Sprint 14A-A (ADR-022 + ADR-004) — the managed-run executor: the first
    # EXERCISED managed-run authority. Loads + validates the trusted pack
    # record, admits through the scheduler, owns the sandbox session
    # (create/exec/destroy), and emits value-free run.* evidence. CC because a
    # bug here lets an unvalidated pack reach sandbox-context construction, or
    # mis-routes the create/exec failure semantics. SDK-free + portal-runtime-
    # free + packs-free (AST-fenced).
    ("src/cognic_agentos/core/run/executor.py", 0.95, 0.90),
```

In `tests/unit/tools/test_check_critical_coverage.py`, bump the count:

```python
_EXPECTED_ENTRY_COUNT = 130
```

- [ ] **Step 8: Run the gate self-test + verify-at-promotion on fresh coverage**

Run: `uv run pytest tests/unit/tools/test_check_critical_coverage.py -q`
Expected: PASS (count guard + duplicate-path guard green at 130).

Then generate fresh branch-coverage for the new module and confirm it meets the floor (the json-no-write gotcha: write coverage.json with a dedicated post-run command):

```bash
uv run pytest tests/unit/core/run/ --cov=src/cognic_agentos --cov-branch -q
uv run coverage json -o coverage.json
uv run python tools/check_critical_coverage.py
```

Expected: `check_critical_coverage.py` exits 0 and reports `core/run/executor.py` at/above 0.95 line / 0.90 branch. If below floor, add focused negative-path tests (e.g. the `session.destroy` raising branch, the `_refusal_detail` None branch) IN THIS COMMIT and re-run.

- [ ] **Step 9: Halt-before-commit reviewer gate (CC stop-rule)**

Produce the halt summary: files modified; the gate ladder evidence (`uv run pytest tests/unit/core/run/ tests/unit/architecture/test_run_no_sdk_import.py tests/unit/tools/test_check_critical_coverage.py -q`; `uv run ruff check .`; `uv run ruff format --check .`; `uv run mypy src tests`); the verify-at-promotion coverage line; the watchpoint→pin map:
- *Actor→TaskActor projection, no runtime portal* → `test_tenant_actor_mismatch_raises_value_error` + `test_core_run_no_runtime_portal_import` + the `if TYPE_CHECKING:` import.
- *no SDK / no packs import* → `test_core_run_no_sdk_import` + `test_core_run_no_packs_import_at_all`.
- *non-zero exit = complete* → `test_non_zero_exit_still_completes`.
- *infra fail = scheduler.fail + finally teardown* → `test_create_raises_marks_failed` + `test_exec_raises_marks_failed_and_destroys`.
- *value-free evidence (separate digests, no raw bytes)* → `test_happy_path_completes_with_value_free_evidence`.
- *four pre-submit checks + trust anchor* → the four `test_refuses_*` + the digest assertion.
- *CC promotion 129→130* → gate file entry + `_EXPECTED_ENTRY_COUNT=130` + the verify-at-promotion run.

Await the commit token, then:

```bash
git add src/cognic_agentos/core/run/__init__.py src/cognic_agentos/core/run/executor.py \
  tests/unit/core/run/__init__.py tests/unit/core/run/test_executor.py \
  tests/unit/architecture/test_run_no_sdk_import.py \
  tools/check_critical_coverage.py tests/unit/tools/test_check_critical_coverage.py
git commit  # message: feat(run): managed-run executor + PackRecordLoader seam (ADR-022/ADR-004) [CC 129->130]
```

---

## Task 2: `harness/sandbox.py` + config + lifespan wiring (off-gate)

**Files:**
- Create: `src/cognic_agentos/harness/sandbox.py`
- Modify: `src/cognic_agentos/core/config.py` (2 settings)
- Modify: `src/cognic_agentos/portal/api/app.py` (lifespan)
- Create: `tests/unit/harness/test_sandbox.py`
- Create: `tests/unit/portal/api/test_app_sandbox_state.py`

- [ ] **Step 1: Add the two settings**

In `src/cognic_agentos/core/config.py`, near the existing `sandbox_*` fields (after `sandbox_canonical_egress_proxy_image` ~`:1656`):

```python
    sandbox_runtime_enabled: bool = Field(
        default=False,
        description=(
            "Sprint 14A-A (ADR-004/022): enable eager construction of the "
            "managed-run sandbox backend + executor in the FastAPI lifespan. "
            "Conservative default False so a kernel deploy does not open a "
            "docker client unbidden; gated additionally on is_sandbox_available()."
        ),
    )
    sandbox_policy_bundle: Path = Field(
        default=Path("policies/_default/sandbox.rego"),
        description=(
            "Sprint 14A-A: the OPA Rego bundle the managed-run sandbox backend's "
            "admission engine evaluates (per ADR-015 + ADR-004)."
        ),
    )
```

- [ ] **Step 2: Write the failing harness test**

Create `tests/unit/harness/test_sandbox.py`:

```python
"""Sprint 14A-A — harness/sandbox.py composition helpers."""

from __future__ import annotations

import sys
import uuid

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.run.executor import LoadedPackRecord
from cognic_agentos.harness.sandbox import (
    PackRecordStoreLoader,
    build_sandbox_backend,
    is_sandbox_available,
)

pytestmark = pytest.mark.asyncio


def test_is_sandbox_available_true_for_docker_sibling_with_aiodocker() -> None:
    # aiodocker IS in the uv venv (adapters extra) — docker_sibling is available.
    s = Settings(sandbox_backend="docker_sibling")
    assert is_sandbox_available(s) is True


def test_is_sandbox_available_false_for_kubernetes_pod_in_14a_a() -> None:
    # 14A-A is DockerSibling-only; kubernetes_pod is deferred -> False.
    s = Settings(sandbox_backend="kubernetes_pod")
    assert is_sandbox_available(s) is False


def test_is_sandbox_available_false_when_aiodocker_absent(monkeypatch) -> None:
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def _fake_import(name, *a, **k):
        if name == "aiodocker" or name.startswith("aiodocker."):
            raise ImportError("simulated missing aiodocker")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", _fake_import)
    monkeypatch.delitem(sys.modules, "aiodocker", raising=False)
    s = Settings(sandbox_backend="docker_sibling")
    assert is_sandbox_available(s) is False


class _StubPackRecord:
    def __init__(self, **kw) -> None:
        self.__dict__.update(kw)


class _StubStore:
    def __init__(self, record) -> None:
        self._record = record
        self.loaded: list[uuid.UUID] = []

    async def load(self, pack_id: uuid.UUID):
        self.loaded.append(pack_id)
        return self._record


async def test_pack_record_store_loader_projects_record() -> None:
    rec = _StubPackRecord(tenant_id="tenant-a", pack_id="cognic-tool-foo", kind="tool",
                          signed_artefact_digest=b"\xab" * 32, state="installed")
    loader = PackRecordStoreLoader(store=_StubStore(rec))  # type: ignore[arg-type]
    pk = uuid.uuid4()
    out = await loader.load_for_run(pack_uuid=pk)
    assert out == LoadedPackRecord(
        tenant_id="tenant-a", pack_id="cognic-tool-foo", kind="tool",
        signed_artefact_digest=b"\xab" * 32, state="installed",
    )
    assert loader._store.loaded == [pk]  # direct uuid load, no scan


async def test_pack_record_store_loader_returns_none_on_missing() -> None:
    loader = PackRecordStoreLoader(store=_StubStore(None))  # type: ignore[arg-type]
    assert await loader.load_for_run(pack_uuid=uuid.uuid4()) is None


async def test_build_sandbox_backend_fail_softs_without_vault_addr() -> None:
    # vault_addr unset -> RuntimeError (the lifespan catches it -> fail-soft).
    s = Settings(sandbox_backend="docker_sibling", vault_addr=None)

    class _Runtime:  # minimal stand-in (build_sandbox_backend reads audit/dh only on the OPA path)
        audit_store = object()
        decision_history_store = object()

    with pytest.raises(RuntimeError, match="vault_addr"):
        await build_sandbox_backend(settings=s, runtime=_Runtime())  # type: ignore[arg-type]


async def test_build_sandbox_backend_closes_client_on_internal_failure(monkeypatch) -> None:
    # The just-created docker client is closed before re-raise when an internal
    # step fails (no leak). aiodocker.Docker -> a spy; OPAEngine.create -> raises.
    from unittest.mock import AsyncMock

    closed = {"v": False}

    class _FakeClient:
        async def close(self) -> None:
            closed["v"] = True

    monkeypatch.setattr("aiodocker.Docker", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(
        "cognic_agentos.core.policy.engine.OPAEngine.create",
        AsyncMock(side_effect=RuntimeError("opa down")),
    )
    s = Settings(sandbox_backend="docker_sibling", vault_addr="http://vault:8200")

    class _Runtime:
        audit_store = object()
        decision_history_store = object()

    with pytest.raises(RuntimeError, match="opa down"):
        await build_sandbox_backend(settings=s, runtime=_Runtime())  # type: ignore[arg-type]
    assert closed["v"] is True  # client closed before the re-raise
```

Run: `uv run pytest tests/unit/harness/test_sandbox.py -x -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.harness.sandbox'`.

- [ ] **Step 3: Implement `harness/sandbox.py`**

Create `src/cognic_agentos/harness/sandbox.py`:

```python
"""Sprint 14A-A (ADR-004 + ADR-022) — managed-run composition wiring.

Off-gate composition module. SDK-free at import: the concrete backend +
``aiodocker`` are imported FUNCTION-LOCALLY inside :func:`build_sandbox_backend`
(only reached on the SDK-present path), so the kernel image (no ``adapters``
extra) imports this module without ``aiodocker``. Mirrors ``harness/mcp_host.py``.

Also home to :class:`PackRecordStoreLoader` — the ``core/run.PackRecordLoader``
conformer — because ``core/run`` cannot import ``packs/storage`` (the
``core -> packs`` arrow is forbidden). The conformer does the direct UUID-keyed
``PackRecordStore.load(pack_uuid)`` and projects to the core-owned
``LoadedPackRecord``.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from cognic_agentos.core.run.executor import LoadedPackRecord
from cognic_agentos.packs.storage import PackRecordStore

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.harness.runtime import Runtime
    from cognic_agentos.sandbox.protocol import SandboxBackend


def is_sandbox_available(settings: Settings) -> bool:
    """True iff 14A-A's DockerSibling backend can be constructed: the selected
    backend is ``docker_sibling`` AND ``aiodocker`` is importable. 14A-A is
    DockerSibling-only — ``kubernetes_pod`` returns False (deferred to 14A-B+)."""
    if settings.sandbox_backend != "docker_sibling":
        return False
    try:
        import aiodocker  # noqa: F401
    except ImportError:
        return False
    return True


class PackRecordStoreLoader:
    """``core/run.PackRecordLoader`` conformer. Does the direct UUID-keyed
    ``PackRecordStore.load(pack_uuid)`` (no tenant scan) and projects
    ``PackRecord -> LoadedPackRecord``."""

    def __init__(self, *, store: PackRecordStore) -> None:
        self._store = store

    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        record = await self._store.load(pack_uuid)
        if record is None:
            return None
        return LoadedPackRecord(
            tenant_id=record.tenant_id,
            pack_id=record.pack_id,
            kind=record.kind,
            signed_artefact_digest=record.signed_artefact_digest,
            state=record.state,
        )


async def build_sandbox_backend(
    *,
    settings: Settings,
    runtime: Runtime,
    checkpoint_store: Any | None = None,
) -> tuple[SandboxBackend, Any]:
    """Construct the DockerSibling backend + return ``(backend, docker_client)``.

    FUNCTION-LOCAL SDK + backend imports keep this module SDK-free-import. Mints
    a ``VaultTransport`` from settings + wraps it in ``VaultCredentialAdapter``
    (NOT ``adapters.secret`` — that is a ``SecretAdapter``, lacking the
    ``lease``/``revoke`` surface). The factory ``get_backend()`` OWNS
    ``image_catalog`` + ``egress_proxy_image``. ``checkpoint_store=None`` in
    14A-A (14A-A2 wires it). On ANY internal failure the just-created
    ``docker_client`` is closed before re-raise (no leak); the lifespan closes
    it on the success path's shutdown."""
    import aiodocker

    from cognic_agentos.core._vault_transport import VaultTransport
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.sandbox.backend_factory import get_backend
    from cognic_agentos.sandbox.credentials import VaultCredentialAdapter

    if not settings.vault_addr:
        raise RuntimeError(
            "sandbox_runtime_build_requires_vault_addr: enabling "
            "sandbox_runtime_enabled requires settings.vault_addr"
        )

    docker_client = aiodocker.Docker()
    try:
        vault_transport = VaultTransport(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            vault_namespace=settings.vault_namespace,
        )
        credential_adapter = VaultCredentialAdapter(transport=vault_transport, settings=settings)
        rego_engine = await OPAEngine.create(
            bundle_path=settings.sandbox_policy_bundle,
            audit_store=runtime.audit_store,
            decision_history_store=runtime.decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        backend = get_backend(
            settings,
            docker_client=docker_client,
            credential_adapter=credential_adapter,
            rego_engine=rego_engine,
            audit_store=runtime.audit_store,
            decision_history_store=runtime.decision_history_store,
            checkpoint_store=checkpoint_store,
            warm_pool=None,
        )
    except Exception:
        await docker_client.close()
        raise
    return backend, docker_client
```

Run: `uv run pytest tests/unit/harness/test_sandbox.py -q`
Expected: PASS (7 tests). Confirm the harness fence still passes (a NEW harness module trips the expected-source set): `uv run pytest tests/unit/architecture/test_harness_fences.py -q` — then **update** `test_harness_dir_has_expected_sources` expected set to include `"sandbox.py"` (reviewed: imports only core/run + packs.storage, no Layer-C, no redis, no second engine, no Bucket-1 default — the sibling fences hold).

- [ ] **Step 4: Wire the lifespan (pre-seed + construction + close)**

In `src/cognic_agentos/portal/api/app.py`:

(a) Top-level import — alongside `from cognic_agentos.protocol import is_a2a_available, is_mcp_available` (~`:74`). It MUST be a top-level module attribute so the lifespan guard calls it AND the lifespan tests can monkeypatch the module attribute `cognic_agentos.portal.api.app.is_sandbox_available`:

```python
from cognic_agentos.harness.sandbox import is_sandbox_available
```

(SDK-free import — `harness/sandbox.py` imports only `core.run` + `packs.storage` at module level; the `aiodocker` probe inside `is_sandbox_available` is function-local. `build_sandbox_backend` + `PackRecordStoreLoader` stay function-local imports inside the construction block, mirroring 13.8's `build_mcp_host`.)

(b) Pre-seed — after `app.state.mcp_host = None` (~`:842`):

```python
    app.state.sandbox_backend = None  # Sprint 14A-A (ADR-004) — SDK-gated; lifespan populates.
    app.state.managed_run_executor = None  # Sprint 14A-A (ADR-022) — lifespan populates.
```

(c) Predeclare the owned client — beside `mcp_http_client: httpx.AsyncClient | None = None` (~`:465`):

```python
        sandbox_docker_client: Any | None = None
```

(ensure `Any` is imported in app.py; if not, add `from typing import Any` or use `object`.)

(d) Construction — after the MCP construction block (~`:655`, before the reaper block):

```python
                # Sprint 14A-A (ADR-004/022): SDK-gated managed-run sandbox
                # backend + executor construction. DockerSibling-only; fail-soft.
                # build_runtime stays SDK-free; this is the lifespan's job (the
                # backend needs aiodocker + Vault + OPA + a real scheduler).
                # sandbox_docker_client is predeclared above so the finally can
                # close it even if construction raised early.
                if (
                    is_sandbox_available(settings)
                    and settings.sandbox_runtime_enabled
                    and runtime.scheduler is not None
                ):
                    from cognic_agentos.core.run.executor import ManagedRunExecutor
                    from cognic_agentos.harness.sandbox import (
                        PackRecordStoreLoader,
                        build_sandbox_backend,
                    )
                    from cognic_agentos.packs.storage import PackRecordStore

                    try:
                        backend, sandbox_docker_client = await build_sandbox_backend(
                            settings=settings, runtime=runtime
                        )
                        app.state.sandbox_backend = backend
                        app.state.managed_run_executor = ManagedRunExecutor(
                            scheduler=runtime.scheduler,
                            sandbox_backend=backend,
                            pack_loader=PackRecordStoreLoader(
                                store=PackRecordStore(adapters.relational.engine)
                            ),
                            decision_history_store=runtime.decision_history_store,
                            settings=settings,
                        )
                    except Exception:
                        logger.error("sandbox.runtime_construction_failed", exc_info=True)
                        if sandbox_docker_client is not None:
                            await sandbox_docker_client.close()
                        sandbox_docker_client = None
                        app.state.sandbox_backend = None
                        app.state.managed_run_executor = None
                elif settings.sandbox_runtime_enabled:
                    logger.warning(
                        "sandbox.runtime_unavailable_or_disabled",
                        extra={
                            "sandbox_backend": settings.sandbox_backend,
                            "scheduler_present": runtime.scheduler is not None,
                        },
                    )
```

(e) Shutdown close — in the `finally`, after the `mcp_http_client` close (~`:717`):

```python
                # Sprint 14A-A: close the lifespan-owned sandbox docker client
                # (predeclared above; bound even if construction failed early).
                if sandbox_docker_client is not None:
                    await sandbox_docker_client.close()
```

- [ ] **Step 5: Write the lifespan wiring test**

Create `tests/unit/portal/api/test_app_sandbox_state.py`:

```python
"""Sprint 14A-A — lifespan sandbox-runtime wiring (pre-seed + fail-soft).

Mirrors the 13.8 tests/unit/portal/api/test_app_mcp_host_state.py harness:
``create_app(memory_settings, adapter_registry=memory_registry)`` + the
``app.router.lifespan_context`` driver. ``cache_driver="memory"`` makes
``runtime.scheduler`` non-None (the construction guard requires it). All paths
here are skip/fail-soft (both ``app.state`` slots stay None) — the HAPPY backend
construction needs docker + OPA + images and is the env-gated e2e
(test_managed_run_e2e). asyncio_mode=auto -> no explicit asyncio marker.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from pathlib import Path


def _litellm_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


def _settings(memory_settings, tmp_path, **extra):
    return memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory", **extra}
    )


def test_sandbox_state_preseeded_none_before_lifespan(memory_settings, memory_registry, tmp_path):
    app = create_app(_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    assert app.state.sandbox_backend is None
    assert app.state.managed_run_executor is None


async def test_disabled_skips_construction(memory_settings, memory_registry, tmp_path, monkeypatch):
    # sandbox_runtime_enabled defaults False -> build_sandbox_backend MUST NOT run.
    import cognic_agentos.harness.sandbox as hs

    async def _never(**kw):
        raise AssertionError("build_sandbox_backend ran while disabled")

    monkeypatch.setattr(hs, "build_sandbox_backend", _never)
    app = create_app(
        _settings(memory_settings, tmp_path, sandbox_runtime_enabled=False),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None


async def test_enabled_but_unavailable_fail_softs(
    memory_settings, memory_registry, tmp_path, monkeypatch
):
    # is_sandbox_available()==False (SDK-absent / kubernetes_pod) -> both None.
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: False)
    app = create_app(
        _settings(memory_settings, tmp_path, sandbox_runtime_enabled=True,
                  vault_addr="http://vault:8200"),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None


async def test_construction_failure_fail_softs(
    memory_settings, memory_registry, tmp_path, monkeypatch
):
    # is_sandbox_available True (aiodocker in venv) + enabled + scheduler present
    # (cache=memory), but build_sandbox_backend raises -> fail-soft: both None,
    # the app still boots (no unhandled exception escapes the lifespan).
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: True)
    import cognic_agentos.harness.sandbox as hs

    async def _boom(**kw):
        raise RuntimeError("simulated sandbox construction failure")

    monkeypatch.setattr(hs, "build_sandbox_backend", _boom)
    app = create_app(
        _settings(memory_settings, tmp_path, sandbox_runtime_enabled=True,
                  vault_addr="http://vault:8200"),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.runtime is not None  # build_runtime OK; only sandbox failed
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None
```

Run: `uv run pytest tests/unit/portal/api/test_app_sandbox_state.py -q`
Expected: PASS (4 tests). The no-client-leak-on-internal-failure concern is covered by the harness test `test_build_sandbox_backend_closes_client_on_internal_failure` (Step 2), not here — when `build_sandbox_backend` is monkeypatched to raise, no real client is created, so the lifespan's `sandbox_docker_client` stays `None` (the builder owns its own client cleanup on internal failure).

- [ ] **Step 6: Off-gate halt + boundary full suite + CC gate**

Halt summary: files modified; gate ladder (`uv run pytest tests/unit/harness/test_sandbox.py tests/unit/portal/api/test_app_sandbox_state.py tests/unit/architecture/test_harness_fences.py -q`; ruff check/format; `uv run mypy src tests`). Then the **batch boundary**:

```bash
uv run pytest -q                                # full suite green
uv run pytest tests/unit/core/run/ tests/unit/portal/api/ --cov=src/cognic_agentos --cov-branch -q
uv run coverage json -o coverage.json
uv run python tools/check_critical_coverage.py  # 130 entries, executor >= floor
```

Watchpoint→pin: *DockerSibling-only* → `test_is_sandbox_available_false_for_kubernetes_pod_in_14a_a`; *SDK-absent fail-soft* → `test_is_sandbox_available_false_when_aiodocker_absent` + the disabled/fail-soft lifespan tests; *VaultTransport from settings not adapters.secret* → `build_sandbox_backend` body + the vault-addr guard test; *direct uuid load no scan* → `test_pack_record_store_loader_projects_record`; *no client leak on internal failure* → `test_build_sandbox_backend_closes_client_on_internal_failure`; *lifespan fail-soft (both slots None)* → the 4 `test_app_sandbox_state.py` tests. Await the commit token, then commit (paths: `harness/sandbox.py`, `core/config.py`, `portal/api/app.py`, `tests/unit/architecture/test_harness_fences.py`, the two new test files).

---

## Task 3: Env-gated real-docker e2e (valve checkpoint)

**Files:**
- Create: `tests/integration/run/__init__.py` (empty)
- Create: `tests/integration/run/test_managed_run_e2e.py`

- [ ] **Step 1: Write the env-gated e2e**

Create `tests/integration/run/test_managed_run_e2e.py`:

```python
"""Sprint 14A-A — real-docker managed-run e2e. Env-gated; fail-loud on missing
preconditions when opted in, skip-default.

Opt-in: COGNIC_RUN_DOCKER_SANDBOX=1. Preconditions (fail loud, not skip):
  * a reachable docker daemon (the sibling docker.sock);
  * a runnable runtime image (COGNIC_14A_A_RUNTIME_IMAGE, else
    settings.sandbox_canonical_runtime_python_image) — must be inspectable;
  * a runnable egress-proxy image (COGNIC_14A_A_EGRESS_PROXY_IMAGE, else
    settings.sandbox_canonical_egress_proxy_image) — the DockerSibling topology
    always launches the egress sidecar.

Proves the REAL run path: executor -> real DockerSiblingSandboxBackend -> real
container exec -> capture -> scheduler.complete -> value-free run.completed. The
catalog cosign + OPA admission are STUBBED allow-everything (the same pattern
the z3 docker integration test uses) — the run e2e proves the executor->docker
path, NOT the cosign/OPA admission stack (covered by the sandbox integration
tests). The installed pack is a direct _packs insert (the lifecycle is not under
test here). vault_addr is a dummy value (the no-creds run never contacts Vault).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.skipif(  # asyncio_mode=auto -> no explicit asyncio marker
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="real-docker e2e: set COGNIC_RUN_DOCKER_SANDBOX=1 to run",
)

# Opt-in path: plain imports — a missing optional extra MUST fail loud as
# ImportError (NOT importorskip), per the repo integration-test doctrine.
import aiodocker  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from cognic_agentos.core.audit import _chain_heads, _metadata  # noqa: E402
from cognic_agentos.core.canonical import ZERO_HASH  # noqa: E402
from cognic_agentos.core.config import Settings  # noqa: E402
from cognic_agentos.core.decision_history import (  # noqa: E402
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.core.run.executor import ManagedRunExecutor, RunRequest  # noqa: E402
from cognic_agentos.core.scheduler._types import PolicyDecision  # noqa: E402
from cognic_agentos.core.scheduler.engine import SchedulerEngine  # noqa: E402
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps  # noqa: E402
from cognic_agentos.core.scheduler.storage import SchedulerStorage  # noqa: E402
from cognic_agentos.harness.sandbox import PackRecordStoreLoader  # noqa: E402
from cognic_agentos.packs.storage import PackRecordStore, _packs  # noqa: E402
from cognic_agentos.portal.rbac.actor import Actor  # noqa: E402
from cognic_agentos.sandbox.backends.docker_sibling import (  # noqa: E402
    DockerSiblingSandboxBackend,
)

_TENANT = "tenant-e2e"
_PACK_ID = "cognic-tool-e2e"


class _AllowQuota:
    async def would_admit(self, *, task_id, tenant_id, pack_id, estimated_tokens) -> bool:
        return True

    async def release_reservation(self, task_id) -> None:
        return None


class _AllowKill:
    async def is_active(self, *, tenant_id, pack_id) -> bool:
        return False


class _Installed:
    async def is_installed(self, *, tenant_id, pack_id) -> bool:
        return True


async def _allow_policy(_inp) -> PolicyDecision:
    return PolicyDecision(allow=True, policy_reason=None)


async def test_managed_run_executes_deterministic_argv_in_real_container(tmp_path) -> None:
    settings = Settings(
        sandbox_backend="docker_sibling",
        sandbox_runtime_enabled=True,
        vault_addr="http://vault.example:8200",
    )
    runtime_image = (
        os.environ.get("COGNIC_14A_A_RUNTIME_IMAGE", "").strip()
        or settings.sandbox_canonical_runtime_python_image
    )
    egress_proxy_image = (
        os.environ.get("COGNIC_14A_A_EGRESS_PROXY_IMAGE", "").strip()
        or settings.sandbox_canonical_egress_proxy_image
    )

    docker = aiodocker.Docker()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'e2e.db'}")
    try:
        # --- preconditions: docker reachable + both images present (fail loud) ---
        for image in (runtime_image, egress_proxy_image):
            try:
                await docker.images.inspect(image)
            except aiodocker.exceptions.DockerError as exc:
                pytest.fail(
                    f"required image not present locally: {image!r} ({exc}). Pull it or set "
                    "COGNIC_14A_A_RUNTIME_IMAGE / COGNIC_14A_A_EGRESS_PROXY_IMAGE."
                )
            except Exception as exc:  # noqa: BLE001 — connection error => daemon unreachable
                pytest.fail(f"docker daemon unreachable (opted in via env): {exc}")

        # --- schema + chain heads + a direct installed-pack seed ---
        pack_uuid = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)
            for chain_id in ("audit_event", "decision_history"):
                await conn.execute(
                    _chain_heads.insert().values(
                        chain_id=chain_id, latest_sequence=0, latest_hash=ZERO_HASH,
                        updated_at=datetime.now(UTC),
                    )
                )
            await conn.execute(
                _packs.insert().values(
                    id=pack_uuid, kind="tool", pack_id=_PACK_ID, display_name="e2e",
                    state="installed", manifest_digest=b"\x01" * 32,
                    signed_artefact_digest=b"\xab" * 32, sbom_pointer=None,
                    tenant_id=_TENANT, created_by="e2e", last_actor="e2e",
                    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
                )
            )

        dh_store = DecisionHistoryStore(engine)
        scheduler = SchedulerEngine(
            storage=SchedulerStorage(engine),
            caps=ConcurrencyCaps(per_tenant_interactive=4, per_tenant_background=4,
                                 per_pack=4, per_actor=4),
            class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},  # type: ignore[arg-type]
            quota_interrogator=_AllowQuota(),
            kill_switch_interrogator=_AllowKill(),
            pack_state_interrogator=_Installed(),
            policy_evaluator=_allow_policy,
        )

        # --- real DockerSibling backend; catalog + rego STUBBED (z3 pattern) ---
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        rego = MagicMock()
        rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=MagicMock(),  # no-creds run -> mint_lease never called
            rego_engine=rego,
            audit_store=MagicMock(),
            decision_history_store=dh_store,
            settings=settings,
            warm_pool=None,
            egress_proxy_image=egress_proxy_image,
        )

        executor = ManagedRunExecutor(
            scheduler=scheduler,
            sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(engine)),
            decision_history_store=dh_store,
            settings=settings.model_copy(
                update={"sandbox_canonical_runtime_python_image": runtime_image}
            ),
        )

        marker = "cognic-14a-a-ok"
        result = await executor.run(
            RunRequest(
                tenant_id=_TENANT, pack_id=_PACK_ID, pack_uuid=pack_uuid,
                pack_version="1.0.0", argv=("printf", marker),
                actor=Actor(subject="svc-e2e", tenant_id=_TENANT, scopes=frozenset(),
                            actor_type="service"),
            )
        )

        assert result.terminal_state == "completed", result
        assert result.exit_code == 0
        assert marker.encode() in result.stdout

        async with engine.connect() as conn:
            types = [
                r[0]
                for r in (
                    await conn.execute(
                        select(_decision_history.c.decision_type)
                        .where(_decision_history.c.chain_id == "decision_history")
                        .order_by(_decision_history.c.sequence)
                    )
                ).all()
            ]
        assert "scheduler.admission_accepted" in types
        assert "scheduler.task_completed" in types
        assert "run.completed" in types
    finally:
        await docker.close()
        await engine.dispose()
```

Concrete + runnable: a REAL `DockerSiblingSandboxBackend` over a REAL `aiodocker` client running a REAL container, driven through the executor. Catalog/rego are stubbed allow-everything (the z3 docker-integration pattern — keeps the run e2e off the cosign/OPA infra, which the sandbox integration tests already cover). Missing docker daemon or images → `pytest.fail` (loud), not skip. At implementation, verify the `_packs` column names + `DockerSiblingSandboxBackend.__init__` kwargs against the live source (grounded here from `packs/storage.py:208-223` + the z3 fixture); if a fixture image is used, set `COGNIC_14A_A_RUNTIME_IMAGE` / `COGNIC_14A_A_EGRESS_PROXY_IMAGE`.

- [ ] **Step 2: Verify default-skip + opt-in fail-loud**

Run (default): `uv run pytest tests/integration/run/test_managed_run_e2e.py -q` → SKIPPED.
Run (opt-in, locally with docker): `COGNIC_RUN_DOCKER_SANDBOX=1 uv run pytest tests/integration/run/test_managed_run_e2e.py -q` → PASS when Docker is reachable and the required runtime/proxy images are present; otherwise FAIL loudly with the precondition message (`pytest.fail`), not skip.

- [ ] **Step 3: Valve checkpoint + off-gate halt**

This is the 14A-A valve close. Confirm no gated source changed in T3 (the e2e touches only the test tree). Halt summary + the commit token, then commit (`tests/integration/run/`). **14A-A2** (the `POST /api/v1/runs` route + backend-level checkpoint→wake) starts from here.

---

## Task 4: Docs (ADR + AGENTS.md + capability map)

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`
- Modify: `AGENTS.md`
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR amendments**

Add a `## Sprint 14A-A amendment` section to **ADR-022** and **ADR-004** (verify exact filenames with `ls docs/adrs/ | grep -iE '022|004'` first) covering: the `core/run/executor.py` managed-run authority (Fork A — owns the session, not the scheduler `SandboxAdapter` seam); the `load+validate → submit → mark_running → create → exec → destroy(finally) → complete` loop; the non-zero-exit=complete / infra-exception=fail / value-free `run.*` evidence (separate `stdout_sha256`/`stderr_sha256`); the SDK-gated DockerSibling-only lifespan construction (`is_sandbox_available` + `sandbox_runtime_enabled`); the `PackRecordLoader` seam (`core → packs` arrow); and the deferred 14A-A2 (route + checkpoint→wake) + the multi-backend/MCP-call/approval-exercise defers. Cite `core/run/executor.py`, `harness/sandbox.py`, `protocol.py:650-659`, `factory.py:100/125` at file:line (Read-verified in the same pass).

- [ ] **Step 2: AGENTS.md**

Under the critical-controls "Runtime authority" list, add `core/run/executor.py` (per ADR-022/004 — the managed-run executor; on the gate from Sprint 14A-A; CC count 130; SDK-free + portal-runtime-free + packs-free, AST-fenced; owns the session per Fork A; value-free `run.*` evidence). Add an off-gate note that `harness/sandbox.py` is the managed-run composition site (mirrors `harness/mcp_host.py`; holds `is_sandbox_available` + `build_sandbox_backend` + the `PackRecordStoreLoader` conformer; DockerSibling-only in 14A-A). Verify every cited symbol/line in the same pass (per `feedback_verify_code_citations_at_doc_write`).

- [ ] **Step 3: Capability map**

In `docs/AS_BUILT_CAPABILITY_MAP.md`, move 14A-A from Forward→Landed; mark **pillar 2 (managed runtime)** as the first *exercised* managed-run path (14A-A DONE: executor + DockerSibling backend construction + e2e; **14A-A2 NEXT**: `POST /api/v1/runs` route + backend-level checkpoint→wake). Note the scheduler/MCP seams move from "wired-dormant" toward exercised once a caller drives `app.state.managed_run_executor` (14A-A proves it via the executor API + e2e, not yet a portal route).

- [ ] **Step 4: Docs halt + commit**

Halt summary (docs-only; no pytest needed per the gate-ladder). Await the commit token, then commit (the 3 docs paths — **never** stage `docs/reviews/` or the 2026-05-26 gap-analysis spec).

---

## Self-Review

**Spec coverage (each §):** §2 forks → T1 (F1 executor/CC, F3 lifecycle/failure, F4 argv+request) + T2 (F2 backend construction, DockerSibling) + T3 (F6 e2e) + F5 deferred-route noted in T4. §4 executor (ctor incl. `pack_loader`, `RunRequest`/`RunResult`/`RunRefusalReason`, the seam, the fence) → T1. §5 backend construction (function-local imports, `VaultTransport` mint, `checkpoint_store=None`, no catalog, client ownership, lifespan flag) → T2. §6 (pack-record load+4 checks+derivations, `SubmitInput`, `PackAdmissionContext` incl. `profile="production"`, `SandboxPolicy`, scheduler defense-in-depth) → T1 executor + tests. §7 (workload + two test tiers) → T1 stub-tier + T3 docker-tier. §8 failure table → the 7 executor tests + the lifespan fail-soft tests. §9 CC 129→130 → T1 Step 7-8. §10 task sketch → T1-T4. §11 resolved decisions → all covered.

**Stub/leftover scan:** clean. Both previously-weak bodies are now concrete real code — the T2.5 lifespan test uses the real `memory_settings`/`memory_registry` + `app.router.lifespan_context` harness (4 tests); the T3.1 e2e is a complete real-docker body (z3-pattern backend + direct seed + run + asserts + fail-loud preconditions). No leftover stub markers, incomplete bodies, or undefined symbols. The scan's only ellipsis hits are legitimate Python syntax — variadic-tuple annotations (`tuple[str, …]`) and the `PackRecordLoader` Protocol method body — not stubs.

**Type consistency:** `LoadedPackRecord` (5 fields) identical in `executor.py`, the conformer, and the tests. `PackRecordLoader.load_for_run(*, pack_uuid)` identical across seam + conformer + stubs. `RunRequest`/`RunResult` fields match between the module and every test constructor. `ManagedRunExecutor.__init__` signature (`scheduler`, `sandbox_backend`, `pack_loader`, `decision_history_store`, `settings`) identical in the module, the test `_executor` helper, and the lifespan. `TaskFailedPayload.reason` values match the grounded `SchedulerTaskFailedReason` literal. `backend.create(policy, *, actor, tenant_id, pack_context, requires_credentials=())` matches `protocol.py:650-659`. Accepted outcomes `("accepted_immediate", "accepted_queued")` match the grounded `SchedulerAdmissionOutcome`.

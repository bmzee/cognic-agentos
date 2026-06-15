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

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.scheduler.engine import SchedulerEngine
    from cognic_agentos.portal.rbac.actor import Actor

    # sandbox.policy / sandbox.protocol are imported under TYPE_CHECKING (for the
    # annotations) + FUNCTION-LOCALLY where constructed (_build_policy /
    # _build_pack_context). They are NOT module-level imports because
    # ``sandbox.policy -> sandbox.audit -> core.vault -> hvac`` pulls the Vault
    # SDK, which the kernel image (no ``adapters`` extra) lacks — a module-level
    # import would break the kernel boot when ``app.py`` imports this module.
    # The runtime construction only fires when the executor RUNS, which only
    # happens in the adapters image (where hvac exists). Pinned by
    # tests/unit/architecture/test_run_no_sdk_import.py::test_core_run_imports_without_hvac.
    from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
    from cognic_agentos.sandbox.protocol import SandboxBackend, SandboxExecResult

logger = logging.getLogger(__name__)

#: Minimal fixed admission cost for 14A-A (manifest-driven sizing is 14A-B).
_DEFAULT_ESTIMATED_TOKENS = 1000
#: ISO-control mapping for run.* evidence is a Human-only decision — deferred.
_RUN_EVIDENCE_ISO_CONTROLS: tuple[str, ...] = ()
#: The synchronous 14A-A executor runs a task inline; it can only execute a task
#: the scheduler admitted IMMEDIATELY. An ``accepted_queued`` task (caps
#: saturated, enqueued) is cancelled + refused with this reason — there is no
#: worker to promote it once caps free up (a wait/worker path is 14A-A2+).
_RUN_QUEUED_UNSUPPORTED = "run_admission_queued_unsupported"

#: Closed executor-side pre-submit pack-validation refusal vocabulary.
RunRefusalReason = Literal[
    "pack_record_not_found",
    "pack_record_tenant_mismatch",
    "pack_record_pack_id_mismatch",
    "pack_record_not_installed",
]

RunTerminalState = Literal["completed", "failed", "refused", "pending_approval"]

#: Closed run.failed reason vocabulary (maps 1:1 to the two infra failure modes).
RunFailedReason = Literal["sandbox_create_refused", "workload_runtime_error"]

#: Sprint 14A-A2a (ADR-014) — the single sandbox approval reason that means
#: "pending — go approve" (-> pending_approval/202). Every OTHER
#: SandboxLifecycleRefused (governance/admission refusal) is terminal ->
#: refused/409 (cancel + run.refused), per the F3 status map; only a generic
#: create() exception or an exec() exception is an infra failure -> failed/502.
_SANDBOX_APPROVAL_PENDING_REASON = "sandbox_approval_pending"


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
    #: Sprint 14A-A2a (ADR-014): re-POST correlator for a previously-pending
    #: sandbox approval. Threaded to backend.create -> admit_policy grant
    #: verification in 14A-A2b. None on a fresh run.
    approval_request_id: uuid.UUID | None = None


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
    #: Set ONLY when terminal_state == "pending_approval"; the sandbox approval
    #: correlator the caller re-POSTs after granting. str (OUTPUT side —
    #: SandboxLifecycleRefused carries it as str).
    approval_request_id: str | None = None


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
                "run_request_tenant_actor_mismatch: request.tenant_id != request.actor.tenant_id"
            )

        # Step 0 — load + validate the trusted pack record (pre-submit).
        record = await self._pack_loader.load_for_run(pack_uuid=request.pack_uuid)
        refusal = _validate_pack_record(record, request)
        if refusal is not None:
            await self._emit_refused(request, request_id, refusal)
            return RunResult(None, "refused", None, b"", b"", refusal)
        assert record is not None  # narrowed by _validate_pack_record

        # Step 1 — submit. Project the core-owned TaskActor once; it is reused
        # by the queued-cancellation cleanup path below.
        task_actor = TaskActor(
            subject=request.actor.subject,
            tenant_id=request.actor.tenant_id,
            actor_type=request.actor.actor_type,
        )
        submit_input = SubmitInput(
            tenant_id=request.tenant_id,
            pack_id=request.pack_id,
            actor=task_actor,
            class_="interactive",
            pack_kind=record.kind,
            pack_risk_tier="read_only",
            requested_estimated_tokens=_DEFAULT_ESTIMATED_TOKENS,
        )
        decision = await self._scheduler.submit(submit_input=submit_input, request_id=request_id)

        # Admission contract. The 14A-A executor is SYNCHRONOUS — it runs the task
        # inline immediately, so it can only execute a task the scheduler admitted
        # IMMEDIATELY (a reserved concurrency slot). An ``accepted_queued`` task
        # (caps saturated, enqueued) has NO worker to promote it once caps free
        # up; leaving it queued would LEAK the task + its quota reservation. So
        # the executor CANCELS it — pending -> cancelled removes it from the FIFO
        # queue, releases the reservation, and writes a terminal transition — and
        # surfaces a refusal. It does NOT call mark_running on a queued task
        # (which re-checks FIFO head + caps and would raise
        # SchedulerPromotionRefused on the saturated caps). A real wait/worker
        # path is 14A-A2+.
        if decision.outcome == "accepted_queued":
            assert decision.task_id is not None
            await self._scheduler.cancel(
                uuid.UUID(decision.task_id),
                actor=task_actor,
                reason="actor_cancelled",
                request_id=request_id,
            )
            await self._emit_refused(request, request_id, _RUN_QUEUED_UNSUPPORTED)
            return RunResult(decision.task_id, "refused", None, b"", b"", _RUN_QUEUED_UNSUPPORTED)
        if decision.outcome != "accepted_immediate":
            await self._emit_refused(request, request_id, decision.outcome)
            return RunResult(decision.task_id, "refused", None, b"", b"", decision.outcome)
        assert decision.task_id is not None
        task_id = uuid.UUID(decision.task_id)

        # Step 2 — mark_running (NO sandbox_adapter — Fork A). accepted_immediate
        # uses _attribution (not _queued_attribution), so mark_running skips the
        # FIFO/cap re-check that raises SchedulerPromotionRefused on the queued
        # path — promotion of an immediately-admitted task is safe.
        await self._scheduler.mark_running(task_id, request_id=request_id)

        # Steps 3-7 — create -> exec -> destroy(finally) -> complete/fail -> evidence.
        policy = self._build_policy()
        ctx = self._build_pack_context(record, request)
        # Function-local import: the except clause needs SandboxLifecycleRefused at
        # runtime, but a module-level sandbox import would pull hvac (via
        # sandbox.audit -> core.vault) and break kernel boot. Only fires when the
        # executor RUNS (adapters image, where hvac exists). Pinned by
        # tests/unit/architecture/test_run_no_sdk_import.py.
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

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
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    # pending sandbox approval is NOT a failure: cancel the running
                    # task (running -> cancelled releases quota + counters), emit
                    # value-free pending evidence, return the 202-shaped result.
                    await self._scheduler.cancel(
                        task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                    )
                    await self._emit_pending(
                        request, request_id, task_id, approval_request_id=exc.approval_request_id
                    )
                    return RunResult(
                        decision.task_id,
                        "pending_approval",
                        None,
                        b"",
                        b"",
                        None,
                        exc.approval_request_id,
                    )
                # any OTHER SandboxLifecycleRefused is a governance/admission
                # REFUSAL (high_risk_tier_refused, approval_denied/expired,
                # catalog/egress) -> refused/409, NOT an infra failure (F3 status
                # map). Cancel the running task + emit run.refused with the reason.
                await self._scheduler.cancel(
                    task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                )
                await self._emit_refused(request, request_id, str(exc.reason))
                return RunResult(decision.task_id, "refused", None, b"", b"", str(exc.reason))
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
        # Function-local import: sandbox.policy pulls hvac transitively (via
        # sandbox.audit -> core.vault). This only fires when the executor RUNS,
        # which only happens in the adapters image (where hvac exists) — keeping
        # the module import kernel-boot-clean.
        from cognic_agentos.sandbox.policy import SandboxPolicy

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
        # Function-local import (kernel-boot-clean — see _build_policy).
        from cognic_agentos.sandbox.policy import PackAdmissionContext

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

    async def _emit_pending(
        self,
        request: RunRequest,
        request_id: str,
        task_id: uuid.UUID,
        *,
        approval_request_id: str | None,
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.pending_approval",
                request_id=request_id,
                payload={
                    "task_id": str(task_id),
                    "approval_reason": _SANDBOX_APPROVAL_PENDING_REASON,
                    "approval_request_id": approval_request_id,
                },
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

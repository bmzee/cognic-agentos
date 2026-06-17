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
from typing import TYPE_CHECKING, Final, Literal, Protocol, get_args

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.run._types import (  # core->core, SDK-free
    RunRecord,
    RunTransitionRefused,
)
from cognic_agentos.core.run.storage import (  # core->core, SDK-free
    RunNotFound,
    RunRecordStore,
)
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor, TaskFailedPayload

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.scheduler.engine import SchedulerEngine
    from cognic_agentos.portal.rbac.actor import Actor

    # Sprint 14A-A3b: the executor's run-suspend branch reads the latest
    # checkpoint metadata via the CheckpointStore seam. TYPE_CHECKING-only —
    # sandbox.checkpoint_store -> sandbox.audit -> core.vault pulls hvac, which
    # the kernel image lacks; the import dance keeps the module kernel-boot-clean
    # (the dep is constructed by the lifespan + injected; the executor only calls
    # .load_latest at RUN time). Pinned by test_run_no_sdk_import.py.
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

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
    # Sprint 14A-A4b (ADR-022/004/014) — fail-closed manifest-tier gate:
    "pack_record_risk_tier_unresolved",
    "pack_record_data_classes_malformed",
]

#: Sprint 14A-A4b — local copy of the ADR-014 canonical 8-value risk-tier set
#: (the core/run -> cli architectural arrow forbids importing it; the
#: sandbox/policy.py + packs/conformance/owasp_agentic.py precedent).
#: Drift-pinned test-only against cli._governance_vocab.RiskTier.
RiskTier = Literal[
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
]
_CANONICAL_RISK_TIERS: Final[frozenset[str]] = frozenset(get_args(RiskTier))

RunTerminalState = Literal[
    "completed", "failed", "refused", "pending_approval", "suspended"
]  # +suspended (A3b)

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
    #: Sprint 14A-A3b (F2): when True the executor suspends the session AFTER a
    #: clean exec (final checkpoint + container release) instead of destroying it,
    #: transitions the run-record to ``suspended``, and returns
    #: terminal_state="suspended" with the session_id + checkpoint_id persisted on
    #: the run row (the resume substrate). False = the legacy complete+destroy path.
    suspend_after_exec: bool = False


@dataclass(frozen=True)
class RunResult:
    """Returned to the caller. Raw ``stdout``/``stderr`` are for the caller
    ONLY — never the chain (the chain carries digests + counts)."""

    #: Sprint 14A-A3b (F1): the minted run_id (str), populated on EVERY path —
    #: refusal, failure, pending-approval, completion, suspension. The durable
    #: run-record key + the resume correlator.
    run_id: str
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


class RunNotResumable(Exception):
    """Raised by :meth:`ManagedRunExecutor.resume` when the run record exists but
    is not in ``suspended``. The route maps it to 409 ``run_not_suspended``."""

    def __init__(self, current_state: str) -> None:
        self.current_state = current_state
        super().__init__(f"run_not_suspended: state={current_state}")


class RunResumeConflict(Exception):
    """Raised by :meth:`ManagedRunExecutor.resume` when ``wake()`` succeeded but
    the atomic ``suspended -> woken`` claim lost the race to a concurrent resume
    (the row already moved out of ``suspended``). The route maps it to 409
    ``run_resume_conflict``; resume() leaves ``claimed_woken=False`` so the woken
    session is NOT destroyed (the winning request owns it — destroying would
    tombstone the session it is executing)."""

    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_conflict: {run_id}")


class RunResumePendingApprovalRequired(Exception):
    """resume() of a run already in 'pending_approval' WITHOUT an approval_request_id.
    The route maps it to 409 run_resume_approval_id_required. Raised BEFORE wake() so
    admission Arm A (mint) is never reached — no silent new-pending loop."""

    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_approval_id_required: {run_id}")


class RunResumeApprovalMismatch(Exception):
    """resume() of a 'pending_approval' run with an approval_request_id that does not
    match the run row's stored one. Route -> 409 run_resume_approval_id_mismatch."""

    def __init__(self, run_id: uuid.UUID) -> None:
        self.run_id = run_id
        super().__init__(f"run_resume_approval_id_mismatch: {run_id}")


def _resume_req(actor: Actor, record: RunRecord) -> RunRequest:
    """Minimal :class:`RunRequest` shim built from a loaded run record purely so
    the value-free ``_emit_*`` emitters can read ``actor.subject`` /
    ``tenant_id`` / ``pack_id``. resume() has no real RunRequest (no pack-
    admission context); ``argv`` is intentionally empty (the emitters never read
    it). NOT a managed-run submit — only an emitter-payload carrier."""
    return RunRequest(
        tenant_id=record.tenant_id,
        pack_id=record.pack_id,
        pack_uuid=record.pack_uuid,
        pack_version=record.pack_version,
        argv=(),
        actor=actor,
    )


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
        run_record_store: RunRecordStore,
        checkpoint_store: CheckpointStore,
    ) -> None:
        self._scheduler = scheduler
        self._sandbox_backend = sandbox_backend
        self._pack_loader = pack_loader
        self._dh = decision_history_store
        self._settings = settings
        self._runs = run_record_store
        self._checkpoints = checkpoint_store

    async def run(self, request: RunRequest) -> RunResult:
        request_id = f"run-{uuid.uuid4().hex}"

        # confused-deputy guard — a RunRequest whose tenant disagrees with the
        # authenticated actor is a caller-contract violation, not a governance
        # refusal. Runs BEFORE genesis so a malformed request never mints a row.
        if request.tenant_id != request.actor.tenant_id:
            raise ValueError(
                "run_request_tenant_actor_mismatch: request.tenant_id != request.actor.tenant_id"
            )

        # Sprint 14A-A3b — mint the run_id + genesis run-record (run.lifecycle.
        # pending) BEFORE pack load/submit, so EVERY terminal path below carries
        # a durable run-record + the run_id is populated on the RunResult.
        run_id = uuid.uuid4()
        await self._runs.create_run(
            run_id=run_id,
            tenant_id=request.tenant_id,
            pack_id=request.pack_id,
            pack_uuid=request.pack_uuid,
            pack_version=request.pack_version,
            request_id=request_id,
        )
        rid = str(run_id)

        # Step 0 — load + validate the trusted pack record (pre-submit).
        record = await self._pack_loader.load_for_run(pack_uuid=request.pack_uuid)
        refusal = _validate_pack_record(record, request)
        if refusal is not None:
            await self._runs.transition(
                run_id=run_id,
                tenant_id=request.tenant_id,
                from_state="pending",
                to_state="refused",
                actor_id=request.actor.subject,
                request_id=request_id,
            )
            await self._emit_refused(request, request_id, run_id=rid, task_id=None, reason=refusal)
            return RunResult(
                run_id=rid,
                task_id=None,
                terminal_state="refused",
                exit_code=None,
                stdout=b"",
                stderr=b"",
                refusal_reason=refusal,
            )
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
            # task_id is the scheduler task id here (accepted_queued always carries
            # one); thread it onto the run row + the run.refused join key.
            await self._runs.transition(
                run_id=run_id,
                tenant_id=request.tenant_id,
                from_state="pending",
                to_state="refused",
                actor_id=request.actor.subject,
                request_id=request_id,
                task_id=uuid.UUID(decision.task_id),
            )
            await self._emit_refused(
                request,
                request_id,
                run_id=rid,
                task_id=decision.task_id,
                reason=_RUN_QUEUED_UNSUPPORTED,
            )
            return RunResult(
                run_id=rid,
                task_id=decision.task_id,
                terminal_state="refused",
                exit_code=None,
                stdout=b"",
                stderr=b"",
                refusal_reason=_RUN_QUEUED_UNSUPPORTED,
            )
        if decision.outcome != "accepted_immediate":
            # A refused scheduler outcome has NO task_id (AdmissionDecision.task_id
            # is None on refused outcomes) — the run row stays task_id-less, the
            # run.refused join key is None.
            await self._runs.transition(
                run_id=run_id,
                tenant_id=request.tenant_id,
                from_state="pending",
                to_state="refused",
                actor_id=request.actor.subject,
                request_id=request_id,
            )
            await self._emit_refused(
                request,
                request_id,
                run_id=rid,
                task_id=decision.task_id,
                reason=decision.outcome,
            )
            return RunResult(
                run_id=rid,
                task_id=decision.task_id,
                terminal_state="refused",
                exit_code=None,
                stdout=b"",
                stderr=b"",
                refusal_reason=decision.outcome,
            )
        assert decision.task_id is not None
        task_id = uuid.UUID(decision.task_id)

        # Step 2 — mark_running (NO sandbox_adapter — Fork A). accepted_immediate
        # uses _attribution (not _queued_attribution), so mark_running skips the
        # FIFO/cap re-check that raises SchedulerPromotionRefused on the queued
        # path — promotion of an immediately-admitted task is safe. Mirror the
        # run-record pending -> running transition (durable-first not required:
        # the run-record is auxiliary evidence, mark_running is the scheduler
        # authority that gates the slot).
        await self._scheduler.mark_running(task_id, request_id=request_id)
        await self._runs.transition(
            run_id=run_id,
            tenant_id=request.tenant_id,
            from_state="pending",
            to_state="running",
            actor_id=request.actor.subject,
            request_id=request_id,
            task_id=task_id,
        )

        # Steps 3-7 — create -> exec -> (suspend | complete) -> destroy(finally)
        # -> evidence. ``skip_destroy`` flips True the instant suspend() returns
        # (the container is released; destroying it would error / double-free).
        policy = self._build_policy()
        ctx = self._build_pack_context(record, request)
        # Function-local import: the except clause needs SandboxLifecycleRefused at
        # runtime, but a module-level sandbox import would pull hvac (via
        # sandbox.audit -> core.vault) and break kernel boot. Only fires when the
        # executor RUNS (adapters image, where hvac exists). Pinned by
        # tests/unit/architecture/test_run_no_sdk_import.py.
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        session = None
        skip_destroy = False
        try:
            try:
                session = await self._sandbox_backend.create(
                    policy,
                    actor=request.actor,
                    tenant_id=request.tenant_id,
                    pack_context=ctx,
                    requires_credentials=(),
                    approval_request_id=request.approval_request_id,
                )
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    # pending sandbox approval is NOT a failure: cancel the running
                    # task (running -> cancelled releases quota + counters),
                    # transition the run-record running -> pending_approval (threads
                    # the approval correlator onto the run row), emit value-free
                    # pending evidence, return the 202-shaped result.
                    await self._scheduler.cancel(
                        task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                    )
                    await self._runs.transition(
                        run_id=run_id,
                        tenant_id=request.tenant_id,
                        from_state="running",
                        to_state="pending_approval",
                        actor_id=request.actor.subject,
                        request_id=request_id,
                        approval_request_id=(
                            uuid.UUID(exc.approval_request_id) if exc.approval_request_id else None
                        ),
                    )
                    await self._emit_pending(
                        request,
                        request_id,
                        run_id=rid,
                        task_id=decision.task_id,
                        approval_request_id=exc.approval_request_id,
                    )
                    return RunResult(
                        run_id=rid,
                        task_id=decision.task_id,
                        terminal_state="pending_approval",
                        exit_code=None,
                        stdout=b"",
                        stderr=b"",
                        refusal_reason=None,
                        approval_request_id=exc.approval_request_id,
                    )
                # any OTHER SandboxLifecycleRefused is a governance/admission
                # REFUSAL (high_risk_tier_refused, approval_denied/expired,
                # catalog/egress) -> refused/409, NOT an infra failure (F3 status
                # map). Cancel the running task + run-record running -> refused +
                # emit run.refused with the reason.
                await self._scheduler.cancel(
                    task_id, actor=task_actor, reason="actor_cancelled", request_id=request_id
                )
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    from_state="running",
                    to_state="refused",
                    actor_id=request.actor.subject,
                    request_id=request_id,
                )
                await self._emit_refused(
                    request,
                    request_id,
                    run_id=rid,
                    task_id=decision.task_id,
                    reason=str(exc.reason),
                )
                return RunResult(
                    run_id=rid,
                    task_id=decision.task_id,
                    terminal_state="refused",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=str(exc.reason),
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
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    from_state="running",
                    to_state="failed",
                    actor_id=request.actor.subject,
                    request_id=request_id,
                )
                await self._emit_failed(
                    request,
                    request_id,
                    run_id=rid,
                    task_id=decision.task_id,
                    reason="sandbox_create_refused",
                )
                return RunResult(
                    run_id=rid,
                    task_id=decision.task_id,
                    terminal_state="failed",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=None,
                )

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
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    from_state="running",
                    to_state="failed",
                    actor_id=request.actor.subject,
                    request_id=request_id,
                )
                await self._emit_failed(
                    request,
                    request_id,
                    run_id=rid,
                    task_id=decision.task_id,
                    reason="workload_runtime_error",
                )
                return RunResult(
                    run_id=rid,
                    task_id=decision.task_id,
                    terminal_state="failed",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=None,
                )

            # exec returned cleanly. Branch on the caller's suspend request.
            if request.suspend_after_exec:
                # Sprint 14A-A3b — suspend instead of destroy. suspend() takes a
                # final checkpoint + releases the container; the instant it
                # returns the session is gone, so skip_destroy flips True
                # IMMEDIATELY — a failure in any post-suspend step propagates
                # WITHOUT a (doomed) destroy attempt in the finally.
                await session.suspend()
                skip_destroy = True
                meta, _ = await self._checkpoints.load_latest(
                    session_id=session.session_id, tenant_id=request.tenant_id
                )
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=request.tenant_id,
                    from_state="running",
                    to_state="suspended",
                    actor_id=request.actor.subject,
                    request_id=request_id,
                    session_id=session.session_id,
                    checkpoint_id=meta.checkpoint_id,
                )
                await self._scheduler.complete(task_id, request_id=request_id)
                await self._emit_suspended(
                    request,
                    request_id,
                    run_id=rid,
                    task_id=decision.task_id,
                    result=exec_result,
                    session_id=session.session_id,
                    checkpoint_id=meta.checkpoint_id,
                )
                return RunResult(
                    run_id=rid,
                    task_id=decision.task_id,
                    terminal_state="suspended",
                    exit_code=exec_result.exit_code,
                    stdout=exec_result.stdout,
                    stderr=exec_result.stderr,
                    refusal_reason=None,
                )

            # exec returned (ANY exit_code, incl. non-zero) -> completed run.
            await self._scheduler.complete(task_id, request_id=request_id)
            await self._runs.transition(
                run_id=run_id,
                tenant_id=request.tenant_id,
                from_state="running",
                to_state="completed",
                actor_id=request.actor.subject,
                request_id=request_id,
            )
            await self._emit_completed(
                request, request_id, run_id=rid, task_id=decision.task_id, result=exec_result
            )
            return RunResult(
                run_id=rid,
                task_id=decision.task_id,
                terminal_state="completed",
                exit_code=exec_result.exit_code,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                refusal_reason=None,
            )
        finally:
            if session is not None and not skip_destroy:
                try:
                    await session.destroy()
                except Exception:  # best-effort teardown — never flips the outcome.
                    logger.warning(
                        "run.session_destroy_failed",
                        extra={
                            "request_id": request_id,
                            "run_id": rid,
                            "session_id": session.session_id,
                        },
                    )

    async def resume(
        self,
        *,
        run_id: uuid.UUID,
        actor: Actor,
        argv: tuple[str, ...],
        approval_request_id: uuid.UUID | None = None,
    ) -> RunResult:
        """Sprint 14A-A3b/A3c — resolve a suspended (or re-resumed
        pending_approval) run to its sandbox session, wake it, run a continuation
        ``argv``, and walk the run record ``from_state -> woken -> completed`` (or
        ``-> refused`` / ``-> failed``), where ``from_state`` is ``suspended`` on a
        first resume and ``pending_approval`` on a granted re-resume.

        Sprint 14A-A3c wake approval seam: when ``wake()`` re-runs admission and the
        grant is still pending it raises ``SandboxLifecycleRefused(
        "sandbox_approval_pending", approval_request_id=<str>)`` (the wake-approval
        passthrough). A FIRST resume (from ``suspended``) transitions the run record
        ``suspended -> pending_approval`` + stores the minted ``approval_request_id``
        on the run row + returns terminal_state="pending_approval". The caller
        re-POSTs after granting, supplying that ``approval_request_id``; the
        re-resume threads it into ``wake()`` (admission Arm B — verify, NOT mint).

        No-re-mint guard (F2 pin): a run already in ``pending_approval`` MUST supply
        its stored ``approval_request_id`` — a missing id raises
        ``RunResumePendingApprovalRequired`` and a mismatched id raises
        ``RunResumeApprovalMismatch``, BOTH before ``wake()`` is ever dispatched, so
        a re-resume can never re-enter admission Arm A (mint) and spin up a fresh
        pending. A re-resume whose grant is STILL pending (wake re-raises
        ``sandbox_approval_pending``) is a no-op: ``pending_approval ->
        pending_approval`` is not a legal pair, so NO transition is emitted (no
        self-loop evidence).

        NO scheduler calls: the scheduler slot was freed at suspend (the run()
        suspend branch calls ``scheduler.complete``). ``task_id`` is therefore
        ALWAYS None on resume results + events (no scheduler task). Quota-on-
        resume is a forward item.

        Claim-gated teardown (the resume-side session-tombstone race fix): wake()
        is dispatched FIRST, then an atomic ``from_state -> woken`` claim acts as a
        mutex — exactly one concurrent resume commits it. A loser sees the row
        already moved -> stale -> ``RunTransitionRefused`` -> ``RunResumeConflict``
        (409). The ``finally`` destroys ONLY a session this request OWNS (claimed
        ``from_state -> woken``); if wake() succeeded but the claim failed (a
        concurrent loser, or a non-stale DB error), ``claimed_woken`` stays False
        so the session is NOT destroyed — destroying it would tombstone a session
        the winner is executing / a run that is still resumable. The pending/refused
        arms return BEFORE the claim, so they own nothing + never destroy.

        TRADE-OFF: a claim-failure/loser therefore LEAVES a live woken
        container/pod orphaned. The CheckpointReaper purges only object-store
        checkpoints, NOT backend resources, so this is NOT auto-reclaimed today;
        leaked-backend-resource cleanup is a forward item (resource leak, not
        data-loss)."""
        request_id = f"run-resume-{uuid.uuid4().hex}"
        record = await self._runs.load(run_id, tenant_id=actor.tenant_id)
        if record is None:
            raise RunNotFound(run_id)  # -> route 404 (cross-tenant reads as absent)
        if record.state not in ("suspended", "pending_approval"):  # A3c — widen
            raise RunNotResumable(record.state)  # -> route 409 run_not_suspended
        if record.session_id is None:
            # Invariant: a suspended run ALWAYS has a session_id (run() persists it
            # in the suspend branch). A null here is a corrupt row, not a caller
            # error -> fail loud (never wake(None)).
            raise RuntimeError(f"run_suspended_without_session_id: {run_id}")
        # A3c — suspended (first resume) OR pending_approval (re-resume). The
        # post-wake transitions are keyed off from_state, NOT a hardcoded
        # "suspended", so the claim becomes from_state->woken (both legal per T1).
        from_state = record.state

        # A3c no-re-mint guard (F2 pin): a pending_approval run MUST supply its
        # stored approval_request_id (admission Arm B verify) and never re-enters
        # admission Arm A (mint). Both arms raise BEFORE wake() so Arm A is
        # unreachable on a re-resume — no silent new-pending loop.
        if record.state == "pending_approval":
            if approval_request_id is None:
                raise RunResumePendingApprovalRequired(run_id)
            if (
                record.approval_request_id is None
                or approval_request_id != record.approval_request_id
            ):
                raise RunResumeApprovalMismatch(run_id)
        rid = str(run_id)
        # Function-local import: the except clause needs SandboxLifecycleRefused at
        # runtime; a module-level sandbox import would pull hvac (sandbox.protocol
        # -> sandbox.audit -> core.vault) and break kernel boot. Only fires when
        # the executor RESUMES (adapters image). Pinned by test_run_no_sdk_import.
        from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

        session = None
        claimed_woken = False
        try:
            try:
                session = await self._sandbox_backend.wake(
                    record.session_id,
                    actor=actor,
                    tenant_id=actor.tenant_id,
                    approval_request_id=approval_request_id,  # A3c — Arm B verify correlator
                )
            except SandboxLifecycleRefused as exc:
                if exc.reason == _SANDBOX_APPROVAL_PENDING_REASON:
                    # A3c wake-pending. First resume (from suspended): transition to
                    # pending_approval + store the minted approval_request_id on the
                    # run row. Re-resume already in pending_approval (still awaiting):
                    # NO transition (pending_approval -> pending_approval is not a
                    # legal pair; a self-loop would be misleading evidence). Either
                    # way the pending arm NEVER claims suspended/pending_approval ->
                    # woken, so it owns nothing + the finally never destroys.
                    if from_state != "pending_approval":
                        await self._runs.transition(
                            run_id=run_id,
                            tenant_id=actor.tenant_id,
                            from_state=from_state,
                            to_state="pending_approval",
                            actor_id=actor.subject,
                            request_id=request_id,
                            approval_request_id=(
                                uuid.UUID(exc.approval_request_id)
                                if exc.approval_request_id
                                else None
                            ),
                        )
                    await self._emit_pending(
                        _resume_req(actor, record),
                        request_id,
                        run_id=rid,
                        task_id=None,
                        approval_request_id=exc.approval_request_id,
                    )
                    return RunResult(
                        run_id=rid,
                        task_id=None,
                        terminal_state="pending_approval",
                        exit_code=None,
                        stdout=b"",
                        stderr=b"",
                        refusal_reason=None,
                        approval_request_id=exc.approval_request_id,
                    )
                # any OTHER SandboxLifecycleRefused (sandbox_approval_denied/expired/
                # not_found/binding_mismatch OR sandbox_wake_*) is a governance/
                # restore REFUSAL -> from_state -> refused + run.refused.
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=actor.tenant_id,
                    from_state=from_state,
                    to_state="refused",
                    actor_id=actor.subject,
                    request_id=request_id,
                )
                await self._emit_refused(
                    _resume_req(actor, record),
                    request_id,
                    run_id=rid,
                    task_id=None,
                    reason=str(exc.reason),
                )
                return RunResult(
                    run_id=rid,
                    task_id=None,
                    terminal_state="refused",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=str(exc.reason),
                )
            except Exception:
                # any OTHER wake() exception is an infra failure -> from_state ->
                # failed + run.failed. No session was returned -> nothing to destroy.
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=actor.tenant_id,
                    from_state=from_state,
                    to_state="failed",
                    actor_id=actor.subject,
                    request_id=request_id,
                )
                await self._emit_failed(
                    _resume_req(actor, record),
                    request_id,
                    run_id=rid,
                    task_id=None,
                    reason="workload_runtime_error",
                )
                return RunResult(
                    run_id=rid,
                    task_id=None,
                    terminal_state="failed",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=None,
                )

            # Atomic claim + mutex: exactly one concurrent resume commits
            # from_state -> woken (suspended->woken on a first resume, or
            # pending_approval->woken on a granted re-resume — both legal per T1).
            # A loser sees the row already moved -> stale -> RunTransitionRefused ->
            # RunResumeConflict (409); claimed_woken stays False so the finally does
            # NOT destroy. A non-RunTransitionRefused (DB) error here ALSO propagates
            # with claimed_woken=False -> no destroy -> the rolled-back run stays
            # resumable (no tombstone).
            try:
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=actor.tenant_id,
                    from_state=from_state,
                    to_state="woken",
                    actor_id=actor.subject,
                    request_id=request_id,
                )
            except RunTransitionRefused as exc:
                raise RunResumeConflict(run_id) from exc
            claimed_woken = True

            try:
                exec_result = await session.exec(
                    list(argv), timeout_s=self._build_policy().walltime_s
                )
            except Exception:
                await self._runs.transition(
                    run_id=run_id,
                    tenant_id=actor.tenant_id,
                    from_state="woken",
                    to_state="failed",
                    actor_id=actor.subject,
                    request_id=request_id,
                )
                await self._emit_failed(
                    _resume_req(actor, record),
                    request_id,
                    run_id=rid,
                    task_id=None,
                    reason="workload_runtime_error",
                )
                return RunResult(
                    run_id=rid,
                    task_id=None,
                    terminal_state="failed",
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    refusal_reason=None,
                )

            await self._runs.transition(
                run_id=run_id,
                tenant_id=actor.tenant_id,
                from_state="woken",
                to_state="completed",
                actor_id=actor.subject,
                request_id=request_id,
            )
            await self._emit_completed(
                _resume_req(actor, record),
                request_id,
                run_id=rid,
                task_id=None,
                result=exec_result,
            )
            return RunResult(
                run_id=rid,
                task_id=None,
                terminal_state="completed",
                exit_code=exec_result.exit_code,
                stdout=exec_result.stdout,
                stderr=exec_result.stderr,
                refusal_reason=None,
            )
        finally:
            # Destroy ONLY a session we OWN (claimed suspended -> woken). If wake()
            # succeeded but the claim failed (concurrent loser, or a DB error),
            # destroying would tombstone a session the winner is executing / a run
            # still suspended+resumable -> sandbox_wake_session_tombstoned.
            if session is not None and claimed_woken:
                try:
                    await session.destroy()
                except Exception:  # best-effort teardown — never flips the outcome.
                    logger.warning(
                        "run.session_destroy_failed",
                        extra={
                            "request_id": request_id,
                            "run_id": rid,
                            "session_id": session.session_id,
                        },
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

    # Sprint 14A-A3b (P1b emitter contract): every direct run.* evidence row
    # carries the minted ``run_id`` (always) + the scheduler ``task_id`` (nullable
    # — None for pre-submit / refused-outcome paths). These rows are DISTINCT from
    # the store's run.lifecycle.<state> rows (the store-side lifecycle audit);
    # together they give an examiner both the lifecycle trail + the per-terminal
    # output evidence keyed on the same run_id.
    async def _emit_completed(
        self,
        request: RunRequest,
        request_id: str,
        *,
        run_id: str,
        task_id: str | None,
        result: SandboxExecResult,
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.completed",
                request_id=request_id,
                payload={
                    "run_id": run_id,
                    "task_id": task_id,
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
        self,
        request: RunRequest,
        request_id: str,
        *,
        run_id: str,
        task_id: str | None,
        reason: RunFailedReason,
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.failed",
                request_id=request_id,
                payload={"run_id": run_id, "task_id": task_id, "reason": reason},
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

    async def _emit_pending(
        self,
        request: RunRequest,
        request_id: str,
        *,
        run_id: str,
        task_id: str | None,
        approval_request_id: str | None,
    ) -> None:
        await self._dh.append(
            DecisionRecord(
                decision_type="run.pending_approval",
                request_id=request_id,
                payload={
                    "run_id": run_id,
                    "task_id": task_id,
                    "approval_reason": _SANDBOX_APPROVAL_PENDING_REASON,
                    "approval_request_id": approval_request_id,
                },
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

    async def _emit_refused(
        self,
        request: RunRequest,
        request_id: str,
        *,
        run_id: str,
        task_id: str | None,
        reason: str,
    ) -> None:
        # P1b: run.refused ALSO carries run_id + nullable task_id (join key).
        # task_id is None for pack/preflight refusals, the scheduler task id
        # otherwise (the accepted_queued-cancel path).
        await self._dh.append(
            DecisionRecord(
                decision_type="run.refused",
                request_id=request_id,
                payload={
                    "run_id": run_id,
                    "task_id": task_id,
                    "reason": reason,
                    "pack_id": request.pack_id,
                },
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

    async def _emit_suspended(
        self,
        request: RunRequest,
        request_id: str,
        *,
        run_id: str,
        task_id: str | None,
        result: SandboxExecResult,
        session_id: str,
        checkpoint_id: str,
    ) -> None:
        # Sprint 14A-A3b — value-free suspend evidence: the exec output digests +
        # counts PLUS the session_id + checkpoint_id resume correlators.
        await self._dh.append(
            DecisionRecord(
                decision_type="run.suspended",
                request_id=request_id,
                payload={
                    "run_id": run_id,
                    "task_id": task_id,
                    "exit_code": result.exit_code,
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
                    "stdout_bytes": len(result.stdout),
                    "stderr_bytes": len(result.stderr),
                    "session_id": session_id,
                    "checkpoint_id": checkpoint_id,
                },
                actor_id=request.actor.subject,
                tenant_id=request.tenant_id,
                iso_controls=_RUN_EVIDENCE_ISO_CONTROLS,
            )
        )

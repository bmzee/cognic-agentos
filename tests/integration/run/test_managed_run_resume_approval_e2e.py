"""Sprint 14A-A3c — real-docker wake-APPROVAL managed-run e2e. Env-gated;
fail-loud on missing preconditions when opted in, skip-default.

Mirrors the A3b suspend->resume e2e at
``tests/integration/run/test_managed_run_resume_e2e.py`` (real
:class:`DockerSiblingSandboxBackend` + real :class:`RunRecordStore` + ONE real
shared :class:`CheckpointStore`). The single structural addition is a
**stub/conformer approval engine** wired into the backend so the wake path's
``admit_policy`` re-validation hits the ADR-014 approval gate and PENDS on the
first ``resume()``, then GRANTS after an out-of-band flip on the re-``resume()``.

Why a stub engine (NOT a real ``ApprovalEngine``): the managed-run shape is
``read_only`` (see ``ManagedRunExecutor._build_pack_context``), and ``read_only``
auto-tiers under a real engine — ``create_request`` raises
``auto_tier_no_approval_required`` and admission proceeds unverified, so the
pending->grant cycle is never exercised. Driving a HIGH-RISK run shape (the only
way a real engine would pend) is deferred per F4. The conformer is the
legitimate, F4-sanctioned way to exercise the wake-APPROVAL SEAM + the
pending->grant THREADING end-to-end without a high-risk run. This e2e therefore
proves the **wake/resume mechanics + approval-correlator threading**, NOT
real-approval-engine live behaviour (that is the deferred high-risk shape).

THE COLD-CREATE-VS-WAKE SUBTLETY (load-bearing for the conformer design): BOTH
``DockerSiblingSandboxBackend.create()`` (cold create, ``docker_sibling.py``
:1121) AND ``.wake()`` (:2561) call ``admit_policy(..., approval_engine=self.
_approval_engine, approval_request_id=...)``. On a FRESH run both pass
``approval_request_id=None`` -> ``_consult_approval_engine`` Arm A
(``create_request``). A conformer that pended on EVERY admit would therefore pend
the COLD CREATE -> the executor's ``run(suspend_after_exec=True)`` would return
``pending_approval`` and NEVER reach ``suspend()``, so the wake-approval cycle
could not be exercised. The wake leg is the part under test, not the cold-create
approval. The conformer below distinguishes the two Arm-A admits by CALL COUNT:
the 1st ``create_request`` (the cold create) AUTO-ADMITS (raises
``auto_tier_no_approval_required``, exactly as a real engine does for a
``read_only`` tier), and the 2nd+ ``create_request`` (the first resume's wake)
PENDS. The re-resume carries the minted ``approval_request_id`` -> Arm B
(``verify_grant_for_action``) -> ``"granted"`` after the flip. The conformer
mirrors EXACTLY the two methods ``_consult_approval_engine``
(``sandbox/admission.py``) calls:

  * Arm A (request-time ``approval_request_id=None``):
    ``create_request(envelope=...)`` -> a request object with ``.request_id``
    (uuid) + ``.flow``; OR raises ``ApprovalTransitionRefused(
    "auto_tier_no_approval_required")`` for the auto path (the 1st call). When it
    returns a pending request, ``_consult_approval_engine`` raises
    ``SandboxLifecycleRefused("sandbox_approval_pending",
    approval_request_id=str(request.request_id))``. ``wake()`` lets the approval
    family pass through un-rewrapped (``_APPROVAL_WAKE_PASSTHROUGH_REASONS``), so
    the executor sees the pending refusal + the minted id.

  * Arm B (re-resume with the granted ``approval_request_id``):
    ``verify_grant_for_action(request_id=, tenant_id=, expected_args_digest=,
    expected_tool_identity=)`` -> an ``ApprovalCheckResult``-shaped object whose
    ``.state`` is ``"pending"`` BEFORE the flip and ``"granted"`` AFTER (echoing
    the ``expected_*`` digest/identity so the granted result is self-consistent;
    ``_consult_approval_engine`` trusts the engine to have done the binding
    check). On ``"granted"`` it returns True and admission proceeds; ``wake()``
    restores the checkpoint + the run continues.

The "grant flip" is a single in-process flag the test toggles between the two
resume calls — the out-of-band portal grant in production.

Proves the REAL wake-approval vertical:
  run(suspend_after_exec=True) -> DockerSibling create [admit AUTO] -> exec ->
  suspend() [persists __suspend__ checkpoint] -> run row ``suspended``;
  resume() [wake -> admit Arm A -> PENDING] -> run row ``pending_approval`` +
  a 202-shaped RunResult + ``approval_request_id``;
  [flip the conformer to granted];
  resume(approval_request_id=<id>) [wake -> admit Arm B -> GRANTED -> restore]
  -> exec -> run row ``completed``.
Asserts the ``runs`` row walks
``pending -> running -> suspended -> pending_approval -> woken -> completed``
and that the store-side ``run.lifecycle.*`` rows AND the executor-side
``run.suspended`` / ``run.pending_approval`` / ``run.completed`` output-evidence
rows exist.

The catalog cosign + OPA admission are STUBBED allow-everything (the z3 / 14A-A
/ A3b pattern) — the run e2e proves the executor->docker->suspend->wake->approve
path, NOT the cosign/OPA admission stack. The installed pack is a direct
``_packs`` insert (the lifecycle is not under test here). ``vault_addr`` is a
dummy value (the no-creds run never contacts Vault).

Module-level skip BEFORE the SDK imports so the kernel image (no ``adapters``
extra, no aiodocker / hvac) collects this module cleanly when not opted in.
"""

from __future__ import annotations

import os

import pytest

if os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1":
    pytest.skip(
        "real-docker e2e: set COGNIC_RUN_DOCKER_SANDBOX=1 to run",
        allow_module_level=True,
    )

# Opt-in path: plain imports — a missing optional extra MUST fail loud as
# ImportError (NOT importorskip), per the repo integration-test doctrine.
import dataclasses
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import aiodocker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import ApprovalEnvelope, ApprovalTransitionRefused
from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.core.run.executor import ManagedRunExecutor, RunRequest
from cognic_agentos.core.run.storage import RunRecordStore
from cognic_agentos.core.scheduler._types import SubmitInput
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.harness.sandbox import PackRecordStoreLoader
from cognic_agentos.packs.storage import PackRecordStore, _packs
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

_TENANT = "tenant-e2e"
_PACK_ID = "cognic-tool-e2e"


class _AllowQuota:
    async def would_admit(
        self, *, task_id: uuid.UUID, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        return True

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        return None


class _AllowKill:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _Installed:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


async def _allow_policy(_inp: SubmitInput) -> PolicyDecision:
    return PolicyDecision(allow=True, policy_reason=None)


# --- A3c: the stub/conformer approval engine that drives pending->grant -------


@dataclasses.dataclass(frozen=True)
class _ConformerRequest:
    """Minimal ``create_request`` return value — ``_consult_approval_engine``
    Arm A reads ``.request_id`` (the pending correlator) + ``.flow`` (the pending
    detail string). Mirrors :class:`ApprovalRequest`'s read surface."""

    request_id: uuid.UUID
    flow: str


@dataclasses.dataclass(frozen=True)
class _ConformerGrantResult:
    """Minimal ``verify_grant_for_action`` return value — ``_consult_approval_
    engine`` Arm B reads ``.state`` (``"granted"`` admits; anything else -> the
    state->reason map) + ``.flow`` (pending detail). ``.args_digest`` /
    ``.tool_identity`` are present for shape parity with
    :class:`ApprovalCheckResult` (the seam trusts the engine's internal binding
    check rather than re-comparing in Arm B; the real engine raises
    ``approval_binding_mismatch`` itself — this conformer echoes the
    ``expected_*`` values so a granted result is always self-consistent)."""

    state: str
    flow: str
    args_digest: bytes
    tool_identity: str


class _PendingThenGrantApprovalEngine:
    """Test double for :class:`ApprovalEngine` exercising the wake-approval seam
    without a high-risk run (F4 deferred). Only the two methods
    ``_consult_approval_engine`` calls are implemented; the grant-side surface
    (``grant`` / ``deny`` / ...) is irrelevant — the flip stands in for the
    out-of-band portal grant.

    ``create_request`` (Arm A) is CALL-COUNT-aware: the 1st call (the cold
    ``create()`` admit) AUTO-ADMITS by raising
    ``ApprovalTransitionRefused("auto_tier_no_approval_required")`` — exactly what
    a real engine does for a ``read_only`` tier, letting the run reach
    ``suspend()``. The 2nd+ call (the first resume's ``wake()`` admit) returns a
    PENDING request, which the seam turns into ``sandbox_approval_pending``.

    ``verify_grant_for_action`` (Arm B, the re-resume) returns ``"pending"`` until
    :meth:`flip_to_granted` is called, then ``"granted"``. It echoes the
    ``expected_*`` digest/identity (the recomputed admission shape) so the granted
    result is self-consistent — the SAME ``read_only`` admission shape is
    recomputed at re-resume, so the binding holds."""

    def __init__(self) -> None:
        self._granted = False
        self._create_calls = 0
        self._request_id: uuid.UUID | None = None

    def flip_to_granted(self) -> None:
        """Out-of-band 'grant' — toggles ``verify_grant_for_action`` to
        ``"granted"`` between the two resume calls."""
        self._granted = True

    async def create_request(self, *, envelope: ApprovalEnvelope) -> _ConformerRequest:
        self._create_calls += 1
        if self._create_calls == 1:
            # 1st admit = the cold create() — auto-admit so run() reaches
            # suspend() (a real engine auto-tiers the read_only shape identically).
            raise ApprovalTransitionRefused("auto_tier_no_approval_required")
        # 2nd+ admit = the wake() — mint + pend so the executor gets the
        # sandbox_approval_pending passthrough + the minted correlator.
        self._request_id = uuid.uuid4()
        return _ConformerRequest(request_id=self._request_id, flow="require_single_approval")

    async def verify_grant_for_action(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        expected_args_digest: bytes,
        expected_tool_identity: str,
    ) -> _ConformerGrantResult:
        # Arm B: granted after the flip, pending before. Echo the expected
        # digest/identity (the recomputed admission shape) so a granted result is
        # self-consistent. tenant_id is accepted + ignored (single-tenant e2e).
        assert request_id == self._request_id, "re-resume must carry the minted wake id"
        return _ConformerGrantResult(
            state="granted" if self._granted else "pending",
            flow="require_single_approval",
            args_digest=expected_args_digest,
            tool_identity=expected_tool_identity,
        )


async def test_managed_run_wake_pends_then_grants_in_real_container(tmp_path: Path) -> None:
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
    # Pin the runtime image the executor's _build_policy uses to the resolved
    # (possibly env-overridden) image, mirroring the A3b e2e.
    run_settings = settings.model_copy(
        update={"sandbox_canonical_runtime_python_image": runtime_image}
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
            except Exception as exc:
                pytest.fail(f"docker daemon unreachable (opted in via env): {exc}")

        # --- schema + chain heads + a direct installed-pack seed ---
        pack_uuid = uuid.uuid4()
        async with engine.begin() as conn:
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
            await conn.execute(
                _packs.insert().values(
                    id=pack_uuid,
                    kind="tool",
                    pack_id=_PACK_ID,
                    display_name="e2e",
                    state="installed",
                    manifest_digest=b"\x01" * 32,
                    signed_artefact_digest=b"\xab" * 32,
                    sbom_pointer=None,
                    tenant_id=_TENANT,
                    created_by="e2e",
                    last_actor="e2e",
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
            )

        dh_store = DecisionHistoryStore(engine)
        scheduler = SchedulerEngine(
            storage=SchedulerStorage(engine),
            caps=ConcurrencyCaps(
                per_tenant_interactive=4, per_tenant_background=4, per_pack=4, per_actor=4
            ),
            class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},
            quota_interrogator=_AllowQuota(),
            kill_switch_interrogator=_AllowKill(),
            pack_state_interrogator=_Installed(),
            policy_evaluator=_allow_policy,
        )

        # --- ONE real CheckpointStore over a local_fs object store, shared by
        # BOTH the backend (suspend() persists the __suspend__ checkpoint + wake()
        # restores it) AND the executor (the suspend branch's load_latest reads
        # it). SAME instance threaded into both consumers below — a mock store
        # would NOT survive suspend->wake (the backend actually persists +
        # restores tar bytes through this store). Mirrors the A3b e2e. ---
        object_store_root = tmp_path / "object-store"
        object_store_root.mkdir(parents=True, exist_ok=True)
        checkpoint_store = CheckpointStore(
            object_store=LocalObjectStoreAdapter(root=object_store_root),
            audit_store=AuditStore(engine),
            decision_history_store=dh_store,
            settings=settings,
        )

        # --- A3c: the conformer approval engine driving pending->grant. Wired
        # into the backend so wake()'s admit_policy re-validation consults it. The
        # cold create()'s admit consults it too, but the conformer auto-admits the
        # FIRST call (cold create) and pends the SECOND (wake) — see the conformer
        # docstring for the cold-create-vs-wake call-count rationale. ---
        approval_engine = _PendingThenGrantApprovalEngine()

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
            settings=run_settings,
            warm_pool=None,
            egress_proxy_image=egress_proxy_image,
            # the SAME store the executor uses (suspend persists + wake restores).
            checkpoint_store=checkpoint_store,
            # A3c — the wake-approval seam: admit_policy (re-run inside wake())
            # consults this engine + pends on the 2nd admit (the first resume).
            # The arg-type ignore mirrors the established seam-test pattern at
            # tests/unit/sandbox/test_approval_seam.py — the conformer is a
            # duck-typed test double, not an ApprovalEngine subclass.
            approval_engine=approval_engine,  # type: ignore[arg-type]
        )

        run_record_store = RunRecordStore(engine)
        executor = ManagedRunExecutor(
            scheduler=scheduler,
            sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(engine)),
            decision_history_store=dh_store,
            settings=run_settings,
            run_record_store=run_record_store,
            # the SAME CheckpointStore instance the backend uses (the suspend
            # branch calls load_latest on this store).
            checkpoint_store=checkpoint_store,
        )

        actor = Actor(
            subject="svc-e2e", tenant_id=_TENANT, scopes=frozenset(), actor_type="service"
        )

        # --- 1) submit with suspend_after_exec=True -> suspended ---------------
        # The cold create()'s admit is the conformer's 1st create_request call ->
        # auto-admit -> the run reaches suspend(). The run row lands ``suspended``
        # with a session_id + checkpoint_id (the resume substrate).
        suspend_marker = "cognic-14a-a3c-suspend-ok"
        suspended = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", suspend_marker),
                actor=actor,
                suspend_after_exec=True,
            )
        )

        assert suspended.terminal_state == "suspended", suspended
        assert suspended.exit_code == 0
        assert suspend_marker.encode() in suspended.stdout
        assert suspended.run_id  # the resume correlator
        run_id = uuid.UUID(suspended.run_id)

        rec_suspended = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_suspended is not None
        assert rec_suspended.state == "suspended"
        assert rec_suspended.session_id is not None
        assert rec_suspended.checkpoint_id is not None

        # --- 2) first resume() -> wake -> admit Arm A (2nd create_request) ->
        # PENDING -> run row pending_approval + a 202-shaped result + the minted
        # approval_request_id. NO id passed (a fresh first resume). ------------
        pending = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", "ignored-while-pending"),
        )

        assert pending.terminal_state == "pending_approval", pending
        assert pending.exit_code is None
        assert pending.refusal_reason is None
        assert pending.task_id is None  # resume has no scheduler task
        assert pending.run_id == suspended.run_id  # same durable run
        assert pending.approval_request_id is not None  # the re-POST correlator
        approval_request_id = uuid.UUID(pending.approval_request_id)

        rec_pending = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_pending is not None
        assert rec_pending.state == "pending_approval"
        # the run row stored the minted correlator (the no-re-mint guard reads it).
        assert rec_pending.approval_request_id == approval_request_id

        # --- out-of-band grant (the portal approval in production) -------------
        approval_engine.flip_to_granted()

        # --- 3) re-resume(approval_request_id=<id>) -> wake -> admit Arm B
        # (verify_grant_for_action) -> GRANTED -> restore -> exec -> completed --
        resume_marker = "cognic-14a-a3c-resume-ok"
        completed = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", resume_marker),
            approval_request_id=approval_request_id,
        )

        assert completed.terminal_state == "completed", completed
        assert completed.exit_code == 0
        assert resume_marker.encode() in completed.stdout
        assert completed.run_id == suspended.run_id  # same durable run
        assert completed.task_id is None  # resume has no scheduler task

        rec_completed = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_completed is not None
        assert rec_completed.state == "completed"

        # --- 4) chain rows: the run row walked pending->running->suspended->
        # pending_approval->woken->completed (store-side run.lifecycle.*) AND the
        # executor emitted run.suspended + run.pending_approval + run.completed
        # output-evidence rows. ------------------------------------------------
        async with engine.connect() as conn:
            types = [
                r[0]
                for r in (
                    await conn.execute(
                        select(_decision_history.c.event_type).order_by(
                            _decision_history.c.sequence
                        )
                    )
                ).all()
            ]

        # store-side run-lifecycle audit trail (full 6-state walk).
        for lifecycle_event in (
            "run.lifecycle.pending",
            "run.lifecycle.running",
            "run.lifecycle.suspended",
            "run.lifecycle.pending_approval",
            "run.lifecycle.woken",
            "run.lifecycle.completed",
        ):
            assert lifecycle_event in types, types

        # executor-side per-terminal output-evidence rows (DISTINCT family).
        assert "run.suspended" in types, types
        assert "run.pending_approval" in types, types
        assert "run.completed" in types, types

        # scheduler evidence — the suspend leg admitted + completed the task (the
        # scheduler slot is freed at suspend; resume makes NO scheduler calls).
        assert "scheduler.admission_accepted" in types, types
        assert "scheduler.task_completed" in types, types
    finally:
        await docker.close()
        await engine.dispose()

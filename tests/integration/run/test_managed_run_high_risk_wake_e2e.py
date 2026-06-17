"""Sprint 14A-A4c — real-docker high-risk WAKE managed-run e2e. Env-gated;
fail-loud on missing preconditions when opted in, skip-default.

Closes the A3c "F4" caveat FOR THE WAKE PATH ("the wake-approval seam is WIRED
but the production run shape is ``read_only``, which auto-tiers under a real
:class:`ApprovalEngine` and never pends"). A high-risk run runs TWO approval
cycles, BOTH of which pend NATURALLY under a REAL ``ApprovalEngine`` (no
call-count conformer trick is needed — the high-risk tier is NOT auto-run, so
every ``admit_policy`` consult pends until granted):

  CYCLE 1 — cold-create (A4b): ``run(suspend_after_exec=True)`` pends on the
  high-risk tier at the COLD ``create()`` BEFORE exec → ``pending_approval`` +
  ``id1``; the real ``ApprovalEngine.grant(id1)`` by a DISTINCT human holding
  the tier's grant scope flips it to ``granted``; the re-POST (a FRESH ``run()``)
  carrying the granted ``id1`` + ``suspend_after_exec=True`` admits via Arm B →
  exec → ``session.suspend()`` → the durable run SUSPENDS (a NEW ``run_id`` —
  this is the run that suspends + later resumes).

  CYCLE 2 — wake (A3c): ``resume(run_id)`` re-runs ``admit_policy`` against the
  PERSISTED high-risk checkpoint → Arm A mints a fresh pending → the SAME durable
  run walks to ``pending_approval`` + carries ``id2`` (the no-re-mint guard reads
  it off the run row); ``ApprovalEngine.grant(id2)``; the re-resume carrying
  ``id2`` admits via wake Arm B → woken → exec → ``completed``.

``customer_data_read`` classifies to ``require_single_approval`` in
``tools.rego`` — so ONE grant per cycle → ``granted``. The wake's
``approval_request_id`` correlates the WAKE GRANT; the run row is the same
durable run across both resume calls (``resume`` makes NO scheduler call, so
``task_id`` is always ``None`` on resume).

Proves the REAL high-risk WAKE vertical (the F4-wake-closing proof):
  run(suspend_after_exec) [cold create Arm A -> PENDING] -> ``pending_approval`` +
  ``id1``; grant(id1); run(suspend_after_exec, id1) [cold create Arm B -> exec ->
  suspend()] -> ``suspended`` (durable run_id);
  resume(run_id) [wake Arm A -> PENDING] -> ``pending_approval`` + ``id2`` (same
  run); grant(id2); resume(run_id, id2) [wake Arm B -> woken -> exec] ->
  ``completed``.
Asserts the durable run's full 6-state run-lifecycle walk (pending -> running ->
suspended -> pending_approval -> woken -> completed) PLUS the executor-side
per-terminal output-evidence rows (``run.suspended`` + ``run.pending_approval`` +
``run.completed``).

The catalog cosign + sandbox-admission OPA are STUBBED allow-everything (the z3 /
14A-A / A3b / A3c pattern) — the run e2e proves the executor->docker->approve
path, NOT the cosign/OPA admission stack. The APPROVAL engine's OPA (tier->flow
classification) is REAL (it consults ``tools.rego``) — that is the part under
test. The installed pack is a direct ``_packs`` insert PLUS a real
``pack.lifecycle.submitted`` chain row carrying the high-risk manifest (the
loader reads the tier off that row). ``vault_addr`` is a dummy value (the
no-creds run never contacts Vault).

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
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import aiodocker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import ApprovalActor
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.policy import ApprovalPolicy
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.core.policy.engine import OPAEngine
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


async def test_high_risk_wake_pends_then_grants_in_real_container(tmp_path: Path) -> None:
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
    # (possibly env-overridden) image, mirroring the A3b/A3c e2e.
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

        # --- A4b: a real pack.lifecycle.submitted chain row carrying the HIGH-RISK
        # manifest. The loader (PackRecordStoreLoader.load_for_run) reads the tier
        # off find_latest_submit_row(load_lifecycle_history(pack_uuid)) ->
        # payload["manifest"]["risk_tier"]["tier"]. load_lifecycle_history filters
        # event_type LIKE 'pack.lifecycle.%' AND payload["pack_id"] == str(pack_uuid);
        # find_latest_submit_row matches decision_type == "pack.lifecycle.submitted".
        # WITHOUT this row the loader returns risk_tier=None -> the run would NOT be
        # high-risk and would NOT pend (exactly the A3c read_only F4 gap). ---
        await dh_store.append(
            DecisionRecord(
                decision_type="pack.lifecycle.submitted",
                request_id="a4b-high-risk-submit",
                tenant_id=_TENANT,
                actor_id="svc-a",
                payload={
                    "pack_id": str(pack_uuid),
                    "manifest": {
                        "risk_tier": {"tier": "customer_data_read"},
                        "data_governance": {"data_classes": ["customer_pii"]},
                    },
                },
            )
        )

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

        # --- ONE real CheckpointStore over a local_fs object store, threaded into
        # BOTH the backend + the executor. The high-risk cold-create flow does NOT
        # suspend/wake, but the executor + backend still require a real store at
        # construction; reuse the A3b/A3c shared-instance pattern. ---
        object_store_root = tmp_path / "object-store"
        object_store_root.mkdir(parents=True, exist_ok=True)
        audit_store = AuditStore(engine)
        checkpoint_store = CheckpointStore(
            object_store=LocalObjectStoreAdapter(root=object_store_root),
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )

        # --- A4b: a REAL ApprovalEngine (NO conformer). Its policy OPA consults the
        # real tools.rego (customer_data_read -> require_single_approval), so the
        # high-risk cold-create admit genuinely PENDS (Arm A mints a pending
        # request) + a single real grant() flips it to granted (Arm B). ---
        approval_opa = await OPAEngine.create(
            bundle_path=settings.tools_policy_bundle,
            audit_store=audit_store,
            decision_history_store=dh_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        approval_engine = ApprovalEngine(
            policy=ApprovalPolicy(opa_engine=approval_opa),
            store=ApprovalRequestStore(dh_store),
            settings=settings,
            clock=lambda: datetime.now(UTC),
        )

        # --- real DockerSibling backend; catalog + admission-rego STUBBED (z3
        # pattern). The REAL approval_engine is threaded into the SAME slot the A3c
        # conformer occupied — admit_policy's _consult_approval_engine consults it
        # on cold create() (Arm A) + re-POST (Arm B). ---
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
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=run_settings,
            warm_pool=None,
            egress_proxy_image=egress_proxy_image,
            checkpoint_store=checkpoint_store,
            # A4b — the cold-create approval seam: admit_policy consults this REAL
            # engine + pends on the high-risk tier (Arm A), then admits after the
            # real grant (Arm B). NO arg-type ignore — this is a real ApprovalEngine.
            approval_engine=approval_engine,
        )

        run_record_store = RunRecordStore(engine)
        executor = ManagedRunExecutor(
            scheduler=scheduler,
            sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(engine)),
            decision_history_store=dh_store,
            settings=run_settings,
            run_record_store=run_record_store,
            checkpoint_store=checkpoint_store,
        )

        actor = Actor(subject="svc-a", tenant_id=_TENANT, scopes=frozenset(), actor_type="service")

        async def _grant(approval_request_id: uuid.UUID) -> None:
            # the out-of-band human grant (portal approval in production); single-
            # approval tier -> one grant() -> granted; a DISTINCT human holding scope.
            await approval_engine.grant(
                request_id=approval_request_id,
                tenant_id=_TENANT,
                approver=ApprovalActor(
                    subject="rev@bank.example",
                    tenant_id=_TENANT,
                    scopes=frozenset({"tool.approve.customer_data"}),
                    actor_type="human",
                ),
            )

        # === CYCLE 1 — cold-create (A4b): pend -> grant -> re-POST(suspend) -> suspended ===
        # 1a) first run with suspend_after_exec=True. The cold create() pends on the
        #     high-risk tier BEFORE exec (so suspend is never reached) -> pending_approval
        #     + id1. This run_id is abandoned at pending_approval (the re-POST is fresh).
        cold_pending = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4c-suspend"),
                actor=actor,
                suspend_after_exec=True,
            )
        )
        assert cold_pending.terminal_state == "pending_approval", cold_pending
        assert cold_pending.approval_request_id is not None
        await _grant(uuid.UUID(cold_pending.approval_request_id))

        # 1b) re-POST with the granted id1 + suspend_after_exec=True -> cold-create
        #     Arm-B verify -> admit -> exec -> session.suspend() -> SUSPENDED. This is
        #     the durable run that suspends + resumes (a NEW run_id).
        suspended = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4c-suspend"),
                actor=actor,
                suspend_after_exec=True,
                approval_request_id=uuid.UUID(cold_pending.approval_request_id),
            )
        )
        assert suspended.terminal_state == "suspended", suspended
        assert suspended.exit_code == 0
        assert suspended.run_id
        run_id = uuid.UUID(suspended.run_id)
        rec_suspended = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_suspended is not None
        assert rec_suspended.state == "suspended"
        assert rec_suspended.session_id is not None
        assert rec_suspended.checkpoint_id is not None

        # === CYCLE 2 — wake (A3c): resume -> wake pends -> grant -> re-resume -> completed ===
        # 2a) first resume (NO id) -> wake re-runs admit_policy against the persisted
        #     HIGH-RISK checkpoint -> Arm A mints a fresh pending -> pending_approval + id2.
        wake_pending = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", "ignored-while-pending"),
        )
        assert wake_pending.terminal_state == "pending_approval", wake_pending
        assert wake_pending.run_id == suspended.run_id  # same durable run
        assert wake_pending.task_id is None  # resume makes no scheduler call
        assert wake_pending.approval_request_id is not None
        wake_id = uuid.UUID(wake_pending.approval_request_id)
        rec_pending = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_pending is not None
        assert rec_pending.state == "pending_approval"
        assert rec_pending.approval_request_id == wake_id  # the no-re-mint guard reads it

        # 2b) grant id2, then re-resume carrying it -> wake Arm-B verify -> woken -> exec
        #     -> COMPLETED.
        await _grant(wake_id)
        resume_marker = "cognic-14a-a4c-resume-ok"
        completed = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", resume_marker),
            approval_request_id=wake_id,
        )
        assert completed.terminal_state == "completed", completed
        assert completed.exit_code == 0
        assert resume_marker.encode() in completed.stdout
        assert completed.run_id == suspended.run_id
        rec_completed = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_completed is not None
        assert rec_completed.state == "completed"

        # === chain rows: the durable run walked the full high-risk wake path ===
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
        # store-side run-lifecycle audit trail — the suspending run's full 6-state
        # walk (pending -> running -> suspended -> pending_approval -> woken ->
        # completed); all six exist in the chain (run_B walks the full path).
        for lifecycle_event in (
            "run.lifecycle.pending",
            "run.lifecycle.running",
            "run.lifecycle.suspended",
            "run.lifecycle.pending_approval",
            "run.lifecycle.woken",
            "run.lifecycle.completed",
        ):
            assert lifecycle_event in types, types
        # executor-side per-terminal output-evidence rows.
        assert "run.suspended" in types, types
        assert "run.pending_approval" in types, types
        assert "run.completed" in types, types
    finally:
        await docker.close()
        await engine.dispose()

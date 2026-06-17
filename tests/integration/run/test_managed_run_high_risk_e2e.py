"""Sprint 14A-A4b — real-docker COLD-CREATE high-risk managed-run e2e. Env-gated;
fail-loud on missing preconditions when opted in, skip-default.

Closes the A3c "F4" caveat ("the wake-approval seam is WIRED but the production
run shape is ``read_only``, which auto-tiers under a real :class:`ApprovalEngine`
and never pends"). Sprint 14A-A4b T1-T4 wired the executor to thread a pack's
*validated manifest risk tier* into BOTH the scheduler submit (the A4a
``approval_delegated_to="sandbox_admission"`` affordance) AND the sandbox
``PackAdmissionContext``. This e2e proves the resulting HIGH-RISK cold-create run
genuinely PENDS under a REAL ``ApprovalEngine`` — then grants → re-POST →
completes — i.e. the production ``POST /api/v1/runs`` path, NO stub/conformer, NO
suspend→wake.

Unlike the A3c wake e2e (which needs a CALL-COUNT-aware conformer to auto-admit
the cold create + pend only the wake), this run is high-risk FROM THE COLD
CREATE: the loader reads ``risk_tier="customer_data_read"`` off the pack's submit
manifest, the executor delegates to the sandbox seam, and ``admit_policy``'s
``_consult_approval_engine`` Arm A (request-time, ``approval_request_id=None``)
hits the REAL engine → ``create_request`` mints a pending request (the tier is NOT
auto-run) → ``SandboxLifecycleRefused("sandbox_approval_pending", ...)`` → the
executor cancels the scheduler task + walks the run row to ``pending_approval`` +
returns a 202-shaped ``RunResult`` carrying the minted ``approval_request_id``.

The out-of-band human grant (the portal approval in production) is a real
``ApprovalEngine.grant(...)`` by a DISTINCT human holding the tier's grant scope
(``tool.approve.customer_data``). ``customer_data_read`` classifies to
``require_single_approval`` in ``tools.rego`` — so ONE grant → ``granted``.

The re-POST is a FRESH ``run()`` (new ``run_id``) carrying the granted
``approval_request_id``. ``_consult_approval_engine`` Arm B
(``verify_grant_for_action``) sees the granted state + the matching binding →
admission proceeds → exec → ``completed``. The ``approval_request_id`` correlates
the GRANT, NOT the run — so this e2e does NOT assert run_id equality across the
two ``run()`` calls.

Proves the REAL cold-create high-risk vertical:
  run() [submit -> scheduler admit (delegated) -> DockerSibling create -> admit
  Arm A -> PENDING] -> run row ``pending_approval`` + a 202-shaped RunResult +
  ``approval_request_id``;
  [real ApprovalEngine.grant by a distinct human with the tier scope];
  run(approval_request_id=<id>) [submit -> scheduler admit (delegated) ->
  DockerSibling create -> admit Arm B -> GRANTED -> exec] -> run row ``completed``.
Asserts both run-evidence rows exist (``run.pending_approval`` for the cold-create
pend + ``run.completed`` for the granted completion).

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


async def test_high_risk_run_pends_then_grants_in_real_container(tmp_path: Path) -> None:
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

        # 1) cold-create high-risk run -> GENUINE Arm-A pend under the real engine
        #    (the production POST /api/v1/runs path; NO suspend_after_exec, NO stub,
        #    NO bypass).
        pending = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4b"),
                actor=actor,
            )
        )
        assert pending.terminal_state == "pending_approval", pending
        assert pending.approval_request_id is not None

        # 2) out-of-band human grant (the portal approval in production). single-approval
        #    tier -> one grant() -> granted; approver is a DISTINCT human holding the tier scope.
        await approval_engine.grant(
            request_id=uuid.UUID(pending.approval_request_id),
            tenant_id=_TENANT,
            approver=ApprovalActor(
                subject="rev@bank.example",
                tenant_id=_TENANT,
                scopes=frozenset({"tool.approve.customer_data"}),
                actor_type="human",
            ),
        )

        # 3) re-POST with the granted id -> cold-create admit Arm-B verify -> exec -> completed.
        completed = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4b"),
                actor=actor,
                approval_request_id=uuid.UUID(pending.approval_request_id),
            )
        )
        assert completed.terminal_state == "completed", completed
        assert completed.exit_code == 0

        # 4) both run-evidence rows exist (cold-create pend + the granted completion).
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
        assert "run.pending_approval" in types, types
        assert "run.completed" in types, types
    finally:
        await docker.close()
        await engine.dispose()

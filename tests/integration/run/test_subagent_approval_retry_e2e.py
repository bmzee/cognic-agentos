"""Sprint 2026-06-20 (ADR-005 + ADR-020) — sub-agent child approval-retry e2e.
Env-gated; fail-loud on missing preconditions when opted in, skip-default.

Opt-in: COGNIC_RUN_DOCKER_SANDBOX=1. Preconditions (fail loud, not skip):
  * a reachable docker daemon (the sibling docker.sock);
  * a runnable runtime image (COGNIC_14A_A_RUNTIME_IMAGE, else
    settings.sandbox_canonical_runtime_python_image) — must be inspectable;
  * a runnable egress-proxy image (COGNIC_14A_A_EGRESS_PROXY_IMAGE, else
    settings.sandbox_canonical_egress_proxy_image) — the DockerSibling topology
    always launches the egress sidecar.

Proves the child approval-retry vertical end-to-end on the LIVE SubAgentSpawner:
a HIGH-RISK child sub-agent (manifest ``risk_tier == "customer_data_read"``)
PENDS at sandbox cold-create under a REAL ``ApprovalEngine`` -> the spawner
returns a ``SubAgentResult`` whose ``child_result.terminal_state ==
"pending_approval"`` carrying the minted ``approval_request_id``; the parent
chain records an HONEST ``subagent.return(outcome="pending_approval")`` (carrying
the ids) and SKIPS the ``subagent.budget`` row (zero work to account for). An
out-of-band human grant (the portal approval in production) then flips the
request to ``granted``, and a re-spawn of the SAME child spec carrying the
granted ``approval_request_id`` admits + execs + completes -> a FRESH
``subagent.spawn -> subagent.return(outcome="completed")`` + a ``subagent.budget``
row.

This harness is COPIED + COMBINED from the two proven real-docker bases:

  * ``test_managed_run_subagent_e2e.py`` (the Fork-B live-dispatch e2e) — the
    module-level skip-before-SDK-imports guard, the allow-everything scheduler
    stubs, the ``build_subagent_spawner`` composition, the ``_RuntimeStub``, the
    direct installed-pack ``_packs`` seed, the seeded RUNNING parent + the real
    ``SchedulerTaskParentBudgetResolver`` (so the child has a realistic parent
    context + an inherited budget ceiling), and the ``spawner.spawn(...)`` call
    shape. We spawn via the spawner DIRECTLY — the route's 202 mapping is
    unit-tested in T5; this e2e proves the real
    spawner -> runner -> executor -> sandbox-cold-create -> ApprovalEngine ->
    retry path + the audit chain.
  * ``test_managed_run_high_risk_e2e.py`` (the 14A-A4b cold-create high-risk
    e2e) — the HIGH-RISK ``pack.lifecycle.submitted`` manifest tier
    (``customer_data_read`` + ``data_governance.data_classes``), the REAL
    ``ApprovalEngine`` (NO conformer; its policy OPA consults the real
    ``tools.rego`` so ``customer_data_read -> require_single_approval`` genuinely
    pends), the ``CheckpointStore`` over a ``local_fs`` object store threaded
    into BOTH the backend + the executor, the ``AuditStore``, and the real
    ``grant()`` by a DISTINCT human holding the tier grant scope
    (``tool.approve.customer_data`` -> one grant -> ``granted``).

The catalog cosign + sandbox-admission OPA are STUBBED allow-everything (the z3 /
14A-A / A4b pattern) — this e2e proves the spawner->runner->executor->docker->
approve->retry path, NOT the cosign/OPA admission stack. The APPROVAL engine's
OPA (tier->flow classification) is REAL — that is the part under test.

The child argv is a real exit-0 command (``printf``) so a granted child genuinely
completes (``ok is True``) against a real container.

NOTE (the retry data-flow this e2e exercises): on the re-spawn, the granted id
rides ``SubAgentSpawnRequest.approval_request_id`` and MUST reach
``RunRequest.approval_request_id`` (the path
``SubAgentSpawnRequest -> ChildRunContext -> ManagedRunChildRunner ->
RunRequest``) so the sandbox ``admit_policy`` Arm B verifies the grant and the
child completes instead of pending again. This is the FIRST test that exercises
that full threading on the real spawner path (the unit tests set
``ChildRunContext.approval_request_id`` directly or stub the spawner).

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
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import aiodocker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
from cognic_agentos.core.run.executor import ManagedRunExecutor
from cognic_agentos.core.run.storage import RunRecordStore
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.budget_resolver import SchedulerTaskParentBudgetResolver
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.harness.sandbox import PackRecordStoreLoader, build_subagent_spawner
from cognic_agentos.packs.storage import PackRecordStore, _packs
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from cognic_agentos.subagent._types import ManagedRunChildSpec, SubAgentSpawnRequest

_TENANT = "tenant-subagent-approval-retry-e2e"
_PACK_ID = "cognic-tool-subagent-approval-retry-e2e"
_PACK_VERSION = "1.0.0"
#: The parent's granted ceiling (N). Deliberately < the child's request below so
#: the child inherits the narrowed budget — a realistic parent context (the
#: budget-inheritance PROOF itself is the sibling test_managed_run_subagent_e2e).
_PARENT_TOKENS = 120
_CHILD_REQUESTED_TOKENS = 200
#: A real exit-0 command for the child container (the proven `printf`).
_CHILD_ARGV = ("printf", "subagent-approval-retry-ok")
#: The high-risk tier that classifies to require_single_approval in tools.rego
#: (so cold-create genuinely PENDS under a real ApprovalEngine) + its grant scope.
_HIGH_RISK_TIER = "customer_data_read"
_GRANT_SCOPE = "tool.approve.customer_data"


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


class _RuntimeStub:
    """Minimal Runtime stand-in for build_subagent_spawner, which reads ONLY
    ``runtime.decision_history_store`` (the audit emitter's history backend)."""

    def __init__(self, *, decision_history_store: DecisionHistoryStore) -> None:
        self.decision_history_store = decision_history_store


async def _seed_running_parent(engine: AsyncEngine, *, tokens: int) -> uuid.UUID:
    """Seed a RUNNING parent scheduler task granted ``tokens`` via the real
    SchedulerStorage submit -> transition path. tenant_id == _TENANT so the
    tenant-scoped resolver finds it; RUNNING is non-terminal so the resolver
    confers its granted budget."""
    store = SchedulerStorage(engine)
    task_id = uuid.uuid4()
    await store.submit(
        task_id=task_id,
        submit_input=SubmitInput(
            tenant_id=_TENANT,
            pack_id=_PACK_ID,
            actor=TaskActor(subject="svc-parent", tenant_id=_TENANT, actor_type="service"),
            class_="interactive",
            pack_kind="tool",
            pack_risk_tier="internal_write",
            requested_estimated_tokens=tokens,
        ),
        request_id=f"seed-parent-{task_id}",
    )
    await store.transition(
        task_id=task_id,
        from_state="pending",
        to_state="running",
        actor_id="seed",
        request_id=f"seed-parent-run-{task_id}",
        payload_extras={},
    )
    return task_id


async def _payloads_by_type(engine: AsyncEngine, event_type: str) -> list[dict[str, Any]]:
    """Return the decision_history payloads of a given ``event_type``, oldest
    first. The persisted chain column is ``event_type`` (the DecisionRecord's
    ``decision_type``); ``DecisionHistoryStore.append`` merges ``actor_id`` into
    the persisted payload, so callers assert specific keys, not the whole dict."""
    async with engine.connect() as conn:
        rows = (
            await conn.execute(
                select(_decision_history.c.payload)
                .where(_decision_history.c.event_type == event_type)
                .order_by(_decision_history.c.sequence)
            )
        ).all()
    return [row.payload for row in rows]


async def test_high_risk_subagent_child_pends_then_grants_then_completes(
    tmp_path: Path,
) -> None:
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
    # (possibly env-overridden) image, mirroring the high-risk e2e.
    run_settings = settings.model_copy(
        update={"sandbox_canonical_runtime_python_image": runtime_image}
    )

    docker = aiodocker.Docker()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'subagent-approval-retry.db'}")
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
                    display_name="subagent-approval-retry-e2e",
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

        # --- a real pack.lifecycle.submitted chain row carrying the HIGH-RISK
        # manifest. PackRecordStoreLoader.load_for_run reads the tier off
        # find_latest_submit_row(load_lifecycle_history(pack_uuid)) ->
        # payload["manifest"]["risk_tier"]["tier"]. WITHOUT this row the loader
        # returns risk_tier=None and the A4b executor gate (_validate_pack_record)
        # REFUSES with pack_record_risk_tier_unresolved. customer_data_read is
        # HIGH-RISK (require_single_approval), so the child cold-create PENDS. ---
        await dh_store.append(
            DecisionRecord(
                decision_type="pack.lifecycle.submitted",
                request_id="subagent-approval-retry-submit",
                tenant_id=_TENANT,
                actor_id="svc-a",
                payload={
                    "pack_id": str(pack_uuid),
                    "manifest": {
                        "risk_tier": {"tier": _HIGH_RISK_TIER},
                        "data_governance": {"data_classes": ["customer_pii"]},
                    },
                },
            )
        )

        # --- seed a RUNNING parent scheduler task granted N tokens; the child
        # inherits min(child_request, parent_grant) (a realistic parent context). ---
        parent_id = await _seed_running_parent(engine, tokens=_PARENT_TOKENS)

        # --- scheduler WITH the real parent-budget resolver (the budget authority) ---
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
            parent_budget_resolver=SchedulerTaskParentBudgetResolver(
                reader=SchedulerStorage(engine)
            ),
        )

        # --- ONE real CheckpointStore over a local_fs object store, threaded into
        # BOTH the backend + the executor. The high-risk cold-create flow does NOT
        # suspend/wake, but the executor + backend still require a real store at
        # construction; reuse the high-risk e2e's shared-instance pattern. ---
        object_store_root = tmp_path / "object-store"
        object_store_root.mkdir(parents=True, exist_ok=True)
        audit_store = AuditStore(engine)
        checkpoint_store = CheckpointStore(
            object_store=LocalObjectStoreAdapter(root=object_store_root),
            audit_store=audit_store,
            decision_history_store=dh_store,
            settings=settings,
        )

        # --- a REAL ApprovalEngine (NO conformer). Its policy OPA consults the
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
        # pattern). The REAL approval_engine is threaded into the approval seam —
        # admit_policy's _consult_approval_engine consults it on cold create()
        # (Arm A pends) + re-POST with the granted id (Arm B admits). ---
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
            approval_engine=approval_engine,
        )

        executor = ManagedRunExecutor(
            scheduler=scheduler,
            sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(engine)),
            decision_history_store=dh_store,
            settings=run_settings,
            run_record_store=RunRecordStore(engine),
            checkpoint_store=checkpoint_store,
        )

        # --- compose the live SubAgentSpawner (child-is-a-managed-run) ---
        spawner = build_subagent_spawner(
            runtime=cast(Any, _RuntimeStub(decision_history_store=dh_store)),
            managed_run_executor=executor,
            engine=engine,
            settings=settings,
        )

        def _request(*, approval_request_id: str | None = None) -> SubAgentSpawnRequest:
            return SubAgentSpawnRequest(
                prompt="run the high-risk child as a managed run",
                parent_tool_allow_list=frozenset(),
                requested_tool_allow_list=frozenset(),
                current_depth=0,
                requested_estimated_tokens=_CHILD_REQUESTED_TOKENS,
                tenant_id=_TENANT,
                parent_task_id=str(parent_id),
                approval_request_id=approval_request_id,
            )

        managed_run = ManagedRunChildSpec(
            pack_id=_PACK_ID, pack_version=_PACK_VERSION, argv=_CHILD_ARGV
        )
        actor = Actor(
            subject="svc-subagent", tenant_id=_TENANT, scopes=frozenset(), actor_type="service"
        )

        # 1) HIGH-RISK child spawn -> GENUINE Arm-A pend under the real engine.
        pending = await spawner.spawn(
            request=_request(),
            managed_run=managed_run,
            actor=actor,
            parent_trace_id="trace-subagent-approval-retry",
        )
        assert pending.child_result.terminal_state == "pending_approval", pending.child_result
        assert pending.child_result.ok is False
        assert pending.child_result.run_id is not None
        appr_id = pending.child_result.approval_request_id
        assert appr_id is not None

        # (a) the parent chain records an HONEST pending return carrying the ids,
        #     and SKIPS the budget row entirely (zero work to account for).
        returns_after_pend = await _payloads_by_type(engine, "subagent.return")
        assert len(returns_after_pend) == 1, returns_after_pend
        assert returns_after_pend[0]["outcome"] == "pending_approval"
        assert returns_after_pend[0]["approval_request_id"] == appr_id
        assert returns_after_pend[0]["run_id"] == pending.child_result.run_id
        assert await _payloads_by_type(engine, "subagent.budget") == []
        assert len(await _payloads_by_type(engine, "subagent.spawn")) == 1

        # 2) out-of-band human grant (the portal approval in production). single-approval
        #    tier -> one grant() -> granted; approver is a DISTINCT human with the tier scope.
        await approval_engine.grant(
            request_id=uuid.UUID(appr_id),
            tenant_id=_TENANT,
            approver=ApprovalActor(
                subject="rev@bank.example",
                tenant_id=_TENANT,
                scopes=frozenset({_GRANT_SCOPE}),
                actor_type="human",
            ),
        )

        # 3) re-spawn the SAME child spec carrying the granted approval_request_id
        #    -> the id threads request -> ChildRunContext -> runner -> RunRequest ->
        #    admit_policy Arm-B verify -> exec -> completed.
        completed = await spawner.spawn(
            request=_request(approval_request_id=appr_id),
            managed_run=managed_run,
            actor=actor,
            parent_trace_id="trace-subagent-approval-retry",
        )
        assert completed.child_result.terminal_state == "completed", completed.child_result
        assert completed.child_result.ok is True

        # (b) a FRESH subagent.spawn (now 2) + a completed subagent.return (now 2,
        #     the newest "completed", with NO conditional pending ids) + a
        #     subagent.budget row (now 1 — the completed child's work IS accounted).
        assert len(await _payloads_by_type(engine, "subagent.spawn")) == 2
        returns_after_complete = await _payloads_by_type(engine, "subagent.return")
        assert len(returns_after_complete) == 2, returns_after_complete
        assert returns_after_complete[-1]["outcome"] == "completed"
        assert "approval_request_id" not in returns_after_complete[-1]
        assert "run_id" not in returns_after_complete[-1]
        assert len(await _payloads_by_type(engine, "subagent.budget")) == 1
    finally:
        await docker.close()
        await engine.dispose()

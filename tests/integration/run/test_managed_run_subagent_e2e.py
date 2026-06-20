"""Sprint 2026-06-20 (ADR-005 + ADR-022) — live sub-agent dispatch e2e
(child-is-a-managed-run). Env-gated; fail-loud on missing preconditions when
opted in, skip-default.

Opt-in: COGNIC_RUN_DOCKER_SANDBOX=1. Preconditions (fail loud, not skip):
  * a reachable docker daemon (the sibling docker.sock);
  * a runnable runtime image (COGNIC_14A_A_RUNTIME_IMAGE, else
    settings.sandbox_canonical_runtime_python_image) — must be inspectable;
  * a runnable egress-proxy image (COGNIC_14A_A_EGRESS_PROXY_IMAGE, else
    settings.sandbox_canonical_egress_proxy_image) — the DockerSibling topology
    always launches the egress sidecar.

Proves the FIRST production sub-agent dispatch path: the live SubAgentSpawner
narrows privilege + audits + delegates to the ManagedRunChildRunner, which
adapts the child into a governed managed run on the REAL executor ->
DockerSiblingSandboxBackend -> real container exec -> capture ->
scheduler.complete. The scheduler is the single budget authority — a seeded
parent task's granted ceiling narrows the child's requested budget via the real
SchedulerTaskParentBudgetResolver.

This harness is COPIED from ``test_managed_run_e2e.py`` (the 14A-A managed-run
e2e) — same module-level skip-before-SDK-imports guard, same allow-everything
stubs, same real DockerSibling backend, same direct ``_packs`` install seed.
TWO additions beyond that harness, both required for a correct sub-agent proof:

  1. A real ``pack.lifecycle.submitted`` chain row carrying a SAFE-tier manifest
     (``risk_tier.tier == "internal_write"``). The 14A-A4b executor gate
     (``_validate_pack_record``) REFUSES a pack whose risk tier is unresolved,
     and ``PackRecordStoreLoader.load_for_run`` reads the tier off the latest
     submit chain row's ``payload["manifest"]``. A direct ``_packs`` insert
     alone (as in the pre-A4b ``test_managed_run_e2e.py`` harness) yields
     ``risk_tier=None`` -> the child would be REFUSED, not completed. A SAFE
     tier (not a high-risk one) keeps the run on the auto/non-pending path so it
     completes. This mirrors ``test_managed_run_high_risk_e2e.py``'s submit-row
     seed (which uses a high-risk tier to PEND on purpose).
  2. A seeded RUNNING parent scheduler task granted ``_PARENT_TOKENS`` + the
     real ``SchedulerTaskParentBudgetResolver`` wired into the scheduler, so the
     child's larger requested budget is narrowed to the parent's grant
     (``min(child_request, parent_grant)``) — the budget-inheritance proof.

The child argv is a real exit-0 command (``printf``) — the working command the
copied harness uses — so ``result.child_result.ok is True`` actually holds
against a real container. (The plan's illustrative ``argv=("--run",)`` is a
placeholder shape from the unit tests; it is not a runnable command and would
not exit 0.)

Module-level skip BEFORE the SDK imports so the kernel image (no ``adapters``
extra, no aiodocker) collects this module cleanly when not opted in.
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

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.core.run.executor import ManagedRunExecutor
from cognic_agentos.core.run.storage import RunRecordStore, _runs
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.core.scheduler.budget_resolver import SchedulerTaskParentBudgetResolver
from cognic_agentos.core.scheduler.engine import PolicyDecision, SchedulerEngine
from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
from cognic_agentos.core.scheduler.storage import SchedulerStorage
from cognic_agentos.harness.sandbox import PackRecordStoreLoader, build_subagent_spawner
from cognic_agentos.packs.storage import PackRecordStore, _packs
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.subagent._types import ManagedRunChildSpec, SubAgentSpawnRequest

_TENANT = "tenant-subagent-e2e"
_PACK_ID = "cognic-tool-subagent-e2e"
_PACK_VERSION = "1.0.0"
#: The parent's granted ceiling (N). Deliberately < the child's request below so
#: the budget narrowing visibly fires: the child requests 200 but inherits 120.
_PARENT_TOKENS = 120
_CHILD_REQUESTED_TOKENS = 200
#: A real exit-0 command for the child container (the copied harness's `printf`).
_CHILD_ARGV = ("printf", "subagent-child-ok")


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
    ``runtime.decision_history_store`` (the audit emitter's history backend). The
    14A-A harness builds the chain store by hand rather than via build_runtime,
    so a full Runtime is unnecessary here."""

    def __init__(self, *, decision_history_store: DecisionHistoryStore) -> None:
        self.decision_history_store = decision_history_store


async def _seed_running_parent(engine: AsyncEngine, *, tokens: int) -> uuid.UUID:
    """Seed a RUNNING parent scheduler task granted ``tokens`` via the real
    SchedulerStorage submit -> transition path (mirrors the engine test's
    ``_seed_parent``). tenant_id == _TENANT so the tenant-scoped resolver finds
    it; RUNNING is non-terminal so the resolver confers its granted budget."""
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


async def test_subagent_dispatch_runs_child_as_managed_run_with_inherited_budget(
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

    docker = aiodocker.Docker()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'subagent-e2e.db'}")
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
                    display_name="subagent-e2e",
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

        # --- A4b: a real pack.lifecycle.submitted chain row carrying a SAFE-tier
        # manifest. PackRecordStoreLoader.load_for_run reads the tier off
        # find_latest_submit_row(load_lifecycle_history(pack_uuid)) ->
        # payload["manifest"]["risk_tier"]["tier"]. WITHOUT this row the loader
        # returns risk_tier=None and the A4b executor gate (_validate_pack_record)
        # REFUSES with pack_record_risk_tier_unresolved. internal_write is SAFE
        # (no approval pend), so the child run completes. ---
        await dh_store.append(
            DecisionRecord(
                decision_type="pack.lifecycle.submitted",
                request_id="subagent-e2e-submit",
                tenant_id=_TENANT,
                actor_id="svc-a",
                payload={
                    "pack_id": str(pack_uuid),
                    "manifest": {"risk_tier": {"tier": "internal_write"}},
                },
            )
        )

        # --- seed a RUNNING parent scheduler task granted N tokens; its granted
        # ceiling is what the child's larger request narrows to. ---
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
            # The non-suspend child run never calls load_latest, so the checkpoint
            # store is a never-invoked mock here (matches the 14A-A harness).
            run_record_store=RunRecordStore(engine),
            checkpoint_store=MagicMock(),
        )

        # --- compose the live SubAgentSpawner (child-is-a-managed-run) ---
        spawner = build_subagent_spawner(
            runtime=cast(Any, _RuntimeStub(decision_history_store=dh_store)),
            managed_run_executor=executor,
            engine=engine,
            settings=settings,
        )

        result = await spawner.spawn(
            request=SubAgentSpawnRequest(
                prompt="run the child as a managed run",
                parent_tool_allow_list=frozenset(),
                requested_tool_allow_list=frozenset(),
                current_depth=0,
                requested_estimated_tokens=_CHILD_REQUESTED_TOKENS,
                tenant_id=_TENANT,
                parent_task_id=str(parent_id),
            ),
            managed_run=ManagedRunChildSpec(
                pack_id=_PACK_ID, pack_version=_PACK_VERSION, argv=_CHILD_ARGV
            ),
            actor=Actor(
                subject="svc-subagent", tenant_id=_TENANT, scopes=frozenset(), actor_type="service"
            ),
            parent_trace_id="trace-subagent",
        )

        # (a) the child sub-agent run completed.
        assert result.child_result.ok is True, result.child_result

        # (b) a runs run-record row exists for the child managed run (exactly one;
        # the parent was seeded into scheduler_tasks, not runs).
        async with engine.connect() as conn:
            run_rows = (
                await conn.execute(
                    select(_runs.c.run_id, _runs.c.state)
                    .where(_runs.c.tenant_id == _TENANT)
                    .where(_runs.c.pack_id == _PACK_ID)
                )
            ).all()
        assert len(run_rows) == 1, run_rows
        assert run_rows[0].state == "completed"

        # (c) the child's scheduler.admission_accepted chain row carries the
        # INHERITED budget min(child_request, parent_grant). The seeded parent's
        # admission row carries parent_task_id=None; only the child's carries
        # str(parent_id), so filter by it.
        async with engine.connect() as conn:
            accepted = (
                await conn.execute(
                    select(_decision_history.c.payload).where(
                        _decision_history.c.event_type == "scheduler.admission_accepted"
                    )
                )
            ).all()
        child_rows = [
            row.payload for row in accepted if row.payload.get("parent_task_id") == str(parent_id)
        ]
        assert len(child_rows) == 1, child_rows
        assert child_rows[0]["requested_estimated_tokens"] == min(
            _CHILD_REQUESTED_TOKENS, _PARENT_TOKENS
        )
    finally:
        await docker.close()
        await engine.dispose()

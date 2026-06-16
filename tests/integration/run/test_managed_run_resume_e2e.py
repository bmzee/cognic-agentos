"""Sprint 14A-A3b — real-docker suspend->resume managed-run e2e. Env-gated;
fail-loud on missing preconditions when opted in, skip-default.

Mirrors the 14A-A e2e at ``tests/integration/run/test_managed_run_e2e.py``;
the ONE structural difference is a REAL shared :class:`CheckpointStore` (over a
``local_fs`` :class:`LocalObjectStoreAdapter` rooted under ``tmp_path``) wired
into BOTH the backend (so ``suspend()``'s final ``__suspend__`` checkpoint
persists) AND the executor (so the suspend branch's ``load_latest`` resolves the
checkpoint metadata, and ``resume()`` -> ``backend.wake`` restores it). This is
the single-shared-store composition the ``app.py`` lifespan does (see
``_build_checkpoint_store_from_adapters`` + the 14A-A3b sandbox-runtime block).

Opt-in: COGNIC_RUN_DOCKER_SANDBOX=1. Preconditions (fail loud, not skip):
  * a reachable docker daemon (the sibling docker.sock);
  * a runnable runtime image (COGNIC_14A_A_RUNTIME_IMAGE, else
    settings.sandbox_canonical_runtime_python_image) — must be inspectable;
  * a runnable egress-proxy image (COGNIC_14A_A_EGRESS_PROXY_IMAGE, else
    settings.sandbox_canonical_egress_proxy_image) — the DockerSibling topology
    always launches the egress sidecar.

Proves the REAL resumable-session vertical:
  submit(suspend_after_exec=True) -> real DockerSibling create -> exec ->
  session.suspend() [persists __suspend__ checkpoint] -> run row suspended;
  then resume(run_id, argv) -> backend.wake() [restores the checkpoint] ->
  exec -> complete. Asserts the ``runs`` row walks
  ``pending -> running -> suspended -> woken -> completed`` and that both the
  store-side ``run.lifecycle.*`` rows AND the executor-side
  ``run.suspended`` / ``run.completed`` output-evidence rows exist.

The catalog cosign + OPA admission are STUBBED allow-everything (the same
pattern the 14A-A e2e + z3 docker integration test use) — the run e2e proves
the executor->docker->suspend->wake path, NOT the cosign/OPA admission stack
(covered by the sandbox integration tests). The installed pack is a direct
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
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import aiodocker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine

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


async def test_managed_run_suspends_then_resumes_in_real_container(tmp_path: Path) -> None:
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
    # (possibly env-overridden) image, mirroring the 14A-A e2e.
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

        # --- A3b: ONE real CheckpointStore over a local_fs object store, shared
        # by BOTH the backend (suspend() persists the __suspend__ checkpoint)
        # AND the executor (the suspend branch + resume()/wake() read it). This
        # mirrors app.py's _build_checkpoint_store_from_adapters single-store
        # composition. SAME instance threaded into both consumers below — a
        # mock checkpoint store would NOT survive suspend->wake (the backend
        # actually persists + restores tar bytes through this store). ---
        object_store_root = tmp_path / "object-store"
        object_store_root.mkdir(parents=True, exist_ok=True)
        checkpoint_store = CheckpointStore(
            object_store=LocalObjectStoreAdapter(root=object_store_root),
            audit_store=AuditStore(engine),
            decision_history_store=dh_store,
            settings=settings,
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
            settings=run_settings,
            warm_pool=None,
            egress_proxy_image=egress_proxy_image,
            # A3b — the SAME store the executor uses (suspend persists here).
            checkpoint_store=checkpoint_store,
        )

        run_record_store = RunRecordStore(engine)
        executor = ManagedRunExecutor(
            scheduler=scheduler,
            sandbox_backend=backend,
            pack_loader=PackRecordStoreLoader(store=PackRecordStore(engine)),
            decision_history_store=dh_store,
            settings=run_settings,
            run_record_store=run_record_store,
            # A3b — the SAME CheckpointStore instance the backend uses (the
            # suspend branch calls load_latest on this store).
            checkpoint_store=checkpoint_store,
        )

        actor = Actor(
            subject="svc-e2e", tenant_id=_TENANT, scopes=frozenset(), actor_type="service"
        )

        # --- 1) submit with suspend_after_exec=True -> suspended ---
        suspend_marker = "cognic-14a-a3b-suspend-ok"
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

        # The run row is durably ``suspended`` with a session_id + checkpoint_id.
        rec_suspended = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_suspended is not None
        assert rec_suspended.state == "suspended"
        assert rec_suspended.session_id is not None
        assert rec_suspended.checkpoint_id is not None

        # --- 2) resume(run_id, argv) -> wake + exec continuation -> completed ---
        resume_marker = "cognic-14a-a3b-resume-ok"
        completed = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", resume_marker),
        )

        assert completed.terminal_state == "completed", completed
        assert completed.exit_code == 0
        assert resume_marker.encode() in completed.stdout
        assert completed.run_id == suspended.run_id  # same durable run

        # The run row is now ``completed``.
        rec_completed = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_completed is not None
        assert rec_completed.state == "completed"

        # --- 3) chain rows: the run row walked pending->running->suspended->
        # woken->completed (store-side run.lifecycle.*) AND the executor emitted
        # run.suspended + run.completed output-evidence rows. ---
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

        # store-side run-lifecycle audit trail (full 5-state walk).
        for lifecycle_event in (
            "run.lifecycle.pending",
            "run.lifecycle.running",
            "run.lifecycle.suspended",
            "run.lifecycle.woken",
            "run.lifecycle.completed",
        ):
            assert lifecycle_event in types, types

        # executor-side per-terminal output-evidence rows (DISTINCT family).
        assert "run.suspended" in types, types
        assert "run.completed" in types, types

        # scheduler evidence — the suspend leg admitted + completed the task.
        assert "scheduler.admission_accepted" in types, types
        assert "scheduler.task_completed" in types, types
    finally:
        await docker.close()
        await engine.dispose()

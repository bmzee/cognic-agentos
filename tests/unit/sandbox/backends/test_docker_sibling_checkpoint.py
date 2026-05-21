"""Sprint 8.5 T6 — DockerSibling checkpoint → suspend → wake → exec
round-trip on real Docker.

ENV-GATED: skipped unless ``COGNIC_RUN_DOCKER_SANDBOX=1`` AND a
Docker daemon is reachable + the canonical Sprint-8A images are
pre-pulled. Mirrors the env-gating pattern at
``test_docker_sibling_lifecycle.py``.

Per spec §7.1: checkpoint() runs ``tar czf - -C /workspace .`` over
docker exec; wake() runs ``tar xzf - -C /workspace`` on the fresh
container. Round-trip MUST preserve workspace contents.

Per spec §3.1 Q1 lock: workspace-tar (NOT CRIU + NOT container
commit). Wave-1 doctrine.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

pytest.importorskip("aiodocker")

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="Docker daemon required — set COGNIC_RUN_DOCKER_SANDBOX=1 to run",
)


@dataclass
class _StubSettings:
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)
_ACTOR = Actor(
    subject="alice@bank",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)


@pytest_asyncio.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'dh.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def checkpoint_store(tmp_path: Path, engine: AsyncEngine) -> CheckpointStore:
    return CheckpointStore(
        object_store=LocalObjectStoreAdapter(root=tmp_path / "objects"),
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=_StubSettings(),
    )


@pytest_asyncio.fixture
async def backend_with_checkpoints(
    docker_client: object,
    catalog: object,
    checkpoint_store: CheckpointStore,
) -> DockerSiblingSandboxBackend:
    """Real DockerSiblingSandboxBackend with CheckpointStore wired —
    extends the fixture pattern from conftest.py.

    Per ``test_docker_sibling_lifecycle.py``: cosign + syft are mocked
    at the catalog seam via monkeypatch in each test method so we
    don't shell out to the real binaries.
    """
    rego = AsyncMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    return DockerSiblingSandboxBackend(
        docker_client=docker_client,  # type: ignore[arg-type]
        image_catalog=catalog,  # type: ignore[arg-type]
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=checkpoint_store._audit_store,
        decision_history_store=checkpoint_store._dh_store,
        settings=_StubSettings(),  # type: ignore[arg-type]
        warm_pool=None,
        checkpoint_store=checkpoint_store,
    )


class TestCheckpointSuspendWakeRoundTrip:
    @pytest.mark.asyncio
    async def test_checkpoint_suspend_wake_exec_preserves_workspace_state(
        self,
        backend_with_checkpoints: DockerSiblingSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per spec §7.1 + §7.3: write a sentinel file in /workspace,
        suspend (final checkpoint), wake, exec ``cat`` → assert
        contents preserved."""
        from cognic_agentos.sandbox.catalog import (
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        # Bypass cosign + SBOM at the catalog seam (T6 owns the real
        # subprocess impl tests).
        monkeypatch.setattr(
            backend_with_checkpoints._catalog,
            "verify_cosign_or_refuse",
            AsyncMock(return_value=CosignVerifyResult(passed=True, detail="")),
        )
        monkeypatch.setattr(
            backend_with_checkpoints._catalog,
            "verify_sbom_policy_or_refuse",
            AsyncMock(return_value=SBOMVerifyResult(passed=True, detail="")),
        )

        session = await backend_with_checkpoints.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        try:
            # 1. Write a sentinel file in /workspace.
            await session.exec(
                [
                    "sh",
                    "-c",
                    "echo 'hello-from-pre-suspend' > /workspace/sentinel.txt",
                ]
            )

            # 2. Suspend (takes final checkpoint + tears down container).
            await session.suspend()

            # 3. Wake the session by id.
            woken = await backend_with_checkpoints.wake(
                session.session_id, actor=_ACTOR, tenant_id="t-1"
            )
            assert woken.session_id == session.session_id

            # 4. Read back the sentinel.
            result = await woken.exec(["cat", "/workspace/sentinel.txt"])
            assert b"hello-from-pre-suspend" in result.stdout
        finally:
            # Cleanup — destroy() may succeed OR raise if container is
            # already gone (the test's tar/wake path may have left the
            # original gone; the woken session's destroy is unaware).
            # Best-effort: swallow any teardown exception so the
            # finally block doesn't mask a real assertion failure above.
            import contextlib

            with contextlib.suppress(Exception):
                await backend_with_checkpoints.destroy(session)

"""Sprint 8.5 T7 — KubernetesPod checkpoint → suspend → wake → exec
round-trip on a real K8s cluster.

ENV-GATED: skipped unless ``COGNIC_RUN_K8S_SANDBOX=1`` AND a real
K8s cluster is reachable via ``KUBECONFIG`` (or in-cluster
ServiceAccount when running inside a pod). Standard pytest runs
skip these tests; local development with a real cluster + the
Sprint-8B sandbox-integration CI lane (if + when one is added)
runs them. Mirrors the env-gating pattern at
``test_kubernetes_pod_lifecycle.py`` per the user-locked 2026-05-17
preflight decision: NO kind in CI; live-cluster runs are deliberately
env-gated.

Per spec §7.2: checkpoint() runs ``tar czf - -C /workspace .`` over
the K8s pods/exec websocket; wake() runs ``head -c N | tar xzf -
--strip-components=1 --no-overwrite-dir -C /workspace`` on the fresh
Pod via the STDIN_CHANNEL of a new pods/exec websocket. Round-trip
MUST preserve workspace contents without rewriting the OpenShift
``emptyDir`` mount-root metadata.

Per spec §3.1 Q1 lock: workspace-tar (NOT CRIU + NOT pod commit).
Wave-1 doctrine.
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

pytest.importorskip("kubernetes_asyncio")

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
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
)
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_K8S_SANDBOX") != "1",
    reason=(
        "K8s cluster required — set COGNIC_RUN_K8S_SANDBOX=1 AND configure "
        "KUBECONFIG (or run inside a Pod with a ServiceAccount) to run. "
        "Per the 2026-05-17 Sprint 8B preflight decision: NO kind in CI; "
        "live-cluster runs are deliberately env-gated."
    ),
)


@dataclass
class _StubSettings:
    sandbox_per_tenant_max_cpu: float = 4.0
    sandbox_per_tenant_max_memory: int = 4096
    sandbox_per_tenant_max_walltime: float = 300.0
    sandbox_checkpoint_retention_s: int = 86_400
    sandbox_max_checkpoints_per_session: int = 10
    sandbox_reaper_interval_s: int = 300


_VALID_DIGEST = "sha256:" + "a" * 64
_VALID_PACK_DIGEST = "sha256:" + "b" * 64
_VALID_IMAGE_REF = "cognic/sandbox-runtime-python:v1@" + _VALID_DIGEST

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image=_VALID_IMAGE_REF,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest=_VALID_PACK_DIGEST,
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


@pytest.fixture(scope="module")
def kube_namespace() -> str:
    return os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox-it")


@pytest.fixture
async def kube_api_client() -> AsyncIterator[object]:
    """Load kubeconfig + return a configured ApiClient. The client is
    closed in the fixture teardown so no event-loop warnings surface
    on test exit."""
    from kubernetes_asyncio import client, config

    await config.load_kube_config()
    api_client = client.ApiClient()
    try:
        yield api_client
    finally:
        await api_client.close()


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
    kube_api_client: object,
    kube_namespace: str,
    checkpoint_store: CheckpointStore,
) -> KubernetesPodSandboxBackend:
    """Real KubernetesPodSandboxBackend with CheckpointStore wired —
    extends the env-gated fixture pattern from
    ``test_kubernetes_pod_lifecycle.py``.

    Cosign + SBOM verification at the catalog seam is mocked in the
    test body via monkeypatch — T6 catalog tests own the real
    subprocess impl coverage.
    """
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = AsyncMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    return KubernetesPodSandboxBackend(
        kube_api_client=kube_api_client,  # type: ignore[arg-type]
        namespace=kube_namespace,
        image_catalog=catalog,
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
        backend_with_checkpoints: KubernetesPodSandboxBackend,
    ) -> None:
        """Per spec §7.2 + §7.3: write a sentinel file in /workspace,
        suspend (final checkpoint), wake, exec ``cat`` → assert
        contents preserved across the K8s Pod lifecycle (delete + fresh
        Pod restart)."""
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

            # 2. Suspend (takes final checkpoint + deletes Pod +
            # NetworkPolicy).
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
            import contextlib

            with contextlib.suppress(Exception):
                await backend_with_checkpoints.destroy(session)

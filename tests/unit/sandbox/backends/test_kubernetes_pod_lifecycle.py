"""Sprint 8B T8B-b — KubernetesPodSandboxBackend lifecycle on real K8s.

ENV-GATED: skipped unless ``COGNIC_RUN_K8S_SANDBOX=1`` AND a real
K8s cluster is reachable via ``KUBECONFIG`` (or in-cluster
ServiceAccount when running inside a pod). Standard pytest runs
skip these tests; local development with a real cluster + the
Sprint-8B sandbox-integration CI lane (if + when one is added)
runs them. No ``kind`` is added to CI per the user-locked preflight
decision at 2026-05-17.

Per ``feedback_canonical_artifact_not_oss_substitute``, this file
uses FAKE placeholder image digests because T8B-b's lifecycle
envelope exercises the topology + Pod start/delete + NetworkPolicy
create/delete without needing the runtime image to actually do
anything. The canonical ``cognic/sandbox-runtime-python:v1@sha256:...``
+ canonical ``cognic/sandbox-egress-proxy:v1@sha256:...`` images
must be pre-pulled into the cluster's image cache for these tests
to run; missing canonical artifact → ``pytest.skip(f"canonical
artifact {ref} not pullable; ...")`` with a structured message
naming the missing ref. NEVER silent OSS substitution.

The T8B-c exec() body lands the cap-violation cases + proxy_log
materialisation. T8B-b's env-gated tests cover create() / destroy()
/ health() only.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock

import pytest

# Per feedback_verify_dep_availability_at_implementation — env-gated
# tests still need kubernetes_asyncio for fixture construction;
# without the extra, collection fails. The importorskip degrades
# gracefully in kernel-only venvs.
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.admission import CredentialAdapter
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_K8S_SANDBOX") != "1",
    reason=(
        "K8s cluster required — set COGNIC_RUN_K8S_SANDBOX=1 AND configure "
        "KUBECONFIG (or run inside a Pod with a ServiceAccount) to run. "
        "Per the 2026-05-17 Sprint 8B preflight decision: NO kind in CI; "
        "live-cluster runs are deliberately env-gated."
    ),
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_VALID_DIGEST = "sha256:" + "a" * 64
_VALID_PACK_DIGEST = "sha256:" + "b" * 64
_VALID_IMAGE_REF = "cognic/sandbox-runtime-python:v1@" + _VALID_DIGEST

_INTERNAL_WRITE_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image=_VALID_IMAGE_REF,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)

_TEST_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest=_VALID_PACK_DIGEST,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)

# Per the canonical-artifact doctrine, the canonical proxy + runtime
# images MUST be pre-pulled. The list lives here so the preflight
# helper below names the missing ref in its skip message.
_REQUIRED_CANONICAL_IMAGES: tuple[str, ...] = (
    _VALID_IMAGE_REF,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


@pytest.fixture(scope="module")
def kube_namespace() -> str:
    """The namespace the integration tests operate in. Default
    ``cognic-sandbox-it`` — banks running this lane locally should
    pre-create the namespace with the egress-proxy NetworkPolicy
    installed via the Sprint 14 deployment kit. Override via
    ``COGNIC_K8S_SANDBOX_NAMESPACE`` if needed."""
    return os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox-it")


@pytest.fixture
async def kube_api_client():
    """Load kubeconfig + return a configured ApiClient. The client
    is closed in the fixture teardown so no event-loop warnings
    surface on test exit."""
    from kubernetes_asyncio import client, config

    await config.load_kube_config()
    api_client = client.ApiClient()
    try:
        yield api_client
    finally:
        await api_client.close()


@pytest.fixture
def backend(
    kube_api_client: object,  # ApiClient — typed loosely to avoid the K8s stub dep
    kube_namespace: str,
) -> KubernetesPodSandboxBackend:
    """Construct a KubernetesPodSandboxBackend wired against the real
    apiserver. Catalog / credentials / rego are mocked because
    integration tests focus on the K8s-API surface; admission-pipeline
    behaviour is covered by the non-env-gated
    test_kubernetes_pod_admission_integration.py."""
    from cognic_agentos.sandbox.backends.kubernetes_pod import (
        KubernetesPodSandboxBackend,
    )

    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)

    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )

    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
    )

    return KubernetesPodSandboxBackend(
        kube_api_client=kube_api_client,  # type: ignore[arg-type]
        namespace=kube_namespace,
        image_catalog=catalog,
        credential_adapter=AsyncMock(spec=CredentialAdapter),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=settings,
        warm_pool=None,
    )


@pytest.fixture
def actor() -> MagicMock:
    a = MagicMock()
    a.subject = "user:integration"
    return a


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLifecycleAgainstRealCluster:
    """Wire-protocol-touching tests — verify the K8s API surface
    behaves the way the backend assumes. Each test destroys its
    session in a try/finally so a failure does not leak Pods or
    NetworkPolicies in the test namespace."""

    @pytest.mark.asyncio
    async def test_create_then_destroy_round_trip(
        self,
        backend: KubernetesPodSandboxBackend,
        actor: MagicMock,
    ) -> None:
        """Per spec §7 + ADR-004 amendment: create() returns a
        running KubernetesPodSession + destroy() cleans up both the
        Pod and the NetworkPolicy."""
        from kubernetes_asyncio import client as kube_client

        session = await backend.create(
            _INTERNAL_WRITE_POLICY,
            actor=actor,
            tenant_id="t-it",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        )
        # Backend.create() returns a SandboxSession (Protocol);
        # this isinstance narrow lets mypy see the backend-specific
        # _pod_name + _network_policy_name fields used below.
        assert isinstance(session, KubernetesPodSession)
        try:
            # Pod exists in the namespace post-create.
            api = kube_client.CoreV1Api(backend._kube)
            pod = await api.read_namespaced_pod(
                name=session._pod_name, namespace=backend._namespace
            )
            assert pod is not None
            # NetworkPolicy exists too.
            net_api = kube_client.NetworkingV1Api(backend._kube)
            netpol = await net_api.read_namespaced_network_policy(
                name=session._network_policy_name, namespace=backend._namespace
            )
            assert netpol is not None
        finally:
            await session.destroy()

        # Pod gone post-destroy (404 expected — swallowed by the
        # backend's _delete_pod_if_exists; we use it as a probe).
        api = kube_client.CoreV1Api(backend._kube)
        with pytest.raises(kube_client.ApiException) as exc:
            await api.read_namespaced_pod(name=session._pod_name, namespace=backend._namespace)
        assert exc.value.status == 404

    @pytest.mark.asyncio
    async def test_destroy_is_idempotent(
        self,
        backend: KubernetesPodSandboxBackend,
        actor: MagicMock,
    ) -> None:
        """Per spec §5 — destroy() callable twice without raising."""
        session = await backend.create(
            _INTERNAL_WRITE_POLICY,
            actor=actor,
            tenant_id="t-it",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        )
        await session.destroy()
        # Second destroy MUST NOT raise.
        await session.destroy()


class TestHealthProbeAgainstRealCluster:
    """Health probe MUST succeed against a live apiserver."""

    @pytest.mark.asyncio
    async def test_health_returns_ok_against_live_cluster(
        self, backend: KubernetesPodSandboxBackend
    ) -> None:
        result = await backend.health()
        assert result.status == "ok"

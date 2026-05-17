"""Sprint 8A T10c + Sprint 8B T8B-c — shared backend conformance fixtures.

Parametrized over BOTH Wave-1 backend implementations as of
Sprint 8B T8B-c. New backends (Wave-2 gVisor / Firecracker / Kata
/ etc.) add their backend-id to the params list + supply a fixture
branch.

Per spec §15.3 — every Protocol-conforming ``SandboxBackend``
implementation MUST pass the shared conformance suite.

Both arms are env-gated:

* ``docker_sibling`` — ``COGNIC_RUN_DOCKER_SANDBOX=1`` + Docker
  daemon + canonical image catalog pulled.
* ``kubernetes_pod`` — ``COGNIC_RUN_K8S_SANDBOX=1`` + reachable
  K8s cluster + canonical images in the cluster's image cache.
  Per the 2026-05-17 Sprint 8B preflight decision: NO ``kind``
  added to CI; live-cluster runs are deliberately env-gated.

Standard pytest runs skip both arms entirely. Sprint-8A's existing
docker conformance is unchanged; Sprint-8B T8B-c adds the K8s
arm via the same conftest, same test bodies, different fixture
wiring.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("aiodocker")
pytest.importorskip("kubernetes_asyncio")


_CANONICAL_SPRINT_8A_IMAGES = (
    "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
    "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


@pytest.fixture(params=["docker_sibling", "kubernetes_pod"])
async def backend(request, tmp_path):
    """Backend-parametrized conformance fixture.

    Sprint 8A: ``docker_sibling`` (Wave-1 dev/CI backend).
    Sprint 8B T8B-c: + ``kubernetes_pod`` (Wave-1 production
    backend per ``project_openshift_deployment_target``).

    Wave-2 backends extend further (gVisor / Firecracker / Kata /
    rootless Docker / etc.) — each adds an ``elif request.param ==
    "<backend>"`` branch.
    """
    if request.param == "docker_sibling":
        # Skip entire param when env-gate not set (avoid attempting
        # to open a Docker connection in unit-only CI).
        if os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1":
            pytest.skip(
                "Docker backend conformance requires "
                "COGNIC_RUN_DOCKER_SANDBOX=1 + Docker daemon + canonical "
                "image catalog pulled. See "
                "feedback_canonical_artifact_not_oss_substitute for "
                "the canonical-vs-fixture-proxy doctrine."
            )

        from unittest.mock import AsyncMock, MagicMock

        import aiodocker
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )
        from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

        docker = aiodocker.Docker()
        # Canonical-artifact preflight — skip if any canonical image
        # missing per feedback_canonical_artifact_not_oss_substitute.
        try:
            for ref in _CANONICAL_SPRINT_8A_IMAGES:
                try:
                    await docker.images.inspect(ref)
                except aiodocker.exceptions.DockerError as e:
                    pytest.skip(
                        f"canonical artifact {ref!r} not pullable from "
                        f"local docker daemon ({e}); env-gated "
                        f"conformance suite requires canonical "
                        f"Sprint-8A image catalog. Real cosign-signed "
                        f"digests are published by Sprint-14 deploy kit."
                    )

            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            engine = create_async_engine("sqlite+aiosqlite:///:memory:")
            rego = AsyncMock()
            decision = MagicMock()
            decision.allow = True
            decision.reasoning = ""
            rego.evaluate = AsyncMock(return_value=decision)
            settings = MagicMock(
                sandbox_per_tenant_max_cpu=4.0,
                sandbox_per_tenant_max_memory=4096,
                sandbox_per_tenant_max_walltime=300.0,
            )
            yield DockerSiblingSandboxBackend(
                docker_client=docker,
                image_catalog=catalog,
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=rego,
                audit_store=AuditStore(engine=engine),
                decision_history_store=DecisionHistoryStore(engine=engine),
                settings=settings,
                warm_pool=None,
            )
        finally:
            await docker.close()
    elif request.param == "kubernetes_pod":
        # Sprint 8B T8B-c — K8s backend conformance arm. Env-gated
        # on COGNIC_RUN_K8S_SANDBOX=1 per the 2026-05-17 preflight
        # decision (no kind in CI; live-cluster runs only).
        if os.environ.get("COGNIC_RUN_K8S_SANDBOX") != "1":
            pytest.skip(
                "K8s backend conformance requires "
                "COGNIC_RUN_K8S_SANDBOX=1 + a reachable K8s cluster "
                "via KUBECONFIG (or in-cluster ServiceAccount when "
                "running inside a pod) + canonical image catalog in "
                "the cluster image cache. Per the 2026-05-17 Sprint 8B "
                "preflight decision: NO kind in CI; live-cluster runs "
                "are deliberately env-gated. See "
                "feedback_canonical_artifact_not_oss_substitute for "
                "the canonical-image doctrine."
            )

        from unittest.mock import AsyncMock, MagicMock

        from kubernetes_asyncio import client as kube_client
        from kubernetes_asyncio import config as kube_config
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
        from cognic_agentos.sandbox.backends.kubernetes_pod import (
            KubernetesPodSandboxBackend,
        )
        from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

        # Load cluster config — prefer in-cluster (when running
        # inside a pod with a ServiceAccount) else fall back to
        # KUBECONFIG. Both paths are env-driven so the fixture stays
        # OS-deployment-agnostic.
        try:
            kube_config.load_incluster_config()  # type: ignore[no-untyped-call]
        except kube_config.ConfigException:
            try:
                await kube_config.load_kube_config()
            except (kube_config.ConfigException, FileNotFoundError) as e:
                pytest.skip(
                    f"K8s config load failed ({e}); env-gated K8s "
                    f"conformance suite requires either in-cluster "
                    f"ServiceAccount or a readable KUBECONFIG."
                )

        api_client = kube_client.ApiClient()
        try:
            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            engine = create_async_engine("sqlite+aiosqlite:///:memory:")
            rego = AsyncMock()
            decision = MagicMock()
            decision.allow = True
            decision.reasoning = ""
            rego.evaluate = AsyncMock(return_value=decision)
            settings = MagicMock(
                sandbox_per_tenant_max_cpu=4.0,
                sandbox_per_tenant_max_memory=4096,
                sandbox_per_tenant_max_walltime=300.0,
            )
            yield KubernetesPodSandboxBackend(
                kube_api_client=api_client,
                namespace=os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox"),
                image_catalog=catalog,
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=rego,
                audit_store=AuditStore(engine=engine),
                decision_history_store=DecisionHistoryStore(engine=engine),
                settings=settings,
                warm_pool=None,
            )
        finally:
            await api_client.close()
    else:
        pytest.skip(f"Unknown backend param: {request.param!r}")

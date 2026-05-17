"""Sprint 8A T10c — shared backend conformance suite fixtures.

Parametrized over backend implementations. Sprint 8A only the
Docker arm is parametrized (``docker_sibling``); Sprint 8B adds
``kubernetes_pod`` via the same conftest, same test bodies,
different fixture wiring.

Per spec §15.3 — every Protocol-conforming ``SandboxBackend``
implementation MUST pass the shared conformance suite. New
backends (Wave-2 gVisor / Firecracker / Kata / etc.) add their
backend-id to the params list + supply a fixture branch.

The Docker arm is env-gated on ``COGNIC_RUN_DOCKER_SANDBOX=1``
via the autouse canonical-artifact preflight inherited from
``tests/unit/sandbox/backends/conftest.py``-style pattern.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("aiodocker")


_CANONICAL_SPRINT_8A_IMAGES = (
    "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
    "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


@pytest.fixture(params=["docker_sibling"])
async def backend(request, tmp_path):
    """Backend-parametrized conformance fixture.

    Sprint 8A: ``docker_sibling`` only.
    Sprint 8B will extend ``params=[..., "kubernetes_pod"]``.
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
    elif request.param == "kubernetes_pod":  # Sprint 8B placeholder
        pytest.skip("KubernetesPodSandboxBackend ships in Sprint 8B")
    else:
        pytest.skip(f"Unknown backend param: {request.param!r}")

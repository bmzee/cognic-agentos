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
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("aiodocker")
pytest.importorskip("kubernetes_asyncio")


_CANONICAL_SPRINT_8A_IMAGES = (
    "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
    "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


def _backend_unavailable(request: Any, message: str) -> None:
    """Resolve a per-backend runtime-unavailability outcome.

    Covers EVERY per-arm bail-out reason: the initial env-var gate
    (``COGNIC_RUN_*_SANDBOX`` not set) AND the later availability /
    preflight failures (canonical image missing, kube-config
    unreachable).

    Default conformance suites (e.g. ``test_backend_conformance.py``)
    treat a missing per-backend runtime as a benign ``pytest.skip`` — a
    CI box may legitimately have only Docker, or only a K8s cluster.

    But a module marked ``require_both_backends`` (the Sprint-8.5 T9
    cross-backend parity modules) is asserting both runtimes are
    present. A backend arm that then cannot run is a genuine FAILURE of
    the cross-backend parity guarantee — NOT a skip — because a
    single-arm skip alongside a passing sibling would be a one-backend
    false-green for a parity gate.

    Routing the env-var gate through here (not just the later preflight
    failures) is load-bearing: it makes the ``require_both_backends``
    marker an INDEPENDENT enforcer. The require_both modules ALSO carry
    a module-level skipif requiring both env vars — but that skipif is
    hand-written per module and could drift or be omitted. With the
    env-var gate routed here, even a broken/missing module skipif
    cannot produce a one-backend green: a require_both arm that reaches
    this fixture with a missing env var fails loud.
    """
    if request.node.get_closest_marker("require_both_backends") is not None:
        pytest.fail(
            f"cross-backend parity gate: {message} — both env gates are "
            f"set, so this backend MUST be runnable; a skipped arm "
            f"alongside a passing sibling would be a one-backend "
            f"false-green."
        )
    pytest.skip(message)


async def _build_checkpoint_layer(tmp_path: Path, settings: Any) -> tuple[Any, Any, Any, Any]:
    """Build a file-backed DecisionHistory engine (schema created +
    both chain heads seeded) + a ``CheckpointStore`` rooted under
    ``tmp_path``.

    Sprint 8.5 T9 — the cross-backend conformance suite exercises the
    FULL ``SandboxBackend`` Protocol surface: the Sprint-8A
    create / exec / destroy AND the Sprint-8.5 checkpoint / suspend /
    wake. checkpoint / suspend / wake all require a wired
    ``CheckpointStore``; create / destroy emit audit + chain rows. So
    the conformance ``backend`` fixture wires the result of this
    helper.

    A file-backed sqlite URL (NOT ``:memory:``) is load-bearing: the
    audit + decision-history stores open independent connections, and
    an in-memory sqlite database is per-connection — schema created on
    one connection is invisible to the next. The round-trip + tombstone
    conformance tests emit audit + chain rows across several
    connections, so the engine MUST be file-backed. (The pre-T9
    fixture used ``:memory:`` — latent because no audit-emitting
    conformance test had ever run live.)

    Returns ``(engine, audit_store, dh_store, checkpoint_store)``; the
    caller disposes ``engine`` in its fixture teardown.
    """
    from datetime import UTC, datetime

    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
    from cognic_agentos.core.canonical import ZERO_HASH
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.db.adapters.local_object_store_adapter import (
        LocalObjectStoreAdapter,
    )
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'conformance-dh.db'}")
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
    audit_store = AuditStore(engine)
    dh_store = DecisionHistoryStore(engine)
    checkpoint_store = CheckpointStore(
        object_store=LocalObjectStoreAdapter(root=tmp_path / "objects"),
        audit_store=audit_store,
        decision_history_store=dh_store,
        settings=settings,
    )
    return engine, audit_store, dh_store, checkpoint_store


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
        # Per-arm env-gate. Routed through _backend_unavailable so a
        # require_both_backends module fails (not skips) here — see that
        # helper's docstring. In the default suite this is a benign skip.
        if os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1":
            _backend_unavailable(
                request,
                "Docker backend conformance requires "
                "COGNIC_RUN_DOCKER_SANDBOX=1 + Docker daemon + canonical "
                "image catalog pulled. See "
                "feedback_canonical_artifact_not_oss_substitute for "
                "the canonical-vs-fixture-proxy doctrine.",
            )

        from unittest.mock import AsyncMock, MagicMock

        import aiodocker

        from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )
        from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

        docker = aiodocker.Docker()
        # ``engine`` is built inside the try (after the canonical-image
        # preflight that may pytest.skip); pre-bind to None so the
        # finally can dispose it conditionally without a NameError.
        engine = None
        # Canonical-artifact preflight — skip if any canonical image
        # missing per feedback_canonical_artifact_not_oss_substitute.
        try:
            for ref in _CANONICAL_SPRINT_8A_IMAGES:
                try:
                    await docker.images.inspect(ref)
                except aiodocker.exceptions.DockerError as e:
                    _backend_unavailable(
                        request,
                        f"canonical artifact {ref!r} not pullable from "
                        f"local docker daemon ({e}); env-gated "
                        f"conformance suite requires canonical "
                        f"Sprint-8A image catalog. Real cosign-signed "
                        f"digests are published by Sprint-14 deploy kit.",
                    )

            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            rego = AsyncMock()
            decision = MagicMock()
            decision.allow = True
            decision.reasoning = ""
            rego.evaluate = AsyncMock(return_value=decision)
            # Sprint 8.5 T9 — the 3 checkpoint Settings caps are wired
            # alongside the Sprint-8A tenant-max caps so the SAME
            # settings object satisfies both the backend admission path
            # AND the CheckpointStore ``_CheckpointSettings`` Protocol.
            settings = MagicMock(
                sandbox_per_tenant_max_cpu=4.0,
                sandbox_per_tenant_max_memory=4096,
                sandbox_per_tenant_max_walltime=300.0,
                sandbox_checkpoint_retention_s=86_400,
                sandbox_max_checkpoints_per_session=10,
                sandbox_reaper_interval_s=300,
            )
            engine, audit_store, dh_store, checkpoint_store = await _build_checkpoint_layer(
                tmp_path, settings
            )
            yield DockerSiblingSandboxBackend(
                docker_client=docker,
                image_catalog=catalog,
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=rego,
                audit_store=audit_store,
                decision_history_store=dh_store,
                settings=settings,
                warm_pool=None,
                checkpoint_store=checkpoint_store,
            )
        finally:
            await docker.close()
            if engine is not None:
                await engine.dispose()
    elif request.param == "kubernetes_pod":
        # Sprint 8B T8B-c — K8s backend conformance arm. Env-gated
        # on COGNIC_RUN_K8S_SANDBOX=1 per the 2026-05-17 preflight
        # decision (no kind in CI; live-cluster runs only).
        if os.environ.get("COGNIC_RUN_K8S_SANDBOX") != "1":
            _backend_unavailable(
                request,
                "K8s backend conformance requires "
                "COGNIC_RUN_K8S_SANDBOX=1 + a reachable K8s cluster "
                "via KUBECONFIG (or in-cluster ServiceAccount when "
                "running inside a pod) + canonical image catalog in "
                "the cluster image cache. Per the 2026-05-17 Sprint 8B "
                "preflight decision: NO kind in CI; live-cluster runs "
                "are deliberately env-gated. See "
                "feedback_canonical_artifact_not_oss_substitute for "
                "the canonical-image doctrine.",
            )

        from unittest.mock import AsyncMock, MagicMock

        from kubernetes_asyncio import client as kube_client
        from kubernetes_asyncio import config as kube_config

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
                _backend_unavailable(
                    request,
                    f"K8s config load failed ({e}); env-gated K8s "
                    f"conformance suite requires either in-cluster "
                    f"ServiceAccount or a readable KUBECONFIG.",
                )

        api_client = kube_client.ApiClient()
        # Pre-bind ``engine`` to None so the finally can dispose it
        # conditionally without a NameError (it is built mid-try).
        engine = None
        try:
            trust_root = tmp_path / "cognic-cosign.pub"
            trust_root.write_text("# fixture trust root for conformance suite")
            catalog = CanonicalImageCatalog(
                canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
                tenant_trust_roots={"t-conformance": trust_root},
                tenant_allow_lists={"t-conformance": frozenset()},
            )
            rego = AsyncMock()
            decision = MagicMock()
            decision.allow = True
            decision.reasoning = ""
            rego.evaluate = AsyncMock(return_value=decision)
            # Sprint 8.5 T9 — the 3 checkpoint Settings caps are wired
            # alongside the Sprint-8A tenant-max caps so the SAME
            # settings object satisfies both the backend admission path
            # AND the CheckpointStore ``_CheckpointSettings`` Protocol.
            settings = MagicMock(
                sandbox_per_tenant_max_cpu=4.0,
                sandbox_per_tenant_max_memory=4096,
                sandbox_per_tenant_max_walltime=300.0,
                sandbox_checkpoint_retention_s=86_400,
                sandbox_max_checkpoints_per_session=10,
                sandbox_reaper_interval_s=300,
            )
            engine, audit_store, dh_store, checkpoint_store = await _build_checkpoint_layer(
                tmp_path, settings
            )
            yield KubernetesPodSandboxBackend(
                kube_api_client=api_client,
                namespace=os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "cognic-sandbox"),
                image_catalog=catalog,
                credential_adapter=KernelDefaultCredentialAdapter(),
                rego_engine=rego,
                audit_store=audit_store,
                decision_history_store=dh_store,
                settings=settings,
                warm_pool=None,
                checkpoint_store=checkpoint_store,
            )
        finally:
            await api_client.close()
            if engine is not None:
                await engine.dispose()
    else:
        pytest.skip(f"Unknown backend param: {request.param!r}")

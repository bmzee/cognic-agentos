"""ADR-016 2026-05-29 canonical license carve-out — sidecar sites.

Critical-controls modules per AGENTS.md (`sandbox/backends/*` are on
the durable per-file coverage gate; `sandbox/` is a stop-rule isolation
boundary).

The ADR-016 2026-05-29 amendment (Sprint 10.6 / T30, "canonical
platform-image license-policy carve-out") decreed: the tenant/default
license-DENY policy does NOT apply to canonical platform images at
sandbox-create time — canonical-image license acceptance is an AgentOS
release/signing decision attested by the canonical cosign signature;
tenant/pack images keep the full gate. T30 implemented the skip at
admission step 8 (`admission.py:807-808`, pinned by
`test_admission_pipeline.py`) but MISSED the two egress-proxy sidecar
verification sites, which predated the amendment (Sprint 8A T10c R1
P1.1) and kept running the license gate on an image class the same
code REQUIRES to be canonical — the exact inversion of the carve-out.

Surfaced by the M6 live proof (run 13, 2026-07-04) — the FIRST live
execution of the gate: the canonical Debian-based egress proxy refused
with 666 license-policy violations (`GPL-2`, `Expat`, `BSD-3-clause`
Debian free-text spellings) that the amendment's own rationale
predicted ("applying the permissive-allow-only deny policy to them
would make every canonical image unadmittable", naming tinyproxy
GPL-2.0).

This file pins the corrected contract in CROSS-BACKEND LOCKSTEP
(mirroring `test_approval_threading.py`'s pattern):

* canonical proxy → cosign STILL verifies; the license/SBOM policy
  call is SKIPPED (the release/signing decision stands);
* non-canonical proxy → refused outright at the membership gate
  (`sandbox_image_digest_not_in_canonical_catalog`) BEFORE any verify
  call — stronger than license-gating; the tenant/pack license gate at
  admission step 8 is unchanged (pinned at
  `test_admission_pipeline.py`);
* the REAL-catalog GPL/unlabeled tests are the TM-revert targets:
  re-adding the license-policy call at either sidecar site makes them
  fail again with the run-13 refusal.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("kubernetes_asyncio")
pytest.importorskip("aiodocker")

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend
from cognic_agentos.sandbox.backends.kubernetes_pod import KubernetesPodSandboxBackend
from cognic_agentos.sandbox.catalog import CanonicalImageCatalog
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_RUNTIME_IMAGE = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
_PROXY_IMAGE = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64
_PROXY_DIGEST = "sha256:" + "d" * 64

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image=_RUNTIME_IMAGE,
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
    subject="carveout-actor",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)

#: The run-13-shaped SBOM: genuine copyleft (tinyproxy GPL-2.0 — the
#: license ADR-016's rationale names), a Debian free-text spelling
#: (``GPL-2``), and a fully-unlabeled artifact (Go-buildinfo module).
#: EVERY entry refuses under the shipped default-deny license policy —
#: which is exactly why the carve-out must skip the policy for the
#: canonical proxy.
_GPL_UNLABELED_SBOM = json.dumps(
    {
        "artifacts": [
            {"name": "tinyproxy", "version": "1.11.1", "licenses": [{"value": "GPL-2.0"}]},
            {"name": "apt", "version": "2.6.1", "licenses": [{"value": "GPL-2"}]},
            {"name": "go-module-in-static-binary", "version": "v1.0.0"},
        ]
    }
).encode()


def _mock_catalog(*, proxy_canonical: bool = True) -> MagicMock:
    catalog = MagicMock()
    catalog.is_canonical.return_value = proxy_canonical
    catalog.is_tenant_allow_listed.return_value = False
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return catalog


def _real_catalog(tmp_path: Path) -> CanonicalImageCatalog:
    """REAL catalog (not a mock) so the real ``_run_syft_inspect``
    license-policy code would execute if the sidecar called it — the
    property the TM-revert tests depend on. Subprocesses are patched
    at the ``asyncio.create_subprocess_exec`` boundary per the
    ``test_image_catalog.py`` pattern."""

    trust_root = tmp_path / "cognic-canonical-cosign.pub"
    trust_root.write_text("# fixture canonical trust root (mocked subprocess)\n")
    return CanonicalImageCatalog(
        canonical_refs=frozenset({_RUNTIME_IMAGE, _PROXY_IMAGE}),
        tenant_trust_roots={"t-1": trust_root},
        tenant_allow_lists={},
        canonical_trust_root=trust_root,
    )


def _make_dispatching_subprocess_fake(*, syft_stdout: bytes) -> tuple[Any, list[str]]:
    """Fake ``asyncio.create_subprocess_exec`` dispatching on argv[0]:
    cosign → exit 0 (signature valid); syft → exit 0 with the
    configured SBOM stdout. Records every argv[0] so tests can assert
    WHICH subprocesses the gate actually launched."""

    invoked: list[str] = []

    async def _fake(*argv: str, **_kwargs: Any) -> AsyncMock:
        invoked.append(argv[0])
        proc = AsyncMock()
        if argv[0] == "cosign":
            proc.communicate = AsyncMock(return_value=(b"cosign: verified", b""))
        elif argv[0] == "syft":
            proc.communicate = AsyncMock(return_value=(syft_stdout, b""))
        else:  # pragma: no cover - defensive
            raise AssertionError(f"unexpected subprocess launch: {argv!r}")
        proc.returncode = 0
        return proc

    return _fake, invoked


# ---------------------------------------------------------------------------
# DockerSibling — _start_proxy_sidecar
# ---------------------------------------------------------------------------


def _docker_backend(catalog: Any) -> DockerSiblingSandboxBackend:
    docker = MagicMock()
    container = MagicMock()
    container.start = AsyncMock(return_value=None)
    docker.containers.create_or_replace = AsyncMock(return_value=container)
    network = MagicMock()
    network.connect = AsyncMock(return_value=None)
    docker.networks.get = AsyncMock(return_value=network)
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )
    return DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=AsyncMock(),
        settings=settings,
        warm_pool=None,
        egress_proxy_image=_PROXY_IMAGE,
    )


async def _drive_docker_sidecar(backend: DockerSiblingSandboxBackend) -> None:
    await backend._start_proxy_sidecar(
        policy=_POLICY,
        session_id="sess-carveout",
        container_name="sb-sess-carveout-proxy",
        internal_net_name="sb-int-carveout",
        egress_net_name="sb-egr-carveout",
        tenant_id="t-1",
    )


class TestDockerSidecarLicenseCarveout:
    async def test_canonical_proxy_skips_license_policy_but_still_cosigns(self) -> None:
        """The carve-out contract at the docker sidecar site: cosign
        verification STILL runs on the proxy digest; the license/SBOM
        policy call is SKIPPED (canonical-image license acceptance is
        a release/signing decision per ADR-016 2026-05-29)."""

        catalog = _mock_catalog(proxy_canonical=True)
        backend = _docker_backend(catalog)
        await _drive_docker_sidecar(backend)
        catalog.verify_cosign_or_refuse.assert_awaited_once()
        assert catalog.verify_cosign_or_refuse.await_args.args[0] == _PROXY_DIGEST
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_non_canonical_proxy_refuses_at_membership_gate(self) -> None:
        """A non-canonical proxy refuses OUTRIGHT at the membership
        gate — stronger than license-gating; neither verify call runs.
        (The tenant/pack-image license gate lives at admission step 8,
        unchanged — pinned at ``test_admission_pipeline.py``.)"""

        catalog = _mock_catalog(proxy_canonical=False)
        backend = _docker_backend(catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            await _drive_docker_sidecar(backend)
        assert exc_info.value.reason == "sandbox_image_digest_not_in_canonical_catalog"
        catalog.verify_cosign_or_refuse.assert_not_called()
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_canonical_gpl_unlabeled_proxy_admitted_without_license_evaluation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TM-REVERT TARGET — the run-13 reality pin through the REAL
        catalog: a canonical proxy whose SBOM carries GPL-2.0 +
        Debian-spelled GPL-2 + a fully-unlabeled artifact starts
        cleanly, because the sidecar never launches syft at all.
        Re-adding the license-policy call at the sidecar site makes
        this fail with the run-13 ``sandbox_image_sbom_check_failed``
        refusal."""

        catalog = _real_catalog(tmp_path)
        fake, invoked = _make_dispatching_subprocess_fake(syft_stdout=_GPL_UNLABELED_SBOM)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        backend = _docker_backend(catalog)
        await _drive_docker_sidecar(backend)
        assert "cosign" in invoked  # signature identity STILL verified
        assert "syft" not in invoked  # license policy NOT re-evaluated


# ---------------------------------------------------------------------------
# KubernetesPod — create() proxy preflight
# ---------------------------------------------------------------------------


def _k8s_backend(catalog: Any) -> KubernetesPodSandboxBackend:
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )
    dh_store = AsyncMock()
    dh_store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    backend = KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store,
        settings=settings,
        warm_pool=None,
        egress_proxy_image=_PROXY_IMAGE,
    )
    # Mock the K8s topology seams so create() never touches a cluster
    # (mirrors test_kubernetes_pod_credentials.py::_make_backend).
    backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_pod_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_proxy_audit_log_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend


def _patched_admission() -> Any:
    """Patch admit_policy to isolate the SIDECAR preflight — the
    admission-side canonical skip is separately pinned at
    ``test_admission_pipeline.py`` (canonical → not called at
    :576; tenant-allow-listed → awaited at :614)."""

    return patch(
        "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
        new=AsyncMock(return_value=None),
    )


async def _drive_k8s_create(backend: KubernetesPodSandboxBackend) -> None:
    await backend.create(
        _POLICY,
        actor=_ACTOR,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        use_warm_pool=False,
    )


class TestKubernetesSidecarLicenseCarveout:
    async def test_canonical_proxy_skips_license_policy_but_still_cosigns(self) -> None:
        """LOCKSTEP with the docker arm — with admission patched out,
        the ONLY catalog verify calls are the sidecar preflight's:
        cosign runs on the proxy digest; the license/SBOM policy call
        is skipped."""

        catalog = _mock_catalog(proxy_canonical=True)
        backend = _k8s_backend(catalog)
        with _patched_admission():
            await _drive_k8s_create(backend)
        catalog.verify_cosign_or_refuse.assert_awaited_once()
        assert catalog.verify_cosign_or_refuse.await_args.args[0] == _PROXY_DIGEST
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_non_canonical_proxy_refuses_at_membership_gate(self) -> None:
        catalog = _mock_catalog(proxy_canonical=False)
        backend = _k8s_backend(catalog)
        with _patched_admission(), pytest.raises(SandboxLifecycleRefused) as exc_info:
            await _drive_k8s_create(backend)
        assert exc_info.value.reason == "sandbox_image_digest_not_in_canonical_catalog"
        catalog.verify_cosign_or_refuse.assert_not_called()
        catalog.verify_sbom_policy_or_refuse.assert_not_called()

    async def test_canonical_gpl_unlabeled_proxy_admitted_without_license_evaluation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TM-REVERT TARGET — K8s mirror of the docker real-catalog
        pin. Re-adding the license-policy call at the K8s preflight
        makes this fail with ``sandbox_image_sbom_check_failed``."""

        catalog = _real_catalog(tmp_path)
        fake, invoked = _make_dispatching_subprocess_fake(syft_stdout=_GPL_UNLABELED_SBOM)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake)
        backend = _k8s_backend(catalog)
        with _patched_admission():
            await _drive_k8s_create(backend)
        assert "cosign" in invoked
        assert "syft" not in invoked

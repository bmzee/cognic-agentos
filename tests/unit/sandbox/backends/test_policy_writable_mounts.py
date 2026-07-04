"""M6 run-14 amendment — ``SandboxPolicy.writable_mounts`` ENFORCEMENT.

Critical-controls modules per AGENTS.md (`sandbox/backends/*` +
`sandbox/protocol.py` are on the durable per-file coverage gate;
`sandbox/` is a stop-rule isolation boundary).

Discovered by the M6 live proof (run 14, 2026-07-04): the
``SandboxPolicy.writable_mounts`` field (Sprint-8A spec §6 shape) was
DECLARED but never ENFORCED by any backend — both backends consumed it
solely in the policy→audit-payload projection, so the chain evidence
recorded mounts the workload container never received. The M6 skill
executor's broker-socket mount (`executor.py` ``_build_policy``) was
silently dropped; the in-sandbox runner's first governed tool call
crashed at ``open_unix_connection`` (exit 1, empty stdout). Part-A unit
tests used stub backends that honored the policy by construction — the
test-fixture-papers-over-production-gap failure mode.

The corrected contract (maintainer-approved shape):

* **Docker** — a separate ``policy_mounts`` channel on
  ``_start_sandbox_container`` renders ``:rw`` / ``:ro`` from each
  ``WritableMount.read_only``; ``create()`` AND ``wake()`` thread
  ``policy.writable_mounts``. The Sprint-10.6 T21 credential
  ``extra_mounts`` seam is UNTOUCHED — credential projections remain
  read-only by construction. The egress-proxy sidecar receives NO
  policy mounts.
* **K8s** — FAIL-CLOSED: ``create()`` refuses a non-empty
  ``policy.writable_mounts`` with the closed-enum
  ``sandbox_writable_mounts_unsupported_on_backend`` until the
  same-Pod-sidecar + emptyDir realization (spec §5.5) lands. NOT a
  silent audit-only deferral — that would recreate the exact bug class
  (policy/evidence says a mount exists, runtime does not enforce it).

The docker ``:rw`` bind pin is the TM-revert target: unthreading
``policy_mounts`` from ``create()`` makes it fail again with the
run-14 missing-mount shape.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("kubernetes_asyncio")
pytest.importorskip("aiodocker")

from cognic_agentos.core.vault import VaultLeaseActorRef, VaultLeaseRequest
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    CheckpointId,
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends import docker_sibling as _ds
from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend
from cognic_agentos.sandbox.backends.kubernetes_pod import KubernetesPodSandboxBackend
from cognic_agentos.sandbox.checkpoint_store import CheckpointMetadata
from cognic_agentos.sandbox.policy import WritableMount

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_RUNTIME_IMAGE = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
_PROXY_IMAGE = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64

_BROKER_HOST_DIR = "/var/lib/test-broker/csk-" + "f" * 32
_BROKER_CONTAINER_DIR = "/run/cognic-skill"

_RW_MOUNT = WritableMount(
    host_path=_BROKER_HOST_DIR,
    container_path=_BROKER_CONTAINER_DIR,
    read_only=False,
)
_RO_MOUNT = WritableMount(
    host_path="/var/lib/test-refs/ref-1",
    container_path="/opt/refs",
    read_only=True,
)


def _policy(mounts: tuple[WritableMount, ...]) -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=_RUNTIME_IMAGE,
        egress_allow_list=(),
        vault_path=None,
        writable_mounts=mounts,
    )


_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="read_only",
    declares_dynamic_install=False,
    profile="production",
)
_ACTOR = Actor(
    subject="mounts-actor",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)


def _passing_catalog() -> MagicMock:
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = False
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return catalog


# ---------------------------------------------------------------------------
# DockerSibling — policy_mounts rendering + threading
# ---------------------------------------------------------------------------


def _docker_backend(docker_client: Any | None = None) -> DockerSiblingSandboxBackend:
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )
    return DockerSiblingSandboxBackend(
        docker_client=docker_client if docker_client is not None else AsyncMock(),
        image_catalog=_passing_catalog(),
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=AsyncMock(),
        settings=settings,
        warm_pool=None,
        egress_proxy_image=_PROXY_IMAGE,
    )


def _workload_config(docker_client: Any) -> dict[str, Any]:
    """The captured ``containers.create_or_replace`` config."""

    assert docker_client.containers.create_or_replace.await_count == 1
    call = docker_client.containers.create_or_replace.await_args
    assert call is not None
    config = call.kwargs["config"]
    assert isinstance(config, dict)
    return config


def _patch_docker_create_seams(
    monkeypatch: pytest.MonkeyPatch, backend: DockerSiblingSandboxBackend
) -> None:
    """Isolate the REAL ``_start_sandbox_container`` inside ``create()``:
    admission, networks, the proxy sidecar, and the lifecycle emit are
    not under test here (each has its own suite)."""

    monkeypatch.setattr(_ds, "admit_policy", AsyncMock(return_value=None))
    monkeypatch.setattr(_ds, "emit_sandbox_event", AsyncMock(return_value=None))
    monkeypatch.setattr(backend, "_create_internal_network", AsyncMock(return_value=None))
    monkeypatch.setattr(backend, "_create_egress_network", AsyncMock(return_value=None))
    monkeypatch.setattr(backend, "_start_proxy_sidecar", AsyncMock(return_value=None))


class TestDockerPolicyWritableMounts:
    async def test_create_binds_rw_policy_mount_on_workload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TM-REVERT TARGET — the run-14 pin: the broker-socket mount
        the M6 executor declares MUST reach the workload container's
        binds as ``:rw``. Unthreading ``policy_mounts`` from
        ``create()`` makes this fail with the run-14 missing-mount
        shape."""

        docker = AsyncMock()
        backend = _docker_backend(docker)
        _patch_docker_create_seams(monkeypatch, backend)
        await backend.create(
            _policy((_RW_MOUNT,)),
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        binds = _workload_config(docker).get("HostConfig", {}).get("Binds", [])
        assert f"{_BROKER_HOST_DIR}:{_BROKER_CONTAINER_DIR}:rw" in binds

    async def test_create_renders_read_only_policy_mount_ro(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        docker = AsyncMock()
        backend = _docker_backend(docker)
        _patch_docker_create_seams(monkeypatch, backend)
        await backend.create(
            _policy((_RO_MOUNT,)),
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        binds = _workload_config(docker).get("HostConfig", {}).get("Binds", [])
        assert f"{_RO_MOUNT.host_path}:{_RO_MOUNT.container_path}:ro" in binds

    async def test_start_sandbox_container_keeps_credential_mounts_ro_alongside_policy_rw(
        self,
    ) -> None:
        """The Sprint-10.6 T21 credential seam is UNTOUCHED: credential
        ``extra_mounts`` render ``:ro`` by construction while the new
        ``policy_mounts`` channel renders per ``read_only`` — the two
        trust classes coexist on one container config."""

        docker = AsyncMock()
        backend = _docker_backend(docker)
        await backend._start_sandbox_container(
            policy=_policy(()),
            session_id="sb-mounts-1",
            internal_net_name="sb-int-1",
            extra_mounts=[("/var/lib/creds/lease-1", "/run/cognic-credentials/app_role")],
            policy_mounts=(_RW_MOUNT,),
        )
        binds = _workload_config(docker).get("HostConfig", {}).get("Binds", [])
        assert "/var/lib/creds/lease-1:/run/cognic-credentials/app_role:ro" in binds
        assert f"{_BROKER_HOST_DIR}:{_BROKER_CONTAINER_DIR}:rw" in binds

    async def test_sidecar_receives_no_policy_mounts(self) -> None:
        """The egress-proxy sidecar is dual-homed network plumbing — it
        must NEVER receive the workload's policy mounts (a broker
        socket reachable from the egress path would be a new surface)."""

        docker = AsyncMock()
        network = MagicMock()
        network.connect = AsyncMock(return_value=None)
        docker.networks.get = AsyncMock(return_value=network)
        backend = _docker_backend(docker)
        await backend._start_proxy_sidecar(
            policy=_policy((_RW_MOUNT,)),
            session_id="sb-mounts-2",
            container_name="sb-mounts-2-proxy",
            internal_net_name="sb-int-2",
            egress_net_name="sb-egr-2",
            tenant_id="t-1",
        )
        sidecar_call = docker.containers.create_or_replace.await_args
        assert sidecar_call is not None
        sidecar_config = sidecar_call.kwargs["config"]
        sidecar_binds = sidecar_config.get("HostConfig", {}).get("Binds", [])
        assert all(_BROKER_HOST_DIR not in bind for bind in sidecar_binds)

    async def test_wake_threads_policy_writable_mounts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wake path rebuilds the workload from the CHECKPOINTED
        policy — leaving it unthreaded would recreate the run-14 bug
        class on resume (policy/evidence says mounted, runtime does
        not enforce)."""

        metadata = CheckpointMetadata(
            checkpoint_id=CheckpointId(_uuid.uuid4().hex),
            session_id="s-wake-1",
            tenant_id="t-1",
            label="__suspend__",
            created_at=datetime.now(UTC),
            policy=_policy((_RW_MOUNT,)),
            pack_context=_PACK_CTX,
            retention_window_s=86_400,
        )
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(return_value=(metadata, b"tar-bytes"))
        docker = AsyncMock()
        rego = MagicMock()
        rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=4096,
            sandbox_per_tenant_max_walltime=300.0,
        )
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=_passing_catalog(),
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=MagicMock(),
            decision_history_store=AsyncMock(),
            settings=settings,
            warm_pool=None,
            checkpoint_store=store,
            egress_proxy_image=_PROXY_IMAGE,
        )
        monkeypatch.setattr(_ds, "admit_policy", AsyncMock(return_value=None))
        monkeypatch.setattr(
            backend, "_read_suspend_event_id", AsyncMock(return_value=_uuid.uuid4())
        )
        monkeypatch.setattr(backend, "_create_internal_network", AsyncMock(return_value=None))
        monkeypatch.setattr(backend, "_create_egress_network", AsyncMock(return_value=None))
        monkeypatch.setattr(backend, "_start_proxy_sidecar", AsyncMock(return_value=None))
        start_container = AsyncMock(return_value=None)
        monkeypatch.setattr(backend, "_start_sandbox_container", start_container)
        monkeypatch.setattr(backend, "_restore_workspace_tar", AsyncMock(return_value=None))
        monkeypatch.setattr(_ds, "sandbox_lifecycle_woken", AsyncMock(return_value=None))

        await backend.wake("s-wake-1", actor=_ACTOR, tenant_id="t-1")

        start_container.assert_awaited_once()
        assert start_container.await_args is not None
        assert start_container.await_args.kwargs["policy_mounts"] == metadata.policy.writable_mounts


# ---------------------------------------------------------------------------
# KubernetesPod — fail-closed until the spec §5.5 sidecar realization lands
# ---------------------------------------------------------------------------


def _k8s_backend() -> KubernetesPodSandboxBackend:
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )
    dh_store = AsyncMock()
    dh_store.append_with_precondition.return_value = (_uuid.uuid4(), b"\x00" * 32)
    backend = KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="test-ns",
        image_catalog=_passing_catalog(),
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store,
        settings=settings,
        warm_pool=None,
        egress_proxy_image=_PROXY_IMAGE,
    )
    backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_pod_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_proxy_audit_log_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend


def _patched_k8s_admission() -> Any:
    return patch(
        "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
        new=AsyncMock(return_value=None),
    )


class TestKubernetesWritableMountsFailClosed:
    async def test_nonempty_writable_mounts_refuse_fail_closed(self) -> None:
        """K8s cannot realize host-path writable mounts (multi-node
        pods; the skill topology is same-Pod sidecar + emptyDir per
        spec §5.5, not yet landed) — so a policy that DECLARES them
        MUST refuse rather than silently run unmounted while the audit
        payload records the mount as real."""

        backend = _k8s_backend()
        with _patched_k8s_admission(), pytest.raises(SandboxLifecycleRefused) as exc_info:
            await backend.create(
                _policy((_RW_MOUNT,)),
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )
        assert exc_info.value.reason == "sandbox_writable_mounts_unsupported_on_backend"
        # Fail-fast shape check — no K8s API call, no pod, no netpol.
        backend._create_network_policy.assert_not_called()  # type: ignore[attr-defined]
        backend._create_pod.assert_not_called()  # type: ignore[attr-defined]

    async def test_empty_writable_mounts_proceed(self) -> None:
        """The default empty tuple keeps the pre-existing green path —
        the refusal fires ONLY on declared mounts."""

        backend = _k8s_backend()
        with _patched_k8s_admission():
            await backend.create(
                _policy(()),
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )
        backend._create_pod.assert_awaited_once()  # type: ignore[attr-defined]

    async def test_pair_guard_still_wins_over_writable_mounts_refusal(self) -> None:
        """ORDERING pin (T21 lock #1): the credential pair guard runs
        FIRST — a malformed ``(requires_credentials, credential_decls)``
        pair raises its ``ValueError`` even when ``writable_mounts`` is
        ALSO non-empty. The mounts fail-closed check sits AFTER the
        pair guard (still before warm pool / admission / mint); a
        refactor that hoists it above the pair guard breaks the
        established lock and fails this test."""

        backend = _k8s_backend()
        lease_request = VaultLeaseRequest(
            secret_path="database/creds/app-role",
            ttl_s=900,
            tenant_id="t-1",
            actor_ref=VaultLeaseActorRef(actor_subject="mounts-actor", actor_type="human"),
            scope_label="primary-db",
        )
        with _patched_k8s_admission(), pytest.raises(ValueError, match="non-empty"):
            await backend.create(
                _policy((_RW_MOUNT,)),  # mounts declared AND pair malformed
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(lease_request,),
                credential_decls=(),  # one-sided pair -> ValueError arm
            )

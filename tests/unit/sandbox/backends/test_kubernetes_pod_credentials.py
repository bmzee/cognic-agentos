"""Sprint 10 T10 K8s — KubernetesPodSandboxBackend credential lifecycle.

NON-env-gated unit tests pinning the T10 credential-leasing behaviour
of ``KubernetesPodSandboxBackend.create()`` + ``destroy()`` + the Q5
LOCK on ``KubernetesPodSession.checkpoint()`` / ``.suspend()`` per
Sprint-10 spec §3.6 + §4.2 + §4.2.1 + §4.3 + §4.5 + §6.1 + §7.1 + §7.2
+ §7.3.

Mirrors ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py``
in structure + watchpoint coverage, minus the 3 cross-backend
invariants now covered by ``tests/unit/sandbox/test_credential_lifecycle.py``
(mint-failure closed-enum mapping x 4 params + destroy fail-soft +
Q5 LOCK x 2). The K8s-specific axes pinned only here:

* Pre-flight proxy-image catalog refusal does NOT mint
  (K8s create() runs a canonical-image catalog check on the proxy
  sidecar image BEFORE any topology work; per the round-1 reviewer
  P1 cleanup-envelope shape, this check sits OUTSIDE the cleanup
  envelope because it allocates no state).
* K8s-specific topology shape (NetworkPolicy → Pod →
  wait_for_pod_ready) interaction with the mint loop ordering.

Uses MagicMock for the kubernetes_asyncio client + admit_policy seam
+ a hand-rolled in-process ``CredentialAdapter`` stub for the
mint/revoke behaviour, so these tests do NOT need a real K8s cluster
OR a real Vault. Mirrors the fixture pattern at
``test_kubernetes_pod_checkpoint_unit.py`` per the existing pure-unit
test convention for this directory (env-gated tests live in
``test_kubernetes_pod_lifecycle.py`` + cover the same paths
end-to-end when ``COGNIC_RUN_K8S_SANDBOX=1``).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultUnavailable,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


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
    subject="consumer-actor-id",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)
_ACTOR_REF = VaultLeaseActorRef(
    actor_subject="consumer-actor-id",
    actor_type="human",
)


def _make_lease_request(
    *,
    secret_path: str = "database/creds/app-role",
    ttl_s: int = 900,
    scope_label: str = "primary-db",
) -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=ttl_s,
        tenant_id="t-1",
        actor_ref=_ACTOR_REF,
        scope_label=scope_label,
    )


def _make_minted_lease(
    *,
    request: VaultLeaseRequest | None = None,
    lease_id: str | None = None,
    ttl_s_granted: int = 600,
    token: dict[str, str] | None = None,
) -> CredentialLease:
    req = request or _make_lease_request()
    now = datetime.now(UTC)
    return CredentialLease(
        lease_id=lease_id or f"vault-lease-{uuid.uuid4().hex[:12]}",
        request=req,
        token=token or {"username": "u", "password": "vault-token-NEVER-on-chain"},
        minted_at=now,
        ttl_s_granted=ttl_s_granted,
        expires_at=now + timedelta(seconds=ttl_s_granted),
    )


def _make_dh_store() -> AsyncMock:
    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


class _StubCredentialAdapter:
    """Hand-rolled in-process CredentialAdapter for T10 K8s unit tests.

    Identical contract to the Docker test file's ``_StubCredentialAdapter``
    so the cross-backend conformance file can use either backend's
    stub interchangeably. Drift between the two stubs is wire-protocol-
    public regression and is caught by the cross-backend conformance
    file at ``tests/unit/sandbox/test_credential_lifecycle.py``.
    """

    def __init__(self) -> None:
        self.mint_calls: list[VaultLeaseRequest] = []
        self.revoke_calls: list[str] = []
        self._mint_overrides: list[CredentialLease | Exception] = []
        self._revoke_overrides: list[None | Exception] = []

    def queue_mint_result(self, result: CredentialLease | Exception) -> None:
        self._mint_overrides.append(result)

    def queue_revoke_result(self, result: None | Exception) -> None:
        self._revoke_overrides.append(result)

    async def fetch_secret(self, path: str) -> str | None:
        raise AssertionError(
            f"_StubCredentialAdapter.fetch_secret({path!r}) called — T10 "
            "code path MUST go through mint_lease / revoke_lease only"
        )

    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        self.mint_calls.append(request)
        if self._mint_overrides:
            queued = self._mint_overrides.pop(0)
            if isinstance(queued, Exception):
                raise queued
            return queued
        return _make_minted_lease(request=request)

    async def revoke_lease(self, lease_id: str) -> None:
        self.revoke_calls.append(lease_id)
        if self._revoke_overrides:
            queued = self._revoke_overrides.pop(0)
            if isinstance(queued, Exception):
                raise queued


def _make_backend(
    *,
    dh_store: AsyncMock | None = None,
    warm_pool: AsyncMock | None = None,
    credential_adapter: Any | None = None,
) -> KubernetesPodSandboxBackend:
    """Backend wired with mocked kubernetes_asyncio client + admit_policy
    + topology seams so create()/destroy() can run without a real
    K8s cluster."""
    kube = MagicMock()
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )
    backend = KubernetesPodSandboxBackend(
        kube_api_client=kube,
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=credential_adapter or KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store or _make_dh_store(),
        settings=settings,
        warm_pool=warm_pool,
    )
    # Mock the K8s topology call sites so create()/destroy() never
    # touch a real cluster. AsyncMock with return_value=None matches
    # the live signatures' Coroutine[None, None, None] returns.
    backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_pod_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend


def _make_session(
    *,
    backend: KubernetesPodSandboxBackend,
    active_leases: tuple[CredentialLease, ...] = (),
) -> KubernetesPodSession:
    """Construct a K8s session directly (bypassing create()) for
    destroy + Q5 LOCK tests in isolation."""
    return KubernetesPodSession(
        session_id=f"sess-{uuid.uuid4().hex[:8]}",
        policy=_POLICY,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _pod_name="sb-x",
        _network_policy_name="sb-x",
        _namespace="test-ns",
        active_leases=active_leases,
    )


# ---------------------------------------------------------------------------
# Batch 1 — Protocol-compat shim cleanup + dataclass shape
# ---------------------------------------------------------------------------


class TestKubernetesPodSessionShape:
    """spec §3.6 — KubernetesPodSession carries
    ``active_leases: tuple[CredentialLease, ...]`` (field added at T10
    Docker as a Protocol-compat shim; T10 K8s exercises it via the
    real mint loop)."""

    def test_session_active_leases_field_defaults_to_empty_tuple(self) -> None:
        import dataclasses

        fields = {f.name: f for f in dataclasses.fields(KubernetesPodSession)}
        assert "active_leases" in fields
        assert fields["active_leases"].default == ()


class TestKubernetesPodCreateAcceptsRequiresCredentials:
    """spec §4.2 — SandboxBackend.create() requires_credentials kwarg
    works on K8s too (Protocol-shape conformance + bisection clean)."""

    @pytest.mark.asyncio
    async def test_create_accepts_requires_credentials_kwarg(self) -> None:
        backend = _make_backend()
        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            session = await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(),
            )
        assert session.active_leases == ()

    @pytest.mark.asyncio
    async def test_default_requires_credentials_is_empty_tuple(self) -> None:
        backend = _make_backend()
        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            session = await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )
        assert session.active_leases == ()


# ---------------------------------------------------------------------------
# Batch 2 — warm-pool short-circuit (spec §4.2.1)
# ---------------------------------------------------------------------------


class TestKubernetesWarmPoolShortCircuit:
    """spec §4.2.1 — non-empty ``requires_credentials`` forces
    cold-create; warm-pool checkout is skipped. Mirrors Docker test
    of the same name."""

    @pytest.mark.asyncio
    async def test_warm_pool_checkout_skipped_when_requires_credentials_non_empty(
        self,
    ) -> None:
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=MagicMock())
        adapter = _StubCredentialAdapter()
        backend = _make_backend(warm_pool=warm_pool, credential_adapter=adapter)

        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=True,
                requires_credentials=(_make_lease_request(),),
            )

        warm_pool.checkout.assert_not_called()

    @pytest.mark.asyncio
    async def test_warm_pool_checkout_still_consulted_when_requires_credentials_empty(
        self,
    ) -> None:
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=None)
        backend = _make_backend(warm_pool=warm_pool)

        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=True,
            )

        warm_pool.checkout.assert_awaited_once()


# ---------------------------------------------------------------------------
# Batch 3 — mint loop + emit ordering (spec §4.2 + §6.2)
# ---------------------------------------------------------------------------


class TestKubernetesMintLoopPostAdmission:
    """spec §4.2 — mint happens AFTER admit_policy AND AFTER the
    K8s-specific pre-flight proxy catalog check AND BEFORE topology.
    Per-request, in order, via ``credential_adapter.mint_lease()``."""

    @pytest.mark.asyncio
    async def test_create_mints_each_requested_lease_in_order(self) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        req_a = _make_lease_request(secret_path="database/creds/a", scope_label="a")
        req_b = _make_lease_request(secret_path="database/creds/b", scope_label="b")

        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            session = await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(req_a, req_b),
            )

        assert [r.secret_path for r in adapter.mint_calls] == [
            "database/creds/a",
            "database/creds/b",
        ]
        assert len(session.active_leases) == 2
        assert session.active_leases[0].request.secret_path == "database/creds/a"
        assert session.active_leases[1].request.secret_path == "database/creds/b"

    @pytest.mark.asyncio
    async def test_create_threads_requires_credentials_into_admit_policy(
        self,
    ) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        req = _make_lease_request()
        admit_mock = AsyncMock(return_value=None)

        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=admit_mock,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(req,),
            )

        admit_mock.assert_awaited_once()
        await_args = admit_mock.await_args
        assert await_args is not None
        call_kwargs = await_args.kwargs
        assert "requires_credentials" in call_kwargs
        assert tuple(call_kwargs["requires_credentials"]) == (req,)

    @pytest.mark.asyncio
    async def test_create_emits_lease_minted_helper_before_lifecycle_created(
        self,
    ) -> None:
        """spec §6.2 — chain row order: lease_minted (per mint)
        precedes lifecycle.created (after topology)."""
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        assert emitted_types.count("sandbox.lifecycle.lease_minted") == 1
        idx_minted = emitted_types.index("sandbox.lifecycle.lease_minted")
        idx_created = emitted_types.index("sandbox.lifecycle.created")
        assert idx_minted < idx_created


# ---------------------------------------------------------------------------
# Batch 4 — mint failure best-effort cleanup (spec §7.1)
# ---------------------------------------------------------------------------


class TestKubernetesMintFailureBestEffortCleanup:
    """spec §7.1 line 649 — mid-batch mint failure best-effort
    revokes leases minted earlier in the same create() attempt.
    Cross-backend mint-failure CLOSED-ENUM MAPPING (per Vault
    exception type → ``sandbox_credential_mint_failed_*``) is
    covered by the parametrized cross-backend file at
    ``tests/unit/sandbox/test_credential_lifecycle.py``; this class
    pins the K8s-specific cleanup behaviour."""

    @pytest.mark.asyncio
    async def test_mid_batch_failure_revokes_already_minted(self) -> None:
        adapter = _StubCredentialAdapter()
        first_lease = _make_minted_lease(lease_id="lease-first")
        adapter.queue_mint_result(first_lease)
        adapter.queue_mint_result(VaultUnavailable("vault 5xx"))
        backend = _make_backend(credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(SandboxLifecycleRefused) as exc_info,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                    _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                ),
            )

        assert exc_info.value.reason == "sandbox_credential_mint_failed_vault_unavailable"
        assert "lease-first" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_mid_batch_failure_swallows_secondary_revoke_failure(self) -> None:
        """The ORIGINAL mint-failure refusal wins even when the
        cleanup revoke ALSO fails — pinned at Docker round-1; mirror
        here for K8s parity."""
        adapter = _StubCredentialAdapter()
        first_lease = _make_minted_lease(lease_id="lease-first")
        adapter.queue_mint_result(first_lease)
        adapter.queue_mint_result(VaultAuthDenied("403 on path-b"))
        adapter.queue_revoke_result(VaultUnavailable("vault 5xx during cleanup"))
        backend = _make_backend(credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(SandboxLifecycleRefused) as exc_info,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                    _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                ),
            )

        assert exc_info.value.reason == "sandbox_credential_mint_failed_auth_denied"


# ---------------------------------------------------------------------------
# Batch 5 — destroy fail-soft revoke (spec §4.3 + §7.2). Cross-backend
# basic case lives in the conformance file; per-backend K8s-specific
# emit ordering + payload shape regressions live here.
# ---------------------------------------------------------------------------


class TestKubernetesDestroyRevokeLoop:
    @pytest.mark.asyncio
    async def test_destroy_revokes_each_active_lease(self) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        lease_a = _make_minted_lease(lease_id="lease-a")
        lease_b = _make_minted_lease(lease_id="lease-b")
        session = _make_session(backend=backend, active_leases=(lease_a, lease_b))

        await backend.destroy(session)

        assert adapter.revoke_calls == ["lease-a", "lease-b"]

    @pytest.mark.asyncio
    async def test_destroy_emits_lease_revoked_before_lifecycle_destroyed(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        lease = _make_minted_lease(lease_id="lease-ok")
        session = _make_session(backend=backend, active_leases=(lease,))

        await backend.destroy(session)

        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        assert "sandbox.lifecycle.lease_revoked" in emitted_types
        assert "sandbox.lifecycle.destroyed" in emitted_types
        assert emitted_types.index("sandbox.lifecycle.lease_revoked") < emitted_types.index(
            "sandbox.lifecycle.destroyed"
        )

    @pytest.mark.asyncio
    async def test_destroy_emits_lease_revoke_failed_with_vault_error_and_continues(
        self,
    ) -> None:
        """spec §7.2 — single revoke attempt per lease; on failure
        emit lease_revoke_failed carrying vault_error + continue
        cleanup; never raise."""
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        adapter.queue_revoke_result(VaultUnavailable("vault 503"))
        adapter.queue_revoke_result(None)  # second revoke succeeds
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        lease_fail = _make_minted_lease(lease_id="lease-fail")
        lease_ok = _make_minted_lease(lease_id="lease-ok")
        session = _make_session(backend=backend, active_leases=(lease_fail, lease_ok))

        await backend.destroy(session)

        assert adapter.revoke_calls == ["lease-fail", "lease-ok"]
        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        assert "sandbox.lifecycle.lease_revoke_failed" in emitted_types
        assert "sandbox.lifecycle.lease_revoked" in emitted_types

        for call in dh_store.append_with_precondition.await_args_list:
            record = call.kwargs["record_builder"](None)
            if record.decision_type == "sandbox.lifecycle.lease_revoke_failed":
                assert "vault_error" in record.payload
                assert "vault 503" in record.payload["vault_error"]

    @pytest.mark.asyncio
    async def test_destroy_with_no_active_leases_emits_zero_lease_events(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        session = _make_session(backend=backend)

        await backend.destroy(session)

        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        assert not any(t.startswith("sandbox.lifecycle.lease_") for t in emitted_types)
        assert adapter.revoke_calls == []


# ---------------------------------------------------------------------------
# Batch 6 — Q5 LOCK on checkpoint + suspend (spec §4.5). Cross-backend
# parity tests for the positive cases live in the conformance file;
# the symmetric backward-compat regressions (lease-less session
# DOES NOT trip the Q5 lock) live per-backend.
# ---------------------------------------------------------------------------


class TestKubernetesQ5LockSymmetricBackwardCompat:
    @pytest.mark.asyncio
    async def test_checkpoint_does_not_q5_block_when_active_leases_empty(
        self,
    ) -> None:
        """A lease-less K8s session takes the existing 8.5 checkpoint
        path — Q5 lock does NOT fire. Assert error message does NOT
        mention "Sprint 10.x" (would mean Q5 lock fired)."""
        backend = _make_backend()
        session = _make_session(backend=backend)

        with pytest.raises(NotImplementedError) as exc_info:
            await session.checkpoint("label")
        assert "Sprint 10.x" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_suspend_does_not_q5_block_when_active_leases_empty(
        self,
    ) -> None:
        backend = _make_backend()
        session = _make_session(backend=backend)

        with pytest.raises(NotImplementedError) as exc_info:
            await session.suspend()
        assert "Sprint 10.x" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Batch 7 — K8s-specific: pre-flight proxy-image refusal MUST NOT mint
# ---------------------------------------------------------------------------


class TestKubernetesPreflightProxyRefusalDoesNotMint:
    """K8s create() runs a canonical-image catalog check on the proxy
    sidecar image BEFORE the mint loop per the round-1 reviewer P1
    cleanup-envelope shape (proxy verification is pure shape +
    allocates no state → stays OUTSIDE the cleanup envelope so a
    proxy-refusal doesn't trigger no-op cleanup of zero state).

    Pinning that ordering is critical because a future refactor that
    reorders pre-flight AFTER mint would silently allocate leases
    for sessions that proxy-refusal aborts — leases would leak."""

    @pytest.mark.asyncio
    async def test_canonical_catalog_refusal_aborts_before_mint(self) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        # Force pre-flight refusal: catalog.is_canonical returns False
        # for the proxy image.
        catalog_mock = cast(MagicMock, backend._catalog)
        catalog_mock.is_canonical.return_value = False

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(SandboxLifecycleRefused) as exc_info,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        assert exc_info.value.reason == "sandbox_image_digest_not_in_canonical_catalog"
        # Mint MUST NOT have been called — the pre-flight aborted
        # BEFORE the cleanup envelope opened.
        assert adapter.mint_calls == []
        # Revoke MUST NOT have been called either (nothing to clean
        # up — symmetric proof that pre-flight sits OUTSIDE the
        # cleanup envelope).
        assert adapter.revoke_calls == []


# ---------------------------------------------------------------------------
# Batch 8 — non-Vault post-mint cleanup envelope (spec §7.3 row
# "Any backend failure post-mint"). Mirrors the Docker reviewer P1
# round-2 + round-3 4-regression matrix:
#
# 1. lease_minted audit emit raises mid-batch (DH unavailable etc.)
# 2. Topology build raises after mint (K8s _create_pod / NetworkPolicy / wait)
# 3. lifecycle.created emit raises after Session construct
# 4. asyncio.CancelledError during the post-mint try body
#
# All 4 paths converge on the K8s _cleanup_post_admission_failure
# helper. CancelledError is load-bearing because
# asyncio.CancelledError subclasses BaseException NOT Exception
# (Python 3.8+ MRO change), so a generic ``except Exception`` does
# NOT catch it — without the explicit asyncio.CancelledError arm a
# cancelled create() task would leak leases.
# ---------------------------------------------------------------------------


class TestKubernetesPostMintCleanupOnNonVaultFailure:
    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_lease_minted_emit_fails(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        dh_store.append_with_precondition.side_effect = RuntimeError("DH chain head conflict")
        adapter = _StubCredentialAdapter()
        adapter.queue_mint_result(_make_minted_lease(lease_id="lease-emit-fail"))
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(RuntimeError, match="DH chain head conflict"),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        assert "lease-emit-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_topology_fails(self) -> None:
        adapter = _StubCredentialAdapter()
        adapter.queue_mint_result(_make_minted_lease(lease_id="lease-topology-fail"))
        backend = _make_backend(credential_adapter=adapter)
        # Inject K8s topology failure: _create_pod raises after mint.
        cast(AsyncMock, backend._create_pod).side_effect = RuntimeError(
            "K8s API refused Pod creation"
        )

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(RuntimeError, match="K8s API refused Pod creation"),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        assert "lease-topology-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_lifecycle_created_emit_fails(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        dh_store.append_with_precondition.side_effect = [
            (uuid.uuid4(), b"\x00" * 32),  # lease_minted succeeds
            RuntimeError("DH canonical-form rejection"),  # lifecycle.created fails
        ]
        adapter = _StubCredentialAdapter()
        adapter.queue_mint_result(_make_minted_lease(lease_id="lease-lifecycle-emit-fail"))
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(RuntimeError, match="DH canonical-form rejection"),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        assert "lease-lifecycle-emit-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_create_cancelled_post_mint(
        self,
    ) -> None:
        """Reviewer P1 from Docker round-3 carried forward to K8s:
        asyncio.CancelledError subclasses BaseException NOT Exception
        (Python 3.8+ MRO: [CancelledError, BaseException, object];
        issubclass(asyncio.CancelledError, Exception) is False).
        Without the explicit except asyncio.CancelledError arm a
        cancelled create() task would skip cleanup + leak the lease."""
        dh_store = _make_dh_store()
        dh_store.append_with_precondition.side_effect = asyncio.CancelledError()
        adapter = _StubCredentialAdapter()
        adapter.queue_mint_result(_make_minted_lease(lease_id="lease-cancelled-post-mint"))
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
            )

        assert "lease-cancelled-post-mint" in adapter.revoke_calls

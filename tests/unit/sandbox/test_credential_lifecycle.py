"""Sprint 10 T10 — cross-backend credential-lifecycle conformance.

Per the plan T10 fileset: cross-backend abstract conformance tests
applied to BOTH backends via parametrized fixture. The Docker half
ships in the T10 Docker commit; the K8s commit extends the
parametrize to run the same tests against
``KubernetesPodSandboxBackend``.

The CONTRACT pinned here is symmetric across backends — drift
between Docker + K8s on any of these axes is wire-protocol-public
regression (the closed-enum vocabulary lives in
``sandbox/protocol.py``'s ``SandboxRefusalReason`` +
``SandboxLifecycleEvent`` Literals; emission goes through the
backend-agnostic typed helpers at ``sandbox/audit.py``).

What the conformance tests cover (one regression each — backend-
specific edge cases live in the per-backend test files):

* Mint-failure exception → ``sandbox_credential_mint_failed_*``
  closed-enum reason mapping (per spec §7.1 + the module-level
  ``_mint_exception_to_refusal_reason`` helper at
  ``sandbox/backends/docker_sibling.py:_mint_exception_to_refusal_reason``).
* Destroy-time fail-soft revoke — destroy() never raises even when
  every revoke fails (per spec §7.2).
* Q5 LOCK — session.checkpoint() + session.suspend() raise
  ``NotImplementedError`` on non-empty ``active_leases`` (per spec
  §4.5).

Backend-specific concerns (warm-pool short-circuit, container vs
Pod topology, etc.) stay in the per-backend test files
(``test_docker_sibling_credentials.py`` for Docker; the K8s
counterpart lands at the T10 K8s commit).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ---------------------------------------------------------------------------
# Shared fixture data
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


def _make_lease_request() -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path="database/creds/app-role",
        ttl_s=900,
        tenant_id="t-1",
        actor_ref=_ACTOR_REF,
        scope_label="primary-db",
    )


def _make_minted_lease(*, lease_id: str = "lease-abc") -> CredentialLease:
    now = datetime.now(UTC)
    return CredentialLease(
        lease_id=lease_id,
        request=_make_lease_request(),
        token={"username": "u", "password": "p-NEVER-on-chain"},
        minted_at=now,
        ttl_s_granted=600,
        expires_at=now + timedelta(seconds=600),
    )


class _StubAdapter:
    """Records mint/revoke + can be primed with per-call results.
    Mirrors the stub at ``test_docker_sibling_credentials.py`` so
    cross-backend tests can use the same fixture pattern."""

    def __init__(self) -> None:
        self.mint_calls: list[VaultLeaseRequest] = []
        self.revoke_calls: list[str] = []
        self._mint_overrides: list[CredentialLease | Exception] = []
        self._revoke_overrides: list[None | Exception] = []

    def queue_mint(self, result: CredentialLease | Exception) -> None:
        self._mint_overrides.append(result)

    def queue_revoke(self, result: None | Exception) -> None:
        self._revoke_overrides.append(result)

    async def fetch_secret(self, path: str) -> str | None:
        raise AssertionError(f"fetch_secret({path!r}) called — T10 path uses mint/revoke only")

    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        self.mint_calls.append(request)
        if self._mint_overrides:
            queued = self._mint_overrides.pop(0)
            if isinstance(queued, Exception):
                raise queued
            return queued
        return _make_minted_lease()

    async def revoke_lease(self, lease_id: str) -> None:
        self.revoke_calls.append(lease_id)
        if self._revoke_overrides:
            queued = self._revoke_overrides.pop(0)
            if isinstance(queued, Exception):
                raise queued


def _make_docker_backend(
    *,
    adapter: Any | None = None,
) -> DockerSiblingSandboxBackend:
    """Construct a mocked-aiodocker ``DockerSiblingSandboxBackend`` for
    the Docker half of the conformance tests."""
    import aiodocker

    docker = MagicMock()
    docker.networks.create = AsyncMock()
    docker.containers.create_or_replace = AsyncMock()
    docker.containers.create_or_replace.return_value.start = AsyncMock()
    docker.containers.get = AsyncMock(
        side_effect=aiodocker.exceptions.DockerError(404, "not found")
    )
    mock_network = MagicMock()
    mock_network.connect = AsyncMock()
    mock_network.delete = AsyncMock()
    docker.networks.get = AsyncMock(return_value=mock_network)
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    decision = MagicMock()
    decision.allow = True
    decision.reasoning = ""
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )
    dh = AsyncMock()
    dh.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=adapter or KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh,
        settings=settings,
        warm_pool=None,
    )


def _make_docker_session(
    *,
    backend: DockerSiblingSandboxBackend,
    active_leases: tuple[CredentialLease, ...] = (),
) -> DockerSiblingSession:
    return DockerSiblingSession(
        session_id=f"sess-{uuid.uuid4().hex[:8]}",
        policy=_POLICY,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name="cognic-sb-internal-x",
        _sidecar_container_name="x-proxy",
        _egress_network_name="cognic-sb-egress-x",
        active_leases=active_leases,
    )


# ---------------------------------------------------------------------------
# Parametrized fixtures — Docker half ships now; the T10 K8s commit
# adds a ``"k8s"`` entry to the params list + the corresponding
# fixture-builder helper above.
# ---------------------------------------------------------------------------


@pytest.fixture(
    params=[
        "docker",
        # T10 K8s commit appends: "k8s",
    ],
)
def backend_kind(request: pytest.FixtureRequest) -> str:
    param: str = request.param
    return param


@pytest.fixture
def backend_and_adapter(backend_kind: str) -> tuple[Any, _StubAdapter]:
    adapter = _StubAdapter()
    if backend_kind == "docker":
        backend = _make_docker_backend(adapter=adapter)
        return backend, adapter
    # T10 K8s commit adds:
    # if backend_kind == "k8s":
    #     backend = _make_k8s_backend(adapter=adapter)
    #     return backend, adapter
    raise AssertionError(  # pragma: no cover
        f"unknown backend_kind {backend_kind!r} — Docker ships now; K8s "
        "extends in the T10 K8s commit"
    )


@pytest.fixture
def session_factory(
    backend_kind: str,
) -> Callable[..., Any]:
    if backend_kind == "docker":

        def _factory(
            backend: Any, *, active_leases: tuple[CredentialLease, ...] = ()
        ) -> DockerSiblingSession:
            return _make_docker_session(backend=backend, active_leases=active_leases)

        return _factory
    # T10 K8s commit adds: similar _factory for KubernetesPodSession
    raise AssertionError(  # pragma: no cover
        f"unknown backend_kind {backend_kind!r}"
    )


# ---------------------------------------------------------------------------
# Cross-backend conformance — mint-failure mapping (spec §7.1)
# ---------------------------------------------------------------------------


class TestCrossBackendMintFailureMapping:
    """spec §7.1 — every backend MUST collapse the 4-value core.vault
    exception taxonomy onto the same 3-value
    ``sandbox_credential_mint_failed_*`` closed-enum vocabulary.
    Drift between backends is wire-protocol-public regression."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("exc_factory", "expected_reason"),
        [
            (
                lambda: VaultUnavailable("vault 5xx"),
                "sandbox_credential_mint_failed_vault_unavailable",
            ),
            (
                lambda: VaultPathNotFound("404 on path"),
                "sandbox_credential_mint_failed_secret_path_unknown",
            ),
            (
                lambda: VaultAuthDenied("403 on path"),
                "sandbox_credential_mint_failed_auth_denied",
            ),
            (
                lambda: VaultProtocolError("malformed"),
                "sandbox_credential_mint_failed_vault_unavailable",
            ),
        ],
    )
    async def test_mint_failure_raises_mapped_closed_enum(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        exc_factory: Any,
        expected_reason: str,
    ) -> None:
        backend, adapter = backend_and_adapter
        adapter.queue_mint(exc_factory())

        with (
            patch(
                "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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

        assert exc_info.value.reason == expected_reason


# ---------------------------------------------------------------------------
# Cross-backend conformance — destroy fail-soft (spec §7.2)
# ---------------------------------------------------------------------------


class TestCrossBackendDestroyFailSoft:
    """spec §7.2 — destroy() NEVER raises, even when every revoke
    fails. Vault TTL is the operational safety net."""

    @pytest.mark.asyncio
    async def test_destroy_does_not_raise_when_all_revokes_fail(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        backend, adapter = backend_and_adapter
        # Every revoke fails:
        adapter.queue_revoke(VaultUnavailable("vault 503"))
        adapter.queue_revoke(VaultAuthDenied("403"))

        session = session_factory(
            backend,
            active_leases=(
                _make_minted_lease(lease_id="lease-1"),
                _make_minted_lease(lease_id="lease-2"),
            ),
        )

        # MUST NOT raise — fail-soft per spec §7.2.
        await backend.destroy(session)

        # Both revoke attempts made (single attempt per lease).
        assert adapter.revoke_calls == ["lease-1", "lease-2"]


# ---------------------------------------------------------------------------
# Cross-backend conformance — Q5 LOCK (spec §4.5)
# ---------------------------------------------------------------------------


class TestCrossBackendQ5Lock:
    """spec §4.5 — every backend's session implementation MUST raise
    NotImplementedError on checkpoint()/suspend() when active_leases
    is non-empty. Resolution of the leased-session checkpoint/suspend
    model is deferred to a follow-up sprint."""

    @pytest.mark.asyncio
    async def test_checkpoint_raises_not_implemented_on_leased_session(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        backend, _ = backend_and_adapter
        session = session_factory(backend, active_leases=(_make_minted_lease(),))

        with pytest.raises(NotImplementedError, match=r"Sprint 10\.x"):
            await session.checkpoint("label")

    @pytest.mark.asyncio
    async def test_suspend_raises_not_implemented_on_leased_session(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        backend, _ = backend_and_adapter
        session = session_factory(backend, active_leases=(_make_minted_lease(),))

        with pytest.raises(NotImplementedError, match=r"Sprint 10\.x"):
            await session.suspend()

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
  ``sandbox/backends/_shared_credentials.py:_mint_exception_to_refusal_reason``
  — moved out of ``docker_sibling.py`` at T10 K8s round-2 reviewer-P1
  per Gap I; see the dependency-neutral contract pin at
  ``tests/unit/sandbox/backends/test_shared_credentials.py``).
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
from typing import Any, cast
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
from cognic_agentos.sandbox._preflight import PreflightResult
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
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


def _make_credential_decl_for_request(
    req: VaultLeaseRequest,
    *,
    logical_name: str = "app_role",
) -> Any:
    """Sprint 10.6 T21 — derive a ``CredentialDecl`` from a paired
    ``VaultLeaseRequest`` so the T21 pair-invariant guard passes by
    construction:

      * ``vault_path = req.secret_path``
      * ``tenant_id = req.tenant_id``
      * ``ttl_s     = req.ttl_s``

    Multi-credential tests pass distinct ``logical_name`` per call
    so the per-credential audit rows stay disambiguated.
    """
    from cognic_agentos.sandbox.projection import CredentialDecl

    return CredentialDecl(
        logical_name=logical_name,
        vault_path=req.secret_path,
        expected_fields=["password", "username"],
        ttl_s=req.ttl_s,
        purpose_category="application_database_read",
        purpose_description="Cross-backend conformance test.",
        tenant_id=req.tenant_id,
    )


def _make_credential_decl() -> Any:
    """Convenience for the default ``_make_lease_request()`` shape."""
    return _make_credential_decl_for_request(_make_lease_request())


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
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=adapter or KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh,
        settings=settings,
        warm_pool=None,
    )
    # Sprint 10.6 T21 — pre-mock the substrate preflight + cleanup +
    # T19 executor seams so cross-backend lifecycle tests don't need
    # ``/proc/mounts`` / ``/dev/shm/cognic`` provisioning on macOS.
    backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
        return_value=PreflightResult(
            resolved_gid=1000,
            file_mode=0o440,
            dir_mode=0o750,
            dev_escape_downgrade_reason=None,
        )
    )
    backend._cleanup_projection_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]

    async def _stub_execute(
        *, plan: Any, preflight: Any, session_opaque: str, credential_opaque: str
    ) -> Any:
        from cognic_agentos.sandbox.backends._docker_executor import (
            ProjectionExecutorResult,
        )

        return ProjectionExecutorResult(
            logical_name=plan.logical_name,
            vault_path=plan.vault_path,
            tenant_id=plan.tenant_id,
            lease_id=plan.lease_id,
            projected_field_count=plan.projected_field_count,
            purpose_category=plan.purpose_category,
            purpose_description=plan.purpose_description,
            host_staging_dir=f"/dev/shm/cognic/{session_opaque}/{credential_opaque}",
            container_mount_target=f"/run/credentials/{plan.logical_name}",
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
            dev_escape_downgrade_reason=None,
        )

    backend._execute_projection_plan_docker = _stub_execute  # type: ignore[method-assign]

    # Mock the Docker teardown call so cross-backend regressions can
    # inject teardown-failure side_effects symmetrically with the
    # K8s fixture below (per the round-2 reviewer-P2 cross-backend
    # invariant that destroy() revokes leases even when teardown
    # raises).
    backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend


def _make_k8s_backend(
    *,
    adapter: Any | None = None,
) -> KubernetesPodSandboxBackend:
    """Construct a mocked-kubernetes_asyncio ``KubernetesPodSandboxBackend``
    for the K8s half of the conformance tests. Topology call sites
    mocked so create()/destroy() never touch a real cluster."""
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
    dh = AsyncMock()
    dh.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    backend = KubernetesPodSandboxBackend(
        kube_api_client=kube,
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=adapter or KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh,
        settings=settings,
        warm_pool=None,
    )
    backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_pod_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    # T30/T14.2 — create() now also gates on the proxy-log readiness probe.
    backend._wait_for_proxy_audit_log_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
    # Sprint 10.6 T21 slice 5+6 — pre-mock the K8s preflight + the
    # K8s Secret-create + Secret-delete seams so cross-backend
    # lifecycle tests don't need a real cluster.
    backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
        return_value=PreflightResult(
            resolved_gid=1000,
            file_mode=0o440,
            dir_mode=0o750,
            dev_escape_downgrade_reason=None,
        )
    )
    backend._k8s_create_namespaced_secret = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._k8s_delete_namespaced_secret = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend


def _make_k8s_session(
    *,
    backend: KubernetesPodSandboxBackend,
    active_leases: tuple[CredentialLease, ...] = (),
) -> KubernetesPodSession:
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
        "k8s",
    ],
)
def backend_kind(request: pytest.FixtureRequest) -> str:
    param: str = request.param
    return param


@pytest.fixture
def backend_and_adapter(backend_kind: str) -> tuple[Any, _StubAdapter]:
    adapter = _StubAdapter()
    backend: Any
    if backend_kind == "docker":
        backend = _make_docker_backend(adapter=adapter)
        return backend, adapter
    if backend_kind == "k8s":
        backend = _make_k8s_backend(adapter=adapter)
        return backend, adapter
    raise AssertionError(  # pragma: no cover
        f"unknown backend_kind {backend_kind!r}"
    )


@pytest.fixture
def admit_policy_patch_path(backend_kind: str) -> str:
    """Module-path string for ``patch(...)`` targeting the
    ``admit_policy`` import binding in each backend's namespace.
    Python patches the binding where it's LOOKED UP — each backend
    imports admit_policy into its own module namespace — so the
    cross-backend tests dispatch the patch target per-backend.
    """
    if backend_kind == "docker":
        return "cognic_agentos.sandbox.backends.docker_sibling.admit_policy"
    if backend_kind == "k8s":
        return "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy"
    raise AssertionError(  # pragma: no cover
        f"unknown backend_kind {backend_kind!r}"
    )


@pytest.fixture
def session_factory(
    backend_kind: str,
) -> Callable[..., Any]:
    if backend_kind == "docker":

        def _docker_factory(
            backend: Any, *, active_leases: tuple[CredentialLease, ...] = ()
        ) -> DockerSiblingSession:
            return _make_docker_session(backend=backend, active_leases=active_leases)

        return _docker_factory
    if backend_kind == "k8s":

        def _k8s_factory(
            backend: Any, *, active_leases: tuple[CredentialLease, ...] = ()
        ) -> KubernetesPodSession:
            return _make_k8s_session(backend=backend, active_leases=active_leases)

        return _k8s_factory
    raise AssertionError(  # pragma: no cover
        f"unknown backend_kind {backend_kind!r}"
    )


# ---------------------------------------------------------------------------
# Cross-backend conformance — mint-failure mapping (spec §7.1)
# ---------------------------------------------------------------------------


class TestCrossBackendMintFailureMapping:
    """spec §7.1 — every backend MUST collapse the hvac-mapped subset
    of the 5-value core.vault exception taxonomy (4 hvac-mapped values:
    ``VaultUnavailable`` / ``VaultPathNotFound`` / ``VaultAuthDenied``
    / ``VaultProtocolError``) onto the 3-value
    ``sandbox_credential_mint_failed_*`` closed-enum vocabulary.
    Drift between backends is wire-protocol-public regression.

    Sprint-10.1 amendment per ADR-004 §25 — the 5th value
    ``VaultLeaseGrantExceedsRequest`` (post-mint granted-vs-requested
    TTL refusal) maps to its OWN closed-enum value
    ``sandbox_credential_lease_ttl_grant_exceeds_request`` (NOT one
    of the ``mint_failed_*`` set) at the same cross-backend boundary;
    that mapping is covered by the dedicated Sprint-10.1 backend test
    classes at
    ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py::TestGrantExceedsRequestClosedEnumMapping``
    +
    ``tests/unit/sandbox/backends/test_kubernetes_pod_credentials.py::TestKubernetesGrantExceedsRequestClosedEnumMapping``
    rather than as a 5th parametrize row here, because the new
    exception's source (post-mint enforcement) is conceptually
    distinct from the hvac-mapped mint-failure path this class
    covers."""

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
        admit_policy_patch_path: str,
        exc_factory: Any,
        expected_reason: str,
    ) -> None:
        backend, adapter = backend_and_adapter
        adapter.queue_mint(exc_factory())

        with (
            patch(admit_policy_patch_path, new=AsyncMock(return_value=None)),
            pytest.raises(SandboxLifecycleRefused) as exc_info,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl(),),
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


class TestCrossBackendDestroyAuditEmitConditionalSuppress:
    """Reviewer P1 from T10 K8s round 3 (2026-05-24): the round-2 fix
    wrapped audit emits in ``contextlib.suppress(Exception)``
    UNCONDITIONALLY to prevent the audit-emit exception from
    shadowing the teardown exception on the teardown-failure path
    (Python finally-block semantics). But that also silently
    suppressed audit-emit failures on the NORMAL path (teardown
    succeeded), which violates spec §7.2's bank-grade contract:
    "banks have audit evidence for every revoke failure".

    The fix: condition the suppress on whether teardown succeeded.
    On the teardown-failure path the suppress stays (preserve the
    teardown exception per Python finally semantics). On the normal
    path the suppress goes away (audit-emit failures propagate so
    operators see them rather than silently losing audit evidence).

    Cross-backend invariant — same contract on Docker + K8s. Drift
    fires at this one site for both backends.
    """

    @pytest.mark.asyncio
    async def test_destroy_propagates_audit_emit_failure_on_normal_path_when_revoke_succeeded(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        """Normal destroy (teardown succeeded), revoke succeeded,
        but the ``sandbox.lifecycle.lease_revoked`` audit emit
        raises (DH chain head conflict / canonical-form rejection /
        etc.). The emit exception MUST propagate so banks see the
        audit-chain failure rather than silently lose evidence of a
        successful revoke.

        Side-effect setup: ONLY the first DH append raises (the
        lease_revoked emit); subsequent appends (lifecycle.destroyed,
        tombstone, etc.) would succeed if reached — this ensures the
        test fires for the right reason (a vacuous unconditional
        side_effect would let an unconditional suppress pass silently
        and then a LATER emit raises, masking what was actually
        tested).
        """
        backend, adapter = backend_and_adapter
        cast(AsyncMock, backend._dh).append_with_precondition.side_effect = [
            RuntimeError("DH chain head conflict during lease_revoked emit"),
            # Any subsequent emits (lifecycle.destroyed etc.) would
            # succeed — proves the propagation is FROM the lease_revoked
            # emit, NOT a later emit.
            (uuid.uuid4(), b"\x00" * 32),
            (uuid.uuid4(), b"\x00" * 32),
        ]
        session = session_factory(
            backend,
            active_leases=(_make_minted_lease(lease_id="lease-1"),),
        )

        with pytest.raises(RuntimeError, match="DH chain head conflict"):
            await backend.destroy(session)

        # Revoke DID succeed before the emit failure.
        assert adapter.revoke_calls == ["lease-1"]

    @pytest.mark.asyncio
    async def test_destroy_propagates_audit_emit_failure_on_normal_path_when_revoke_failed(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        """Normal destroy (teardown succeeded), revoke RAISED, then
        the ``sandbox.lifecycle.lease_revoke_failed`` audit emit
        ALSO raises. The audit-emit exception MUST propagate — spec
        §7.2's "banks have audit evidence for every revoke failure"
        is the bank-grade contract that silently swallowing
        revoke-failure evidence violates."""
        backend, adapter = backend_and_adapter
        adapter.queue_revoke(VaultUnavailable("vault 503 during revoke"))
        # ONLY the first DH append (lease_revoke_failed for the failed
        # revoke) raises; subsequent emits would succeed (see the
        # vacuous-test rationale above).
        cast(AsyncMock, backend._dh).append_with_precondition.side_effect = [
            RuntimeError("DH canonical-form rejection during lease_revoke_failed emit"),
            (uuid.uuid4(), b"\x00" * 32),
            (uuid.uuid4(), b"\x00" * 32),
        ]
        session = session_factory(
            backend,
            active_leases=(_make_minted_lease(lease_id="lease-1"),),
        )

        with pytest.raises(RuntimeError, match="DH canonical-form rejection"):
            await backend.destroy(session)

        assert adapter.revoke_calls == ["lease-1"]

    @pytest.mark.asyncio
    async def test_destroy_normal_path_still_revokes_remaining_leases_after_emit_failure(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        """Reviewer P2 from T10 K8s round-4 (2026-05-24): the round-3
        conditional-suppress fix propagated audit-emit exceptions
        IMMEDIATELY on the normal path. With multiple active leases,
        an emit failure on lease 1 aborted the loop and lease 2
        never got its revoke attempt — leaving Vault TTL as the
        first line of defence for the remaining leases, which
        undercuts spec §7.2's single-attempt-per-lease cleanup
        contract.

        Fix shape: capture the FIRST audit-emit exception, continue
        the loop so every lease gets its revoke attempt + emit, and
        raise the captured exception AFTER the loop. Bank-grade
        audit-evidence contract still surfaces (operator sees the
        exception) AND every lease gets its single attempt per §7.2.

        Cross-backend invariant — same contract on Docker + K8s."""
        backend, adapter = backend_and_adapter
        # Lease 1's lease_revoked emit raises; lease 2's lease_revoked
        # emit succeeds; subsequent emits (lifecycle.destroyed) would
        # also succeed if reached.
        cast(AsyncMock, backend._dh).append_with_precondition.side_effect = [
            RuntimeError("DH conflict during lease-1 lease_revoked emit"),
            (uuid.uuid4(), b"\x00" * 32),
            (uuid.uuid4(), b"\x00" * 32),
        ]
        session = session_factory(
            backend,
            active_leases=(
                _make_minted_lease(lease_id="lease-1"),
                _make_minted_lease(lease_id="lease-2"),
            ),
        )

        # The first emit exception MUST eventually propagate — the
        # bank audit-evidence contract is not silently swallowed.
        with pytest.raises(RuntimeError, match="DH conflict during lease-1"):
            await backend.destroy(session)

        # AND every lease MUST have gotten its single revoke attempt
        # per spec §7.2 — the emit failure on lease 1 did NOT abort
        # the loop before lease 2's revoke.
        assert adapter.revoke_calls == ["lease-1", "lease-2"]

    @pytest.mark.asyncio
    async def test_destroy_preserves_teardown_exception_when_emit_also_raises(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        """Teardown-failure path: teardown raises AND the audit
        emit in finally ALSO raises. The ORIGINAL teardown exception
        MUST propagate (audit-emit failure suppressed) — operators
        need to see the actual teardown error, not the secondary
        audit failure that fired because of it."""
        backend, adapter = backend_and_adapter
        cast(AsyncMock, backend._teardown_session_state).side_effect = RuntimeError(
            "teardown-error-must-propagate"
        )
        adapter.queue_revoke(VaultUnavailable("vault 503 during revoke"))
        # Audit emit also raises:
        cast(AsyncMock, backend._dh).append_with_precondition.side_effect = RuntimeError(
            "DH conflict during emit; MUST be suppressed to preserve teardown exception"
        )
        session = session_factory(
            backend,
            active_leases=(_make_minted_lease(lease_id="lease-1"),),
        )

        # The TEARDOWN exception wins, not the DH/emit one.
        with pytest.raises(RuntimeError, match="teardown-error-must-propagate"):
            await backend.destroy(session)

        # Revoke still attempted in the finally branch.
        assert adapter.revoke_calls == ["lease-1"]


class TestCrossBackendDestroyRevokesEvenWhenTeardownRaises:
    """Reviewer P2 from T10 K8s round 2: destroy() awaits
    ``_teardown_session_state`` BEFORE the active-lease revoke loop.
    K8s teardown intentionally PROPAGATES non-404 ApiException per
    its docstring ("fail-closed so a real teardown failure does not
    silently leak"); Docker teardown swallows only DockerError so
    non-DockerError surfaces likewise. If the teardown propagation
    fires, the function exits before the revoke loop runs and the
    active leases never get revoked — they sit in Vault until
    server-side TTL.

    Cross-backend invariant: destroy() MUST best-effort revoke
    active leases EVEN WHEN the teardown raises. Per spec §7.2 the
    Vault TTL is the FINAL safety net (not the FIRST line of
    defence); the destroy() revoke is the operational guarantee
    examiners + SOC depend on for the "lease lifetime ≤ session
    lifetime" claim.

    Fix shape per the reviewer's suggestion: try/finally around
    teardown so the revoke loop runs in the finally branch
    regardless of whether teardown raised. The original teardown
    exception still propagates after the finally — semantically
    correct (the session WASN'T cleanly destroyed) but examiners
    have audit evidence that the leases were revoked.
    """

    @pytest.mark.asyncio
    async def test_destroy_revokes_active_leases_when_teardown_raises(
        self,
        backend_and_adapter: tuple[Any, _StubAdapter],
        session_factory: Any,
    ) -> None:
        backend, adapter = backend_and_adapter
        # Inject teardown failure on BOTH backends. Both _make_*_backend
        # fixtures mock _teardown_session_state as AsyncMock — overriding
        # side_effect simulates the non-404 propagation path.
        cast(AsyncMock, backend._teardown_session_state).side_effect = RuntimeError(
            "apiserver returned 500 / docker daemon unreachable"
        )
        session = session_factory(
            backend,
            active_leases=(_make_minted_lease(lease_id="lease-must-be-revoked"),),
        )

        # destroy() MUST propagate the teardown error (the session
        # wasn't cleanly destroyed); both backends preserve this
        # semantic.
        with pytest.raises(RuntimeError, match="apiserver returned 500"):
            await backend.destroy(session)

        # BUT the lease MUST have been revoked best-effort BEFORE the
        # teardown error propagated — the audit-evidence claim
        # examiners + SOC rely on per spec §7.2 cannot fail-soft on
        # a teardown crash + lease leak combination.
        assert "lease-must-be-revoked" in adapter.revoke_calls


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

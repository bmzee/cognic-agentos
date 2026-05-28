"""Sprint 10 T10 — DockerSiblingSandboxBackend credential lifecycle.

NON-env-gated unit tests pinning the T10 credential-leasing behaviour
of ``DockerSiblingSandboxBackend.create()`` + ``destroy()`` + the Q5
LOCK on ``DockerSiblingSession.checkpoint()`` / ``.suspend()`` per
Sprint-10 spec §3.6 + §4.2 + §4.2.1 + §4.3 + §4.5 + §6.1 + §7.1 + §7.2.

Uses MagicMock for the aiodocker client + admit_policy seam + a
hand-rolled in-process ``CredentialAdapter`` stub for the mint/revoke
behaviour, so these tests do NOT need a real Docker daemon OR a real
Vault. Mirrors the fixture pattern at
``test_docker_sibling_audit_emission.py`` per the existing pure-unit
test convention for this directory (env-gated tests live in
``test_docker_sibling_lifecycle.py`` + cover the same paths
end-to-end when ``COGNIC_RUN_DOCKER_SANDBOX=1``).

Watchpoints pinned by this file (per the T10 HALT-summary CC map):

* Warm-pool short-circuit — `requires_credentials` non-empty MUST
  force cold-create (skip warm-pool checkout). Per spec §4.2.1.
* Mint loop — per request, in order, AFTER admit_policy AND BEFORE
  the topology build. Per spec §4.2.
* Mint failure → closed-enum mapping — the 4-value
  ``core.vault`` exception taxonomy collapses to 3
  ``sandbox_credential_mint_failed_*`` ``SandboxRefusalReason``
  values per spec §7.1 (VaultProtocolError collapses to
  vault_unavailable for closed-enum stability).
* Mint failure → best-effort cleanup — leases minted earlier in the
  same create() attempt MUST be revoked (best-effort) before raising
  the closed-enum refusal. Per spec §7.1 line 649.
* Typed helper emission — ``sandbox_lifecycle_lease_minted`` per
  mint; ``sandbox_lifecycle_lease_revoked`` per successful revoke;
  ``sandbox_lifecycle_lease_revoke_failed`` per failed revoke
  (carries ``vault_error``; ``auto_expiry_at`` derived from
  ``lease.expires_at`` per T9 contract). Per spec §6.2.
* Destroy fail-soft — single revoke attempt per lease; on failure
  emit + continue; never raise from destroy(). Per spec §7.2.
* Q5 LOCK — ``DockerSiblingSession.checkpoint(label)`` AND
  ``DockerSiblingSession.suspend()`` MUST raise
  ``NotImplementedError`` when ``self.active_leases`` is non-empty.
  Production-grade fail-loud scaffolding per spec §4.5.
"""

from __future__ import annotations

import asyncio
import uuid
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
from cognic_agentos.sandbox.protocol import (
    SandboxLifecycleRefused,
    SandboxRefusalReason,
    SandboxSession,
)

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


def _make_credential_decl_for_request(
    req: VaultLeaseRequest,
    *,
    logical_name: str = "app_role",
) -> Any:
    """Sprint 10.6 T21 — paired ``CredentialDecl`` derived from a
    ``VaultLeaseRequest`` so the T21 pair-invariant guard passes
    by construction (same vault_path / tenant_id / ttl_s).
    Multi-credential tests pass distinct ``logical_name`` so the
    per-credential audit rows stay disambiguated.
    """
    from cognic_agentos.sandbox.projection import CredentialDecl

    return CredentialDecl(
        logical_name=logical_name,
        vault_path=req.secret_path,
        expected_fields=["password", "username"],
        ttl_s=req.ttl_s,
        purpose_category="application_database_read",
        purpose_description="Docker-backend conformance test.",
        tenant_id=req.tenant_id,
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
    """Decision-history-store mock matching emit_sandbox_event's
    ``await store.append_with_precondition(...)`` contract."""
    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


class _StubCredentialAdapter:
    """Hand-rolled in-process ``CredentialAdapter`` for T10 unit tests.

    Records every ``mint_lease`` / ``revoke_lease`` call in order. Each
    ``mint_lease`` call returns a deterministic ``CredentialLease`` built
    from the request unless a per-call override is queued. Per-call
    raise lists let tests drive mid-batch failure scenarios. The
    Sprint-8A ``fetch_secret`` is left as a stub-raise so any accidental
    call surfaces loudly (T10 NEVER invokes it).
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
) -> DockerSiblingSandboxBackend:
    """Backend wired with mocked aiodocker + admit_policy seam so
    create() / destroy() can run without a real Docker daemon."""
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
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=credential_adapter or KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store or _make_dh_store(),
        settings=settings,
        warm_pool=warm_pool,
    )
    # Sprint 10.6 T21 — pre-mock the substrate preflight + cleanup-dir
    # so tests that exercise create()/destroy() lifecycle don't try
    # to read /proc/mounts or rm /dev/shm paths on macOS. Tests that
    # need to drive preflight refusal override this with a side_effect.
    backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
        return_value=PreflightResult(
            resolved_gid=1000,
            file_mode=0o440,
            dir_mode=0o750,
            dev_escape_downgrade_reason=None,
        )
    )
    backend._cleanup_projection_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]

    # Pre-mock the T19 executor seam so the existing mint-mechanics
    # tests don't need ``/dev/shm/cognic`` on the host (the real
    # executor writes credential bytes to that tmpfs path).
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
    return backend


# ---------------------------------------------------------------------------
# Batch 1 — foundational Protocol + dataclass shape
# ---------------------------------------------------------------------------


class TestSandboxSessionProtocolShape:
    """spec §3.6 — SandboxSession Protocol carries
    ``active_leases: tuple[CredentialLease, ...]``."""

    def test_protocol_lists_active_leases_in_annotations(self) -> None:
        # ``SandboxSession`` is a Protocol class; its `__annotations__`
        # MUST include `active_leases` per the §3.6 extension.
        annotations = SandboxSession.__annotations__
        assert "active_leases" in annotations, (
            f"SandboxSession Protocol missing active_leases per spec §3.6; "
            f"got annotations: {sorted(annotations.keys())}"
        )

    def test_docker_sibling_session_carries_active_leases_field(self) -> None:
        """The concrete ``DockerSiblingSession`` dataclass MUST carry the
        field with a tuple type + default empty tuple so existing
        construction paths (warm-pool, lease-less cold-create) stay
        backward-compatible."""
        import dataclasses

        fields = {f.name: f for f in dataclasses.fields(DockerSiblingSession)}
        assert "active_leases" in fields, (
            f"DockerSiblingSession missing active_leases field per spec §3.6; "
            f"got fields: {sorted(fields.keys())}"
        )
        # Default MUST be the empty tuple (not None, not list) so
        # existing constructors don't have to pass the field.
        assert fields["active_leases"].default == (), (
            f"DockerSiblingSession.active_leases must default to () per "
            f"spec §3.6 backward-compat clause; got "
            f"{fields['active_leases'].default!r}"
        )


class TestSandboxBackendCreateAcceptsRequiresCredentials:
    """spec §4.2 — SandboxBackend.create() accepts
    ``requires_credentials: Sequence[VaultLeaseRequest] = ()``."""

    @pytest.mark.asyncio
    async def test_create_accepts_requires_credentials_kwarg(self) -> None:
        """A baseline cold-create with an explicit empty
        ``requires_credentials=()`` MUST succeed (no extra kwarg-error)."""
        backend = _make_backend()
        # admit_policy is the Stage-2 trust-gate-equivalent; patch at the
        # backend module's import binding so we don't drag in real
        # admission + Rego eval for this shape test.
        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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
        """Existing Sprint-8A callers (no ``requires_credentials`` kwarg)
        MUST still work — backward-compat per spec §4.2 line 366."""
        backend = _make_backend()
        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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


class TestWarmPoolShortCircuitOnRequiresCredentials:
    """spec §4.2.1 — when ``requires_credentials`` is non-empty,
    ``create()`` MUST skip the warm-pool checkout entirely + force
    cold-create. Warm-pool members were pre-created without an actor
    context so they cannot carry actor-scoped lease evidence; a warm
    hit on a credentialed call would silently bypass cross-tenant +
    Rego TTL + mint."""

    @pytest.mark.asyncio
    async def test_warm_pool_checkout_skipped_when_requires_credentials_non_empty(
        self,
    ) -> None:
        warm_pool = AsyncMock()
        # If checkout WERE called, it would return a warm session here.
        # The test asserts it is NOT called at all.
        warm_pool.checkout = AsyncMock(return_value=MagicMock())
        adapter = _StubCredentialAdapter()
        backend = _make_backend(warm_pool=warm_pool, credential_adapter=adapter)

        req = _make_lease_request()
        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=True,
                requires_credentials=(req,),
                credential_decls=(_make_credential_decl_for_request(req),),
            )

        warm_pool.checkout.assert_not_called()

    @pytest.mark.asyncio
    async def test_warm_pool_checkout_still_consulted_when_requires_credentials_empty(
        self,
    ) -> None:
        """Backward-compat: existing 8A warm-pool path stays alive when
        ``requires_credentials=()`` (the default)."""
        warm_pool = AsyncMock()
        # Return None — pool miss → cold-create. This proves the warm
        # path WAS consulted (checkout was awaited).
        warm_pool.checkout = AsyncMock(return_value=None)
        backend = _make_backend(warm_pool=warm_pool)

        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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
# Batch 3 — mint loop + emit (spec §4.2 + §6.2)
# ---------------------------------------------------------------------------


class TestCreateMintLoopPostAdmission:
    """spec §4.2 — mint happens AFTER admit_policy AND BEFORE the
    topology build. Per-request, in order, via
    ``credential_adapter.mint_lease(request)``."""

    @pytest.mark.asyncio
    async def test_create_mints_each_requested_lease_in_order(self) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        req_a = _make_lease_request(secret_path="database/creds/a", scope_label="a")
        req_b = _make_lease_request(secret_path="database/creds/b", scope_label="b")

        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            session = await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(req_a, req_b),
                credential_decls=(
                    _make_credential_decl_for_request(req_a, logical_name="cred_a"),
                    _make_credential_decl_for_request(req_b, logical_name="cred_b"),
                ),
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
        """spec §4.1 + §4.2 — admit_policy receives the
        ``requires_credentials`` sequence so the cross-tenant check +
        Rego TTL cap fire BEFORE any Vault round-trip."""
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        req = _make_lease_request()
        admit_mock = AsyncMock(return_value=None)

        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
            new=admit_mock,
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(req,),
                credential_decls=(_make_credential_decl_for_request(req),),
            )

        admit_mock.assert_awaited_once()
        await_args = admit_mock.await_args
        assert await_args is not None
        call_kwargs = await_args.kwargs
        assert "requires_credentials" in call_kwargs
        assert tuple(call_kwargs["requires_credentials"]) == (req,)

    @pytest.mark.asyncio
    async def test_create_emits_lease_minted_typed_helper_per_mint(self) -> None:
        """spec §6.2 — one ``sandbox.lifecycle.lease_minted`` chain row
        per successful mint. Payload derived from the lease via T9's
        single-source-of-truth helper."""
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        req_a = _make_lease_request(secret_path="database/creds/a", scope_label="a")
        req_b = _make_lease_request(secret_path="database/creds/b", scope_label="b")

        with patch(
            "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
            new=AsyncMock(return_value=None),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(req_a, req_b),
                credential_decls=(
                    _make_credential_decl_for_request(req_a, logical_name="cred_a"),
                    _make_credential_decl_for_request(req_b, logical_name="cred_b"),
                ),
            )

        # Chain rows: 2 lease_minted (one per mint) + 1 lifecycle.created
        # = 3 total appends. Inspect emitted decision_types.
        emitted_types: list[str] = []
        for call in dh_store.append_with_precondition.await_args_list:
            record_builder = call.kwargs["record_builder"]
            record = record_builder(None)
            emitted_types.append(record.decision_type)

        # Two lease_minted rows MUST appear, in order, before
        # lifecycle.created.
        assert emitted_types.count("sandbox.lifecycle.lease_minted") == 2, (
            f"expected 2 lease_minted events; got {emitted_types}"
        )
        assert "sandbox.lifecycle.created" in emitted_types

        # Order: both lease_minted rows BEFORE the lifecycle.created row
        # (mint runs before topology+emit per spec §4.2).
        idx_minted = [
            i for i, t in enumerate(emitted_types) if t == "sandbox.lifecycle.lease_minted"
        ]
        idx_created = emitted_types.index("sandbox.lifecycle.created")
        assert max(idx_minted) < idx_created, (
            f"lease_minted events must precede lifecycle.created; emitted order: {emitted_types}"
        )


# ---------------------------------------------------------------------------
# Batch 4 — mint failure mapping + best-effort cleanup (spec §7.1)
# ---------------------------------------------------------------------------


class TestMintFailureClosedEnumMapping:
    """spec §7.1 — the 4-value ``core.vault`` exception taxonomy maps
    to 3 ``sandbox_credential_mint_failed_*`` ``SandboxRefusalReason``
    values; ``VaultProtocolError`` collapses to vault_unavailable for
    closed-enum stability."""

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
                lambda: VaultProtocolError("malformed response"),
                "sandbox_credential_mint_failed_vault_unavailable",
            ),
        ],
    )
    async def test_mint_failure_raises_mapped_closed_enum_refusal(
        self,
        exc_factory: Any,
        expected_reason: SandboxRefusalReason,
    ) -> None:
        adapter = _StubCredentialAdapter()
        adapter.queue_mint_result(exc_factory())
        backend = _make_backend(credential_adapter=adapter)
        req = _make_lease_request()

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
                requires_credentials=(req,),
                credential_decls=(_make_credential_decl_for_request(req),),
            )

        assert exc_info.value.reason == expected_reason


class TestGrantExceedsRequestClosedEnumMapping:
    """Sprint 10.1 — pin that ``create()`` refuses with
    ``SandboxRefusalReason("sandbox_credential_lease_ttl_grant_exceeds_request")``
    when the credential adapter raises
    :class:`VaultLeaseGrantExceedsRequest` (the post-mint
    granted-vs-requested TTL refusal at
    ``core/vault.lease_credential`` per ADR-004 §25 amendment).

    Lands alongside the closed-enum + cross-backend mapping + backend
    except-tuple extension in the SAME commit per Finding B of the
    2026-05-24 plan-review round 1 — the 4-value backend except-tuple
    at ``docker_sibling.py:1099-1103`` does NOT auto-catch the new
    exception just because the shared mapping helper accepts it.

    Uses the REAL helpers (``_make_backend`` /
    ``_StubCredentialAdapter`` / ``_POLICY`` / ``_ACTOR`` /
    ``_PACK_CTX`` / ``_make_lease_request``) per Finding D of the
    2026-05-24 plan-review round 1.
    """

    @pytest.mark.asyncio
    async def test_create_refuses_when_grant_exceeds_request_ttl_s(self) -> None:
        from cognic_agentos.core.vault import VaultLeaseGrantExceedsRequest

        adapter = _StubCredentialAdapter()
        # Synthetic message includes lease_id token to mirror the
        # production-path format (per Finding 3 of the 2026-05-24
        # plan-review round 2 — backends pass ``detail=str(exc)`` to
        # ``SandboxLifecycleRefused``, so the lease_id must live in the
        # formatted message to reach the chain payload).
        adapter.queue_mint_result(
            VaultLeaseGrantExceedsRequest(
                "grant=3600 > request=900 "
                "lease_id='database/creds/test-role/lease-z' "
                "cleanup revoke_outcome=revoked.",
                lease_id="database/creds/test-role/lease-z",
                revoke_outcome="revoked",
            )
        )
        backend = _make_backend(credential_adapter=adapter)
        req = _make_lease_request()

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
                requires_credentials=(req,),
                credential_decls=(_make_credential_decl_for_request(req),),
            )

        assert exc_info.value.reason == ("sandbox_credential_lease_ttl_grant_exceeds_request")
        # Detail field carries the original exception message for
        # examiner traceability. Finding 3 of the 2026-05-24 plan-review
        # round 2 — lease_id MUST surface through the backend's detail
        # string so audit + observability can correlate refused-lease
        # events with the Vault-side dangling lease (relevant when
        # revoke_outcome="revoke_failed").
        detail = str(exc_info.value)
        assert "3600" in detail
        assert "database/creds/test-role/lease-z" in detail


class TestMintFailureBestEffortCleanup:
    """spec §7.1 line 649 — on mid-batch mint failure, leases already
    minted in the same create() attempt MUST be revoked (best-effort)
    before raising the closed-enum refusal."""

    @pytest.mark.asyncio
    async def test_mid_batch_failure_revokes_already_minted(self) -> None:
        """First request mints successfully; second request raises
        VaultUnavailable. The first lease MUST be revoked before the
        refusal propagates."""
        adapter = _StubCredentialAdapter()
        first_lease = _make_minted_lease(
            request=_make_lease_request(secret_path="database/creds/a", scope_label="a"),
            lease_id="lease-first",
        )
        adapter.queue_mint_result(first_lease)
        adapter.queue_mint_result(VaultUnavailable("vault 5xx"))
        backend = _make_backend(credential_adapter=adapter)

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
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                    _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                ),
                credential_decls=(
                    _make_credential_decl_for_request(
                        _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                        logical_name="cred_a",
                    ),
                    _make_credential_decl_for_request(
                        _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                        logical_name="cred_b",
                    ),
                ),
            )

        assert exc_info.value.reason == "sandbox_credential_mint_failed_vault_unavailable"
        # Best-effort cleanup MUST have revoked the first lease before
        # propagating the refusal.
        assert "lease-first" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_mid_batch_failure_swallows_secondary_revoke_failure(self) -> None:
        """Best-effort cleanup MUST NOT raise — if the cleanup revoke
        also fails, the closed-enum refusal for the ORIGINAL mint
        failure MUST still be the one that propagates."""
        adapter = _StubCredentialAdapter()
        first_lease = _make_minted_lease(lease_id="lease-first")
        adapter.queue_mint_result(first_lease)
        adapter.queue_mint_result(VaultAuthDenied("403 on path-b"))
        # Cleanup revoke ALSO fails:
        adapter.queue_revoke_result(VaultUnavailable("vault 5xx during cleanup"))
        backend = _make_backend(credential_adapter=adapter)

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
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                    _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                ),
                credential_decls=(
                    _make_credential_decl_for_request(
                        _make_lease_request(secret_path="database/creds/a", scope_label="a"),
                        logical_name="cred_a",
                    ),
                    _make_credential_decl_for_request(
                        _make_lease_request(secret_path="database/creds/b", scope_label="b"),
                        logical_name="cred_b",
                    ),
                ),
            )

        # Mint-failure refusal — NOT a revoke-failure refusal. The
        # ORIGINAL VaultAuthDenied wins; the cleanup-revoke exception
        # is swallowed.
        assert exc_info.value.reason == "sandbox_credential_mint_failed_auth_denied"


# ---------------------------------------------------------------------------
# Batch 5 — destroy fail-soft revoke (spec §4.3 + §7.2)
# ---------------------------------------------------------------------------


class TestDestroyRevokesActiveLeasesFailSoft:
    """spec §4.3 + §7.2 — destroy() revokes each lease (single
    attempt); on success emit ``sandbox.lifecycle.lease_revoked``; on
    failure emit ``sandbox.lifecycle.lease_revoke_failed`` carrying
    ``vault_error``; never raise, never block cleanup."""

    @pytest.mark.asyncio
    async def test_destroy_revokes_each_active_lease(self) -> None:
        adapter = _StubCredentialAdapter()
        backend = _make_backend(credential_adapter=adapter)
        # Construct a session WITH active leases (pre-built directly so
        # we test destroy() in isolation without going through create).
        lease_a = _make_minted_lease(lease_id="lease-a")
        lease_b = _make_minted_lease(lease_id="lease-b")
        session = DockerSiblingSession(
            session_id="sess-1",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-1",
            _sidecar_container_name="sess-1-proxy",
            _egress_network_name="cognic-sb-egress-sess-1",
            active_leases=(lease_a, lease_b),
        )

        await backend.destroy(session)

        # Both leases revoked, in order.
        assert adapter.revoke_calls == ["lease-a", "lease-b"]

    @pytest.mark.asyncio
    async def test_destroy_emits_lease_revoked_on_success(self) -> None:
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        lease = _make_minted_lease(lease_id="lease-ok")
        session = DockerSiblingSession(
            session_id="sess-2",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-2",
            _sidecar_container_name="sess-2-proxy",
            _egress_network_name="cognic-sb-egress-sess-2",
            active_leases=(lease,),
        )

        await backend.destroy(session)

        emitted_types = []
        for call in dh_store.append_with_precondition.await_args_list:
            record_builder = call.kwargs["record_builder"]
            record = record_builder(None)
            emitted_types.append(record.decision_type)
        assert "sandbox.lifecycle.lease_revoked" in emitted_types
        # destroy() also emits sandbox.lifecycle.destroyed; both must be
        # present + the revoked event MUST come first.
        idx_revoked = emitted_types.index("sandbox.lifecycle.lease_revoked")
        idx_destroyed = emitted_types.index("sandbox.lifecycle.destroyed")
        assert idx_revoked < idx_destroyed

    @pytest.mark.asyncio
    async def test_destroy_emits_lease_revoke_failed_and_continues(self) -> None:
        """spec §7.2 — single revoke attempt per lease; on failure emit
        ``lease_revoke_failed`` carrying ``vault_error``; CONTINUE
        cleanup (do NOT raise)."""
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        adapter.queue_revoke_result(VaultUnavailable("vault 503"))
        # second revoke succeeds — proves we continued past the first
        # failure
        adapter.queue_revoke_result(None)
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        lease_fail = _make_minted_lease(lease_id="lease-fail")
        lease_ok = _make_minted_lease(lease_id="lease-ok")
        session = DockerSiblingSession(
            session_id="sess-3",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-3",
            _sidecar_container_name="sess-3-proxy",
            _egress_network_name="cognic-sb-egress-sess-3",
            active_leases=(lease_fail, lease_ok),
        )

        # MUST NOT raise.
        await backend.destroy(session)

        # Both revoke calls attempted (single attempt each; second
        # succeeded).
        assert adapter.revoke_calls == ["lease-fail", "lease-ok"]

        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        assert "sandbox.lifecycle.lease_revoke_failed" in emitted_types
        assert "sandbox.lifecycle.lease_revoked" in emitted_types

        # vault_error in the failed-revoke payload — derived from the
        # exception's str()
        for call in dh_store.append_with_precondition.await_args_list:
            record = call.kwargs["record_builder"](None)
            if record.decision_type == "sandbox.lifecycle.lease_revoke_failed":
                assert "vault_error" in record.payload
                assert "vault 503" in record.payload["vault_error"]

    @pytest.mark.asyncio
    async def test_destroy_with_no_active_leases_emits_zero_lease_events(
        self,
    ) -> None:
        """Backward-compat: a session with empty active_leases produces
        ZERO lease lifecycle events (existing 8A destroy path
        unchanged)."""
        dh_store = _make_dh_store()
        adapter = _StubCredentialAdapter()
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)
        session = DockerSiblingSession(
            session_id="sess-4",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-4",
            _sidecar_container_name="sess-4-proxy",
            _egress_network_name="cognic-sb-egress-sess-4",
        )

        await backend.destroy(session)

        emitted_types = [
            call.kwargs["record_builder"](None).decision_type
            for call in dh_store.append_with_precondition.await_args_list
        ]
        # NO lease events; only the 8A lifecycle.destroyed.
        assert not any(t.startswith("sandbox.lifecycle.lease_") for t in emitted_types)
        # adapter.revoke_lease NEVER invoked.
        assert adapter.revoke_calls == []


# ---------------------------------------------------------------------------
# Batch 6 — Q5 LOCK on checkpoint + suspend (spec §4.5)
# ---------------------------------------------------------------------------


class TestQ5LockCheckpointSuspendOnLeasedSession:
    """spec §4.5 — DockerSiblingSession.checkpoint() AND .suspend()
    MUST raise NotImplementedError when active_leases is non-empty;
    production-grade fail-loud scaffolding pointing at Sprint 10.x."""

    @pytest.mark.asyncio
    async def test_checkpoint_raises_not_implemented_when_active_leases_non_empty(
        self,
    ) -> None:
        backend = _make_backend()
        lease = _make_minted_lease()
        session = DockerSiblingSession(
            session_id="sess-q5-cp",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-q5-cp",
            _sidecar_container_name="sess-q5-cp-proxy",
            _egress_network_name="cognic-sb-egress-sess-q5-cp",
            active_leases=(lease,),
        )

        with pytest.raises(NotImplementedError, match=r"Sprint 10\.x"):
            await session.checkpoint("manual-label")

    @pytest.mark.asyncio
    async def test_suspend_raises_not_implemented_when_active_leases_non_empty(
        self,
    ) -> None:
        backend = _make_backend()
        lease = _make_minted_lease()
        session = DockerSiblingSession(
            session_id="sess-q5-su",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-q5-su",
            _sidecar_container_name="sess-q5-su-proxy",
            _egress_network_name="cognic-sb-egress-sess-q5-su",
            active_leases=(lease,),
        )

        with pytest.raises(NotImplementedError, match=r"Sprint 10\.x"):
            await session.suspend()

    @pytest.mark.asyncio
    async def test_checkpoint_does_not_q5_block_when_active_leases_empty(
        self,
    ) -> None:
        """A lease-less session takes the existing 8.5 checkpoint path —
        Q5 lock does NOT fire. We assert that the lock raise-path is NOT
        the failure mode by checking the exception type."""
        backend = _make_backend()
        session = DockerSiblingSession(
            session_id="sess-q5-empty-cp",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-q5-empty-cp",
            _sidecar_container_name="sess-q5-empty-cp-proxy",
            _egress_network_name="cognic-sb-egress-sess-q5-empty-cp",
        )

        # The backend has NO checkpoint_store wired in this fixture, so
        # the 8.5 checkpoint path will raise NotImplementedError("wire
        # CheckpointStore..."). The KEY assertion is that the raise
        # text does NOT mention "Sprint 10.x" (which would be the Q5
        # lock firing instead of the 8.5 missing-store path).
        with pytest.raises(NotImplementedError) as exc_info:
            await session.checkpoint("label")
        assert "Sprint 10.x" not in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_suspend_does_not_q5_block_when_active_leases_empty(
        self,
    ) -> None:
        backend = _make_backend()
        session = DockerSiblingSession(
            session_id="sess-q5-empty-su",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-sess-q5-empty-su",
            _sidecar_container_name="sess-q5-empty-su-proxy",
            _egress_network_name="cognic-sb-egress-sess-q5-empty-su",
        )

        with pytest.raises(NotImplementedError) as exc_info:
            await session.suspend()
        assert "Sprint 10.x" not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Batch 7 — non-Vault post-mint cleanup envelope (spec §7.3 row
# "Create — mint | Any backend failure post-mint")
#
# Per the reviewer P1 fix: minted leases MUST be best-effort revoked
# on ANY post-mint exception path — NOT just Vault taxonomy
# exceptions from mint_lease itself. Three distinct failure modes:
#
# 1. lease_minted audit emit raises mid-batch (DB unavailable /
#    canonical-form rejection / hash-chain head conflict / etc.).
#    The mint succeeded → the lease IS active in Vault → but the
#    sandbox creation aborts → the lease MUST be revoked.
# 2. Topology build raises after the mint loop completed (network
#    creation / container start / image pull / etc.).
# 3. lifecycle.created emit raises after topology + Session
#    construction (DB error / canonical-form / etc.).
#
# All 3 paths converge on the same fail-loud cleanup contract:
# best-effort revoke each minted lease, best-effort teardown any
# topology state, then propagate the ORIGINAL exception unchanged.
# ---------------------------------------------------------------------------


class TestPostMintCleanupOnNonVaultFailure:
    """spec §7.3 row "Any backend failure post-mint" — every
    post-mint exception path (audit emit, topology, lifecycle.created
    emit) MUST revoke minted leases best-effort before propagating."""

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_lease_minted_emit_fails(
        self,
    ) -> None:
        """The mint succeeded but the lease_minted audit emit raises
        (DB unavailable / canonical-form rejection / etc.). The lease
        IS active in Vault → MUST be revoked before the original
        exception propagates."""
        dh_store = _make_dh_store()
        # First (and only) emit attempt raises — the lease_minted
        # emit for the single requested lease.
        dh_store.append_with_precondition.side_effect = RuntimeError("DH chain head conflict")
        adapter = _StubCredentialAdapter()
        minted = _make_minted_lease(lease_id="lease-emit-fail")
        adapter.queue_mint_result(minted)
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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
                credential_decls=(_make_credential_decl_for_request(_make_lease_request()),),
            )

        # Best-effort cleanup MUST have revoked the minted lease
        # before the audit-emit exception propagates. WITHOUT this
        # guarantee the lease leaks: it stays active in Vault until
        # its TTL expires, but the sandbox aborted so no destroy()
        # will ever call revoke.
        assert "lease-emit-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_topology_fails(self) -> None:
        """Mint loop completed; topology build raises (network
        creation / container start). MUST revoke minted leases
        before propagating the topology error per spec §7.3
        "Any backend failure post-mint"."""
        adapter = _StubCredentialAdapter()
        minted = _make_minted_lease(lease_id="lease-topology-fail")
        adapter.queue_mint_result(minted)
        backend = _make_backend(credential_adapter=adapter)

        # Inject topology failure: container start raises a RuntimeError
        # AFTER mint succeeded. ``backend._docker`` is typed as
        # ``aiodocker.Docker`` at the class level; the test fixture
        # constructs a MagicMock under that name, so a local cast keeps
        # the .return_value access satisfying mypy without polluting
        # the production typing.
        docker_mock = cast(MagicMock, backend._docker)
        docker_mock.containers.create_or_replace.return_value.start = AsyncMock(
            side_effect=RuntimeError("docker daemon refused container start")
        )

        with (
            patch(
                "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(RuntimeError, match="docker daemon refused"),
        ):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl_for_request(_make_lease_request()),),
            )

        # The minted lease MUST have been revoked best-effort before
        # the topology error propagated.
        assert "lease-topology-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_lifecycle_created_emit_fails(
        self,
    ) -> None:
        """Full path succeeded through mint + topology + Session
        construct; lifecycle.created emit raises. The minted lease
        MUST be revoked before the emit exception propagates — the
        existing R2 P1.1 cleanup envelope tore down docker state but
        did NOT revoke leases (the bug the reviewer P1 found)."""
        dh_store = _make_dh_store()
        # First emit (lease_minted) succeeds; second emit
        # (lifecycle.created) raises.
        dh_store.append_with_precondition.side_effect = [
            (uuid.uuid4(), b"\x00" * 32),
            RuntimeError("DH canonical-form rejection"),
        ]
        adapter = _StubCredentialAdapter()
        minted = _make_minted_lease(lease_id="lease-lifecycle-emit-fail")
        adapter.queue_mint_result(minted)
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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
                credential_decls=(_make_credential_decl_for_request(_make_lease_request()),),
            )

        # MUST have revoked the minted lease before the emit exception
        # propagated. The pre-fix code's cleanup envelope tore down
        # docker state but skipped the revoke.
        assert "lease-lifecycle-emit-fail" in adapter.revoke_calls

    @pytest.mark.asyncio
    async def test_revokes_minted_lease_when_create_cancelled_post_mint(
        self,
    ) -> None:
        """Reviewer P1 (T10 Docker round 3): ``asyncio.CancelledError``
        subclasses ``BaseException``, NOT ``Exception``. The cleanup
        envelope's ``except Exception`` arm DOES NOT catch
        cancellation, so a create() task cancelled mid-flight after a
        successful mint would skip cleanup entirely and leak the
        lease (lease active in Vault, no Session returned for
        destroy(), no future revoke until server-side TTL expires).

        Independent verification: ``asyncio.CancelledError`` MRO is
        ``[CancelledError, BaseException, object]``;
        ``issubclass(asyncio.CancelledError, Exception) is False``.

        Fix: explicit ``except asyncio.CancelledError:`` arm BEFORE
        the ``except Exception:`` arm. Cleanup helper called, then
        cancellation re-raised UNCHANGED (never swallowed —
        cancellation semantics MUST propagate; Vault TTL is the final
        safety net if the cleanup itself gets cancelled by a nested
        re-cancel).
        """
        dh_store = _make_dh_store()
        # Mint succeeds (adapter returns lease) → sandbox_lifecycle_lease_minted
        # emit is the first DH append → it raises CancelledError mid-await.
        # Realistic shape: the create() task was cancelled while awaiting
        # the audit-DB append AFTER the lease was already live in Vault.
        dh_store.append_with_precondition.side_effect = asyncio.CancelledError()
        adapter = _StubCredentialAdapter()
        minted = _make_minted_lease(lease_id="lease-cancelled-post-mint")
        adapter.queue_mint_result(minted)
        backend = _make_backend(dh_store=dh_store, credential_adapter=adapter)

        with (
            patch(
                "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
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
                credential_decls=(_make_credential_decl_for_request(_make_lease_request()),),
            )

        # The lease MUST have been revoked before cancellation
        # propagated. Without the explicit CancelledError arm the
        # cleanup helper never runs.
        assert "lease-cancelled-post-mint" in adapter.revoke_calls

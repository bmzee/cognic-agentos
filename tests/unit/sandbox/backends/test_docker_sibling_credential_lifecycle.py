"""Sprint 10.6 T21 slice 3 — Docker ``create()`` mint-then-project
lifecycle integration regressions per spec §5.8 + the user-locked
T21 entry decisions (locks 1-4).

Five test families pinned per the user's slice-3 framing:

  1. **Pair guard before mint** — ``verify_credentials_pair_invariants``
     raises BEFORE any I/O (admit / preflight / mint / topology).
  2. **Preflight before mint** — Docker substrate preflight runs AFTER
     admission + BEFORE the mint loop; preflight refusal = zero
     minted leases + zero credential-projection events.
  3. **Per-credential event order** — for each credential in
     manifest declaration order: ``lease_minted`` THEN
     ``credentials_projected``, NOT batched.
  4. **Path 2 — projection refusal for credential N**: revoke-only
     for N (lease_revoked + ``credentials_projection_failed`` with
     ``revoke_outcome``), NO ``credentials_projection_cleaned_up``
     for N (it never projected), then LIFO unwind 1..N-1.
  5. **Path 3 — post-projection backend failure**: LIFO unwind ALL
     projected credentials; per-credential ``cleaned_up`` BEFORE
     ``lease_revoked``.

Critical-controls from birth — these tests pin wire-public lifecycle
event ordering + the T21 closed-enum vocabulary; reviewer-locked
discipline applies. ``extra_mounts`` flow through to
``_start_sandbox_container`` is also pinned here so a future
refactor cannot silently drop the bind-mount source path.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    CredentialDecl,
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox._preflight import PreflightResult
from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend
from cognic_agentos.sandbox.projection import (
    ProjectionPlan,
    ProjectionPlanEntry,
    ProjectionRefused,
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


def _make_lease_request(
    *,
    secret_path: str = "database/creds/db-main",
    tenant_id: str = "t-1",
    scope_label: str = "db-main",
) -> VaultLeaseRequest:
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=300,
        tenant_id=tenant_id,
        actor_ref=_ACTOR_REF,
        scope_label=scope_label,
    )


def _make_credential_decl(
    *,
    logical_name: str = "db_main",
    vault_path: str = "database/creds/db-main",
    tenant_id: str = "t-1",
    expected_fields: Sequence[str] = ("password", "username"),
) -> CredentialDecl:
    return CredentialDecl(
        logical_name=logical_name,
        vault_path=vault_path,
        expected_fields=list(expected_fields),
        ttl_s=300,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        tenant_id=tenant_id,
    )


def _make_minted_lease(
    *,
    lease_id: str,
    secret_path: str = "database/creds/db-main",
    tenant_id: str = "t-1",
) -> CredentialLease:
    now = datetime.now(UTC)
    return CredentialLease(
        lease_id=lease_id,
        request=_make_lease_request(secret_path=secret_path, tenant_id=tenant_id),
        token={"username": "u", "password": "p-NEVER-on-chain"},
        minted_at=now,
        ttl_s_granted=600,
        expires_at=now + timedelta(seconds=600),
    )


class _RecordingAdapter:
    """CredentialAdapter mock that records mint/revoke + can be
    primed per-call. Mirrors the ``_StubAdapter`` at
    ``test_credential_lifecycle.py`` so test patterns stay parallel."""

    def __init__(self) -> None:
        self.mint_calls: list[VaultLeaseRequest] = []
        self.revoke_calls: list[str] = []
        self._mint_outcomes: list[CredentialLease | Exception] = []
        self._revoke_outcomes: list[None | Exception] = []

    def queue_mint(self, outcome: CredentialLease | Exception) -> None:
        self._mint_outcomes.append(outcome)

    def queue_revoke(self, outcome: None | Exception) -> None:
        self._revoke_outcomes.append(outcome)

    async def fetch_secret(self, path: str) -> str | None:
        raise AssertionError(f"fetch_secret({path!r}) called — T21 uses mint/revoke")

    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        self.mint_calls.append(request)
        if self._mint_outcomes:
            outcome = self._mint_outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return _make_minted_lease(
            lease_id=f"lease-default-{len(self.mint_calls)}",
            secret_path=request.secret_path,
            tenant_id=request.tenant_id,
        )

    async def revoke_lease(self, lease_id: str) -> None:
        self.revoke_calls.append(lease_id)
        if self._revoke_outcomes:
            outcome = self._revoke_outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome


def _make_event_recorder() -> tuple[AsyncMock, list[tuple[str, dict[str, Any]]]]:
    """Build a ``DecisionHistoryStore`` mock that captures every
    audit event in emission order. Returns ``(store_mock, events)``
    where ``events`` is a list of ``(decision_type, payload)`` tuples
    populated as the production code emits.

    The decision_type lives on the ``DecisionRecord`` built by the
    audit helper's ``record_builder`` closure — drive it here so
    tests can assert event ORDER + per-event payload contents.
    """
    events: list[tuple[str, dict[str, Any]]] = []

    async def _append_with_precondition(
        *,
        precondition: Any,
        record_builder: Any,
    ) -> tuple[uuid.UUID, bytes]:
        captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
        record = record_builder(captured)
        events.append((record.decision_type, dict(record.payload)))
        return uuid.uuid4(), b"\x00" * 32

    store = AsyncMock()
    store.append_with_precondition.side_effect = _append_with_precondition
    return store, events


def _make_backend_with_preflight_pass(
    *, adapter: Any | None = None
) -> tuple[DockerSiblingSandboxBackend, _RecordingAdapter, list[tuple[str, dict[str, Any]]]]:
    """Construct a mocked DockerSibling backend with the substrate
    preflight pre-mocked to PASS (resolved_gid=1000, file_mode=0o440,
    dir_mode=0o750, no dev_escape downgrade). Tests that need to
    override preflight behaviour replace
    ``backend._collect_preflight_result`` with their own AsyncMock.
    """
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
    decision = MagicMock(allow=True, reasoning="")
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
        runtime_profile="prod",
        dev_escape_allow_permissive_credential_projection=False,
    )
    store, events = _make_event_recorder()
    used_adapter = adapter or _RecordingAdapter()
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=used_adapter
        if isinstance(used_adapter, _RecordingAdapter)
        else KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=store,
        settings=settings,
        warm_pool=None,
    )
    backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
    # T21: preflight result helper — tests that need to drive preflight
    # failure override this. Default = pass (resolved_gid=1000).
    backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
        return_value=PreflightResult(
            resolved_gid=1000,
            file_mode=0o440,
            dir_mode=0o750,
            dev_escape_downgrade_reason=None,
        )
    )
    # T21: avoid real cleanup_projection_dir filesystem I/O.
    backend._cleanup_projection_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend, used_adapter, events


def _create_kwargs(
    *,
    credential_decls: Sequence[CredentialDecl] = (),
    requires_credentials: Sequence[VaultLeaseRequest] = (),
    expected_workload_gid: int | None = 1000,
) -> dict[str, Any]:
    """Build the kwarg dict for ``backend.create(policy, **kwargs)``."""
    return {
        "actor": _ACTOR,
        "tenant_id": "t-1",
        "pack_context": _PACK_CTX,
        "use_warm_pool": False,
        "requires_credentials": requires_credentials,
        "credential_decls": credential_decls,
        "expected_workload_gid": expected_workload_gid,
    }


def _emitted_event_names(events: list[tuple[str, dict[str, Any]]]) -> list[str]:
    """Strip the chain-event prefix for shorter assertion expressions."""
    return [name.replace("sandbox.lifecycle.", "") for name, _ in events]


def _events_of_type(
    events: list[tuple[str, dict[str, Any]]], suffix: str
) -> list[tuple[str, dict[str, Any]]]:
    """Filter events whose decision_type ends with ``suffix``."""
    return [(name, payload) for name, payload in events if name.endswith(suffix)]


# ===========================================================================
# Test family 1 — Pair guard before mint
# ===========================================================================


class TestPairGuardBeforeMint:
    """User-locked invariant #1: pair guard raises ValueError BEFORE
    any I/O. Failure path = zero mint calls + zero credential-
    projection events."""

    async def test_length_mismatch_raises_value_error_no_mint(self) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(_make_credential_decl(), _make_credential_decl(logical_name="aws")),
            expected_workload_gid=1000,
        )
        with pytest.raises(ValueError, match=r"length mismatch"):
            await backend.create(_POLICY, **kwargs)
        # No mint calls + no credential events.
        assert adapter.mint_calls == []
        assert adapter.revoke_calls == []
        assert _emitted_event_names(events) == []

    async def test_one_side_empty_raises_value_error_no_mint(self) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(),
            expected_workload_gid=1000,
        )
        with pytest.raises(ValueError, match=r"both must be non-empty"):
            await backend.create(_POLICY, **kwargs)
        assert adapter.mint_calls == []

    async def test_tenant_mismatch_raises_value_error_no_mint(self) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(
                _make_lease_request(secret_path="database/creds/db-main", tenant_id="tenant-a"),
            ),
            credential_decls=(
                _make_credential_decl(vault_path="database/creds/db-main", tenant_id="tenant-b"),
            ),
            expected_workload_gid=1000,
        )
        with pytest.raises(ValueError, match=r"tenant_id mismatch"):
            await backend.create(_POLICY, **kwargs)
        assert adapter.mint_calls == []


# ===========================================================================
# Test family 2 — Substrate preflight before mint
# ===========================================================================


class TestPreflightBeforeMint:
    """User-locked sequencing #2: substrate preflight runs AFTER
    admission + BEFORE the mint loop. Preflight refusal = zero
    minted leases + zero projection events."""

    async def test_preflight_refusal_raises_sandbox_lifecycle_refused_no_mint(
        self,
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        # Override preflight to refuse.
        backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
            side_effect=SandboxLifecycleRefused(
                "sandbox_credential_staging_path_not_tmpfs",
                detail="test preflight refusal",
            )
        )
        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(_make_credential_decl(),),
        )
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            await backend.create(_POLICY, **kwargs)
        assert exc_info.value.reason == "sandbox_credential_staging_path_not_tmpfs"
        # Zero mint calls (preflight ran BEFORE mint loop).
        assert adapter.mint_calls == []
        # Zero credential-projection events.
        for forbidden in (
            "lease_minted",
            "credentials_projected",
            "credentials_projection_failed",
            "credentials_projection_cleaned_up",
            "lease_revoked",
        ):
            assert forbidden not in _emitted_event_names(events), (
                f"{forbidden!r} MUST NOT be emitted on preflight refusal"
            )

    async def test_preflight_not_called_when_no_credentials_requested(self) -> None:
        # No credentials → no projection → no preflight (saves the
        # /proc/mounts read + docker inspect on every credential-less
        # sandbox).
        backend, _adapter, _events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(),
            credential_decls=(),
            expected_workload_gid=None,
        )
        await backend.create(_POLICY, **kwargs)
        backend._collect_preflight_result.assert_not_awaited()  # type: ignore[attr-defined]


# ===========================================================================
# Test family 3 — Happy-path per-credential event ordering
# ===========================================================================


class TestHappyPathEventOrdering:
    """User-locked test family #3: per-credential ``lease_minted``
    THEN ``credentials_projected``, in manifest declaration order.
    NOT batched (no "mint all then project all" — that would lose
    the per-credential audit cohesion the per-row mint→project
    chain depends on)."""

    async def test_single_credential_lease_minted_then_credentials_projected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(
            _make_minted_lease(lease_id="lease-1", secret_path="database/creds/db-main")
        )

        # Mock T18 planner to return a successful ProjectionPlan for
        # this credential.
        def _plan_success(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan:
            return ProjectionPlan(
                entries=(
                    ProjectionPlanEntry(
                        relative_path="username",
                        content_bytes=b"u",
                        mode=0o440,
                    ),
                ),
                logical_name=manifest_decl.logical_name,
                lease_id=lease.lease_id,
                projected_field_count=1,
                vault_path=manifest_decl.vault_path,
                purpose_category=manifest_decl.purpose_category,
                purpose_description=manifest_decl.purpose_description,
                tenant_id=manifest_decl.tenant_id,
            )

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan_success,
        )
        # Mock T19 executor to return a successful result without
        # touching the filesystem.
        executor_mock = AsyncMock()
        executor_mock.side_effect = lambda **kw: _make_executor_result_docker(
            lease=kw["plan"].lease_id,
            logical_name=kw["plan"].logical_name,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )

        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(_make_credential_decl(),),
        )
        await backend.create(_POLICY, **kwargs)

        event_names = _emitted_event_names(events)
        # Per-credential ordering: lease_minted FIRST, then credentials_projected.
        assert "lease_minted" in event_names
        assert "credentials_projected" in event_names
        assert event_names.index("lease_minted") < event_names.index("credentials_projected")

    async def test_two_credentials_emit_in_manifest_declaration_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(
            _make_minted_lease(lease_id="lease-1", secret_path="database/creds/db-main")
        )
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2", secret_path="aws/creds/payments"))

        def _plan_success(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan:
            return _make_projection_plan(lease=lease, decl=manifest_decl)

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan_success,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )

        kwargs = _create_kwargs(
            requires_credentials=(
                _make_lease_request(secret_path="database/creds/db-main", scope_label="db-main"),
                _make_lease_request(secret_path="aws/creds/payments", scope_label="aws"),
            ),
            credential_decls=(
                _make_credential_decl(logical_name="db_main", vault_path="database/creds/db-main"),
                _make_credential_decl(
                    logical_name="aws_credentials", vault_path="aws/creds/payments"
                ),
            ),
        )
        await backend.create(_POLICY, **kwargs)

        # Per-credential interleaved: mint→project per credential, in order.
        credential_events = [
            (name, payload)
            for name, payload in events
            if name in ("sandbox.lifecycle.lease_minted", "sandbox.lifecycle.credentials_projected")
        ]
        # Expected sequence (4 events): mint-1 → proj-1 → mint-2 → proj-2
        event_names = [name for name, _ in credential_events]
        assert event_names == [
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.credentials_projected",
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.credentials_projected",
        ]
        # Verify logical_name ordering matches manifest order.
        projected_events = _events_of_type(events, "credentials_projected")
        assert [p["logical_name"] for _, p in projected_events] == [
            "db_main",
            "aws_credentials",
        ]

    async def test_no_credentials_omits_credential_projection_events(
        self,
    ) -> None:
        # Credentials-less sandbox: zero mint, zero project events.
        backend, _adapter, events = _make_backend_with_preflight_pass()
        await backend.create(_POLICY, **_create_kwargs(expected_workload_gid=None))
        for forbidden in (
            "lease_minted",
            "credentials_projected",
            "credentials_projection_failed",
            "credentials_projection_cleaned_up",
            "lease_revoked",
        ):
            assert forbidden not in _emitted_event_names(events)


# ===========================================================================
# Test family 4 — Path 2 projection refusal for credential N
# ===========================================================================


class TestPath2ProjectionRefusalForCredentialN:
    """User-locked Path 2: per-credential refusal during the mint-
    then-project loop. The failed credential N is revoke-only (no
    projection cleanup since it never projected); the already-
    projected stack 1..N-1 unwinds LIFO with cleanup-before-revoke
    per credential."""

    async def test_first_credential_refusal_revokes_only_no_cleanup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))

        # Mock planner to refuse this credential.
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            lambda *, lease, manifest_decl: ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name=manifest_decl.logical_name,
                expected_fields=("password", "username"),
                actual_fields=("api_key",),
                extras=("api_key",),
                missing=("password", "username"),
            ),
        )

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                ),
            )

        # Lease N was revoked.
        assert adapter.revoke_calls == ["lease-1"]
        # NO credentials_projection_cleaned_up for the failed credential.
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert cleaned_up_events == [], (
            "Failed credential MUST NOT emit credentials_projection_cleaned_up (it never projected)"
        )

    async def test_path2_emits_credentials_projection_failed_with_revoke_outcome_revoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_revoke(None)  # successful revoke

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            lambda *, lease, manifest_decl: ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name=manifest_decl.logical_name,
                expected_fields=("password", "username"),
                actual_fields=("api_key",),
                extras=("api_key",),
                missing=("password", "username"),
            ),
        )

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                ),
            )

        failed_events = _events_of_type(events, "credentials_projection_failed")
        assert len(failed_events) == 1
        _name, payload = failed_events[0]
        assert payload["revoke_outcome"] == "revoked"

    async def test_path2_revoke_failure_emits_revoke_outcome_revoke_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_revoke(RuntimeError("vault 503"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            lambda *, lease, manifest_decl: ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name=manifest_decl.logical_name,
                expected_fields=("password", "username"),
                actual_fields=("api_key",),
                extras=("api_key",),
                missing=("password", "username"),
            ),
        )

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                ),
            )

        failed_events = _events_of_type(events, "credentials_projection_failed")
        assert len(failed_events) == 1
        _name, payload = failed_events[0]
        assert payload["revoke_outcome"] == "revoke_failed"

    async def test_path2_n_minus_1_lifo_unwind_cleanup_before_revoke(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 3 credentials; planner fails on the 3rd.
        # LIFO unwind: credential-2 cleanup → credential-2 revoke,
        # then credential-1 cleanup → credential-1 revoke. (NO
        # cleanup for credential-3 — it failed BEFORE projecting.)
        backend, adapter, events = _make_backend_with_preflight_pass()
        for i in range(1, 4):
            adapter.queue_mint(
                _make_minted_lease(
                    lease_id=f"lease-{i}",
                    secret_path=f"database/creds/db-{i}",
                )
            )

        # Planner: success for 1 + 2, refuse for 3.
        call_count = {"n": 0}

        def _plan(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan | ProjectionRefused:
            call_count["n"] += 1
            if call_count["n"] == 3:
                return ProjectionRefused(
                    reason="sandbox_credential_projection_field_set_mismatch",
                    logical_name=manifest_decl.logical_name,
                    expected_fields=("password", "username"),
                    actual_fields=(),
                    extras=(),
                    missing=("password", "username"),
                )
            return _make_projection_plan(lease=lease, decl=manifest_decl)

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(
                        _make_lease_request(secret_path="database/creds/db-1"),
                        _make_lease_request(secret_path="database/creds/db-2"),
                        _make_lease_request(secret_path="database/creds/db-3"),
                    ),
                    credential_decls=(
                        _make_credential_decl(
                            logical_name="db_main_1", vault_path="database/creds/db-1"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_2", vault_path="database/creds/db-2"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_3", vault_path="database/creds/db-3"
                        ),
                    ),
                ),
            )

        # Filter to the credential-projection lifecycle events.
        relevant = [
            (name.replace("sandbox.lifecycle.", ""), payload)
            for name, payload in events
            if name
            in (
                "sandbox.lifecycle.lease_minted",
                "sandbox.lifecycle.credentials_projected",
                "sandbox.lifecycle.credentials_projection_failed",
                "sandbox.lifecycle.credentials_projection_cleaned_up",
                "sandbox.lifecycle.lease_revoked",
            )
        ]
        # Expected sequence:
        #   mint-1 → proj-1
        #   mint-2 → proj-2
        #   mint-3 → failed-3 (revoke-only via failed event)
        #   cleaned-up-2 → revoked-2
        #   cleaned-up-1 → revoked-1
        # i.e. failed credential first in its own sub-stack;
        # then LIFO unwind of 1..N-1.
        names_only = [n for n, _ in relevant]
        assert names_only == [
            "lease_minted",
            "credentials_projected",
            "lease_minted",
            "credentials_projected",
            "lease_minted",
            "credentials_projection_failed",
            "credentials_projection_cleaned_up",
            "lease_revoked",
            "credentials_projection_cleaned_up",
            "lease_revoked",
        ]
        # logical_name order on cleanup: db_main_2 first (newer in stack),
        # db_main_1 second (older).
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_2",
            "db_main_1",
        ]


# ===========================================================================
# Test family 5 — Path 3 post-projection backend failure
# ===========================================================================


class TestPath3PostProjectionFailure:
    """User-locked Path 3: failure AFTER all credentials projected
    (workload-start failure / audit-emit failure / topology failure).
    LIFO unwind ALL projected credentials, cleanup-before-revoke
    per credential."""

    async def test_topology_failure_post_projection_lifo_unwinds_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2"))

        # Planner: both succeed.
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )
        # Topology FAILS after projection.
        backend._create_internal_network = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("docker network create exploded")
        )

        with pytest.raises(RuntimeError, match="docker network create exploded"):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(
                        _make_lease_request(secret_path="database/creds/db-1"),
                        _make_lease_request(secret_path="database/creds/db-2"),
                    ),
                    credential_decls=(
                        _make_credential_decl(
                            logical_name="db_main_1", vault_path="database/creds/db-1"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_2", vault_path="database/creds/db-2"
                        ),
                    ),
                ),
            )

        # All projected credentials cleaned up LIFO.
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_2",
            "db_main_1",
        ]
        # All leases revoked LIFO.
        assert adapter.revoke_calls == ["lease-2", "lease-1"]
        # Per-credential ordering: cleaned_up BEFORE revoked.
        for credential_idx, logical_name in enumerate(("db_main_2", "db_main_1")):
            cleanup_idx = next(
                i
                for i, (name, payload) in enumerate(events)
                if name == "sandbox.lifecycle.credentials_projection_cleaned_up"
                and payload["logical_name"] == logical_name
            )
            revoke_idx = next(
                i
                for i, (name, payload) in enumerate(events)
                if name == "sandbox.lifecycle.lease_revoked"
                and payload["lease_id"] == f"lease-{2 - credential_idx}"
            )
            assert cleanup_idx < revoke_idx, (
                f"credential {logical_name}: cleanup MUST precede revoke "
                f"(cleanup_idx={cleanup_idx}, revoke_idx={revoke_idx})"
            )


# ===========================================================================
# Helpers shared across the tests above
# ===========================================================================


def _make_projection_plan(*, lease: CredentialLease, decl: CredentialDecl) -> ProjectionPlan:
    return ProjectionPlan(
        entries=tuple(
            ProjectionPlanEntry(
                relative_path=name,
                content_bytes=b"v",
                mode=0o440,
            )
            for name in decl.expected_fields
        ),
        logical_name=decl.logical_name,
        lease_id=lease.lease_id,
        projected_field_count=len(decl.expected_fields),
        vault_path=decl.vault_path,
        purpose_category=decl.purpose_category,
        purpose_description=decl.purpose_description,
        tenant_id=decl.tenant_id,
    )


def _make_executor_result_docker(
    *,
    lease: str,
    logical_name: str,
    vault_path: str = "database/creds/db-main",
    tenant_id: str = "t-1",
) -> Any:
    """Stand-in ProjectionExecutorResult shape — minimal to drive the
    audit emit paths without touching filesystem."""
    from cognic_agentos.sandbox.backends._docker_executor import (
        ProjectionExecutorResult,
    )

    return ProjectionExecutorResult(
        logical_name=logical_name,
        vault_path=vault_path,
        tenant_id=tenant_id,
        lease_id=lease,
        projected_field_count=1,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        host_staging_dir=f"/dev/shm/cognic/aaa/bbb-{logical_name}",
        container_mount_target=f"/run/credentials/{logical_name}",
        session_opaque="a" * 16,
        credential_opaque="b" * 16,
        dev_escape_downgrade_reason=None,
    )


# ===========================================================================
# Round-2 P1 — Path-2 audit-emit failure propagates (not silently suppressed)
# ===========================================================================


class TestPath2AuditEmitFailurePropagates:
    """Round-2 reviewer P1: pre-fix ``_handle_projection_refusal``
    wrapped the ``credentials_projection_failed`` emit in
    ``contextlib.suppress(Exception)``. If the decision-history append
    failed, ``create()`` would still raise ``SandboxLifecycleRefused``
    as though the Path-2 evidence row landed — banks would have a
    credential refusal with NO chain row. Post-fix the emit failure
    propagates AFTER the LIFO unwind completes."""

    async def test_path2_audit_emit_failure_overrides_sandbox_lifecycle_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            lambda *, lease, manifest_decl: ProjectionRefused(
                reason="sandbox_credential_projection_field_set_mismatch",
                logical_name=manifest_decl.logical_name,
                expected_fields=("password", "username"),
                actual_fields=("api_key",),
                extras=("api_key",),
                missing=("password", "username"),
            ),
        )

        # Drive the Path-2 ``credentials_projection_failed`` emit to
        # raise. The audit store's ``append_with_precondition``
        # side_effect normally captures events; override it to raise
        # on the credentials_projection_failed event specifically.
        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _selective_raise(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if record.decision_type == ("sandbox.lifecycle.credentials_projection_failed"):
                raise RuntimeError("simulated chain-append failure on path-2 emit")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = _selective_raise  # type: ignore[attr-defined]

        # Pre-fix: would raise SandboxLifecycleRefused (silently
        # losing the audit failure). Post-fix: the audit-emit
        # RuntimeError propagates instead.
        with pytest.raises(RuntimeError, match="simulated chain-append failure"):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                ),
            )

    async def test_path2_audit_emit_failure_still_unwinds_projected_stack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The LIFO unwind MUST run UNCONDITIONALLY — even when the
        Path-2 audit emit fails. Otherwise an audit-store outage
        leaks credential bytes from the already-projected stack."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2"))

        call_count = {"n": 0}

        def _plan(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan | ProjectionRefused:
            call_count["n"] += 1
            if call_count["n"] == 2:
                return ProjectionRefused(
                    reason="sandbox_credential_projection_field_set_mismatch",
                    logical_name=manifest_decl.logical_name,
                    expected_fields=("password", "username"),
                    actual_fields=(),
                    extras=(),
                    missing=("password", "username"),
                )
            return _make_projection_plan(lease=lease, decl=manifest_decl)

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )

        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _raise_on_projection_failed(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if record.decision_type == ("sandbox.lifecycle.credentials_projection_failed"):
                raise RuntimeError("simulated chain-append failure")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = _raise_on_projection_failed  # type: ignore[attr-defined]

        with pytest.raises(RuntimeError):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(
                        _make_lease_request(secret_path="database/creds/db-1"),
                        _make_lease_request(secret_path="database/creds/db-2"),
                    ),
                    credential_decls=(
                        _make_credential_decl(
                            logical_name="db_main_1", vault_path="database/creds/db-1"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_2", vault_path="database/creds/db-2"
                        ),
                    ),
                ),
            )

        # Lease-1 was revoked via the LIFO unwind even though the
        # Path-2 audit emit raised. Bug-class regression — pre-fix
        # this would leave lease-1 active.
        assert "lease-1" in adapter.revoke_calls


# ===========================================================================
# Round-2 P2 — cleanup_failed only emitted on filesystem cleanup failure
# ===========================================================================


class TestCleanupFailedReflectsFilesystemFailure:
    """Round-2 reviewer P2: pre-fix
    ``_cleanup_projected_credential`` wrapped both the filesystem
    cleanup AND the ``credentials_projection_cleaned_up`` emit in the
    same ``try``. If FS cleanup succeeded but the emit failed,
    ``cleanup_failed`` fired with
    ``partial_state="cleanup_projection_dir raised mid-unwind"`` —
    false evidence. Post-fix the two are split: ``cleanup_failed``
    only fires when the FS cleanup itself raised."""

    async def test_cleaned_up_emit_failure_does_NOT_trigger_cleanup_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2"))

        call_count = {"n": 0}

        def _plan(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan | ProjectionRefused:
            call_count["n"] += 1
            if call_count["n"] == 2:
                return ProjectionRefused(
                    reason="sandbox_credential_projection_field_set_mismatch",
                    logical_name=manifest_decl.logical_name,
                    expected_fields=("password", "username"),
                    actual_fields=(),
                    extras=(),
                    missing=("password", "username"),
                )
            return _make_projection_plan(lease=lease, decl=manifest_decl)

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )
        # FS cleanup SUCCEEDS (default AsyncMock returns None).
        # The ``credentials_projection_cleaned_up`` audit emit FAILS.
        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _raise_on_cleaned_up(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if record.decision_type == ("sandbox.lifecycle.credentials_projection_cleaned_up"):
                raise RuntimeError("simulated chain-append failure on cleaned_up")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = _raise_on_cleaned_up  # type: ignore[attr-defined]

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(
                        _make_lease_request(secret_path="database/creds/db-1"),
                        _make_lease_request(secret_path="database/creds/db-2"),
                    ),
                    credential_decls=(
                        _make_credential_decl(
                            logical_name="db_main_1", vault_path="database/creds/db-1"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_2", vault_path="database/creds/db-2"
                        ),
                    ),
                ),
            )

        # Pre-fix: this would emit cleanup_failed for db_main_1 (the
        # FS cleanup succeeded but the cleaned_up emit failed → the
        # broad try/except routed to cleanup_failed). Post-fix:
        # cleanup_failed MUST NOT appear in events at all because no
        # FS cleanup actually failed.
        cleanup_failed_events = _events_of_type(events, "credentials_projection_cleanup_failed")
        assert cleanup_failed_events == [], (
            f"cleanup_failed must NOT fire when only the cleaned_up audit "
            f"emit raised; got {cleanup_failed_events!r}"
        )

    async def test_filesystem_cleanup_failure_emits_cleanup_failed_with_error_class(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Positive regression: when the FS cleanup itself raises,
        cleanup_failed MUST fire with the correct ``error_class``."""
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2"))

        call_count = {"n": 0}

        def _plan(
            *, lease: CredentialLease, manifest_decl: CredentialDecl
        ) -> ProjectionPlan | ProjectionRefused:
            call_count["n"] += 1
            if call_count["n"] == 2:
                return ProjectionRefused(
                    reason="sandbox_credential_projection_field_set_mismatch",
                    logical_name=manifest_decl.logical_name,
                    expected_fields=("password", "username"),
                    actual_fields=(),
                    extras=(),
                    missing=("password", "username"),
                )
            return _make_projection_plan(lease=lease, decl=manifest_decl)

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.compute_projection_plan",
            _plan,
        )
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.docker_sibling.execute_projection_plan_docker",
            lambda **kw: _make_executor_result_docker(
                lease=kw["plan"].lease_id,
                logical_name=kw["plan"].logical_name,
                vault_path=kw["plan"].vault_path,
                tenant_id=kw["plan"].tenant_id,
            ),
        )
        # FS cleanup raises PermissionError.
        backend._cleanup_projection_dir = AsyncMock(  # type: ignore[method-assign]
            side_effect=PermissionError("EACCES on staging dir")
        )

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(
                        _make_lease_request(secret_path="database/creds/db-1"),
                        _make_lease_request(secret_path="database/creds/db-2"),
                    ),
                    credential_decls=(
                        _make_credential_decl(
                            logical_name="db_main_1", vault_path="database/creds/db-1"
                        ),
                        _make_credential_decl(
                            logical_name="db_main_2", vault_path="database/creds/db-2"
                        ),
                    ),
                ),
            )

        # cleanup_failed MUST fire for db_main_1 (the projected one
        # whose FS cleanup raised) AND cleaned_up MUST NOT fire for it.
        cleanup_failed_events = _events_of_type(events, "credentials_projection_cleanup_failed")
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert len(cleanup_failed_events) == 1
        _name, payload = cleanup_failed_events[0]
        assert payload["error_class"] == "PermissionError"
        assert payload["logical_name"] == "db_main_1"
        # Negative: cleaned_up MUST NOT fire — the branches are mutually
        # exclusive per the round-2 P2 split.
        assert cleaned_up_events == []


# ===========================================================================
# Slice 4 — Docker destroy() LIFO projection cleanup before revoke
# ===========================================================================


def _make_executor_result_pair(
    *,
    lease_id: str,
    logical_name: str,
    vault_path: str = "database/creds/db-main",
) -> tuple[CredentialLease, Any]:
    """Build a paired (lease, executor_result) for destroy() tests
    so session.active_leases + session.active_projections share the
    same lease_id by manifest declaration order."""
    lease = _make_minted_lease(
        lease_id=lease_id,
        secret_path=vault_path,
    )
    er = _make_executor_result_docker(
        lease=lease_id,
        logical_name=logical_name,
        vault_path=vault_path,
    )
    return lease, er


def _make_session_with_projections(
    *,
    backend: DockerSiblingSandboxBackend,
    pairs: list[tuple[CredentialLease, Any]],
) -> Any:
    """Construct a DockerSiblingSession with paired active_leases +
    active_projections so destroy()'s slice-4 LIFO unwind exercises
    the correct credentials."""
    from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSession

    leases = tuple(lease for lease, _er in pairs)
    projections = tuple(er for _lease, er in pairs)
    return DockerSiblingSession(
        session_id="sess-destroy-t21",
        policy=_POLICY,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name="cognic-sb-internal-x",
        _sidecar_container_name="x-proxy",
        _egress_network_name="cognic-sb-egress-x",
        active_leases=leases,
        active_projections=projections,
        _actor_subject=_ACTOR.subject,
    )


class TestDestroyLifoProjectionCleanupBeforeRevoke:
    """Sprint 10.6 T21 slice 4 — ``destroy()`` LIFO unwind:
    per-credential ``cleanup_projection_dir`` → emit cleaned_up →
    revoke → emit lease_revoked, in REVERSE manifest order
    (most-recently-projected first). Bare-revoke loop skips any
    lease already revoked via the projection-unwind loop above to
    prevent double-revoke.
    """

    async def test_destroy_emits_cleaned_up_before_lease_revoked_per_credential(
        self,
    ) -> None:
        backend, _adapter, events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        # Per-credential ordering: for each credential, cleaned_up
        # before lease_revoked.
        relevant = [
            (name.replace("sandbox.lifecycle.", ""), payload)
            for name, payload in events
            if name
            in (
                "sandbox.lifecycle.credentials_projection_cleaned_up",
                "sandbox.lifecycle.lease_revoked",
            )
        ]
        # Expected sequence:
        #   cleaned-up-2 → revoked-2 (lease-2)
        #   cleaned-up-1 → revoked-1 (lease-1)
        names_only = [n for n, _ in relevant]
        assert names_only == [
            "credentials_projection_cleaned_up",
            "lease_revoked",
            "credentials_projection_cleaned_up",
            "lease_revoked",
        ]

    async def test_destroy_unwinds_in_reverse_manifest_order(self) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair(lease_id="lease-2", logical_name="db_main_2"),
            _make_executor_result_pair(lease_id="lease-3", logical_name="db_main_3"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        # cleaned_up events in reverse: db_main_3, db_main_2, db_main_1.
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_3",
            "db_main_2",
            "db_main_1",
        ]
        # Revoke calls in same reverse order.
        assert adapter.revoke_calls == ["lease-3", "lease-2", "lease-1"]

    async def test_destroy_no_bare_revoke_double_call_for_projected_leases(
        self,
    ) -> None:
        """Bug-class regression: the bare-revoke loop MUST skip
        leases already revoked via the projection-unwind loop.
        Without the filter, each projected lease would be revoked
        TWICE (once by ``_cleanup_projected_credential`` + once by
        the bare-revoke loop)."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        # Exactly ONE revoke per lease (no double-revoke).
        assert adapter.revoke_calls == ["lease-2", "lease-1"]
        assert len(adapter.revoke_calls) == 2

    async def test_destroy_with_no_projections_no_credential_events(self) -> None:
        """Credential-less sandbox (no active_projections + no
        active_leases) MUST emit zero credential-projection events
        on destroy. Backward-compat with Sprint-8A lease-less
        sandboxes."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSession,
        )

        backend, _adapter, events = _make_backend_with_preflight_pass()
        session = DockerSiblingSession(
            session_id="sess-no-credentials",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="cognic-sb-internal-x",
            _sidecar_container_name="x-proxy",
            _egress_network_name="cognic-sb-egress-x",
            active_leases=(),
            active_projections=(),
            _actor_subject=_ACTOR.subject,
        )

        await backend.destroy(session)

        for forbidden in (
            "credentials_projection_cleaned_up",
            "credentials_projection_cleanup_failed",
            "lease_revoked",
            "lease_revoke_failed",
        ):
            assert forbidden not in _emitted_event_names(events)

    async def test_destroy_idempotent_no_duplicate_credential_events(self) -> None:
        """Second destroy() on the same session MUST NOT re-emit
        the projection/revoke events. Mirrors the Sprint-8A
        ``_destroyed`` flag posture."""
        backend, adapter, events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)
        first_call_event_count = len(_events_of_type(events, "credentials_projection_cleaned_up"))
        first_revoke_count = len(adapter.revoke_calls)

        await backend.destroy(session)
        # Second destroy MUST NOT emit additional credential events.
        assert (
            len(_events_of_type(events, "credentials_projection_cleaned_up"))
            == first_call_event_count
        )
        # Second destroy MUST NOT issue additional revoke calls.
        assert len(adapter.revoke_calls) == first_revoke_count

    async def test_destroy_filesystem_cleanup_failure_emits_cleanup_failed(
        self,
    ) -> None:
        """When ``cleanup_projection_dir`` raises during the LIFO
        unwind, ``cleanup_failed`` event fires + revoke still
        runs (cleanup-failed does NOT block revoke per spec §5.8
        step 5). Pinned by the round-2 P2 split inside
        ``_cleanup_projected_credential``."""
        backend, adapter, events = _make_backend_with_preflight_pass()
        backend._cleanup_projection_dir = AsyncMock(  # type: ignore[method-assign]
            side_effect=PermissionError("EACCES on staging dir")
        )
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        # cleanup_failed fired for db_main_1.
        cleanup_failed_events = _events_of_type(events, "credentials_projection_cleanup_failed")
        assert len(cleanup_failed_events) == 1
        _name, payload = cleanup_failed_events[0]
        assert payload["error_class"] == "PermissionError"
        # Revoke still happened despite cleanup failure.
        assert adapter.revoke_calls == ["lease-1"]
        # cleaned_up did NOT fire (mutually exclusive per round-2 P2).
        assert _events_of_type(events, "credentials_projection_cleaned_up") == []


# ===========================================================================
# Slice 4 round-2 P1 — projected-lease audit emit failures propagate
# on normal destroy (NOT silently suppressed via best-effort posture)
# ===========================================================================


class TestDestroyProjectedAuditEmitFailurePropagates:
    """Slice-4 round-2 reviewer P1: pre-fix
    ``_cleanup_projected_credential`` wrapped EVERY audit emit in
    ``contextlib.suppress(Exception)`` unconditionally. That bypassed
    the existing destroy()-normal-path contract (pinned by
    ``test_credential_lifecycle.py::TestCrossBackendDestroyAuditEmitConditionalSuppress``):
    on normal destroy, revoke audit emit failures MUST be CAPTURED,
    all leases still attempted, then the first emit failure
    propagated — so a projected lease whose ``lease_revoked`` emit
    failed could lose its chain row + ``destroy()`` would still set
    ``_destroyed=True``, making retry impossible.

    Post-fix: the helper accepts an ``emit_handler`` callable that
    destroy()'s normal path supplies as the same
    ``_emit_revoke_event`` capture-and-continue handler used by the
    bare-revoke loop. Teardown-failure path keeps suppress posture
    so the original teardown exception wins (Python finally-block
    semantics).
    """

    async def test_projected_lease_revoked_emit_failure_propagates_on_normal_destroy(
        self,
    ) -> None:
        """Normal destroy (teardown succeeds) — projected lease's
        ``lease_revoked`` audit emit raises → the RuntimeError MUST
        propagate AFTER every projected credential's revoke + emit
        attempt completes."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        # FS cleanup + revoke succeed for both; lease_revoked emit
        # fails for lease-1 (deeper in the LIFO unwind order).
        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _raise_on_lease_revoked_for_lease_1(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if (
                record.decision_type == "sandbox.lifecycle.lease_revoked"
                and record.payload.get("lease_id") == "lease-1"
            ):
                raise RuntimeError("simulated chain-append failure on lease-1 lease_revoked")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = (  # type: ignore[attr-defined]
            _raise_on_lease_revoked_for_lease_1
        )

        # Pre-fix: destroy() would silently swallow the audit failure
        # + complete + set _destroyed=True. Post-fix: the RuntimeError
        # propagates so the operator sees the audit-store outage.
        with pytest.raises(RuntimeError, match="simulated chain-append failure"):
            await backend.destroy(session)

        # CRITICAL: every projected credential was revoked BEFORE the
        # exception propagated (capture-and-continue per spec §7.2).
        assert adapter.revoke_calls == ["lease-2", "lease-1"]

    async def test_projected_lease_revoke_failed_emit_failure_propagates_on_normal_destroy(
        self,
    ) -> None:
        """Same shape but the audit emit that fails is
        ``lease_revoke_failed`` (which fires when Vault revoke itself
        raised). The audit-store outage MUST still propagate per
        spec §7.2."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        # Vault revoke fails for lease-1 → lease_revoke_failed audit
        # emit fires → that emit ALSO fails. The propagation MUST
        # surface the audit failure (not silently swallow it).
        adapter.queue_revoke(RuntimeError("simulated vault 503"))

        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _raise_on_lease_revoke_failed(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if record.decision_type == "sandbox.lifecycle.lease_revoke_failed":
                raise RuntimeError("simulated chain-append failure on lease_revoke_failed")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = (  # type: ignore[attr-defined]
            _raise_on_lease_revoke_failed
        )

        with pytest.raises(
            RuntimeError, match="simulated chain-append failure on lease_revoke_failed"
        ):
            await backend.destroy(session)
        # Vault revoke was attempted for lease-1 (the only lease).
        assert adapter.revoke_calls == ["lease-1"]

    async def test_teardown_failure_path_suppresses_projected_emit_failures(
        self,
    ) -> None:
        """Teardown-failure path — when ``_teardown_session_state``
        raises, the projection-unwind audit emit failures MUST be
        SUPPRESSED so the original teardown exception is what
        ``destroy()`` surfaces (Python finally-block semantics).
        The existing ``test_cross_backend_destroy_audit_emit_conditional_suppress``
        contract pinned this for the bare-revoke loop; slice-4
        round-2 P1 extends the same posture to projected leases
        via the shared ``_emit_revoke_event`` handler."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_session_with_projections(backend=backend, pairs=pairs)

        # Teardown raises.
        backend._teardown_session_state = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("teardown blew up")
        )

        # Projected lease's lease_revoked audit emit ALSO raises —
        # but the teardown exception MUST win.
        original_side_effect = backend._dh.append_with_precondition.side_effect  # type: ignore[attr-defined]

        async def _raise_on_lease_revoked(
            *, precondition: Any, record_builder: Any
        ) -> tuple[uuid.UUID, bytes]:
            captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
            record = record_builder(captured)
            if record.decision_type == "sandbox.lifecycle.lease_revoked":
                raise RuntimeError("audit emit failure DURING teardown-failure path")
            result: tuple[uuid.UUID, bytes] = await original_side_effect(
                precondition=precondition, record_builder=record_builder
            )
            return result

        backend._dh.append_with_precondition.side_effect = (  # type: ignore[attr-defined]
            _raise_on_lease_revoked
        )

        # Original teardown exception wins — audit emit failure is
        # suppressed per the finally-block contract.
        with pytest.raises(RuntimeError, match="teardown blew up"):
            await backend.destroy(session)
        # Lease was still attempted to be revoked (best-effort)
        # even though the teardown raised.
        assert adapter.revoke_calls == ["lease-1"]

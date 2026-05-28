"""Sprint 10.6 T21 slice 5 — K8s ``create()`` mint-then-project
lifecycle integration regressions per spec §5.8 + the user-locked
T21 entry decisions (locks 1-4).

Mirrors the Docker slice-3 test file
(``test_docker_sibling_credential_lifecycle.py``) but adjusted for
K8s-specific shapes:

  * No host-filesystem staging — credential bytes live in a K8s
    ``Secret`` object created via ``create_namespaced_secret``.
  * No bind-mount ``extra_mounts`` — the Pod spec is extended with
    per-credential ``volumes`` + ``volumeMounts`` + a pod-level
    ``fsGroup`` derived from ``expected_workload_gid``.
  * ``cleanup_target="secret_resource"`` (vs Docker's
    ``"staging_dir"``) on every cleanup-side audit event.
  * No dev-escape (the K8s preflight signature has no
    ``dev_escape_enabled`` / ``profile`` params — type-system level
    prevention per slice-1 lock #2).
  * K8s ``Secret`` creation MUST happen AFTER mint AND BEFORE Pod
    create — the kubelet projects the Secret into the Pod at
    container-start time, so the Secret resource has to exist by
    the time the kubelet picks up the Pod manifest.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")

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
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
)
from cognic_agentos.sandbox.projection import (
    ProjectionPlan,
    ProjectionPlanEntry,
    ProjectionRefused,
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
    """CredentialAdapter mock recording mint/revoke + per-call
    primable. Mirrors the Docker fixture pattern."""

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
) -> tuple[KubernetesPodSandboxBackend, _RecordingAdapter, list[tuple[str, dict[str, Any]]]]:
    """Construct a mocked-kubernetes_asyncio backend with the
    substrate preflight pre-mocked to PASS + the Secret-create +
    Secret-delete seams pre-mocked so tests don't need a real
    cluster."""
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
    store, events = _make_event_recorder()
    used_adapter = adapter or _RecordingAdapter()
    backend = KubernetesPodSandboxBackend(
        kube_api_client=kube,
        namespace="test-ns",
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
    backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._wait_for_pod_ready = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
        return_value=PreflightResult(
            resolved_gid=1000,
            file_mode=0o440,
            dir_mode=0o750,
            dev_escape_downgrade_reason=None,
        )
    )
    # Pre-mock the K8s Secret create + delete seams so tests don't
    # hit a real cluster. Tests that need to drive Secret-create
    # failure override these via side_effect.
    backend._k8s_create_namespaced_secret = AsyncMock(return_value=None)  # type: ignore[method-assign]
    backend._k8s_delete_namespaced_secret = AsyncMock(return_value=None)  # type: ignore[method-assign]
    return backend, used_adapter, events


def _create_kwargs(
    *,
    credential_decls: Sequence[CredentialDecl] = (),
    requires_credentials: Sequence[VaultLeaseRequest] = (),
    expected_workload_gid: int | None = 1000,
) -> dict[str, Any]:
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
    return [name.replace("sandbox.lifecycle.", "") for name, _ in events]


def _events_of_type(
    events: list[tuple[str, dict[str, Any]]], suffix: str
) -> list[tuple[str, dict[str, Any]]]:
    return [(name, payload) for name, payload in events if name.endswith(suffix)]


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


# ===========================================================================
# Test family 1 — Pair guard before mint (cross-backend invariant)
# ===========================================================================


class TestPairGuardBeforeMint:
    """Cross-backend invariant: pair guard refuses one-side-empty +
    length-mismatch + path-mismatch + tenant-mismatch BEFORE any
    I/O. Slice-3 scaffolding wired this on K8s; slice-5 keeps it
    pinned even though K8s now does the full mint-then-project
    lifecycle."""

    async def test_length_mismatch_raises_value_error_no_mint(self) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(_make_credential_decl(), _make_credential_decl(logical_name="aws")),
            expected_workload_gid=1000,
        )
        with pytest.raises(ValueError, match=r"length mismatch"):
            await backend.create(_POLICY, **kwargs)
        assert adapter.mint_calls == []
        assert _emitted_event_names(events) == []

    async def test_tenant_mismatch_raises_value_error_no_mint(self) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        kwargs = _create_kwargs(
            requires_credentials=(
                _make_lease_request(secret_path="database/creds/db-main", tenant_id="tenant-a"),
            ),
            credential_decls=(
                _make_credential_decl(vault_path="database/creds/db-main", tenant_id="tenant-b"),
            ),
        )
        with pytest.raises(ValueError, match=r"tenant_id mismatch"):
            await backend.create(_POLICY, **kwargs)
        assert adapter.mint_calls == []


# ===========================================================================
# Test family 2 — K8s preflight before mint + dev-escape no-leak
# ===========================================================================


class TestK8sPreflightBeforeMint:
    """K8s preflight runs AFTER admission + proxy image verify +
    BEFORE the mint-then-project loop. Refusal = zero minted leases
    + zero credential-projection events.

    Slice-1 lock #2: K8s preflight signature has NO ``dev_escape_enabled``
    param — Docker-only dev escape MUST NOT leak. Verified at the
    type-system level by the K8s preflight signature; this slice
    pins the runtime behaviour."""

    async def test_preflight_refusal_raises_no_mint_no_secret(self) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
            side_effect=SandboxLifecycleRefused(
                "sandbox_credential_projection_workload_gid_unknown",
                detail="test preflight refusal",
            )
        )
        kwargs = _create_kwargs(
            requires_credentials=(_make_lease_request(),),
            credential_decls=(_make_credential_decl(),),
        )
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            await backend.create(_POLICY, **kwargs)
        assert exc_info.value.reason == ("sandbox_credential_projection_workload_gid_unknown")
        # Zero mint calls + zero Secret-create calls + zero events.
        assert adapter.mint_calls == []
        backend._k8s_create_namespaced_secret.assert_not_called()  # type: ignore[attr-defined]
        for forbidden in (
            "lease_minted",
            "credentials_projected",
            "credentials_projection_failed",
        ):
            assert forbidden not in _emitted_event_names(events)

    async def test_preflight_not_called_when_no_credentials_requested(self) -> None:
        backend, _adapter, _events = _make_backend_with_preflight_pass()
        await backend.create(_POLICY, **_create_kwargs(expected_workload_gid=None))
        backend._collect_preflight_result.assert_not_awaited()  # type: ignore[attr-defined]

    async def test_dev_escape_env_var_has_no_k8s_effect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Slice-1 lock #2 runtime regression: setting the
        Docker-only ``COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION``
        env var MUST have NO effect on the K8s flow. The K8s preflight
        signature has no acceptance point for the dev_escape flag."""
        monkeypatch.setenv("COGNIC_DEV_ALLOW_PERMISSIVE_CREDENTIAL_PROJECTION", "1")
        backend, _adapter, _events = _make_backend_with_preflight_pass()
        backend._collect_preflight_result = AsyncMock(  # type: ignore[method-assign]
            side_effect=SandboxLifecycleRefused(
                "sandbox_credential_projection_root_workload_refused",
                detail="root workload refused",
            )
        )
        with pytest.raises(SandboxLifecycleRefused) as exc_info:
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                    expected_workload_gid=0,
                ),
            )
        # Refusal MUST NOT have been downgraded by the dev-escape env var.
        assert exc_info.value.reason == ("sandbox_credential_projection_root_workload_refused")


# ===========================================================================
# Test family 3 — Happy path per-credential event ordering + K8s Secret
# create order
# ===========================================================================


class TestHappyPathEventOrdering:
    """Per-credential ``lease_minted`` THEN ``credentials_projected``
    in manifest declaration order. K8s Secret create call sits
    BETWEEN those two events per credential."""

    async def test_single_credential_emit_order_and_secret_create(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl(),),
            ),
        )

        event_names = _emitted_event_names(events)
        assert "lease_minted" in event_names
        assert "credentials_projected" in event_names
        assert event_names.index("lease_minted") < event_names.index("credentials_projected")
        # Exactly one Secret-create call.
        assert backend._k8s_create_namespaced_secret.call_count == 1  # type: ignore[attr-defined]

    async def test_two_credentials_emit_in_manifest_declaration_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2", secret_path="aws/creds/payments"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/db-main"),
                    _make_lease_request(secret_path="aws/creds/payments"),
                ),
                credential_decls=(
                    _make_credential_decl(
                        logical_name="db_main", vault_path="database/creds/db-main"
                    ),
                    _make_credential_decl(
                        logical_name="aws_credentials",
                        vault_path="aws/creds/payments",
                    ),
                ),
            ),
        )

        credential_events = [
            (name, payload)
            for name, payload in events
            if name in ("sandbox.lifecycle.lease_minted", "sandbox.lifecycle.credentials_projected")
        ]
        names_only = [name for name, _ in credential_events]
        assert names_only == [
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.credentials_projected",
            "sandbox.lifecycle.lease_minted",
            "sandbox.lifecycle.credentials_projected",
        ]
        projected_events = _events_of_type(events, "credentials_projected")
        assert [p["logical_name"] for _, p in projected_events] == [
            "db_main",
            "aws_credentials",
        ]
        # Exactly two Secret-create calls in order.
        assert backend._k8s_create_namespaced_secret.call_count == 2  # type: ignore[attr-defined]

    async def test_secret_create_happens_BEFORE_pod_create(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User-locked: Secret creation MUST happen AFTER mint AND
        BEFORE Pod create — the kubelet projects the Secret at
        Pod-start, so it has to exist by the time the Pod manifest
        is submitted. Verified via call ordering of the two mocks."""
        backend, adapter, _events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        call_log: list[str] = []
        backend._k8s_create_namespaced_secret = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda **kw: call_log.append("create_secret")
        )
        backend._create_pod = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda body: call_log.append("create_pod")
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl(),),
            ),
        )

        # Secret-create MUST appear before Pod-create.
        assert call_log == ["create_secret", "create_pod"]


# ===========================================================================
# Test family 4 — Path 2 — Projection refusal for credential N
# ===========================================================================


class TestPath2ProjectionRefusalForCredentialN:
    """Per spec §5.8 step 3d: failed credential N is revoke-only
    (NO ``credentials_projection_cleaned_up`` for N — it never
    projected; NO Secret was created for N). Already-projected
    credentials 1..N-1 LIFO-unwind with Secret-delete-before-revoke
    per credential."""

    async def test_first_credential_refusal_revokes_only_no_secret_create(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
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

        # Lease N revoked.
        assert adapter.revoke_calls == ["lease-1"]
        # NO Secret create call for the failed credential.
        backend._k8s_create_namespaced_secret.assert_not_called()  # type: ignore[attr-defined]
        # NO credentials_projection_cleaned_up for the failed credential.
        assert _events_of_type(events, "credentials_projection_cleaned_up") == []

    async def test_path2_emits_failed_with_revoke_outcome_revoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_revoke(None)
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
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

    async def test_path2_lifo_unwind_deletes_secrets_before_revoke(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """3 credentials; planner fails on the 3rd. LIFO unwind:
        Secret-delete-2 → revoke-2 → Secret-delete-1 → revoke-1.
        Secret-3 was NEVER created (planner refused before Secret-create);
        Secret-2 + Secret-1 were created and now get deleted in
        reverse order, with revoke after each Secret-delete per
        spec §5.8 step 5."""
        backend, adapter, events = _make_backend_with_preflight_pass()
        for i in range(1, 4):
            adapter.queue_mint(
                _make_minted_lease(lease_id=f"lease-{i}", secret_path=f"database/creds/db-{i}")
            )

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
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            _plan,
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
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_2",
            "db_main_1",
        ]
        # Cleanup target on every cleaned_up row is secret_resource (K8s).
        for _name, payload in cleaned_up_events:
            assert payload["cleanup_target"] == "secret_resource"
        # 2 Secret-delete calls (one for each unwound credential).
        assert backend._k8s_delete_namespaced_secret.call_count == 2  # type: ignore[attr-defined]


# ===========================================================================
# Test family 5 — Path 3 — Post-projection backend failure
# ===========================================================================


class TestPath3PostProjectionFailure:
    """Failure AFTER all credentials projected (Pod create / audit
    emit / etc): LIFO unwind ALL projected credentials with
    Secret-delete-before-revoke per credential."""

    async def test_pod_create_failure_post_projection_lifo_unwinds_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2"))

        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )
        # Pod create FAILS after projection.
        backend._create_pod = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("k8s pod create exploded")
        )

        with pytest.raises(RuntimeError, match="k8s pod create exploded"):
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

        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_2",
            "db_main_1",
        ]
        assert adapter.revoke_calls == ["lease-2", "lease-1"]


# ===========================================================================
# Test family 6 — Pod spec carries credential_secrets + workload_fs_group
# ===========================================================================


class TestPodSpecCarriesCredentialSecretsAndFsGroup:
    """Per user-locked T20 entry decision: when ``credential_decls``
    is non-empty, the Pod spec submitted to ``_create_pod`` MUST
    include:

      * ``spec.securityContext.fsGroup`` = ``expected_workload_gid``
        (pod-level; pinned by the T20
        ``TestBuildPodSpecWithFsGroup`` test class)
      * ``spec.volumes`` extended with one ``secret``-source volume
        per credential (DNS-1123-safe opaque Secret name as
        ``volume.name``)
      * ``spec.containers[sandbox].volumeMounts`` extended with one
        read-only mount at ``/run/credentials/<logical_name>`` per
        credential"""

    async def test_pod_spec_carries_fsgroup_from_expected_workload_gid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        captured_pod_specs: list[dict[str, Any]] = []
        backend._create_pod = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda body: captured_pod_specs.append(body)
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl(),),
                expected_workload_gid=1234,
            ),
        )

        assert len(captured_pod_specs) == 1
        pod_spec = captured_pod_specs[0]
        assert pod_spec["spec"]["securityContext"] == {"fsGroup": 1234}

    async def test_pod_spec_carries_per_credential_secret_volumes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        adapter.queue_mint(_make_minted_lease(lease_id="lease-2", secret_path="aws/creds/payments"))
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        captured_pod_specs: list[dict[str, Any]] = []
        backend._create_pod = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda body: captured_pod_specs.append(body)
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(
                    _make_lease_request(secret_path="database/creds/db-main"),
                    _make_lease_request(secret_path="aws/creds/payments"),
                ),
                credential_decls=(
                    _make_credential_decl(
                        logical_name="db_main", vault_path="database/creds/db-main"
                    ),
                    _make_credential_decl(
                        logical_name="aws_credentials",
                        vault_path="aws/creds/payments",
                    ),
                ),
            ),
        )

        pod_spec = captured_pod_specs[0]
        # Volumes: 2 secret-source volumes (in addition to baseline
        # workspace + proxy-log).
        secret_volumes = [v for v in pod_spec["spec"]["volumes"] if "secret" in v]
        assert len(secret_volumes) == 2
        # All volume names start with "cognic-cred-" prefix (DNS-1123-safe).
        for vol in secret_volumes:
            assert vol["name"].startswith("cognic-cred-")
        # Mount paths in sandbox container carry the semantic logical_name.
        sandbox_container = next(
            c for c in pod_spec["spec"]["containers"] if c["name"] == "sandbox"
        )
        mount_paths = {m["mountPath"] for m in sandbox_container["volumeMounts"]}
        assert "/run/credentials/db_main" in mount_paths
        assert "/run/credentials/aws_credentials" in mount_paths


# ===========================================================================
# Test family 7 — Backend resource name in audit payload = K8s Secret name
# ===========================================================================


class TestBackendResourceNameOnAuditPayload:
    """K8s spec §5.7: ``backend_resource_name`` on
    ``credentials_projected`` payload = the K8s Secret name (opaque
    ``cognic-cred-<16-hex>``) — NOT the host_staging_dir path
    (Docker-only). Pinned at the audit-payload boundary."""

    async def test_credentials_projected_carries_k8s_secret_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )

        await backend.create(
            _POLICY,
            **_create_kwargs(
                requires_credentials=(_make_lease_request(),),
                credential_decls=(_make_credential_decl(),),
            ),
        )

        projected_events = _events_of_type(events, "credentials_projected")
        assert len(projected_events) == 1
        _name, payload = projected_events[0]
        # K8s backend_resource_name = Secret name = cognic-cred-<16-hex>.
        assert payload["backend_resource_name"].startswith("cognic-cred-")
        # NOT a Docker-style host path.
        assert not payload["backend_resource_name"].startswith("/dev/shm/")


# ===========================================================================
# Round-2 P1 — session_id parity across mint/projected/cleanup chain rows
# ===========================================================================


class TestCleanupRowSessionIdParity:
    """Round-2 reviewer P1: pre-fix the K8s
    ``_cleanup_post_admission_failure`` envelope passed ``pod_name``
    (=``sb-<session_id>``) as session_id to
    ``_cleanup_projected_credential``, breaking chain-row correlation
    with the earlier ``lease_minted`` / ``credentials_projected``
    rows that the create() body emitted with the raw ``session_id``.

    Post-fix: cleanup envelope threads the raw ``session_id`` through.
    Verified by comparing cleanup-row ``payload["session_id"]`` to
    the minted/projected row value + asserting it does NOT carry the
    ``sb-`` pod-name prefix."""

    async def test_cleanup_row_session_id_matches_minted_row_session_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Path 3 — Pod-create failure post-projection triggers the
        # cleanup envelope. Compare session_id across minted / projected /
        # cleaned_up / lease_revoked rows.
        backend, adapter, events = _make_backend_with_preflight_pass()
        adapter.queue_mint(_make_minted_lease(lease_id="lease-1"))
        monkeypatch.setattr(
            "cognic_agentos.sandbox.backends.kubernetes_pod.compute_projection_plan",
            lambda *, lease, manifest_decl: _make_projection_plan(lease=lease, decl=manifest_decl),
        )
        backend._create_pod = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("simulated pod create failure")
        )

        with pytest.raises(RuntimeError, match="simulated pod create failure"):
            await backend.create(
                _POLICY,
                **_create_kwargs(
                    requires_credentials=(_make_lease_request(),),
                    credential_decls=(_make_credential_decl(),),
                ),
            )

        minted_events = _events_of_type(events, "lease_minted")
        projected_events = _events_of_type(events, "credentials_projected")
        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        revoked_events = _events_of_type(events, "lease_revoked")
        assert len(minted_events) == 1
        assert len(projected_events) == 1
        assert len(cleaned_up_events) == 1
        assert len(revoked_events) == 1

        minted_session_id = minted_events[0][1]["session_id"]
        # Sanity: minted row has raw session_id (no ``sb-`` prefix).
        assert not minted_session_id.startswith("sb-"), (
            f"baseline assumption broken: minted session_id={minted_session_id!r}"
        )
        # Round-2 P1 fix: every downstream row shares the same raw
        # session_id (NOT ``sb-<session_id>`` pod_name).
        for _name, payload in projected_events:
            assert payload["session_id"] == minted_session_id
        for _name, payload in cleaned_up_events:
            assert payload["session_id"] == minted_session_id
            assert not payload["session_id"].startswith("sb-")
        for _name, payload in revoked_events:
            assert payload["session_id"] == minted_session_id


# ===========================================================================
# Slice 6 K8s — destroy() LIFO unwind (mirrors Docker slice 4)
# ===========================================================================


def _make_executor_result_pair_k8s(
    *,
    lease_id: str,
    logical_name: str,
    vault_path: str = "database/creds/db-main",
) -> tuple[CredentialLease, K8sExecutorResult]:
    from cognic_agentos.sandbox.backends._k8s_executor import K8sExecutorResult

    lease = _make_minted_lease(lease_id=lease_id, secret_path=vault_path)
    er = K8sExecutorResult(
        logical_name=logical_name,
        vault_path=vault_path,
        tenant_id="t-1",
        lease_id=lease_id,
        projected_field_count=2,
        purpose_category="application_database_read",
        purpose_description="Read-only application database access.",
        secret_name=f"cognic-cred-{lease_id.replace('-', '')[:16].ljust(16, '0')}",
        container_mount_target=f"/run/credentials/{logical_name}",
        session_id="sess-destroy-t21-k8s",
    )
    return lease, er


def _make_k8s_session_with_projections(
    *,
    backend: KubernetesPodSandboxBackend,
    pairs: list[tuple[CredentialLease, K8sExecutorResult]],
) -> Any:
    from cognic_agentos.sandbox.backends.kubernetes_pod import KubernetesPodSession

    leases = tuple(lease for lease, _er in pairs)
    projections = tuple(er for _lease, er in pairs)
    return KubernetesPodSession(
        session_id="sess-destroy-t21-k8s",
        policy=_POLICY,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _pod_name="sb-destroy-t21-k8s",
        _network_policy_name="sb-destroy-t21-k8s",
        _namespace="test-ns",
        active_leases=leases,
        active_projections=projections,
        _actor_subject=_ACTOR.subject,
    )


# Import for type annotations in helpers above.
from cognic_agentos.sandbox.backends._k8s_executor import K8sExecutorResult  # noqa: E402


class TestK8sDestroyLifoProjectionCleanupBeforeRevoke:
    """Sprint 10.6 T21 slice 6 — K8s ``destroy()`` LIFO unwind:
    per-credential Secret-delete → emit cleaned_up → revoke → emit
    lease_revoked, in REVERSE manifest order. Mirrors the Docker
    slice-4 test family."""

    async def test_destroy_emits_cleaned_up_before_lease_revoked_per_credential(
        self,
    ) -> None:
        backend, _adapter, events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair_k8s(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        relevant = [
            (name.replace("sandbox.lifecycle.", ""), payload)
            for name, payload in events
            if name
            in (
                "sandbox.lifecycle.credentials_projection_cleaned_up",
                "sandbox.lifecycle.lease_revoked",
            )
        ]
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
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair_k8s(lease_id="lease-2", logical_name="db_main_2"),
            _make_executor_result_pair_k8s(lease_id="lease-3", logical_name="db_main_3"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        cleaned_up_events = _events_of_type(events, "credentials_projection_cleaned_up")
        assert [p["logical_name"] for _, p in cleaned_up_events] == [
            "db_main_3",
            "db_main_2",
            "db_main_1",
        ]
        assert adapter.revoke_calls == ["lease-3", "lease-2", "lease-1"]
        # Per-credential cleanup_target = secret_resource (K8s).
        for _name, payload in cleaned_up_events:
            assert payload["cleanup_target"] == "secret_resource"

    async def test_destroy_no_double_revoke_for_projected_leases(self) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair_k8s(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)
        # Exactly ONE revoke per lease.
        assert adapter.revoke_calls == ["lease-2", "lease-1"]
        assert len(adapter.revoke_calls) == 2

    async def test_destroy_with_no_projections_no_credential_events(self) -> None:
        """Credential-less K8s sandbox MUST emit zero credential-projection
        events on destroy. Backward-compat with Sprint-8B lease-less
        sandboxes."""
        from cognic_agentos.sandbox.backends.kubernetes_pod import KubernetesPodSession

        backend, _adapter, events = _make_backend_with_preflight_pass()
        session = KubernetesPodSession(
            session_id="sess-no-credentials-k8s",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _pod_name="sb-empty",
            _network_policy_name="sb-empty",
            _namespace="test-ns",
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
        backend, adapter, events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)
        first_call_event_count = len(_events_of_type(events, "credentials_projection_cleaned_up"))
        first_revoke_count = len(adapter.revoke_calls)

        await backend.destroy(session)
        assert (
            len(_events_of_type(events, "credentials_projection_cleaned_up"))
            == first_call_event_count
        )
        assert len(adapter.revoke_calls) == first_revoke_count

    async def test_destroy_secret_delete_failure_emits_cleanup_failed(self) -> None:
        backend, adapter, events = _make_backend_with_preflight_pass()
        backend._k8s_delete_namespaced_secret = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("k8s API 5xx on Secret delete")
        )
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        await backend.destroy(session)

        cleanup_failed_events = _events_of_type(events, "credentials_projection_cleanup_failed")
        assert len(cleanup_failed_events) == 1
        _name, payload = cleanup_failed_events[0]
        assert payload["error_class"] == "RuntimeError"
        assert payload["cleanup_target"] == "secret_resource"
        # Revoke still happened despite Secret-delete failure.
        assert adapter.revoke_calls == ["lease-1"]
        # cleaned_up did NOT fire.
        assert _events_of_type(events, "credentials_projection_cleaned_up") == []


class TestK8sDestroyProjectedAuditEmitFailurePropagates:
    """Mirrors Docker slice-4 round-2 P1 contract on K8s: projected-
    lease audit emit failures on normal destroy MUST be CAPTURED via
    the shared ``_emit_revoke_event`` handler + propagated AFTER
    every credential's revoke + cleanup attempt. Teardown-failure
    path suppresses so the original teardown exception wins."""

    async def test_projected_lease_revoked_emit_failure_propagates_on_normal_destroy(
        self,
    ) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
            _make_executor_result_pair_k8s(lease_id="lease-2", logical_name="db_main_2"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

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

        with pytest.raises(RuntimeError, match="simulated chain-append failure"):
            await backend.destroy(session)

        # All projected credentials revoked BEFORE the exception propagated.
        assert adapter.revoke_calls == ["lease-2", "lease-1"]

    async def test_teardown_failure_path_suppresses_projected_emit_failures(
        self,
    ) -> None:
        backend, adapter, _events = _make_backend_with_preflight_pass()
        pairs = [
            _make_executor_result_pair_k8s(lease_id="lease-1", logical_name="db_main_1"),
        ]
        session = _make_k8s_session_with_projections(backend=backend, pairs=pairs)

        # Teardown raises.
        backend._teardown_session_state = AsyncMock(  # type: ignore[method-assign]
            side_effect=RuntimeError("teardown blew up")
        )

        # Projected lease's lease_revoked audit emit ALSO raises.
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

        # Original teardown exception wins (Python finally-block semantics).
        with pytest.raises(RuntimeError, match="teardown blew up"):
            await backend.destroy(session)
        # Lease was still attempted to be revoked best-effort.
        assert adapter.revoke_calls == ["lease-1"]

"""Sprint 8B T8B-b — KubernetesPodSandboxBackend admission integration.

NON-env-gated (runs in default CI under ``uv sync --all-extras``).
Pins that ``KubernetesPodSandboxBackend.create()`` invokes
:func:`admit_policy` with the right kwargs BEFORE any K8s API call,
and that admission refusals propagate without leaking partial K8s
state.

Mirrors the Sprint-8A admission-pipeline test patterns at
``tests/unit/sandbox/test_admission_pipeline.py``. The K8s backend
MUST reuse the existing 9-step Stage-2 admission pipeline at
``src/cognic_agentos/sandbox/admission.py:177`` — backend-agnostic.
A refactor that bypasses admit_policy on the K8s path would allow
untrusted images / forbidden risk tiers / cap-exceeding policies to
reach Pod creation. These regressions are the load-bearing pins
that catch that class of refactor.

Mocking strategy:
* The ``kube_api_client`` constructor arg is a MagicMock that
  passes isinstance-style usage but never gets called on the
  refusal paths (admit_policy raises BEFORE the backend constructs
  any K8s API call).
* The CoreV1Api + NetworkingV1Api are monkeypatched on the
  ``kubernetes_asyncio.client`` module so the green-path test can
  assert call shape without a real apiserver.
* ``MagicMock()`` keeps sync catalog methods sync; only the async
  catalog methods get AsyncMock per the Sprint-8A admission-pipeline
  fixture convention.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.admission import (
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _CANONICAL_EGRESS_PROXY_IMAGE,
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)

# ---------------------------------------------------------------------------
# Shared fixtures (mirror tests/unit/sandbox/test_admission_pipeline.py)
# ---------------------------------------------------------------------------

_VALID_DIGEST = "sha256:" + "a" * 64
_VALID_PACK_DIGEST = "sha256:" + "b" * 64
_VALID_IMAGE_REF = "cognic/sandbox-runtime-python:v1@" + _VALID_DIGEST
_, _PROXY_IMAGE_DIGEST = _CANONICAL_EGRESS_PROXY_IMAGE.rsplit("@", 1)


def _valid_policy(**overrides: object) -> SandboxPolicy:
    base: dict[str, object] = {
        "cpu_cores": 1.0,
        "cpu_time_budget_s": None,
        "memory_mb": 256,
        "walltime_s": 30.0,
        "runtime_image": _VALID_IMAGE_REF,
        "egress_allow_list": ("api.example.com",),
        "vault_path": None,
    }
    base.update(overrides)
    return SandboxPolicy(**base)  # type: ignore[arg-type]


def _valid_pack_context(**overrides: object) -> PackAdmissionContext:
    base: dict[str, object] = {
        "pack_id": "cognic.test_pack",
        "pack_version": "v1.0.0",
        "pack_artifact_digest": _VALID_PACK_DIGEST,
        "risk_tier": "internal_write",
        "declares_dynamic_install": False,
        "profile": "production",
    }
    base.update(overrides)
    return PackAdmissionContext(**base)  # type: ignore[arg-type]


def _passing_settings() -> MagicMock:
    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
    )


def _passing_catalog() -> MagicMock:
    """Catalog whose ``is_canonical`` returns True for BOTH the
    runtime image digest AND the canonical egress-proxy image
    digest (the backend's pre-flight proxy-image verification at
    create() time mirrors docker_sibling's R1 P1.1 gate)."""
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return catalog


def _passing_rego() -> MagicMock:
    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    return rego


def _actor() -> MagicMock:
    """Actor mock — admit_policy passes it through; the backend uses
    ``actor.subject`` for audit attribution."""
    a = MagicMock()
    a.subject = "user:alice"
    return a


def _backend(
    *,
    catalog: MagicMock | None = None,
    credential_adapter: object | None = None,
    rego: MagicMock | None = None,
    warm_pool: object | None = None,
) -> KubernetesPodSandboxBackend:
    """Construct a KubernetesPodSandboxBackend with mocked deps + a
    MagicMock kube_api_client. The client is never reached on the
    refusal-path tests (admit_policy raises first); the green-path
    test monkeypatches the CoreV1Api + NetworkingV1Api constructors
    on the kubernetes_asyncio.client module."""
    return KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="test-ns",
        image_catalog=catalog if catalog is not None else _passing_catalog(),
        credential_adapter=(
            credential_adapter  # type: ignore[arg-type]
            if credential_adapter is not None
            else AsyncMock(spec=CredentialAdapter)
        ),
        rego_engine=rego if rego is not None else _passing_rego(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=_passing_settings(),
        warm_pool=warm_pool,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Admission-refusal arms — the K8s backend MUST propagate the same
# SandboxLifecycleRefused taxonomy as DockerSibling (admission is
# backend-agnostic; refactor that bypasses admit_policy would catch
# these refusals silently).
# ---------------------------------------------------------------------------


class TestKubernetesPodBackendInvokesAdmitPolicy:
    """The backend's ``create()`` MUST run admit_policy BEFORE any
    K8s API call. The single-seam contract is what keeps the K8s
    backend behaviourally equivalent to DockerSibling at the
    admission boundary."""

    async def test_create_refuses_when_credential_adapter_is_default_stub(
        self,
    ) -> None:
        """admit_policy step 3 — vault_path set + default sentinel
        adapter → ``sandbox_credential_adapter_not_configured``."""
        backend = _backend(
            credential_adapter=KernelDefaultCredentialAdapter(),
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(vault_path="secret/test"),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_credential_adapter_not_configured"

    async def test_create_refuses_on_dynamic_install_in_production(
        self,
    ) -> None:
        """admit_policy step 3a — dynamic_install + production profile."""
        backend = _backend()
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(
                    declares_dynamic_install=True, profile="production"
                ),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_runtime_deps_unsupported_in_production"

    @pytest.mark.parametrize(
        "tier",
        [
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
        ],
    )
    async def test_create_refuses_on_high_risk_tier_pre_13_5(self, tier: str) -> None:
        """admit_policy step 4 — 6 ADR-014 transitional refusal tiers."""
        backend = _backend()
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(risk_tier=tier),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_high_risk_tier_refused_pre_13_5"

    async def test_create_refuses_on_tenant_max_cpu_exceeded(self) -> None:
        """admit_policy step 5 — cpu_cores > tenant max."""
        backend = _backend()
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(cpu_cores=16.0),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"

    async def test_create_refuses_on_image_not_in_catalog(self) -> None:
        """admit_policy step 6 — image_digest missing from both
        canonical set + per-tenant allow-list."""
        catalog = MagicMock()
        catalog.is_canonical.return_value = False
        catalog.is_tenant_allow_listed.return_value = False
        backend = _backend(catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"

    async def test_create_refuses_on_rego_denied(self) -> None:
        """admit_policy step 9 — Rego bundle denies."""
        rego = MagicMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(
                allow=False,
                rule_matched=None,
                reasoning="deny: synthetic",
                decision_data=None,
            )
        )
        backend = _backend(rego=rego)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_policy_rego_denied"


class TestProxyImageGoesThroughCatalogVerification:
    """Per spec §9 + the docker_sibling R1 P1.1 cross-backend parity
    contract — the proxy sidecar image MUST go through the SAME
    catalog trust gate as ``policy.runtime_image`` (canonical-set
    membership + cosign verify + SBOM policy check). The proxy IS
    the egress-enforcement component; without this gate, a
    compromised registry could land an unverified proxy as a trusted
    enforcement point."""

    async def test_create_refuses_when_proxy_image_not_canonical(self) -> None:
        """Catalog returns False for the proxy image digest →
        ``sandbox_image_digest_not_in_canonical_catalog`` BEFORE any
        K8s API call. The pre-flight gate runs AFTER admit_policy
        (which already approved the runtime image)."""
        catalog = MagicMock()

        # Runtime image passes, proxy image fails — split by digest.
        def _is_canonical(digest: str) -> bool:
            return digest != _PROXY_IMAGE_DIGEST

        catalog.is_canonical.side_effect = _is_canonical
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        backend = _backend(catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"
        # The detail message names the proxy image so examiners
        # can distinguish the proxy-gate refusal from the
        # admit_policy step-6 refusal.
        assert "proxy sidecar image" in exc.value.detail.lower() or (
            "egress" in exc.value.detail.lower()
        )

    async def test_create_runs_cosign_on_proxy_image_digest(self) -> None:
        """The proxy-image cosign verify call MUST happen on the
        proxy digest (NOT the runtime digest). Verify by counting
        cosign calls — admit_policy calls once on the runtime
        digest, then the pre-flight calls once more on the proxy
        digest."""
        catalog = _passing_catalog()
        backend = _backend(catalog=catalog)
        # Monkeypatch K8s api calls so the create() can reach the
        # backend's pre-flight proxy-image gate + the audit emit
        # without raising downstream.
        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]

        await backend.create(
            _valid_policy(),
            actor=_actor(),
            tenant_id="t-1",
            pack_context=_valid_pack_context(),
            use_warm_pool=False,
        )
        # 2 verify_cosign calls total — 1 from admit_policy on
        # runtime image, 1 from the backend's pre-flight on proxy
        # image.
        assert catalog.verify_cosign_or_refuse.await_count == 2
        # The 2nd call's positional arg is the proxy digest.
        proxy_call = catalog.verify_cosign_or_refuse.await_args_list[1]
        assert proxy_call.args[0] == _PROXY_IMAGE_DIGEST


class TestGreenPathCallsK8sApiInOrder:
    """Green-path create() invokes the K8s API in load-bearing
    order: NetworkPolicy FIRST (egress lockdown active before the
    Pod starts) → Pod second. Drift would briefly allow the Pod to
    run with default-namespace egress."""

    async def test_create_calls_network_policy_before_pod(self) -> None:
        backend = _backend()
        call_order: list[str] = []

        async def _record_netpol(body: dict[str, object]) -> None:
            call_order.append("network_policy")

        async def _record_pod(body: dict[str, object]) -> None:
            call_order.append("pod")

        backend._create_network_policy = _record_netpol  # type: ignore[method-assign]
        backend._create_pod = _record_pod  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]

        await backend.create(
            _valid_policy(),
            actor=_actor(),
            tenant_id="t-1",
            pack_context=_valid_pack_context(),
            use_warm_pool=False,
        )
        assert call_order == ["network_policy", "pod"]

    async def test_create_returns_kubernetespod_session_with_required_fields(
        self,
    ) -> None:
        backend = _backend()
        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
        actor = _actor()
        pack_ctx = _valid_pack_context()

        session = await backend.create(
            _valid_policy(),
            actor=actor,
            tenant_id="t-1",
            pack_context=pack_ctx,
            use_warm_pool=False,
        )
        assert isinstance(session, KubernetesPodSession)
        assert session.tenant_id == "t-1"
        assert session.pack_context is pack_ctx
        assert session.warm_pool_hit is False
        # session_id is a uuid4 hex (32 lowercase hex chars).
        assert len(session.session_id) == 32
        assert all(c in "0123456789abcdef" for c in session.session_id)
        # actor.subject threads onto the session for audit.
        assert session._actor_subject == "user:alice"


class TestCreateRollsBackOnK8sApiFailure:
    """If pod creation fails after NetworkPolicy was created (or
    vice versa), the cleanup envelope MUST tear down both — no K8s
    objects leak. No lifecycle.created chain row emitted because
    the session never reached a running state."""

    async def test_create_tears_down_network_policy_when_pod_creation_fails(
        self,
    ) -> None:
        backend = _backend()
        netpol_created = False
        teardown_calls: list[str] = []

        async def _create_netpol(body: dict[str, object]) -> None:
            nonlocal netpol_created
            netpol_created = True

        async def _create_pod_failing(body: dict[str, object]) -> None:
            raise RuntimeError("synthetic kube apiserver failure")

        async def _delete_netpol(name: str) -> None:
            teardown_calls.append(f"netpol:{name}")

        async def _delete_pod(name: str) -> None:
            teardown_calls.append(f"pod:{name}")

        backend._create_network_policy = _create_netpol  # type: ignore[method-assign]
        backend._create_pod = _create_pod_failing  # type: ignore[method-assign]
        backend._delete_network_policy_if_exists = _delete_netpol  # type: ignore[method-assign]
        backend._delete_pod_if_exists = _delete_pod  # type: ignore[method-assign]
        # The lifecycle.created emit MUST NOT fire on the failure path.
        emit_mock = AsyncMock(return_value=None)
        backend._emit_lifecycle_created = emit_mock  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="synthetic kube apiserver failure"):
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )

        assert netpol_created is True
        # Teardown happened for BOTH objects (the helper is
        # best-effort + idempotent so it asks for both even if
        # the pod was never created).
        assert any(c.startswith("pod:") for c in teardown_calls)
        assert any(c.startswith("netpol:") for c in teardown_calls)
        # lifecycle.created NOT emitted on the failure path.
        emit_mock.assert_not_awaited()

    async def test_create_tears_down_state_on_audit_failure(self) -> None:
        """A transient audit-append failure after K8s objects are
        created MUST trigger teardown so the caller does not see a
        successful return for a session it cannot clean up. Fail-
        closed: re-raise so the caller sees the audit failure."""
        backend = _backend()
        teardown_calls: list[str] = []

        async def _delete_netpol(name: str) -> None:
            teardown_calls.append(f"netpol:{name}")

        async def _delete_pod(name: str) -> None:
            teardown_calls.append(f"pod:{name}")

        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._delete_network_policy_if_exists = _delete_netpol  # type: ignore[method-assign]
        backend._delete_pod_if_exists = _delete_pod  # type: ignore[method-assign]

        emit_mock = AsyncMock(side_effect=RuntimeError("synthetic audit-store outage"))
        backend._emit_lifecycle_created = emit_mock  # type: ignore[method-assign]

        with pytest.raises(RuntimeError, match="synthetic audit-store outage"):
            await backend.create(
                _valid_policy(),
                actor=_actor(),
                tenant_id="t-1",
                pack_context=_valid_pack_context(),
                use_warm_pool=False,
            )
        # Teardown happened post-audit-failure → no orphan K8s objects.
        assert any(c.startswith("pod:") for c in teardown_calls)
        assert any(c.startswith("netpol:") for c in teardown_calls)


class TestExecStubFailsLoud:
    """Per ADR-004 + CLAUDE.md production-grade rule — the K8s
    backend's exec() stub MUST raise NotImplementedError pointing
    at T8B-c, NOT silently return an empty SandboxExecResult.
    A silent no-op would let pack code 'succeed' against an
    unfinished backend in production."""

    async def test_exec_raises_not_implemented_error_pointing_at_t8b_c(
        self,
    ) -> None:
        backend = _backend()
        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
        session = await backend.create(
            _valid_policy(),
            actor=_actor(),
            tenant_id="t-1",
            pack_context=_valid_pack_context(),
            use_warm_pool=False,
        )
        with pytest.raises(NotImplementedError, match="T8B-c"):
            await backend.exec(session, ["echo", "hi"])


class TestDestroyEmitsLifecycleEventOnceAndIsIdempotent:
    """Per spec §5 — destroy() MUST be idempotent (callable twice
    safely). Per spec §4.3 — lifecycle.destroyed chain row emitted
    EXACTLY ONCE per session; the second destroy() MUST NOT emit a
    duplicate row."""

    async def test_destroy_calls_teardown_and_emits_lifecycle_destroyed(
        self,
    ) -> None:
        backend = _backend()
        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
        session = await backend.create(
            _valid_policy(),
            actor=_actor(),
            tenant_id="t-1",
            pack_context=_valid_pack_context(),
            use_warm_pool=False,
        )
        # Mock teardown + emit so destroy() can run end-to-end.
        teardown_mock = AsyncMock(return_value=None)
        emit_destroyed_mock = AsyncMock(return_value=None)
        backend._teardown_session_state = teardown_mock  # type: ignore[method-assign]
        backend._emit_lifecycle_destroyed = emit_destroyed_mock  # type: ignore[method-assign]

        await backend.destroy(session)
        teardown_mock.assert_awaited_once()
        emit_destroyed_mock.assert_awaited_once()
        assert isinstance(session, KubernetesPodSession)
        assert session._destroyed is True

    async def test_double_destroy_does_not_emit_second_chain_row(self) -> None:
        backend = _backend()
        backend._create_network_policy = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._create_pod = AsyncMock(return_value=None)  # type: ignore[method-assign]
        backend._emit_lifecycle_created = AsyncMock(return_value=None)  # type: ignore[method-assign]
        session = await backend.create(
            _valid_policy(),
            actor=_actor(),
            tenant_id="t-1",
            pack_context=_valid_pack_context(),
            use_warm_pool=False,
        )
        backend._teardown_session_state = AsyncMock(return_value=None)  # type: ignore[method-assign]
        emit_destroyed_mock = AsyncMock(return_value=None)
        backend._emit_lifecycle_destroyed = emit_destroyed_mock  # type: ignore[method-assign]

        await backend.destroy(session)
        await backend.destroy(session)  # second destroy — idempotent
        # exactly 1 emission across the 2 destroy() calls.
        assert emit_destroyed_mock.await_count == 1

    async def test_destroy_rejects_foreign_session_type(self) -> None:
        """Cross-backend destroy is an error — DockerSibling session
        passed to KubernetesPod backend MUST raise TypeError."""
        backend = _backend()
        foreign_session = MagicMock(spec=())  # not a KubernetesPodSession
        with pytest.raises(TypeError, match="KubernetesPodSession"):
            await backend.destroy(foreign_session)


class TestHealthProbe:
    """health() pings the K8s apiserver via a bounded
    ``list_namespaced_pod(limit=1)``. Returns ``ok`` on success;
    ``unavailable`` on any exception (the structured
    SandboxBackendHealth result lets /readyz surface the apiserver
    state without raising)."""

    async def test_health_returns_ok_on_apiserver_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _backend()
        # Monkeypatch CoreV1Api on the kubernetes_asyncio.client
        # module so the backend's health() probe call resolves to
        # a mock that returns immediately.
        from kubernetes_asyncio import client as kube_client

        async def _fake_list(*args, **kwargs):
            return MagicMock(items=[])

        fake_api = MagicMock()
        fake_api.list_namespaced_pod = AsyncMock(side_effect=_fake_list)
        monkeypatch.setattr(kube_client, "CoreV1Api", lambda *a, **kw: fake_api)
        result = await backend.health()
        assert result.status == "ok"

    async def test_health_returns_unavailable_on_apiserver_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _backend()
        from kubernetes_asyncio import client as kube_client

        fake_api = MagicMock()
        fake_api.list_namespaced_pod = AsyncMock(
            side_effect=RuntimeError("synthetic apiserver outage")
        )
        monkeypatch.setattr(kube_client, "CoreV1Api", lambda *a, **kw: fake_api)
        result = await backend.health()
        assert result.status == "unavailable"
        assert "synthetic apiserver outage" in result.detail


class TestTeardownIsIdempotentAgainstApiException404:
    """_delete_pod_if_exists + _delete_network_policy_if_exists MUST
    swallow ApiException(status=404) (the K8s object already gone)
    but propagate any non-404 status (real teardown failure → fail-
    closed)."""

    async def test_delete_pod_swallows_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        backend = _backend()
        from kubernetes_asyncio import client as kube_client

        api = MagicMock()
        api.delete_namespaced_pod = AsyncMock(
            side_effect=kube_client.ApiException(status=404, reason="Not Found")
        )
        monkeypatch.setattr(kube_client, "CoreV1Api", lambda *a, **kw: api)
        # Should not raise.
        await backend._delete_pod_if_exists("sb-deadbeef")

    async def test_delete_pod_propagates_non_404_api_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _backend()
        from kubernetes_asyncio import client as kube_client

        api = MagicMock()
        api.delete_namespaced_pod = AsyncMock(
            side_effect=kube_client.ApiException(status=500, reason="Internal Server Error")
        )
        monkeypatch.setattr(kube_client, "CoreV1Api", lambda *a, **kw: api)
        with pytest.raises(kube_client.ApiException):
            await backend._delete_pod_if_exists("sb-deadbeef")

    async def test_delete_network_policy_swallows_404(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _backend()
        from kubernetes_asyncio import client as kube_client

        api = MagicMock()
        api.delete_namespaced_network_policy = AsyncMock(
            side_effect=kube_client.ApiException(status=404, reason="Not Found")
        )
        monkeypatch.setattr(kube_client, "NetworkingV1Api", lambda *a, **kw: api)
        await backend._delete_network_policy_if_exists("sb-deadbeef")

    async def test_delete_network_policy_propagates_non_404_api_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = _backend()
        from kubernetes_asyncio import client as kube_client

        api = MagicMock()
        api.delete_namespaced_network_policy = AsyncMock(
            side_effect=kube_client.ApiException(status=403, reason="Forbidden")
        )
        monkeypatch.setattr(kube_client, "NetworkingV1Api", lambda *a, **kw: api)
        with pytest.raises(kube_client.ApiException):
            await backend._delete_network_policy_if_exists("sb-deadbeef")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

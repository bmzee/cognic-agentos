"""T2 — KubernetesPod egress-proxy image seam tests (#477 §5).

Pins the narrow production seam on KubernetesPodSandboxBackend: an
optional ``egress_proxy_image`` constructor kwarg defaulting to the
canonical proxy image, and the create()-step-4 catalog-gate flow
(AC10) — the injected proxy image's digest, not the canonical
placeholder, is what the gate at ``kubernetes_pod.py`` feeds to
``is_canonical`` / ``verify_cosign_or_refuse`` / ``verify_sbom_policy_or_refuse``.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _CANONICAL_EGRESS_PROXY_IMAGE,
    KubernetesPodSandboxBackend,
)

#: Minimal valid SandboxPolicy + PackAdmissionContext for the AC10
#: create()-path test (the required-field sets — policy.py:162-168
#: for SandboxPolicy, :116-121 for PackAdmissionContext).
_SEAM_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=60.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CONTEXT = PackAdmissionContext(
    pack_id="p-fixture",
    pack_version="1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="read_only",
    declares_dynamic_install=False,
    profile="development",
)


def _default_catalog() -> MagicMock:
    cat = MagicMock()
    cat.is_canonical.return_value = True
    cat.is_tenant_allow_listed.return_value = False
    cat.verify_cosign_or_refuse = AsyncMock(return_value=None)
    cat.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return cat


class _CatalogSpy:
    """Records every digest the proxy gate asks about; allows all."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    def is_canonical(self, image_digest: str) -> bool:
        self.seen.append(("is_canonical", image_digest))
        return True

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        return False

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("cosign", image_digest))

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        self.seen.append(("sbom", image_digest))


@pytest.fixture
def make_k8s_backend():
    """Build a KubernetesPodSandboxBackend with mocked deps; any
    constructor kwarg is overridable via **overrides."""

    def _make(**overrides):
        kwargs: dict[str, Any] = dict(
            kube_api_client=MagicMock(),
            namespace="cognic-sandbox-test",
            image_catalog=_default_catalog(),
            credential_adapter=MagicMock(),
            rego_engine=MagicMock(),
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
        )
        kwargs.update(overrides)
        # Mock deps stand in for the typed constructor params; kwargs is
        # explicitly dict[str, Any] (it mixes the str ``namespace`` with
        # mock objects) so the **kwargs splat type-checks cleanly.
        return KubernetesPodSandboxBackend(**kwargs)

    return _make


def test_default_constructor_uses_canonical_proxy_image(make_k8s_backend):
    backend = make_k8s_backend()  # no egress_proxy_image kwarg
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


def test_injected_proxy_image_is_stored(make_k8s_backend):
    ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    backend = make_k8s_backend(egress_proxy_image=ref)
    assert backend._egress_proxy_image == ref


def test_empty_proxy_image_raises_at_construction(make_k8s_backend):
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_k8s_backend(egress_proxy_image="")
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_k8s_backend(egress_proxy_image="   ")


def test_none_is_not_treated_as_empty(make_k8s_backend):
    # Explicit None-check semantics: None -> canonical default, not a raise.
    backend = make_k8s_backend(egress_proxy_image=None)
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


@pytest.mark.asyncio
async def test_injected_proxy_image_digest_goes_through_k8s_catalog_gate(
    make_k8s_backend, monkeypatch
):
    """AC10 (K8s leg) — the injected proxy image's digest reaches the
    create()-step-4 catalog gate, and the canonical placeholder digest
    never does. admit_policy (create() steps 2-3) is patched out — it
    has its own admission tests; this test pins ONLY the proxy gate.
    """
    injected_ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    injected_digest = "sha256:" + "e" * 64
    canonical_digest = "sha256:" + "d" * 64

    spy = _CatalogSpy()
    backend = make_k8s_backend(egress_proxy_image=injected_ref, image_catalog=spy)

    # Patch admission (steps 2-3) + the post-gate K8s API calls (steps
    # 6-7) so create() runs exactly through the step-4 proxy gate.
    monkeypatch.setattr(
        "cognic_agentos.sandbox.backends.kubernetes_pod.admit_policy",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(backend, "_create_network_policy", AsyncMock())
    monkeypatch.setattr(backend, "_create_pod", AsyncMock())
    monkeypatch.setattr(backend, "_emit_lifecycle_created", AsyncMock())

    actor = MagicMock(subject="op-1")
    await backend.create(
        policy=_SEAM_POLICY,
        actor=actor,
        tenant_id="t-1",
        pack_context=_PACK_CONTEXT,
    )

    assert ("is_canonical", injected_digest) in spy.seen
    assert ("cosign", injected_digest) in spy.seen
    assert ("sbom", injected_digest) in spy.seen
    # The canonical placeholder digest must NEVER reach the gate.
    assert all(digest != canonical_digest for _, digest in spy.seen)

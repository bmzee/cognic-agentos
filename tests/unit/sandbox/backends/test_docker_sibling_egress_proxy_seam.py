"""T1 — DockerSibling egress-proxy image seam tests (#477 §5).

Pins the narrow production seam: an optional ``egress_proxy_image``
constructor kwarg on ``DockerSiblingSandboxBackend``, defaulting to the
canonical proxy image (production behaviour byte-identical), and the
catalog-gate flow (AC10) — the injected proxy image's digest, not the
canonical placeholder, is what ``_start_proxy_sidecar`` feeds to
``is_canonical`` / ``verify_cosign_or_refuse`` / ``verify_sbom_policy_or_refuse``.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    _CANONICAL_EGRESS_PROXY_IMAGE,
    DockerSiblingSandboxBackend,
)

#: Minimal valid SandboxPolicy for the Step-5 AC10 test — the 7
#: required SandboxPolicy fields (policy.py:162-168; read_only_root +
#: any later fields carry defaults). Defined ONCE here so the AC10
#: test reuses it.
_SEAM_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=60.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)


def _default_catalog() -> MagicMock:
    cat = MagicMock()
    cat.is_canonical.return_value = True
    cat.is_tenant_allow_listed.return_value = False
    cat.verify_cosign_or_refuse = AsyncMock(return_value=None)
    cat.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return cat


@pytest.fixture
def make_docker_backend():
    """Build a DockerSiblingSandboxBackend with mocked deps; any
    constructor kwarg is overridable via **overrides (e.g.
    egress_proxy_image=..., image_catalog=...)."""

    def _make(**overrides):
        kwargs = dict(
            docker_client=MagicMock(),
            image_catalog=_default_catalog(),
            credential_adapter=MagicMock(),
            rego_engine=MagicMock(),
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
        )
        kwargs.update(overrides)
        # Mock deps stand in for the typed constructor params; the
        # **kwargs splat is intentionally loosely typed (mypy does not
        # flag the dict splat — no type-ignore needed).
        return DockerSiblingSandboxBackend(**kwargs)

    return _make


def test_default_constructor_uses_canonical_proxy_image(make_docker_backend):
    backend = make_docker_backend()  # no egress_proxy_image kwarg
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


def test_injected_proxy_image_is_stored(make_docker_backend):
    ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    backend = make_docker_backend(egress_proxy_image=ref)
    assert backend._egress_proxy_image == ref


def test_empty_proxy_image_raises_at_construction(make_docker_backend):
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_docker_backend(egress_proxy_image="")
    with pytest.raises(ValueError, match="egress_proxy_image"):
        make_docker_backend(egress_proxy_image="   ")


def test_none_is_not_treated_as_empty(make_docker_backend):
    # Explicit None-check semantics: None -> canonical default, not a raise.
    backend = make_docker_backend(egress_proxy_image=None)
    assert backend._egress_proxy_image == _CANONICAL_EGRESS_PROXY_IMAGE


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


@pytest.mark.asyncio
async def test_injected_proxy_image_digest_goes_through_catalog_gate(make_docker_backend):
    """AC10 — the INJECTED proxy image's digest (not the canonical
    placeholder) is what _start_proxy_sidecar feeds to is_canonical +
    verify_cosign_or_refuse + verify_sbom_policy_or_refuse."""
    injected_ref = "registry.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "e" * 64
    injected_digest = "sha256:" + "e" * 64
    canonical_digest = "sha256:" + "d" * 64  # the placeholder default

    spy = _CatalogSpy()
    backend = make_docker_backend(egress_proxy_image=injected_ref, image_catalog=spy)

    # Mock only the Docker surface _start_proxy_sidecar touches.
    container = MagicMock()
    container.start = AsyncMock()
    backend._docker.containers.create_or_replace = AsyncMock(return_value=container)
    egress_net = MagicMock()
    egress_net.connect = AsyncMock()
    backend._docker.networks.get = AsyncMock(return_value=egress_net)

    await backend._start_proxy_sidecar(
        policy=_SEAM_POLICY,
        session_id="s-1",
        container_name="proxy-s-1",
        internal_net_name="internal-s-1",
        egress_net_name="egress-s-1",
        tenant_id="t-1",
    )

    assert ("is_canonical", injected_digest) in spy.seen
    assert ("cosign", injected_digest) in spy.seen
    assert ("sbom", injected_digest) in spy.seen
    # The canonical placeholder digest must NEVER reach the gate.
    assert all(digest != canonical_digest for _, digest in spy.seen)

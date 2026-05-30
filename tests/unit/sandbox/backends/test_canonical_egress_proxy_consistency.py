"""T12 — the canonical egress-proxy launch selector matches the catalog member.

``_CANONICAL_EGRESS_PROXY_IMAGE`` is the proxy-sidecar LAUNCH selector each
backend uses when no ``egress_proxy_image`` override is given (docker_sibling +
kubernetes_pod). The canonical image CATALOG is built from
``settings.sandbox_canonical_egress_proxy_image`` (backend factory, T11). If the
launch selector's digest is not a canonical-catalog member, admission's
``is_canonical`` gate rejects the sidecar at sandbox-create. These pins keep the
two backends' constants in lockstep with each other AND with the Settings
default, and refuse the old ``"d"*64`` placeholder.
"""

import pytest

pytest.importorskip("aiodocker")
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.sandbox.backends import docker_sibling, kubernetes_pod

_PLACEHOLDER_DIGEST = "d" * 64


def test_constant_is_real_not_placeholder() -> None:
    for const in (
        docker_sibling._CANONICAL_EGRESS_PROXY_IMAGE,
        kubernetes_pod._CANONICAL_EGRESS_PROXY_IMAGE,
    ):
        assert "@sha256:" in const, f"not digest-pinned: {const!r}"
        assert _PLACEHOLDER_DIGEST not in const, f"still the d*64 placeholder: {const!r}"


def test_both_backends_use_the_same_canonical_egress_proxy_ref() -> None:
    assert (
        docker_sibling._CANONICAL_EGRESS_PROXY_IMAGE == kubernetes_pod._CANONICAL_EGRESS_PROXY_IMAGE
    )


def test_constant_matches_settings_canonical_egress_proxy_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Launch-selector == catalog-member: the hardcoded backend constant MUST
    # equal the Settings default that the factory (T11) feeds into the canonical
    # catalog — else the launched sidecar's digest is not a canonical member and
    # admission's is_canonical gate rejects it.
    monkeypatch.delenv("COGNIC_SANDBOX_CANONICAL_EGRESS_PROXY_IMAGE", raising=False)
    settings = build_settings_without_env_file()
    assert (
        settings.sandbox_canonical_egress_proxy_image
        == docker_sibling._CANONICAL_EGRESS_PROXY_IMAGE
    )
    assert (
        settings.sandbox_canonical_egress_proxy_image
        == kubernetes_pod._CANONICAL_EGRESS_PROXY_IMAGE
    )

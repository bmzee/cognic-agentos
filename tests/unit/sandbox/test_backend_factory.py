"""Sprint 8B T8B-c — sandbox.backend_factory.get_backend tests.

Pins the AgentOS-owned default backend-selection seam per ADR-004
amendment §32 + the 2026-05-17 preflight decision. The factory MUST:

* Route ``settings.sandbox_backend == "docker_sibling"`` to
  :class:`DockerSiblingSandboxBackend`.
* Route ``settings.sandbox_backend == "kubernetes_pod"`` to
  :class:`KubernetesPodSandboxBackend`.
* Surface a structured ``NotImplementedError`` pointing at the
  missing extra when the selected backend's optional dep is not
  installed (mirrors the ``sandbox/__init__.py`` re-export pattern).
* Raise ``ValueError`` on unknown values — mypy + Literal narrows
  this branch out at type-check time; the runtime guard is
  defence-in-depth against future Literal extensions.

Per the cross-task invariant doctrine, the **value** of
``settings.sandbox_backend`` IS the wire-protocol-public contract
for bank-overlay env-var overrides; drift here breaks deployments.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")
pytest.importorskip("aiodocker")

from cognic_agentos.sandbox.backend_factory import get_backend
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
)
from cognic_agentos.sandbox.catalog import CanonicalImageCatalog


def _settings(sandbox_backend: str) -> MagicMock:
    """Settings mock — ``sandbox_backend`` drives routing; the three
    ``sandbox_canonical_*`` fields drive the T11 factory-built
    CanonicalImageCatalog. Valid digest-pinned refs so the catalog
    constructs cleanly and the ``@sha256:`` tails make ``is_canonical``
    assertions deterministic."""
    s = MagicMock()
    s.sandbox_backend = sandbox_backend
    s.sandbox_canonical_runtime_python_image = (
        "ghcr.io/cognic/sandbox-runtime-python@sha256:" + "a" * 64
    )
    s.sandbox_canonical_egress_proxy_image = (
        "ghcr.io/cognic/sandbox-egress-proxy@sha256:" + "b" * 64
    )
    s.sandbox_canonical_image_trust_root_path = None
    return s


def _docker_kwargs() -> dict[str, object]:
    """Minimal kwargs to construct a DockerSiblingSandboxBackend.

    NOTE: ``settings`` AND ``image_catalog`` are INTENTIONALLY omitted —
    the factory is AUTHORITATIVE for both and injects them itself
    (``settings`` from its positional param; ``image_catalog`` built from
    the ``sandbox_canonical_*`` Settings at T11). Including either here
    would paper over the injection contract (cf. the original T8B-c P1).
    """
    return {
        "docker_client": MagicMock(),
        "credential_adapter": MagicMock(),
        "rego_engine": MagicMock(),
        "audit_store": MagicMock(),
        "decision_history_store": MagicMock(),
        "warm_pool": None,
    }


def _k8s_kwargs() -> dict[str, object]:
    """Minimal kwargs to construct a KubernetesPodSandboxBackend.

    Same ``settings``- AND ``image_catalog``-omitted contract as
    :func:`_docker_kwargs` (both factory-authoritative).
    """
    return {
        "kube_api_client": MagicMock(),
        "namespace": "test-ns",
        "credential_adapter": MagicMock(),
        "rego_engine": MagicMock(),
        "audit_store": MagicMock(),
        "decision_history_store": MagicMock(),
        "warm_pool": None,
    }


class TestBackendFactoryRoutesByLiteral:
    """The factory dispatches on ``settings.sandbox_backend`` and
    instantiates the matching backend class with forwarded kwargs.

    Both routing tests assert ``backend._settings is routing_settings``
    to pin the documented injection contract — the factory's
    ``settings`` parameter MUST become the backend's ``_settings``,
    NOT a separately-passed (or default-fallback) Settings object.
    """

    def test_routes_docker_sibling_to_docker_sibling_backend(self) -> None:
        routing_settings = _settings("docker_sibling")
        backend = get_backend(routing_settings, **_docker_kwargs())
        assert isinstance(backend, DockerSiblingSandboxBackend)
        # The factory's settings MUST be the one wired into the backend
        # — pins the T8B-c P1 fix per
        # ``feedback_security_regression_hardening``.
        assert backend._settings is routing_settings

    def test_routes_kubernetes_pod_to_kubernetes_pod_backend(self) -> None:
        routing_settings = _settings("kubernetes_pod")
        backend = get_backend(routing_settings, **_k8s_kwargs())
        assert isinstance(backend, KubernetesPodSandboxBackend)
        assert backend._settings is routing_settings
        # T11 — the K8s arm also receives the factory-built canonical catalog.
        assert isinstance(backend._catalog, CanonicalImageCatalog)

    def test_factory_override_wins_over_kwargs_settings(self) -> None:
        """Pin the OVERRIDE semantic per the factory docstring.

        A caller that threads a DIFFERENT ``settings`` entry through
        ``**kwargs`` MUST receive a backend constructed with the
        FACTORY's settings, NOT the kwargs settings. Without the
        override, a caller could route on one Settings + construct
        the backend with another — silent-different-Settings-object
        bug class.
        """
        routing_settings = _settings("docker_sibling")
        bogus_kwargs_settings = MagicMock(name="bogus_kwargs_settings")
        kwargs = _docker_kwargs() | {"settings": bogus_kwargs_settings}
        backend = get_backend(routing_settings, **kwargs)
        # isinstance narrow lets mypy see ``_settings`` on the
        # concrete backend type (Protocol surface does not declare it).
        assert isinstance(backend, DockerSiblingSandboxBackend)
        assert backend._settings is routing_settings
        assert backend._settings is not bogus_kwargs_settings


class TestBackendFactoryBuildsCanonicalCatalog:
    """T11 — the factory builds a real ``CanonicalImageCatalog`` from the T10
    ``sandbox_canonical_*`` Settings and injects it AUTHORITATIVELY as the
    backend's ``image_catalog`` (``_catalog``), exactly like ``settings``. This
    is what wires the canonical refs + the canonical trust root into the runtime
    trust gate; a caller cannot bypass it via ``**kwargs``."""

    def test_factory_builds_canonical_catalog_from_settings(self) -> None:
        routing_settings = _settings("docker_sibling")
        backend = get_backend(routing_settings, **_docker_kwargs())
        assert isinstance(backend, DockerSiblingSandboxBackend)
        catalog = backend._catalog
        assert isinstance(catalog, CanonicalImageCatalog)
        # Both canonical refs are members (membership keyed by the @sha256: tail).
        assert catalog.is_canonical("sha256:" + "a" * 64)
        assert catalog.is_canonical("sha256:" + "b" * 64)
        # Canonical trust root threaded straight from Settings (None here →
        # canonical cosign verification fail-closes until the operator sets it).
        expected_root = routing_settings.sandbox_canonical_image_trust_root_path
        assert catalog._canonical_trust_root is expected_root

    def test_factory_overwrites_caller_supplied_image_catalog_docker(self) -> None:
        """A caller threading a DIFFERENT ``image_catalog`` through ``**kwargs``
        MUST receive the factory-built one — else a caller could bypass
        canonical-image membership + cosign/SBOM verification (the trust gate).
        Mirrors the ``settings`` override semantic (docker_sibling arm)."""
        routing_settings = _settings("docker_sibling")
        sentinel = MagicMock(name="caller_supplied_catalog")
        kwargs = _docker_kwargs() | {"image_catalog": sentinel}
        backend = get_backend(routing_settings, **kwargs)
        # Literal-class isinstance narrows for mypy so ``_catalog`` (a private
        # attr the SandboxBackend Protocol does not expose) is type-visible.
        assert isinstance(backend, DockerSiblingSandboxBackend)
        assert backend._catalog is not sentinel
        assert isinstance(backend._catalog, CanonicalImageCatalog)

    def test_factory_overwrites_caller_supplied_image_catalog_k8s(self) -> None:
        """K8s counterpart — the bypass-close matters equally for
        kubernetes_pod (the factory accepts ``image_catalog`` for both arms), so
        the override is pinned on the K8s arm too."""
        routing_settings = _settings("kubernetes_pod")
        sentinel = MagicMock(name="caller_supplied_catalog")
        kwargs = _k8s_kwargs() | {"image_catalog": sentinel}
        backend = get_backend(routing_settings, **kwargs)
        assert isinstance(backend, KubernetesPodSandboxBackend)
        assert backend._catalog is not sentinel
        assert isinstance(backend._catalog, CanonicalImageCatalog)


class TestBackendFactoryRefusesUnknownValue:
    """Defensive ValueError on unknown values. Literal narrows the
    type at compile time but the runtime guard ensures a future
    Literal extension that lands without a factory update fails
    loudly instead of silently constructing the wrong backend."""

    def test_unknown_value_raises_value_error(self) -> None:
        with pytest.raises(ValueError) as exc:
            get_backend(_settings("nonexistent_backend"), **_docker_kwargs())
        assert "nonexistent_backend" in str(exc.value)
        # Error message names the valid set so operators can correct
        # the misconfiguration without trawling source.
        assert "docker_sibling" in str(exc.value)
        assert "kubernetes_pod" in str(exc.value)


class TestBackendFactoryEnumerateCoverage:
    """Drift detector — every Literal arm in the ``sandbox_backend``
    Setting field MUST have a factory branch. A future arm added
    to the Setting field without a matching factory route would
    silently fall through to the ValueError guard. This test pins
    the field's value set + the factory's accepted set in lockstep.
    """

    def test_all_settings_field_values_are_routed(self) -> None:
        import typing

        from cognic_agentos.core.config import Settings

        field_info = Settings.model_fields["sandbox_backend"]
        # Pull the Literal arms via typing.get_args on the annotation
        annotation = field_info.annotation
        arms = set(typing.get_args(annotation))
        assert arms == {"docker_sibling", "kubernetes_pod"}

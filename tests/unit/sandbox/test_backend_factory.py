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


def _settings(sandbox_backend: str) -> MagicMock:
    """Minimal Settings mock — only the sandbox_backend field is
    consumed by the factory; backend construction kwargs are
    threaded through ``**kwargs``."""
    s = MagicMock()
    s.sandbox_backend = sandbox_backend
    return s


def _docker_kwargs() -> dict[str, object]:
    """Minimal kwargs to construct a DockerSiblingSandboxBackend.

    NOTE: ``settings`` is INTENTIONALLY omitted — the factory is
    AUTHORITATIVE for the backend's ``settings`` kwarg and injects it
    from its own positional ``settings`` parameter (per docstring).
    Including ``settings`` here would have papered over the original
    T8B-c P1 (factory documented injection but did not deliver).
    """
    return {
        "docker_client": MagicMock(),
        "image_catalog": MagicMock(),
        "credential_adapter": MagicMock(),
        "rego_engine": MagicMock(),
        "audit_store": MagicMock(),
        "decision_history_store": MagicMock(),
        "warm_pool": None,
    }


def _k8s_kwargs() -> dict[str, object]:
    """Minimal kwargs to construct a KubernetesPodSandboxBackend.

    Same ``settings``-omitted contract as :func:`_docker_kwargs`.
    """
    return {
        "kube_api_client": MagicMock(),
        "namespace": "test-ns",
        "image_catalog": MagicMock(),
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

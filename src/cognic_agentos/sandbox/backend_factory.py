"""Sprint 8B T8B-c — SandboxBackend factory.

AgentOS-owned default backend selection seam per the 2026-05-17
preflight decision. Per ADR-004 amendment §32: backend swappable
via the COGNIC_SANDBOX_BACKEND env var (consumed by
:class:`cognic_agentos.core.config.Settings.sandbox_backend`); per-
tenant routing deferred to Sprint 14 deployment kit.

Routing table:

* ``settings.sandbox_backend == "docker_sibling"`` →
  :class:`DockerSiblingSandboxBackend` (Sprint 8A; dev/CI default)
* ``settings.sandbox_backend == "kubernetes_pod"`` →
  :class:`KubernetesPodSandboxBackend` (Sprint 8B; Wave-1 K8s
  production backend per ``project_openshift_deployment_target``)

When the selected backend's optional extra is NOT installed, the
factory surfaces a structured :class:`NotImplementedError` pointing
at the missing extra. The pattern mirrors
:mod:`cognic_agentos.sandbox.__init__`'s re-export envelope which
already guards both backend imports with try/except ImportError so
the package itself stays importable in either kernel-only or
single-backend deployments.

The wire-protocol-public contract for bank-overlay env-var override
is the ``Literal["docker_sibling", "kubernetes_pod"]`` arm set on
:attr:`Settings.sandbox_backend`. Drift between that arm set + the
factory's accepted set is caught at test time by the drift detector
at ``tests/unit/sandbox/test_backend_factory.py::TestBackendFactoryEnumerateCoverage``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.sandbox.protocol import SandboxBackend


def get_backend(settings: Settings, /, **kwargs: Any) -> SandboxBackend:
    """Construct the :class:`SandboxBackend` selected by
    ``settings.sandbox_backend``.

    The ``settings`` parameter is positional-only (``/`` separator)
    so a caller threading a ``settings`` entry through ``**kwargs``
    for the backend constructor does NOT collide with the factory's
    routing parameter. The factory then injects ``settings`` into
    the forwarded kwargs (both backends' constructors expect a
    ``settings`` kwarg).

    The remaining ``**kwargs`` are forwarded to the selected
    backend's constructor — each backend has its own keyword set
    (DockerSibling expects ``docker_client``; KubernetesPod expects
    ``kube_api_client`` + ``namespace``). Callers responsible for
    threading the right kwargs; mismatch surfaces as a
    :class:`TypeError` from the backend constructor.

    Raises
    ------
    NotImplementedError
        When the selected backend's optional dep is not installed.
        Message names the install command for the missing extra so
        operators can fix without trawling source.
    ValueError
        When ``settings.sandbox_backend`` carries a value outside
        the ``Literal["docker_sibling", "kubernetes_pod"]`` arm set.
        mypy + the Literal type narrow this branch out at compile
        time; the runtime guard is defence-in-depth against future
        Literal extensions that land without a matching factory
        update.
    """
    # Inject the routing settings into the forwarded kwargs per the
    # docstring contract. Override is intentional: the factory is
    # AUTHORITATIVE for the backend's ``settings`` — a caller that
    # threads a different Settings object through ``**kwargs`` would
    # otherwise silently route on one Settings + construct the
    # backend with another. The override closes that bug class.
    # Pinned by ``test_factory_override_wins_over_kwargs_settings`` +
    # ``test_routed_backend_carries_factory_settings_for_*_arm``.
    kwargs["settings"] = settings

    if settings.sandbox_backend == "docker_sibling":
        try:
            from cognic_agentos.sandbox.backends.docker_sibling import (
                DockerSiblingSandboxBackend,
            )
        except ImportError as e:
            raise NotImplementedError(
                "sandbox_backend='docker_sibling' requires the "
                "'sandbox-docker' optional extra; install via "
                "`pip install -e .[sandbox-docker]` (or `uv sync "
                "--extra sandbox-docker`). If you do not need the "
                "Docker backend, set COGNIC_SANDBOX_BACKEND="
                "kubernetes_pod (requires the sandbox-k8s extra). "
                f"Underlying ImportError: {e}"
            ) from e
        return DockerSiblingSandboxBackend(**kwargs)

    elif settings.sandbox_backend == "kubernetes_pod":
        try:
            from cognic_agentos.sandbox.backends.kubernetes_pod import (
                KubernetesPodSandboxBackend,
            )
        except ImportError as e:
            raise NotImplementedError(
                "sandbox_backend='kubernetes_pod' requires the "
                "'sandbox-k8s' optional extra; install via "
                "`pip install -e .[sandbox-k8s]` (or `uv sync "
                "--extra sandbox-k8s`). If you do not need the "
                "Kubernetes/OpenShift backend, set "
                "COGNIC_SANDBOX_BACKEND=docker_sibling (requires "
                "the sandbox-docker extra). "
                f"Underlying ImportError: {e}"
            ) from e
        return KubernetesPodSandboxBackend(**kwargs)

    else:
        # mypy + Literal narrow this branch out at type-check time;
        # the runtime guard is defence-in-depth against a future
        # Literal arm landing without a matching factory route.
        # Error message names the accepted set so operators can
        # correct misconfiguration without trawling source.
        raise ValueError(
            f"unknown sandbox_backend={settings.sandbox_backend!r}; "
            f"expected one of 'docker_sibling' | 'kubernetes_pod'"
        )


__all__ = ["get_backend"]

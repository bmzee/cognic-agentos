"""Sprint 8A sandbox primitive — public API surface.

Per the Sprint 8A T1 design spec at
``docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md``.

Wave-1 ships the Docker-sibling backend (T10); Wave-1 Kubernetes/
OpenShift backend ships in Sprint 8B. Both conform to the same
``SandboxBackend`` Protocol declared here.

DockerSiblingSandboxBackend import is wrapped in try/except
ImportError so the sandbox package itself stays importable when the
optional ``sandbox-docker`` extra is not installed (e.g. a
KubernetesPod-only deployment per Sprint 8B). When the extra is
missing, calls to construct the backend surface a structured
NotImplementedError pointing at the extra; the package's other
imports remain functional.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from cognic_agentos.sandbox.admission import (
    CatalogProtocol,
    CredentialAdapter,
    KernelDefaultCredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.audit import emit_sandbox_event
from cognic_agentos.sandbox.catalog import (
    CanonicalImageCatalog,
    CosignVerifyResult,
    SBOMVerifyResult,
)
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    RiskTier,
    SandboxPolicy,
    WritableMount,
    validate_policy_shape,
)
from cognic_agentos.sandbox.protocol import (
    ProxyAccessOutcome,
    ProxyAccessRecord,
    SandboxBackend,
    SandboxBackendHealth,
    SandboxBackendHealthStatus,
    SandboxExecResult,
    SandboxLifecycleEvent,
    SandboxLifecycleRefused,
    SandboxPolicyViolated,
    SandboxPolicyViolationReason,
    SandboxRefusalReason,
    SandboxSession,
)
from cognic_agentos.sandbox.proxy import (
    EgressProxyConfig,
    ProxyAccessRefusalReason,
    proxy_log_to_chain_payload,
    render_proxy_config,
)
from cognic_agentos.sandbox.warm_pool import SandboxWarmPool

if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor

# DockerSiblingSandboxBackend — guarded import. The backend module
# imports aiodocker (the sandbox-docker optional extra); a kernel
# install without the extra stays functional, but constructing the
# backend surfaces a structured NotImplementedError.
try:
    from cognic_agentos.sandbox.backends.docker_sibling import (
        DockerSiblingSandboxBackend as _DockerSiblingSandboxBackendReal,
    )

    DockerSiblingSandboxBackend: type = _DockerSiblingSandboxBackendReal
except ImportError as _import_error:  # aiodocker not installed
    _saved_import_error: ImportError = _import_error

    class _DockerSiblingSandboxBackendUnavailable:
        """Fail-loud placeholder when ``aiodocker`` (sandbox-docker
        extra) is not installed. Per AGENTS.md production-grade rule:
        stubs raise NotImplementedError pointing at the missing
        dependency rather than silently failing at first use.

        KubernetesPod-only deployments (Sprint 8B, the production
        target per AGENTS.md) do not need this backend and should
        construct ``KubernetesPodSandboxBackend`` instead.
        """

        def __init__(self, *args: object, **kwargs: object) -> None:
            raise NotImplementedError(
                "DockerSiblingSandboxBackend requires `aiodocker` from "
                "the sandbox-docker optional extra. Install with "
                "`pip install -e .[sandbox-docker]`. If you do not "
                "need the Docker backend (e.g. KubernetesPod-only "
                "production deployment per Sprint 8B), construct "
                "KubernetesPodSandboxBackend instead. "
                f"Underlying ImportError: {_saved_import_error}"
            )

    DockerSiblingSandboxBackend = _DockerSiblingSandboxBackendUnavailable


@asynccontextmanager
async def sandbox_session(
    backend: SandboxBackend,
    policy: SandboxPolicy,
    *,
    actor: Actor,
    tenant_id: str,
    pack_context: PackAdmissionContext,
    use_warm_pool: bool = True,
    warm_pool: SandboxWarmPool | None = None,
) -> AsyncIterator[SandboxSession]:
    """Helper context manager per spec §288-334.

    On entry: calls ``backend.create(policy, actor=..., tenant_id=...,
    pack_context=..., use_warm_pool=use_warm_pool)`` and yields the
    resulting session.

    On exit:

    * If ``use_warm_pool=True`` AND ``warm_pool`` is wired → routes
      through ``warm_pool.release_or_destroy(session)`` so a
      checked-out warm member returns to the pool instead of being
      destroyed (Round-2 P2 reviewer fix per spec §309-311: without
      this, warm-pool members would be one-shot under the ergonomic
      API).
    * Else → ``session.destroy()`` unconditionally.

    Cleanup fires on every exit path including inner-block exceptions
    (the ``try / finally`` envelope ensures the session does not
    leak when user code raises mid-block).

    Not part of the ``SandboxBackend`` Protocol (which stays minimal
    at the 4 primary ops); backend implementors do not need to
    provide their own ``session()`` — this helper works for every
    Protocol-conforming backend.
    """
    session = await backend.create(
        policy,
        actor=actor,
        tenant_id=tenant_id,
        pack_context=pack_context,
        use_warm_pool=use_warm_pool,
    )
    try:
        yield session
    finally:
        if use_warm_pool and warm_pool is not None:
            await warm_pool.release_or_destroy(session)
        else:
            await session.destroy()


__all__ = [
    "CanonicalImageCatalog",
    "CatalogProtocol",
    "CosignVerifyResult",
    "CredentialAdapter",
    "DockerSiblingSandboxBackend",
    "EgressProxyConfig",
    "KernelDefaultCredentialAdapter",
    "PackAdmissionContext",
    "ProxyAccessOutcome",
    "ProxyAccessRecord",
    "ProxyAccessRefusalReason",
    "RiskTier",
    "SBOMVerifyResult",
    "SandboxBackend",
    "SandboxBackendHealth",
    "SandboxBackendHealthStatus",
    "SandboxExecResult",
    "SandboxLifecycleEvent",
    "SandboxLifecycleRefused",
    "SandboxPolicy",
    "SandboxPolicyViolated",
    "SandboxPolicyViolationReason",
    "SandboxRefusalReason",
    "SandboxSession",
    "SandboxWarmPool",
    "WritableMount",
    "admit_policy",
    "emit_sandbox_event",
    "proxy_log_to_chain_payload",
    "render_proxy_config",
    "sandbox_session",
    "validate_policy_shape",
]

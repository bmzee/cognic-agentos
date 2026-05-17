"""Sprint 8A sandbox primitive — public API surface.

Per the Sprint 8A T1 design spec at
``docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md``.

Wave-1 ships the Docker-sibling backend (T10); Wave-1 Kubernetes/
OpenShift backend ships in Sprint 8B. Both conform to the same
``SandboxBackend`` Protocol declared here.
"""

from __future__ import annotations

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

__all__ = [
    "CanonicalImageCatalog",
    "CatalogProtocol",
    "CosignVerifyResult",
    "CredentialAdapter",
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
    "WritableMount",
    "admit_policy",
    "emit_sandbox_event",
    "proxy_log_to_chain_payload",
    "render_proxy_config",
    "validate_policy_shape",
]

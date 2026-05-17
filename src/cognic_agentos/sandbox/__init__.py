"""Sprint 8A sandbox primitive — public API surface.

Per the Sprint 8A T1 design spec at
``docs/superpowers/specs/2026-05-16-sprint-8a-sandbox-primitive-design.md``.

Wave-1 ships the Docker-sibling backend (T10); Wave-1 Kubernetes/
OpenShift backend ships in Sprint 8B. Both conform to the same
``SandboxBackend`` Protocol declared here.
"""

from __future__ import annotations

from cognic_agentos.sandbox.audit import emit_sandbox_event
from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    RiskTier,
    SandboxPolicy,
    WritableMount,
    validate_policy_shape,
)
from cognic_agentos.sandbox.protocol import (
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

__all__ = [
    "PackAdmissionContext",
    "ProxyAccessRecord",
    "RiskTier",
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
    "emit_sandbox_event",
    "validate_policy_shape",
]

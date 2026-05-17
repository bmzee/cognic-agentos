"""Sprint 8A T3 — SandboxBackend + SandboxSession Protocols.

Wire-protocol-public per spec §5. Critical-controls module per AGENTS.md.

Sprint 8A ships:
* 15-value `SandboxRefusalReason` Literal (per spec §4.1)
* 5-value `SandboxPolicyViolationReason` Literal (per spec §4.2)
* 8-value `SandboxLifecycleEvent` Literal (per spec §4.3)
* `SandboxLifecycleRefused` + `SandboxPolicyViolated` exception types
* `SandboxExecResult` + `SandboxBackendHealth` result types
* `SandboxSession` + `SandboxBackend` Protocols

Stage-2 async admission (`admit_policy`) lives in T5 (`sandbox/admission.py`);
Stage-1 pure shape validation (`validate_policy_shape`) lives in T3
(`sandbox/policy.py`). Both stages are sequenced inside admit_policy
per the round-4 single-seam contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Closed-enum vocabularies — wire-protocol-public per spec §4
# ---------------------------------------------------------------------------

#: 15-value closed-enum for sandbox-creation refusals (spec §4.1).
#:
#: Drift between this Literal and consumer error-handling is caught at
#: module load by the partition-invariant test at
#: ``tests/unit/sandbox/test_policy_shape.py``.
SandboxRefusalReason = Literal[
    "sandbox_credential_adapter_not_configured",
    "sandbox_runtime_deps_unsupported_in_production",
    "sandbox_high_risk_tier_refused_pre_13_5",
    "sandbox_image_digest_not_in_canonical_catalog",
    "sandbox_image_cosign_verification_failed",
    "sandbox_image_sbom_check_failed",
    "sandbox_image_digest_format_invalid",
    "sandbox_policy_exceeds_tenant_max_cpu",
    "sandbox_policy_exceeds_tenant_max_memory",
    "sandbox_policy_exceeds_tenant_max_walltime",
    "sandbox_policy_egress_host_invalid",
    "sandbox_policy_egress_protocol_not_http",
    "sandbox_policy_rego_denied",
    "sandbox_backend_unavailable",
    "sandbox_warm_pool_drained",
]

#: 5-value closed-enum for runtime policy violations during ``exec`` (spec §4.2).
#:
#: Note: CPU throttling under the Docker ``--cpus`` cap is NOT a
#: violation by itself — a CPU-bound workload that stays within its
#: budget is expected to be throttled by the kernel scheduler.
#: Workloads needing a hard CPU-seconds budget set
#: ``SandboxPolicy.cpu_time_budget_s``; the runtime monitor reads
#: cgroup ``cpuacct.usage_us`` and kills when exceeded.
SandboxPolicyViolationReason = Literal[
    "cpu_time_budget_exceeded",
    "memory_cap_exceeded",
    "walltime_cap_exceeded",
    "egress_host_not_allow_listed",
    "egress_protocol_not_http",
]

#: 8-value closed-enum for audit chain-row decision_type discriminator
#: (spec §4.3).
#:
#: User-locked taxonomy: replenishment is the cause; the event is
#: still ``precreated``. No ``warm_pool.replenished`` value.
SandboxLifecycleEvent = Literal[
    "sandbox.lifecycle.created",
    "sandbox.lifecycle.exec_completed",
    "sandbox.lifecycle.destroyed",
    "sandbox.lifecycle.refused",
    "sandbox.policy.violated",
    "sandbox.warm_pool.precreated",
    "sandbox.warm_pool.checked_out",
    "sandbox.warm_pool.drained",
]


# ---------------------------------------------------------------------------
# Exception types
# ---------------------------------------------------------------------------


class SandboxLifecycleRefused(Exception):
    """Raised at any admission stage on refusal. Carries the
    closed-enum reason so callers can dispatch on the wire-protocol-
    public ``SandboxRefusalReason`` Literal."""

    def __init__(self, reason: SandboxRefusalReason, *, detail: str = "") -> None:
        self.reason: SandboxRefusalReason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class SandboxPolicyViolated(Exception):
    """Raised at ``exec()`` when a runtime policy cap is exceeded.
    Carries the closed-enum ``SandboxPolicyViolationReason``."""

    def __init__(self, reason: SandboxPolicyViolationReason, *, detail: str = "") -> None:
        self.reason: SandboxPolicyViolationReason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# ---------------------------------------------------------------------------
# Result + health types
# ---------------------------------------------------------------------------


#: Closed-enum 2-value Literal for proxy decisions on outbound requests
#: (spec §10.3 ``outcome`` field). Named alias (NOT anonymous Literal)
#: so the runtime-checkable mirror at
#: :data:`cognic_agentos.sandbox.proxy._VALID_OUTCOMES` can derive via
#: :func:`typing.get_args` and stay in lockstep with the Literal
#: without a hand-maintained copy — symmetric with
#: :data:`cognic_agentos.sandbox.proxy.ProxyAccessRefusalReason`.
ProxyAccessOutcome = Literal["allowed", "refused"]


@dataclass(frozen=True)
class ProxyAccessRecord:
    """Per-request entry in ``SandboxExecResult.proxy_log`` (spec §10.3).

    6 fields per the spec §10.3 audit-emission contract:

    * ``host`` — the requested host the proxy saw (sidecar-side
      ALLOW_LIST is checked against this exact string).
    * ``method`` — HTTP method (``GET`` / ``POST`` / ``CONNECT`` / …).
    * ``timestamp`` — timezone-aware ``datetime`` of when the proxy
      observed the request (sidecar clock; backend renders into ISO
      8601 at chain-row serialisation time). Any aware offset is
      accepted unchanged — UTC is the operational convention but
      not the runtime contract; the only constraint is Python's
      strict aware definition (``tzinfo is not None`` AND
      ``utcoffset() is not None``). The materialiser at
      ``sandbox.proxy.proxy_log_to_chain_payload`` enforces this at
      the evidence boundary.
    * ``policy_id`` — the per-session policy identifier the sidecar
      received via env (allows examiners to correlate proxy_log
      entries with the SandboxPolicy that admitted the session).
    * ``outcome`` — :data:`ProxyAccessOutcome` (``"allowed"`` or
      ``"refused"``). Runtime closed-set enforcement happens at
      ``sandbox.proxy.proxy_log_to_chain_payload`` (the materialiser
      is the single evidence-boundary seam since Python doesn't
      enforce Literal values at runtime).
    * ``refusal_reason`` — ``None`` on allowed; on refused, one of
      the ``ProxyAccessRefusalReason`` Wave-1 values declared at
      ``sandbox.proxy.ProxyAccessRefusalReason``
      (``"not_in_allow_list"`` / ``"non_http_connect_target"``).
      Typed as ``str | None`` here (NOT the Literal) to keep
      ``protocol.py`` free of an import dependency on
      ``sandbox.proxy`` (the dependency arrow runs the other
      direction); the Literal pin lives at the proxy module.

    Sprint 8A T3 declared this dataclass as a 4-field placeholder
    explicitly marked "Fields are placeholders until T7"; Sprint 8A
    T7 expanded to this 6-field shape. The runtime construction
    surface lands at T10 (DockerSibling backend reads the sidecar
    proxy log + builds these records). No existing callsite
    constructs this type pre-T7, so the expansion is backward-
    compatible with the live wire.
    """

    host: str
    method: str
    timestamp: datetime
    policy_id: str
    outcome: ProxyAccessOutcome
    refusal_reason: str | None


@dataclass(frozen=True)
class SandboxExecResult:
    """Result of ``SandboxSession.exec()`` (spec §5)."""

    stdout: bytes
    stderr: bytes
    exit_code: int
    proxy_log: tuple[ProxyAccessRecord, ...] = ()


SandboxBackendHealthStatus = Literal["ok", "degraded", "unavailable"]


@dataclass(frozen=True)
class SandboxBackendHealth:
    """Backend readiness signal. Returned by ``SandboxBackend.health()``."""

    status: SandboxBackendHealthStatus
    detail: str = ""


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------

# Forward refs for types defined in T-task downstream modules — used
# only inside Protocol signatures so the runtime import dance is safe.
# Uses ``TYPE_CHECKING`` (NOT ``if False``) so mypy resolves the
# annotations at the T3 halt gate per the round-3 R3 P1 #1 fix.
if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor
    from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy


@runtime_checkable
class SandboxSession(Protocol):
    """A live sandbox. Identity persists across ``exec()`` calls.

    Per spec §5 — 6 fields. ``pack_context`` carries the admission
    context under which this session was admitted; load-bearing for
    ``SandboxWarmPool.release_or_destroy`` (it derives the pool key
    from ``session.policy`` + ``session.pack_context``) AND for Sprint
    8.5 wake-time re-admission against the same context.
    """

    session_id: str  # uuid4 hex; persists into Sprint 8.5 checkpoint store
    policy: SandboxPolicy
    tenant_id: str
    pack_context: PackAdmissionContext
    created_at: datetime
    warm_pool_hit: bool

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult: ...

    async def destroy(self) -> None: ...


@runtime_checkable
class SandboxBackend(Protocol):
    """Backend-abstracted sandbox lifecycle.

    Wave-1 implementations: ``DockerSiblingSandboxBackend`` (T10 of
    Sprint 8A); ``KubernetesPodSandboxBackend`` (Sprint 8B). Wave-2:
    gVisor, Firecracker, Kata, rootless Docker. All implementations
    MUST honor this contract and the shared conformance test suite at
    ``tests/conformance/sandbox/test_backend_conformance.py``.
    """

    async def create(
        self,
        policy: SandboxPolicy,
        *,
        actor: Actor,
        tenant_id: str,
        pack_context: PackAdmissionContext,
        use_warm_pool: bool = True,
    ) -> SandboxSession:
        """Admit + create a sandbox session.

        Raises ``SandboxLifecycleRefused`` carrying a
        ``SandboxRefusalReason`` closed-enum value on any admission
        failure (per spec §5 + §6.1).

        ``use_warm_pool=True``: attempt warm-pool checkout first (only
        if ``policy.warm_pool_key`` is set AND a matching member
        exists); cold-create on miss. Audit-emits
        ``warm_pool.checked_out`` + ``lifecycle.created`` with
        ``warm_pool_hit=True`` OR ``lifecycle.created`` with
        ``warm_pool_hit=False`` accordingly.

        ``use_warm_pool=False``: forces cold-create path (the
        replenishment contract — ``SandboxWarmPool.precreate`` calls
        this so it never consumes an existing pool member; round-1 P1
        reviewer fix).
        """

    async def exec(
        self,
        session: SandboxSession,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        """Execute a command in the session.

        Raises ``SandboxPolicyViolated`` carrying a
        ``SandboxPolicyViolationReason`` on runtime policy-cap exceeded
        (memory OOM, walltime exceeded, ``cpu_time_budget_s`` exceeded
        when set, or proxy-observed egress violation). Throttling under
        ``--cpus`` cap is NOT a violation by itself.
        """

    async def destroy(self, session: SandboxSession) -> None:
        """Tear down the session. Idempotent.

        For warm-pool members, the public seam is
        ``SandboxWarmPool.release_or_destroy()`` (which routes back to
        the pool when policy + context match an existing key);
        ``destroy()`` is the unconditional teardown.
        """

    async def health(self) -> SandboxBackendHealth:
        """Backend readiness check. Used by ``/readyz`` and at startup."""

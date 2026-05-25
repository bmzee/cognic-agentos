"""Sprint 8A T3 — SandboxBackend + SandboxSession Protocols.

Wire-protocol-public per spec §5. Critical-controls module per AGENTS.md.

Sprint 8A ships:
* 15-value `SandboxRefusalReason` Literal (per spec §4.1)
* 6-value `SandboxPolicyViolationReason` Literal (per spec §4.2 + T10c R1 P1.2)
* 8-value `SandboxLifecycleEvent` Literal (per spec §4.3)
* `SandboxLifecycleRefused` + `SandboxPolicyViolated` exception types
* `SandboxExecResult` + `SandboxBackendHealth` result types
* `SandboxSession` + `SandboxBackend` Protocols

Sprint 8.5 T1 extends:
* `SandboxRefusalReason` 15 → 21 values (6 new wake-time arms per
  spec §3.3).
* `SandboxLifecycleEvent` 8 → 12 values (4 new per spec §3.3).
* `SandboxSession` Protocol with `checkpoint()` + `suspend()` per
  spec §3.1.
* `SandboxBackend` Protocol with `wake()` per spec §3.2.
* `CheckpointId` NewType — declared HERE (not in
  `sandbox/checkpoint_store.py` as spec §3.4 listed) because the
  Protocol method `checkpoint()` returns it; T3's checkpoint_store
  imports the canonical declaration from this module. Plan-vs-reality
  drift documented in the T1 commit body.

Stage-2 async admission (`admit_policy`) lives in T5 (`sandbox/admission.py`);
Stage-1 pure shape validation (`validate_policy_shape`) lives in T3
(`sandbox/policy.py`). Both stages are sequenced inside admit_policy
per the round-4 single-seam contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal, NewType, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Closed-enum vocabularies — wire-protocol-public per spec §4
# ---------------------------------------------------------------------------

#: 27-value closed-enum for sandbox lifecycle refusals (Sprint 8A spec
#: §4.1 + Sprint 8.5 spec §3.3 extension + Sprint 10 spec §4.1 T7 +
#: Sprint 10 spec §6.1 T9). Covers:
#:
#: * 15 admission/create refusals (Sprint 8A) — `admit_policy` + Stage-1
#:   shape validation + backend availability + warm-pool drain.
#: * 6 wake-time refusals (Sprint 8.5 T1) — `wake()` step 1-4 rejection
#:   classes: tombstone-first (with TombstoneCorruptError fail-closed
#:   per P1.r6) / not-found / corrupt-metadata / tenant-mismatch /
#:   retention-expired / policy-revalidation-failed. Wake-time taxonomy
#:   is wake-specific per spec §2.3 — the original 8A admission reason
#:   (if any) lives in the refusal's ``detail`` field for examiner
#:   traceability.
#: * 1 kernel-boundary cross-tenant guard (Sprint 10 T7) — raised by
#:   ``admit_policy`` when ``VaultLeaseRequest.tenant_id`` does not
#:   match the admitting ``actor.tenant_id``. The cross-tenant check is
#:   owned by ``admit_policy`` because ``VaultLeaseRequest`` itself
#:   cannot enforce it at construction time (the architectural arrow
#:   runs ``sandbox → core``, never the other direction).
#: * 3 Vault mint-failure refusals (Sprint 10 T9 Literal; Sprint 10 T10
#:   Stage-2 raise sites at backend ``create()`` post-admission per
#:   Sprint-10 spec §7.1) — ``sandbox_credential_mint_failed_vault_unavailable``
#:   (Vault 5xx / network failure / ``VaultProtocolError`` collapse) /
#:   ``sandbox_credential_mint_failed_secret_path_unknown`` (Vault 404
#:   on secret_path) / ``sandbox_credential_mint_failed_auth_denied``
#:   (Vault 403 on secret_path / auth method denied). T9 lifts the
#:   Literal entries only; T10 wires the create-time mapping from the
#:   then-4-value ``core/vault`` exception taxonomy (the 5th value
#:   ``VaultLeaseGrantExceedsRequest`` extended the taxonomy at
#:   Sprint 10.1 per ADR-004 §25 amendment; its sandbox-boundary
#:   mapping target is the SEPARATE
#:   ``sandbox_credential_lease_ttl_grant_exceeds_request`` value
#:   bulleted below, NOT one of the ``mint_failed_*`` set).
#: * 1 Rego TTL-cap refusal (Sprint 10 T9 Literal ONLY; **NO Stage-2
#:   raise site at T9 or T10**) — ``sandbox_credential_ttl_exceeds_tenant_max``.
#:   The ``policies/_default/sandbox.rego`` rule 6 fires + denies, but
#:   ``OPAEngine.Decision`` (at ``core/policy/engine.py:148-150``)
#:   exposes only ``allow`` + the decision-point-derived generic
#:   ``reasoning`` with no per-rule-name channel, so admission.py's
#:   single generic arm at ``admission.py:601-603`` continues to
#:   surface the cap as ``sandbox_policy_rego_denied``. Rego-reason
#:   surfacing through ``OPAEngine.Decision`` is deferred to a future
#:   task per Sprint-10 spec §7.3 amendment (the follow-up adds either
#:   a per-rule deny-set carried via ``decision_data`` or a
#:   ``rule_name`` channel on ``Decision``, plus the admission.py
#:   dispatch wiring). T9's bare Literal lift gives that future task a
#:   stable closed-enum target without imposing wire-protocol-public
#:   engine work in Sprint 10.
#: * 1 post-mint granted-vs-requested TTL refusal (Sprint 10.1 — finding
#:   #2 amendment per ADR-004 §25) — ``sandbox_credential_lease_ttl_grant_exceeds_request``.
#:   Mapped from the new ``core/vault.VaultLeaseGrantExceedsRequest``
#:   exception (5th value in the ``core/vault`` closed taxonomy;
#:   carries ``lease_id`` + ``revoke_outcome ∈ {"revoked",
#:   "revoke_failed"}`` attrs + includes the ``lease_id`` token in the
#:   formatted message string so the backend
#:   ``SandboxLifecycleRefused.detail=str(exc)`` preserves the
#:   dangling-lease correlator per Finding 3 of plan-review round 2)
#:   at the sandbox boundary via
#:   ``_shared_credentials._mint_exception_to_refusal_reason``. Wired
#:   at the backend ``create()`` Stage-2 except-tuple via the same
#:   shape as the existing ``sandbox_credential_mint_failed_*``
#:   triggers; both backends' (``docker_sibling.py`` +
#:   ``kubernetes_pod.py``) post-mint cleanup except-tuples extended
#:   4 → 5 in the SAME commit as the Literal extension per Finding B
#:   of plan-review round 1 (no intermediate state where the new
#:   exception escapes uncaught at the backend boundary). Complements
#:   the Rego rule-6 pre-mint cap (``sandbox_credential_ttl_exceeds_tenant_max``)
#:   — together they prevent over-cap leases regardless of whether
#:   the caller asked too high (caught by Rego) or the Vault role
#:   default_ttl is too loose (caught here) per the
#:   ``[[feedback_recompute_derived_facts_not_just_wrapper]]`` doctrine.
#:
#: Drift between this Literal and consumer error-handling is caught at
#: module load by the partition-invariant test at
#: ``tests/unit/sandbox/test_policy_shape.py`` (count guard +
#: canonical-values pin) and at the cross-backend dispatch level by
#: ``tests/conformance/sandbox/test_refusal_taxonomy.py`` (membership
#: pin against TRIGGERS_BY_REASON).
SandboxRefusalReason = Literal[
    # Sprint 8A (15 values, unchanged):
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
    # Sprint 8.5 T1 — 6 new wake-time refusal reasons per spec §3.3.
    # Wake-time taxonomy is wake-specific per spec §2.3 — the original
    # 8A admission-time reason (if any) lives in the refusal's `detail`
    # field for examiner traceability.
    "sandbox_wake_checkpoint_not_found",
    "sandbox_wake_checkpoint_corrupt",
    "sandbox_wake_checkpoint_retention_expired",
    "sandbox_wake_session_tombstoned",
    "sandbox_wake_tenant_mismatch",
    "sandbox_wake_policy_revalidation_failed",
    # Sprint 10 T7 — kernel-boundary cross-tenant request guard per
    # Sprint-10 spec §4.1. Raised by admit_policy when any
    # VaultLeaseRequest in ``requires_credentials`` has
    # ``tenant_id != actor.tenant_id``. The remaining 4 Sprint-10
    # reasons are lifted by T9 below; T7 owns ONLY this value because
    # the admit_policy raise statement needs it and every intermediate
    # commit on the branch must lint clean on its own (mypy treats
    # SandboxLifecycleRefused.reason as the SandboxRefusalReason
    # Literal — raising a not-yet-declared value would fail mypy).
    "sandbox_credential_request_tenant_mismatch",
    # Sprint 10 T9 — 3 Vault mint-failure values per Sprint-10 spec
    # §6.1 + §7.1. Literal entries land at T9; the matching Stage-2
    # raise sites land at T10's backend ``create()`` post-admission
    # (the create-time mapping from the ``core/vault`` 4-value
    # exception taxonomy: ``VaultUnavailable`` /
    # ``VaultPathNotFound`` / ``VaultAuthDenied`` /
    # ``VaultProtocolError`` collapse). T9's commit lints clean
    # because mypy does not reject Literal members that lack callers.
    "sandbox_credential_mint_failed_vault_unavailable",
    "sandbox_credential_mint_failed_secret_path_unknown",
    "sandbox_credential_mint_failed_auth_denied",
    # Sprint 10 T9 — 1 Rego TTL-cap value per Sprint-10 spec §6.1.
    # **Literal-only at T9; NO Stage-2 raise site at T9 or T10.** The
    # ``policies/_default/sandbox.rego`` rule 6 fires + denies, but
    # ``OPAEngine.Decision`` (at ``core/policy/engine.py:148-150``)
    # exposes only ``allow`` + the decision-point-derived generic
    # ``reasoning`` with no per-rule-name channel that could
    # distinguish "rule 6 fired vs rule 5 fired" — so admission.py's
    # single generic arm at ``admission.py:601-603`` continues to
    # surface the cap as ``sandbox_policy_rego_denied``. Rego-reason
    # surfacing through ``OPAEngine.Decision`` is deferred to a
    # future task per Sprint-10 spec §7.3 amendment. T9's bare
    # Literal lift gives that future task a stable closed-enum target
    # without imposing wire-protocol-public engine work in Sprint 10.
    "sandbox_credential_ttl_exceeds_tenant_max",
    # Sprint 10.1 — finding #2 from post-merge review of PR #38.
    # Post-mint granted-vs-requested TTL enforcement at `core/vault.py`.
    # Complements `sandbox_credential_ttl_exceeds_tenant_max` (the Rego
    # rule-6 pre-mint cap, Literal-only at Sprint 10 T9). The new
    # post-mint enforcement RAISES; the closed-enum value surfaces via
    # `_shared_credentials._mint_exception_to_refusal_reason` at the
    # backend `create()` Stage-2 except-tuple, same shape as the existing
    # `sandbox_credential_mint_failed_*` triggers per Sprint-10 spec
    # §7.1 amendment. Backend except-tuples extended in the SAME commit
    # to catch `VaultLeaseGrantExceedsRequest` per Finding B of the
    # 2026-05-24 plan-review round 1 (no intermediate state where the
    # new exception escapes backends uncaught).
    "sandbox_credential_lease_ttl_grant_exceeds_request",
]

#: 6-value closed-enum for runtime policy violations during ``exec``
#: (spec §4.2 + T10c R1 P1.2 amendment).
#:
#: Note: CPU throttling under the Docker ``--cpus`` cap is NOT a
#: violation by itself — a CPU-bound workload that stays within its
#: budget is expected to be throttled by the kernel scheduler.
#: Workloads needing a hard CPU-seconds budget set
#: ``SandboxPolicy.cpu_time_budget_s``; the runtime monitor reads
#: cgroup ``cpuacct.usage_us`` and kills when exceeded.
#:
#: ``egress_audit_unreadable`` (T10c R1 P1.2) — additive amendment:
#: surfaces a fail-closed runtime-violation when the proxy sidecar's
#: ALLOW_LIST audit log cannot be read at session ``exec_completed``
#: time. Without this reason, a sidecar that crashes mid-exec OR an
#: unreachable log file would silently elide refusals + emit a
#: green ``exec_completed`` chain row — defeating the §10.3
#: "examiners can prove refused-vs-allowed from the chain row"
#: contract. The bank-grade trust posture requires fail-closed:
#: if AgentOS cannot prove the absence of refusals, treat it as
#: a violation.
SandboxPolicyViolationReason = Literal[
    "cpu_time_budget_exceeded",
    "memory_cap_exceeded",
    "walltime_cap_exceeded",
    "egress_host_not_allow_listed",
    "egress_protocol_not_http",
    "egress_audit_unreadable",
]

#: 15-value closed-enum for audit chain-row decision_type discriminator
#: (Sprint 8A spec §4.3 + Sprint 8.5 spec §3.3 + Sprint 10 spec §6.2).
#: Covers:
#:
#: * 8 Sprint-8A lifecycle events (created / exec_completed / destroyed
#:   / refused / policy.violated / warm_pool.precreated / .checked_out
#:   / .drained).
#: * 4 Sprint-8.5 events (checkpointed / suspended / woken /
#:   checkpoint_purged).
#: * 3 Sprint-10 lease lifecycle events (lease_minted / lease_revoked
#:   / lease_revoke_failed) — emitted from ``SandboxBackend.create()``
#:   post-admission + ``destroy()`` per Sprint-10 spec §4.2 + §4.3 +
#:   §6.2. Typed helpers live at ``sandbox/audit.py`` per the Sprint
#:   8.5 T2 typed-helper pattern; backend call sites land at T10.
#:
#: Tombstoning is a STORAGE artifact NOT a lifecycle event — destroy()
#: reuses 8A's ``sandbox.lifecycle.destroyed`` with 2 new conditional
#: payload keys (``retained_until`` + ``tombstone_object_key``) per
#: spec §5.1 P1.r4.
#:
#: User-locked taxonomy: replenishment is the cause; the event is
#: still ``precreated``. No ``warm_pool.replenished`` value.
SandboxLifecycleEvent = Literal[
    # Sprint 8A (8 values, unchanged):
    "sandbox.lifecycle.created",
    "sandbox.lifecycle.exec_completed",
    "sandbox.lifecycle.destroyed",
    "sandbox.lifecycle.refused",
    "sandbox.policy.violated",
    "sandbox.warm_pool.precreated",
    "sandbox.warm_pool.checked_out",
    "sandbox.warm_pool.drained",
    # Sprint 8.5 T1 — 4 new lifecycle events per spec §3.3.
    # Tombstoning is a STORAGE artifact, NOT a lifecycle event — destroy()
    # reuses 8A's sandbox.lifecycle.destroyed with 2 new conditional
    # payload keys per spec §5.1.
    "sandbox.lifecycle.checkpointed",
    "sandbox.lifecycle.suspended",
    "sandbox.lifecycle.woken",
    "sandbox.lifecycle.checkpoint_purged",
    # Sprint 10 T9 — 3 new lease lifecycle events per Sprint-10 spec
    # §6.2. lease_minted emitted from SandboxBackend.create() per
    # successful mint_lease() round-trip (T10); lease_revoked emitted
    # from SandboxBackend.destroy() per successful revoke round-trip
    # (T10); lease_revoke_failed emitted from destroy() per failed
    # revoke (fail-soft per spec §7.2). Typed helpers at
    # ``sandbox/audit.py`` enforce the 10-key always-payload contract
    # (lease_minted / lease_revoked: 10 fields + session_id;
    # lease_revoke_failed: 10 fields + session_id + vault_error +
    # auto_expiry_at).
    "sandbox.lifecycle.lease_minted",
    "sandbox.lifecycle.lease_revoked",
    "sandbox.lifecycle.lease_revoke_failed",
]


# ---------------------------------------------------------------------------
# Sprint 8.5 T1 — CheckpointId NewType (wire-public per spec §3.4).
# ---------------------------------------------------------------------------

#: Opaque identifier for a persisted checkpoint. Declared in this
#: module (NOT in ``sandbox/checkpoint_store.py`` as spec §3.4 listed)
#: because the ``SandboxSession.checkpoint()`` Protocol method below
#: returns it; the Protocol module is the canonical home for types
#: used in Protocol signatures. T3's checkpoint_store imports this
#: declaration rather than re-declaring its own.
#:
#: ``NewType`` is a static-analysis hint that does NOT enforce runtime
#: opacity (an arbitrary ``str`` can still be cast to ``CheckpointId``
#: at runtime). Runtime construction discipline is enforced by T3's
#: ``CheckpointStore.mint_checkpoint_id()`` (uuid4 hex — the ONLY
#: mint site in production code) + ``_validate_checkpoint_id_or_raise``
#: helper (raises ValueError on non-32-char-hex strings) at every
#: store entry point.
CheckpointId = NewType("CheckpointId", str)


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
    from cognic_agentos.core.vault import CredentialLease, VaultLeaseRequest
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
    #: Sprint 10 T10 — leases minted at ``create()`` post-admission per
    #: spec §3.6 + §4.2. Immutable post-construction (mid-life mutation
    #: out of scope Wave-1). Empty tuple keeps Sprint-8A backward-compat
    #: for lease-less cold-create + warm-pool members. Iterated by the
    #: backend at ``destroy()`` for the per-lease fail-soft revoke loop
    #: per spec §4.3 + §7.2. ALSO gates the Q5 LOCK at spec §4.5 —
    #: non-empty ``active_leases`` forces ``checkpoint()`` + ``suspend()``
    #: to raise ``NotImplementedError`` pointing at Sprint 10.x
    #: (production-grade fail-loud scaffolding; checkpoint/suspend/wake
    #: on a leased session is out-of-scope at Sprint 10).
    active_leases: tuple[CredentialLease, ...]

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult: ...

    async def destroy(self) -> None: ...

    # Sprint 8.5 T1 — checkpoint + suspend per spec §3.1 + Q1 lock.

    async def checkpoint(self, label: str) -> CheckpointId:
        """Persist a workspace-tar snapshot + env metadata + Vault lease
        refs to the CheckpointStore. Emits
        ``sandbox.lifecycle.checkpointed``. Returns the opaque
        ``CheckpointId``; same session can checkpoint multiple times
        (subject to ``Settings.sandbox_max_checkpoints_per_session``).

        Sprint 10 T10 Q5 LOCK (spec §4.5): when ``self.active_leases``
        is non-empty, concrete session implementations MUST raise
        ``NotImplementedError`` pointing at Sprint 10.x — checkpoint /
        suspend / wake on a leased session is out of scope at Sprint
        10 (production-grade fail-loud scaffolding per AGENTS.md;
        choosing the leased-session checkpoint model — re-mint at
        wake vs revoke-at-suspend vs token-in-checkpoint — is the
        follow-up sprint's call).
        """

    async def suspend(self) -> None:
        """Take a final checkpoint (label='__suspend__') and release the
        underlying container/Pod. Subsequent ``exec()`` calls on this
        session raise. ``wake()`` restores the session in a fresh backend
        resource. Emits ``sandbox.lifecycle.suspended``.

        Sprint 10 T10 Q5 LOCK (spec §4.5): same fail-loud contract as
        ``checkpoint()`` above — when ``self.active_leases`` is
        non-empty concrete implementations raise
        ``NotImplementedError`` pointing at Sprint 10.x. The premise
        of the Sprint-8.5 Q4 lock (``vault_lease_refs=()`` always; no
        vault-bearing sessions exist) breaks at Sprint 10; the Q5
        lock defers the resolution to a follow-up sprint rather than
        silently dropping leases at suspend / wake.
        """


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
        requires_credentials: Sequence[VaultLeaseRequest] = (),
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

        ``requires_credentials``: Sprint 10 T10 — sequence of
        ``VaultLeaseRequest`` describing the dynamic credentials the
        sandbox needs minted at create() per spec §4.2. Default ``()``
        keeps existing Sprint-8A callers backward-compat. When
        non-empty: (1) admit_policy's cross-tenant guard + Rego TTL
        cap fire BEFORE any Vault round-trip; (2) the warm-pool
        checkout is SKIPPED per spec §4.2.1 (warm members lack actor
        context for leases); (3) AFTER admit_policy succeeds the
        backend mints each lease in order via
        ``credential_adapter.mint_lease(request)``; (4) on any mid-batch
        mint failure, leases already minted in this attempt are revoked
        best-effort then ``SandboxLifecycleRefused`` is raised with the
        mapped ``sandbox_credential_mint_failed_*`` closed-enum reason
        per spec §7.1; (5) on success the minted leases land on
        ``session.active_leases`` for the per-lease destroy-time revoke
        loop. ``Sequence`` (NOT ``list``) so the empty-tuple default is
        type-consistent with the annotation and matches the live T7
        ``admit_policy`` signature.
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

    # Sprint 8.5 T1 — wake per spec §3.2 + Q5 identity-seam lock.

    async def wake(
        self,
        session_id: str,
        *,
        actor: Actor,
        tenant_id: str,
    ) -> SandboxSession:
        """Restore a suspended session from its latest checkpoint.

        Pipeline (security-reviewed ordering per spec §3.2 step 1-7):

        1. ``CheckpointStore.load_tombstone(session_id, tenant_id)``
           FIRST. Three failure modes (NOT folded — closed-enum
           distinction load-bearing for examiner incident-response):
             (a) Non-None ``TombstoneRecord`` OR raised
                 ``TombstoneCorruptError`` (P1.r6 fail-closed) →
                 ``SandboxLifecycleRefused("sandbox_wake_session_tombstoned")``
                 with tombstone metadata in ``detail``. CHECKED FIRST
                 via the dedicated ``load_tombstone()`` read helper —
                 NOT folded into ``load_latest()``.
             (b) No tombstone AND metadata missing/purged →
                 ``sandbox_wake_checkpoint_not_found``.
             (c) No tombstone, metadata bytes exist but
                 ``from_storage_payload()`` raises ``ValueError`` →
                 ``sandbox_wake_checkpoint_corrupt`` with the
                 ``ValueError`` message in ``detail``.
        2. Cross-check ``metadata.tenant_id`` against caller
           ``tenant_id`` kwarg (defence-in-depth past the prefix-keyed
           lookup). Mismatch → ``sandbox_wake_tenant_mismatch``.
        3. Check ``metadata.retention_window_s`` against
           ``now - metadata.created_at``. Expired →
           ``sandbox_wake_checkpoint_retention_expired``.
        4. Re-run ``admit_policy`` against LIVE tenant policy / catalog
           / Rego / settings. Refusal →
           ``sandbox_wake_policy_revalidation_failed`` (with the
           original 8A reason in ``detail`` per spec §2.3).
        5. Create fresh backend resource; restore workspace-tar
           snapshot into ``/workspace``. No vault-lease re-issue per
           spec §2.4 amended.
        6. Return fresh ``SandboxSession`` with ORIGINAL ``session_id``
           + new container/Pod IDs.
        7. Emit ``sandbox.lifecycle.woken`` chain row with payload keys
           ``suspend_event_id`` + ``restored_from_checkpoint_id`` for
           the chain-verifier walk (no schema migration; linkage lives
           in payload per spec §5.2).

        ``actor`` + ``tenant_id`` keyword-only per Q5 — identity seam
        forward-compat for Sprint 10.5 ``SchedulerEngine.submit()`` wrap
        per ADR-022. Extra design lock: ``session_id`` alone is NEVER
        authorization — the tenant_id cross-check at step 2 is the
        defence-in-depth identity boundary.
        """

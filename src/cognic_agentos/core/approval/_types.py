"""Sprint 13.5a (ADR-014/015) — runtime-approval closed-enum vocab + frozen
contracts + the pure state-machine validator. ``core/`` stop-rule.

Pure types only — no I/O, no OPA, no DB. The substantive enforcement lives in
the on-gate ``policy.py`` / ``storage.py`` / ``engine.py`` consumers; the
closed-enum drift detectors in ``test_types.py`` cover this module, so it stays
OFF the durable coverage gate.
"""

from __future__ import annotations

import dataclasses
import uuid
from typing import Literal

#: The 5 approval-request states (spec §2). ``check()`` returns one of these.
ApprovalState = Literal["pending", "awaiting_second", "granted", "denied", "expired"]

#: The 3-value tier->flow classification from ``tools.rego`` (spec §5).
ApprovalFlow = Literal["auto_run", "require_single_approval", "require_4_eyes"]

#: Envelope validation refusals (raised BEFORE classify/persist; spec §7/§10).
ApprovalEnvelopeInvalidReason = Literal[
    "risk_tier_unknown",
    "data_class_unknown",
    "tool_identity_missing",
    "originator_subject_missing",
    "tenant_id_missing",
    "regulator_audit_ref_missing",
    "redacted_context_too_large",
    "args_digest_malformed",
]

#: State-machine / RBAC / human-only / binding / expiry / reason-policy refusals (spec §10).
ApprovalTransitionRefusedReason = Literal[
    "auto_tier_no_approval_required",
    "approval_already_finalized",
    "approval_expired",
    "approver_scope_not_held",
    "approver_not_human",
    "four_eyes_approver_not_distinct",
    "grant_second_requires_awaiting_second",
    "deny_requires_non_terminal",
    "grant_reason_required",
    "approval_binding_mismatch",
]

#: The mutation actions the state machine accepts.
ApprovalAction = Literal["grant_first", "grant_second", "deny", "expire"]

#: Canonical redacted-context size cap (chars). Bounded per spec §7.
APPROVAL_REDACTED_CONTEXT_MAX_LEN: int = 4096

#: SHA-256 digest length (``args_digest`` / ``envelope_digest`` are 32 bytes).
_DIGEST_LEN: int = 32

#: Inline mirror of the canonical 8-value ADR-014 RiskTier vocab. ``core/`` MUST
#: NOT import ``cli/_governance_vocab`` (architectural arrow) — lockstep is
#: test-only drift-pinned (``test_types.py::test_risk_tier_mirror_matches_canonical``).
_RISK_TIERS: frozenset[str] = frozenset(
    {
        "read_only",
        "internal_write",
        "customer_data_read",
        "customer_data_write",
        "payment_action",
        "regulator_communication",
        "cross_tenant",
        "high_risk_custom",
    }
)

#: Tiers whose grant mandates a reason (spec §7 / ADR-014 §33 + §35).
_REASON_MANDATING_TIERS: frozenset[str] = frozenset(
    {
        "customer_data_write",
        "regulator_communication",
    }
)

#: Terminal states — no transitions out.
_TERMINAL: frozenset[str] = frozenset({"granted", "denied", "expired"})


class ApprovalTransitionRefused(Exception):
    """State-machine / RBAC / human-only / binding / expiry refusal carrying a
    closed-enum ``reason``. Caller-distinct from :class:`ApprovalRequestNotFound`."""

    def __init__(self, reason: ApprovalTransitionRefusedReason) -> None:
        super().__init__(reason)
        self.reason: ApprovalTransitionRefusedReason = reason


class ApprovalEnvelopeInvalid(Exception):
    """Envelope validation refusal (pre-persist) carrying a closed-enum ``reason``."""

    def __init__(self, reason: ApprovalEnvelopeInvalidReason) -> None:
        super().__init__(reason)
        self.reason: ApprovalEnvelopeInvalidReason = reason


class ApprovalRequestNotFound(Exception):
    """Missing / cross-tenant approval request. Caller-distinct from
    :class:`ApprovalTransitionRefused` (mirrors ``SchedulerTaskNotFound``)."""


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalActor:
    """Core-owned actor projection (the engine MUST NOT import ``portal/rbac``).
    The Sprint-13.5b portal binds its ``Actor`` -> this at the boundary
    (mirrors ``core/vault.VaultLeaseActorRef``)."""

    subject: str
    tenant_id: str
    scopes: frozenset[str]
    actor_type: Literal["human", "service"]


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalEnvelope:
    """Caller-supplied, value-free request envelope (spec §7). The engine NEVER
    receives raw tool args — only the caller's ``args_digest``."""

    risk_tier: str
    tool_identity: str
    originator_subject: str
    tenant_id: str
    data_classes: tuple[str, ...]
    args_digest: bytes
    redacted_context: str
    required_refs: dict[str, str]


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Persisted approval-request projection returned by ``create_request``."""

    request_id: uuid.UUID
    tenant_id: str
    flow: ApprovalFlow
    risk_tier: str
    tool_identity: str
    originator_subject: str
    state: ApprovalState
    envelope_digest: bytes
    args_digest: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalCheckResult:
    """Structured ``check()`` / ``verify_grant_for_action()`` result (spec §3) —
    the state plus the bound facts the seam compares for replay protection."""

    state: ApprovalState
    request_id: uuid.UUID
    flow: ApprovalFlow
    risk_tier: str
    tool_identity: str
    args_digest: bytes
    envelope_digest: bytes
    originator_subject: str


def validate_transition(*, from_state: str, action: str, flow: str) -> ApprovalState:
    """Pure state-machine validator (spec §2). Returns the resulting
    :data:`ApprovalState`; raises :class:`ApprovalTransitionRefused` on an
    illegal pair. ``storage.transition`` calls this under the row lock.
    """
    if from_state in _TERMINAL:
        # Any action on a terminal request is already-finalized. ``deny`` gets
        # the more specific ``deny_requires_non_terminal`` per the spec vocab.
        if action == "deny":
            raise ApprovalTransitionRefused("deny_requires_non_terminal")
        raise ApprovalTransitionRefused("approval_already_finalized")
    if action == "grant_first":
        if from_state != "pending":
            raise ApprovalTransitionRefused("approval_already_finalized")
        return "awaiting_second" if flow == "require_4_eyes" else "granted"
    if action == "grant_second":
        if from_state != "awaiting_second":
            raise ApprovalTransitionRefused("grant_second_requires_awaiting_second")
        return "granted"
    if action == "deny":
        return "denied"  # from pending or awaiting_second
    if action == "expire":
        return "expired"  # from pending or awaiting_second
    raise ApprovalTransitionRefused("approval_already_finalized")  # unknown action — defensive

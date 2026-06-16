"""Sprint 10.5a — internal home for scheduler closed enums + frozen
dataclasses. Re-exported from cognic_agentos.core.scheduler.

Closed-enum doctrine per [[feedback_drift_detector_test_only_no_runtime_import]]:
these Literals are pinned by test-only drift detectors at
tests/unit/core/scheduler/test_closed_enums.py; no production code
imports the canonical set from anywhere — each module declares its
own copy if needed.

Critical-controls module (core/ stop-rule per AGENTS.md). Every edit
is halt-before-commit per [[feedback_strict_review_off_gate]].
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

# --- Closed-enum vocabularies (spec §4.2) ----------------------------------

SchedulerAdmissionOutcome = Literal[
    # accepted (2)
    "accepted_immediate",
    "accepted_queued",
    # refused (10; wire-equal to SchedulerRefusalReason)
    "refused_queue_full",
    "refused_quota_exhausted",
    "refused_policy_denied",
    "refused_kill_switch_active",
    "refused_pack_not_installed",
    # Sprint 13.5c2 (ADR-014) — approval-seam refusals
    "refused_approval_pending",
    "refused_approval_denied",
    "refused_approval_expired",
    "refused_approval_binding_mismatch",
    "refused_approval_request_not_found",
]

SchedulerRefusalReason = Literal[
    "refused_queue_full",
    "refused_quota_exhausted",
    "refused_policy_denied",
    "refused_kill_switch_active",
    "refused_pack_not_installed",
    # Sprint 13.5c2 (ADR-014) — approval-seam refusals
    "refused_approval_pending",
    "refused_approval_denied",
    "refused_approval_expired",
    "refused_approval_binding_mismatch",
    "refused_approval_request_not_found",
]

SchedulerTaskState = Literal[
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
    "preempted",
    "expired",
]

SchedulerPriorityClass = Literal["interactive", "background"]

SchedulerTaskCancelledReason = Literal[
    "actor_cancelled",
    "parent_run_cancelled",
    "tenant_admin_cancelled",
    "sandbox_boundary_killed",
]

SchedulerTaskPreemptedReason = Literal["quota_exhausted_in_flight"]

SchedulerTaskFailedReason = Literal[
    "scheduler_task_failed_sandbox_create_refused",
    "scheduler_task_failed_workload_runtime_error",
]

ActorType = Literal["human", "service"]

#: Sprint 14A-A4a (ADR-022 + ADR-014) — named delegate authority. When set on a
#: SubmitInput, the scheduler admits a high-risk task because the named downstream
#: gate owns the human checkpoint; the scheduler mints/verifies no grant of its own.
#: Wave-1: the only authority is the sandbox admission gate. See the A4a spec §3.8
#: setter obligation — only the A4b managed-run executor sets it in production.
SchedulerApprovalDelegate = Literal["sandbox_admission"]

# --- Frozen public dataclasses --------------------------------------------


@dataclass(frozen=True)
class TaskActor:
    """Identity context for submit/cancel/admin actions."""

    subject: str
    tenant_id: str
    actor_type: ActorType


@dataclass(frozen=True)
class SubmitInput:
    """Inputs to SchedulerEngine.submit(...). All fields signed-manifest-derived
    or actor-bound; no free-form policy strings. Three non-standard fields:
    the two Sprint-13.5c2 approval-carrier fields (ADR-014) —
    ``approval_request_id`` is a caller-supplied correlator (UUID-string,
    engine-boundary-validated), and ``approval_verified`` is ENGINE-OWNED (the
    engine unconditionally overwrites whatever the caller set, so it is never
    caller-trusted input) — plus the Sprint-14A-A4a ``approval_delegated_to``
    routing/evidence signal (ADR-022 + ADR-014): the engine reads it to decide
    delegated admission but NEVER binds it into the approval binding digest.
    """

    tenant_id: str
    pack_id: str
    actor: TaskActor
    class_: SchedulerPriorityClass
    pack_kind: str
    pack_risk_tier: str
    requested_estimated_tokens: int
    parent_task_id: str | None = None  # Sprint 11 hook; spec §4.10
    # Sprint 13.5c2 (ADR-014) — approval-seam fields (c2 spec §2):
    approval_request_id: str | None = None  # caller-supplied re-submit carrier
    approval_verified: bool = False  # ENGINE-OWNED attestation; engine ALWAYS overwrites
    data_classes: tuple[str, ...] = ()  # manifest [data_governance].data_classes
    # Sprint 14A-A4a (ADR-022 + ADR-014) — routing/evidence signal (NOT a grant
    # carrier, NOT in the approval binding digest). Default None = no delegation.
    approval_delegated_to: SchedulerApprovalDelegate | None = None


@dataclass(frozen=True)
class AdmissionDecision:
    """Result of scheduler.admit; carries outcome + retry_after when refused."""

    outcome: SchedulerAdmissionOutcome
    task_id: str | None  # None on refused outcomes
    retry_after_s: int | None = None  # Set only for refused_queue_full
    policy_reason: str | None = None  # Set when outcome=refused_policy_denied; opaque to scheduler
    approval_request_id: str | None = None  # Set only for refused_approval_pending


@dataclass(frozen=True)
class TaskFailedPayload:
    """Spec §4.2 — cross-layer correlation payload for task_failed events."""

    reason: SchedulerTaskFailedReason
    sandbox_refusal_reason: str | None = None  # Upstream sandbox closed-enum value
    sandbox_event_id: str | None = None  # Chain-derived event id for correlation


# --- ISO 42001 control tagging (spec §4.9) --------------------------------

SCHEDULER_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.6.2.5",)


# --- State machine (spec §4.4 amended) -------------------------------------

_VALID_TRANSITIONS: Final[frozenset[tuple[SchedulerTaskState, SchedulerTaskState]]] = frozenset(
    {
        # From pending (4 transitions: 2 ADR-022 base + 2 new amendments)
        ("pending", "running"),
        ("pending", "expired"),
        ("pending", "failed"),  # NEW per spec §4.4 amendment
        ("pending", "cancelled"),  # NEW per spec §4.4 amendment
        # From running (4 transitions; quota_exhausted now preempted not cancelled)
        ("running", "completed"),
        ("running", "failed"),
        ("running", "cancelled"),
        ("running", "preempted"),
    }
)


class SchedulerTransitionRefused(Exception):
    """Raised by validate_transition on illegal state pair.

    Thin wrapper carrying only the closed-enum refusal reason — no
    transition_name field on the exception (mirrors
    packs/lifecycle.LifecycleTransitionRefused pattern).
    """

    def __init__(self, reason: Literal["scheduler_transition_invalid_state_pair"]) -> None:
        super().__init__(reason)
        self.reason = reason


def validate_transition(
    *,
    from_state: SchedulerTaskState,
    to_state: SchedulerTaskState,
) -> None:
    """Pure-functional state-machine validator. No I/O; no DB access.

    Mirrors packs/lifecycle.validate_transition pattern. Keyword-only
    args eliminate positional-misuse bug class at the call site.

    Raises SchedulerTransitionRefused on illegal state pair; returns
    None on legal pair.
    """
    if (from_state, to_state) not in _VALID_TRANSITIONS:
        raise SchedulerTransitionRefused("scheduler_transition_invalid_state_pair")

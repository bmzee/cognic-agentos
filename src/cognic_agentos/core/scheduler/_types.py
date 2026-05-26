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
    # refused (5; wire-equal to SchedulerRefusalReason)
    "refused_queue_full",
    "refused_quota_exhausted",
    "refused_policy_denied",
    "refused_kill_switch_active",
    "refused_pack_not_installed",
]

SchedulerRefusalReason = Literal[
    "refused_queue_full",
    "refused_quota_exhausted",
    "refused_policy_denied",
    "refused_kill_switch_active",
    "refused_pack_not_installed",
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
    or actor-bound; no free-form policy strings.
    """

    tenant_id: str
    pack_id: str
    actor: TaskActor
    class_: SchedulerPriorityClass
    pack_kind: str
    pack_risk_tier: str
    requested_estimated_tokens: int
    parent_task_id: str | None = None  # Sprint 11 hook; spec §4.10


@dataclass(frozen=True)
class AdmissionDecision:
    """Result of scheduler.admit; carries outcome + retry_after when refused."""

    outcome: SchedulerAdmissionOutcome
    task_id: str | None  # None on refused outcomes
    retry_after_s: int | None = None  # Set only for refused_queue_full
    policy_reason: str | None = None  # Set when outcome=refused_policy_denied; opaque to scheduler


@dataclass(frozen=True)
class TaskFailedPayload:
    """Spec §4.2 — cross-layer correlation payload for task_failed events."""

    reason: SchedulerTaskFailedReason
    sandbox_refusal_reason: str | None = None  # Upstream sandbox closed-enum value
    sandbox_event_id: str | None = None  # Chain-derived event id for correlation


# --- ISO 42001 control tagging (spec §4.9) --------------------------------

SCHEDULER_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.6.2.5",)

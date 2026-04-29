"""Pure-functional SLA timer — deadline computation + status
classification. No DB, no emission, no I/O.

**Critical-controls module.** Per AGENTS.md: ``core/sla`` is on the
critical-controls list (≥95% line + ≥90% branch coverage; halt-
before-commit per edit). Per the Sprint 2.5 plan-of-record (PR #7
/ commit ``4733b52``): SLA is intentionally pure timer math — it
does NOT emit ``decision_history`` records on breach. Caller
(escalation lifecycle, LLM gateway, kill switch, etc.) decides
whether breach detection triggers downstream effects.

This decoupling matters because:

  - SLA classification is hot-path: every in-flight operation calls
    ``classify(now, deadline)`` to gate a mid-step early-exit. A
    DB write per call would be unacceptable latency.
  - Different consumers want different policies. Some breaches
    trigger an escalation; some trigger an audit-only emission;
    some trigger a kill switch. Putting the emission decision in
    the caller keeps the policy where it belongs.
  - Pure functions are trivially testable with pinned ``now``
    parameters; no fixtures, no clock-skew, no flakes.

Timezone discipline: every datetime crossing the SLA boundary MUST
be timezone-aware. Naive datetimes are rejected with ``ValueError``
to mirror the canonical-form Round-3 hardening from Sprint 2 — any
SLA-tracked timestamp downstream may participate in evidence-pack
export per ADR-006, and the canonical serializer rejects naive
datetimes outright. Reject at the SLA boundary too so failures
surface where they originate.

Validation order in ``SLAPolicy.__post_init__`` is load-bearing
(plan-review P3 fix): ``total_budget > 0`` first, then
``warning_threshold >= 0``, then ``warning_threshold <
total_budget``. The earlier draft put the strict-inequality check
first, which made the ``total_budget=0`` case trip the
warning-threshold message instead of the budget-must-be-positive
message — every precondition needs at least one input that
exercises only it.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from enum import StrEnum


class SLAStatus(StrEnum):
    """SLA classification result. StrEnum so the value round-trips
    through JSON via the canonical-form serializer (Sprint 2 R3
    contract: only string-valued enums are accepted in the chain
    payload)."""

    GREEN = "green"
    """now < warning_at — the operation is on time."""

    WARNING = "warning"
    """warning_at <= now < deadline — operation is past the warning
    threshold but not yet breached. Caller MAY choose to emit a
    soft-warning event or escalate proactively."""

    BREACHED = "breached"
    """now >= deadline — the SLA budget is exhausted. Caller decides
    whether to terminate the operation, escalate, audit, or run a
    fallback path."""


@dataclasses.dataclass(frozen=True, slots=True)
class SLAPolicy:
    """Caller-side SLA policy bundle.

    Frozen + slotted: safe to share across coroutines + threads. The
    constructor enforces the three preconditions in order so each
    has at least one input that exercises only it (see module
    docstring for the order rationale).

    Attributes:
        name: Stable identifier for the policy (e.g. ``"llm-call"``,
            ``"retrieval"``). Used in audit/decision payloads when
            the caller emits SLA-related events.
        total_budget: Hard deadline measured from the operation's
            start time. MUST be strictly positive.
        warning_threshold: Soft warning measured from the operation's
            start time. MUST be non-negative AND strictly less than
            ``total_budget``.
    """

    name: str
    total_budget: timedelta
    warning_threshold: timedelta

    def __post_init__(self) -> None:
        if self.total_budget <= timedelta(0):
            raise ValueError(f"total_budget must be positive; got {self.total_budget}")
        if self.warning_threshold < timedelta(0):
            raise ValueError(
                f"warning_threshold must be non-negative; got {self.warning_threshold}"
            )
        if self.warning_threshold >= self.total_budget:
            raise ValueError(
                f"warning_threshold ({self.warning_threshold}) must be "
                f"strictly less than total_budget ({self.total_budget})"
            )


@dataclasses.dataclass(frozen=True, slots=True)
class SLADeadline:
    """Absolute deadline + warning point for one SLA-tracked
    operation. Frozen + slotted: safe to share + immune to
    after-the-fact mutation that would silently alter downstream
    classification results.

    Built by ``SLATimer.compute_deadline`` from a ``SLAPolicy`` and
    a tz-aware start datetime.

    Attributes:
        policy_name: Carried forward from the originating policy for
            diagnostic + emission convenience.
        started_at: Absolute timestamp of operation start.
        warning_at: ``started_at + policy.warning_threshold``.
        deadline: ``started_at + policy.total_budget``.
    """

    policy_name: str
    started_at: datetime
    warning_at: datetime
    deadline: datetime


def _require_tz_aware(value: datetime, label: str) -> None:
    """Reject naive datetimes + datetimes whose tzinfo returns None
    from utcoffset(). Mirrors the canonical-form Round-3 boundary
    check so any SLA-tracked timestamp can participate in evidence-
    pack export without re-validation downstream.
    """

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{label} must be timezone-aware; got {value!r}")


class SLATimer:
    """Pure-functional SLA timer. Static methods only; the class
    exists for namespacing.

    Two operations:
      - ``compute_deadline(start, policy)``: build the absolute
        ``SLADeadline`` from a tz-aware start + a validated policy.
      - ``classify(now, deadline)``: project ``(now, deadline)``
        onto ``GREEN`` / ``WARNING`` / ``BREACHED``.

    Both are side-effect-free; no DB, no I/O, no emission. Caller
    decides how to react to the classification.
    """

    @staticmethod
    def compute_deadline(start: datetime, policy: SLAPolicy) -> SLADeadline:
        """Project a (start, policy) pair onto an absolute
        SLADeadline. Rejects naive ``start``.
        """

        _require_tz_aware(start, "start")
        return SLADeadline(
            policy_name=policy.name,
            started_at=start,
            warning_at=start + policy.warning_threshold,
            deadline=start + policy.total_budget,
        )

    @staticmethod
    def classify(now: datetime, deadline: SLADeadline) -> SLAStatus:
        """Classify ``now`` against the absolute deadline. Rejects
        naive ``now``.

        Boundaries:
          - now < warning_at         → GREEN
          - warning_at <= now < ddl  → WARNING
          - now >= deadline          → BREACHED

        Both lower bounds are inclusive: ``now == warning_at`` is
        WARNING (not GREEN); ``now == deadline`` is BREACHED (not
        WARNING). This matches the principle "the moment you hit
        the warning point you are at warning"; a strict-inequality
        boundary would have a one-tick blind spot.
        """

        _require_tz_aware(now, "now")
        if now >= deadline.deadline:
            return SLAStatus.BREACHED
        if now >= deadline.warning_at:
            return SLAStatus.WARNING
        return SLAStatus.GREEN


__all__: tuple[str, ...] = (
    "SLADeadline",
    "SLAPolicy",
    "SLAStatus",
    "SLATimer",
)

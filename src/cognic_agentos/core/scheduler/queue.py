"""Sprint 10.5a — bounded FIFO queue + concurrency caps (spec §4.3 + §4.5).

Critical-controls module (core/ stop-rule per AGENTS.md). Every edit
is halt-before-commit per [[feedback_strict_review_off_gate]].

The `BoundedQueue` is single-class single-tenant; the orchestrating
``SchedulerEngine`` (T5) maintains one ``BoundedQueue`` per
(tenant, class) pair. ``ConcurrencyCaps`` is a frozen dataclass
holding the per-tenant + per-pack + per-actor counts; the bounded-
invariant pinning regressions enforce that caps are positive
integers — specific defaults are NOT wire-protocol contract.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

from cognic_agentos.core.scheduler._types import SchedulerPriorityClass


class QueueFull(Exception):
    """Raised by BoundedQueue.enqueue when max_depth reached.

    Caller (SchedulerEngine) catches this to translate into
    AdmissionDecision(outcome="refused_queue_full",
    retry_after_s=queue.compute_retry_after_s())."""


class BoundedQueue:
    """FIFO queue with bounded depth + retry-after computation.

    Spec §4.3 case 3: when full, refuse with retry_after_s derived
    from the oldest queued task's age + the class SLA.

    Wave-1 single-tenant single-class instance; the SchedulerEngine
    composes one instance per (tenant, class) pair.
    """

    def __init__(self, *, max_depth: int, class_sla_s: float) -> None:
        if max_depth < 1:
            raise ValueError(f"max_depth must be >= 1; got {max_depth}")
        if class_sla_s <= 0:
            raise ValueError(f"class_sla_s must be > 0; got {class_sla_s}")
        self._max_depth = max_depth
        self._class_sla_s = class_sla_s
        # _entries: deque of (item, oldest_age_s) tuples in FIFO order
        self._entries: deque[tuple[object, float]] = deque()

    @property
    def depth(self) -> int:
        return len(self._entries)

    @property
    def max_depth(self) -> int:
        return self._max_depth

    def enqueue(self, item: object, *, oldest_age_s: float) -> None:
        """Append item with its age-at-enqueue timestamp.

        Raises QueueFull when at max_depth.
        """
        if len(self._entries) >= self._max_depth:
            raise QueueFull(
                f"BoundedQueue at max_depth={self._max_depth}; "
                f"retry_after_s={self.compute_retry_after_s()}"
            )
        self._entries.append((item, oldest_age_s))

    def dequeue(self) -> object:
        """Pop and return oldest item (FIFO).

        Raises IndexError when empty.
        """
        item, _ = self._entries.popleft()
        return item

    def compute_retry_after_s(self) -> int:
        """Spec §4.3 case 3: retry_after_s = max(1, ceil(class_sla_s - oldest_age_s)).

        Clamped to minimum 1 second so clients don't hot-loop on
        retry. When oldest_age_s already exceeds class_sla_s, the
        ceil delta would be 0 or negative; clamp to 1.
        """
        if not self._entries:
            # No oldest to compute against; return class SLA as best guess
            return max(1, math.ceil(self._class_sla_s))
        # Oldest entry is at the front of the deque per FIFO contract
        _, oldest_age_s = self._entries[0]
        delta = self._class_sla_s - oldest_age_s
        return max(1, math.ceil(delta))


@dataclass(frozen=True)
class ConcurrencyCaps:
    """Spec §4.5 — per-tenant + per-pack + per-actor concurrency caps.

    Pinning regressions enforce the *bounded* invariant (caps cannot
    be zero, negative, or unset); specific defaults are Settings-
    configurable and NOT wire-protocol contract.
    """

    per_tenant_interactive: int
    per_tenant_background: int
    per_pack: int
    per_actor: int

    def __post_init__(self) -> None:
        if self.per_tenant_interactive < 1:
            raise ValueError(
                f"per_tenant_interactive must be >= 1; got {self.per_tenant_interactive}"
            )
        if self.per_tenant_background < 1:
            raise ValueError(
                f"per_tenant_background must be >= 1; got {self.per_tenant_background}"
            )
        if self.per_pack < 1:
            raise ValueError(f"per_pack must be >= 1; got {self.per_pack}")
        if self.per_actor < 1:
            raise ValueError(f"per_actor must be >= 1; got {self.per_actor}")

    def has_headroom_for(
        self,
        *,
        class_: SchedulerPriorityClass,
        tenant_count: int,
        pack_count: int,
        actor_count: int,
    ) -> bool:
        """Return True iff all three caps have strict headroom for
        admitting one more task. Per spec §4.5 — interactive and
        background tenant caps are separate axes; pack and actor caps
        apply uniformly to both classes.
        """
        if class_ == "interactive":
            tenant_cap = self.per_tenant_interactive
        elif class_ == "background":
            tenant_cap = self.per_tenant_background
        else:
            raise ValueError(f"class_ must be interactive or background; got {class_!r}")
        return (
            tenant_count < tenant_cap
            and pack_count < self.per_pack
            and actor_count < self.per_actor
        )

"""Spec §4.3 + §4.5 — bounded FIFO + concurrency caps + retry_after."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from cognic_agentos.core.scheduler.queue import (
    BoundedQueue,
    ConcurrencyCaps,
    QueueFull,
)


def _frozen_clock(seq: list[datetime]) -> Callable[[], datetime]:
    """Return a callable that pops the next datetime from ``seq`` each
    call. Lets tests control the queue's clock seam without freezing
    the process clock."""
    iterator = iter(seq)

    def _clock() -> datetime:
        return next(iterator)

    return _clock


class TestBoundedQueueFIFO:
    def test_dequeue_returns_oldest(self):
        q = BoundedQueue(max_depth=4, class_sla_s=5.0)
        q.enqueue("a")
        q.enqueue("b")
        q.enqueue("c")
        assert q.dequeue() == "a"
        assert q.dequeue() == "b"
        assert q.dequeue() == "c"

    def test_enqueue_raises_QueueFull_at_max(self):
        q = BoundedQueue(max_depth=2, class_sla_s=5.0)
        q.enqueue("a")
        q.enqueue("b")
        with pytest.raises(QueueFull):
            q.enqueue("c")

    def test_depth_tracks_enqueue_dequeue(self):
        q = BoundedQueue(max_depth=4, class_sla_s=5.0)
        assert q.depth == 0
        q.enqueue("a")
        assert q.depth == 1
        q.dequeue()
        assert q.depth == 0

    def test_peek_returns_fifo_head_without_removing(self):
        """Round-7 reviewer P1 — peek is the FIFO head probe consumed
        by SchedulerEngine.mark_running for promotion ordering."""
        q = BoundedQueue(max_depth=4, class_sla_s=5.0)
        assert q.peek() is None  # empty queue → None
        q.enqueue("a")
        q.enqueue("b")
        assert q.peek() == "a"  # oldest item
        assert q.depth == 2  # peek did NOT remove
        assert q.peek() == "a"  # idempotent
        q.dequeue()  # removes "a"
        assert q.peek() == "b"


class TestRetryAfterCalculation:
    """Spec §4.3 case 3 — retry_after_s derived from oldest queued task's
    age + class SLA. Round-6 reviewer P2 fix: age is computed
    dynamically from a wall-clock seam so the value updates as tasks
    wait (the pre-round-6 implementation captured age statically at
    enqueue, so a queue that had waited 4.9s on a 5s SLA still
    reported ~5s)."""

    def test_retry_after_uses_oldest_age_plus_class_sla(self):
        # Pin enqueue + compute clocks: oldest enqueued at t=0;
        # newer at t=4 (younger); compute called at t=8.9 (so oldest
        # age = 8.9s, newer age = 4.9s; SLA = 10s).
        t0 = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)
        clock_seq = [t0, t0 + timedelta(seconds=4), t0 + timedelta(seconds=8, milliseconds=900)]
        q = BoundedQueue(
            max_depth=2,
            class_sla_s=10.0,
            clock=_frozen_clock(clock_seq),
        )
        q.enqueue("a")  # clock pop 1: t0
        q.enqueue("b")  # clock pop 2: t0 + 4s
        # clock pop 3: t0 + 8.9s → oldest age 8.9s → ceil(10 - 8.9) = ceil(1.1) = 2
        assert q.compute_retry_after_s() == 2

    def test_retry_after_dynamic_aging_shrinks_as_time_passes(self):
        """Round-6 reviewer P2 regression: aged queue reports smaller
        retry_after_s than a fresh queue with the same SLA. Pins the
        backpressure-semantics fix."""
        t0 = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)
        # SLA 5s; oldest enqueued at t0; first compute at t0 + 0.1s,
        # second compute at t0 + 4.5s.
        clock_seq = [
            t0,
            t0 + timedelta(milliseconds=100),
            t0 + timedelta(seconds=4, milliseconds=500),
        ]
        q = BoundedQueue(
            max_depth=2,
            class_sla_s=5.0,
            clock=_frozen_clock(clock_seq),
        )
        q.enqueue("a")
        # Fresh: age ~0.1s; retry = ceil(4.9) = 5
        assert q.compute_retry_after_s() == 5
        # Aged 4.5s: age 4.5s; retry = ceil(0.5) = 1
        assert q.compute_retry_after_s() == 1

    def test_retry_after_clamped_minimum_one_second(self):
        """Don't tell clients to retry in 0 seconds; that's a hot loop."""
        t0 = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)
        # SLA 0.2s; oldest enqueued at t0; compute at t0 + 10s.
        clock_seq = [t0, t0 + timedelta(seconds=10)]
        q = BoundedQueue(
            max_depth=2,
            class_sla_s=0.200,
            clock=_frozen_clock(clock_seq),
        )
        q.enqueue("a")
        assert q.compute_retry_after_s() == 1


class TestConcurrencyCapsBounded:
    """Spec §4.5 — pinning regressions enforce *bounded* invariant
    (caps cannot be unbounded/negative/unset), NOT specific defaults."""

    def test_per_tenant_interactive_must_be_positive(self):
        with pytest.raises(ValueError, match="per_tenant_interactive"):
            ConcurrencyCaps(
                per_tenant_interactive=0,
                per_tenant_background=64,
                per_pack=8,
                per_actor=4,
            )

    def test_per_tenant_background_must_be_positive(self):
        with pytest.raises(ValueError, match="per_tenant_background"):
            ConcurrencyCaps(
                per_tenant_interactive=32,
                per_tenant_background=0,
                per_pack=8,
                per_actor=4,
            )

    def test_per_pack_must_be_positive(self):
        with pytest.raises(ValueError, match="per_pack"):
            ConcurrencyCaps(
                per_tenant_interactive=32,
                per_tenant_background=64,
                per_pack=0,
                per_actor=4,
            )

    def test_per_actor_must_be_positive(self):
        with pytest.raises(ValueError, match="per_actor"):
            ConcurrencyCaps(
                per_tenant_interactive=32,
                per_tenant_background=64,
                per_pack=8,
                per_actor=0,
            )

    def test_no_negative_caps(self):
        with pytest.raises(ValueError):
            ConcurrencyCaps(
                per_tenant_interactive=-1,
                per_tenant_background=64,
                per_pack=8,
                per_actor=4,
            )


class TestConcurrencyCapDecisions:
    def test_headroom_when_under_cap(self):
        caps = ConcurrencyCaps(
            per_tenant_interactive=2,
            per_tenant_background=2,
            per_pack=2,
            per_actor=2,
        )
        # All counts at 0; admission has headroom
        assert caps.has_headroom_for(
            class_="interactive", tenant_count=0, pack_count=0, actor_count=0
        )

    def test_no_headroom_at_tenant_interactive_cap(self):
        caps = ConcurrencyCaps(
            per_tenant_interactive=2,
            per_tenant_background=4,
            per_pack=4,
            per_actor=4,
        )
        assert not caps.has_headroom_for(
            class_="interactive", tenant_count=2, pack_count=0, actor_count=0
        )

    def test_no_headroom_at_pack_cap(self):
        caps = ConcurrencyCaps(
            per_tenant_interactive=4,
            per_tenant_background=4,
            per_pack=2,
            per_actor=4,
        )
        assert not caps.has_headroom_for(
            class_="interactive", tenant_count=0, pack_count=2, actor_count=0
        )

    def test_no_headroom_at_actor_cap(self):
        caps = ConcurrencyCaps(
            per_tenant_interactive=4,
            per_tenant_background=4,
            per_pack=4,
            per_actor=2,
        )
        assert not caps.has_headroom_for(
            class_="interactive", tenant_count=0, pack_count=0, actor_count=2
        )

    def test_background_class_uses_background_tenant_cap(self):
        """Per spec §4.5 — interactive and background tenant caps are separate axes."""
        caps = ConcurrencyCaps(
            per_tenant_interactive=2,
            per_tenant_background=4,
            per_pack=8,
            per_actor=8,
        )
        # background tenant cap is 4; count=3 still has headroom
        assert caps.has_headroom_for(
            class_="background", tenant_count=3, pack_count=0, actor_count=0
        )
        # background tenant cap is 4; count=4 at cap
        assert not caps.has_headroom_for(
            class_="background", tenant_count=4, pack_count=0, actor_count=0
        )

    def test_unknown_priority_class_refuses_fail_closed(self):
        caps = ConcurrencyCaps(
            per_tenant_interactive=2,
            per_tenant_background=4,
            per_pack=8,
            per_actor=8,
        )
        with pytest.raises(ValueError, match="class_"):
            caps.has_headroom_for(
                class_="urgent",  # type: ignore[arg-type]
                tenant_count=0,
                pack_count=0,
                actor_count=0,
            )

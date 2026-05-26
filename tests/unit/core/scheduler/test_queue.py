"""Spec §4.3 + §4.5 — bounded FIFO + concurrency caps + retry_after."""

import pytest

from cognic_agentos.core.scheduler.queue import (
    BoundedQueue,
    ConcurrencyCaps,
    QueueFull,
)


class TestBoundedQueueFIFO:
    def test_dequeue_returns_oldest(self):
        q = BoundedQueue(max_depth=4, class_sla_s=5.0)
        q.enqueue("a", oldest_age_s=1.0)
        q.enqueue("b", oldest_age_s=0.5)
        q.enqueue("c", oldest_age_s=0.2)
        assert q.dequeue() == "a"
        assert q.dequeue() == "b"
        assert q.dequeue() == "c"

    def test_enqueue_raises_QueueFull_at_max(self):
        q = BoundedQueue(max_depth=2, class_sla_s=5.0)
        q.enqueue("a", oldest_age_s=1.0)
        q.enqueue("b", oldest_age_s=0.5)
        with pytest.raises(QueueFull):
            q.enqueue("c", oldest_age_s=0.0)

    def test_depth_tracks_enqueue_dequeue(self):
        q = BoundedQueue(max_depth=4, class_sla_s=5.0)
        assert q.depth == 0
        q.enqueue("a", oldest_age_s=0.0)
        assert q.depth == 1
        q.dequeue()
        assert q.depth == 0


class TestRetryAfterCalculation:
    """Spec §4.3 case 3 — retry_after_s derived from oldest queued task's
    age + class SLA."""

    def test_retry_after_uses_oldest_age_plus_class_sla(self):
        q = BoundedQueue(max_depth=2, class_sla_s=10.0)
        q.enqueue("a", oldest_age_s=1.1)
        q.enqueue("b", oldest_age_s=9.0)
        # Oldest queued age = 1.1; SLA 10.0; retry_after = ceil(8.9)
        # even though the newer queued task is closer to the SLA.
        assert q.compute_retry_after_s() == 9

    def test_retry_after_clamped_minimum_one_second(self):
        """Don't tell clients to retry in 0 seconds; that's a hot loop."""
        q = BoundedQueue(max_depth=2, class_sla_s=0.200)
        q.enqueue("a", oldest_age_s=10.0)  # Already exceeded SLA
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

"""Sprint 3 T7 — per-profile concurrency primitive unit tests.

Critical-controls posture per AGENTS.md (``llm/concurrency.py``
feeds into the gateway's saturation-exit path; the per-profile
slot-count discipline is what makes ``LLMGateway.completion``
multi-tenant safe under load).

Test posture:

- Queued mode: ``acquire`` blocks until release. The ``cond.notify(1)``
  wake order is implementation-defined; tests assert "eventually wakes
  one waiter", not a hard FIFO promise.
- Fail-fast mode: ``acquire`` raises ``LLMConcurrencyExceeded``
  immediately when saturated.
- Per-profile isolation: tier1 saturation does NOT block tier2.
- Slot release on exception inside the async-with body.
- Round-8 reviewer-P2 atomicity proof: two complementary tests
  showing fail_fast cannot block on slot availability.
"""

from __future__ import annotations

import asyncio
from typing import Literal

import pytest

from cognic_agentos.llm.concurrency import (
    LLMConcurrencyExceeded,
    ProfileRateLimiter,
    _ProfileState,
)

# ---------------------------------------------------------------------------
# TestQueuedMode — block + eventual wake (no hard FIFO promise).
# ---------------------------------------------------------------------------


class TestQueuedMode:
    async def test_first_acquire_succeeds_immediately(self) -> None:
        limiter = ProfileRateLimiter(per_profile=1, mode="queued")
        async with limiter.acquire(profile="tier1"):
            pass  # held briefly; releases on exit

    async def test_capacity_is_respected(self) -> None:
        """``per_profile=2`` allows two concurrent acquires; the third
        waits until one releases."""
        limiter = ProfileRateLimiter(per_profile=2, mode="queued")
        held: list[str] = []

        async def hold(name: str, hold_time: float) -> None:
            async with limiter.acquire(profile="tier1"):
                held.append(name)
                await asyncio.sleep(hold_time)

        a = asyncio.create_task(hold("a", 0.1))
        b = asyncio.create_task(hold("b", 0.1))
        c = asyncio.create_task(hold("c", 0.0))
        await asyncio.sleep(0.05)
        # a + b started immediately; c is still waiting.
        assert sorted(held) == ["a", "b"]
        await asyncio.gather(a, b, c)
        # c eventually got in.
        assert sorted(held) == ["a", "b", "c"]

    async def test_saturated_acquire_blocks_until_release(self) -> None:
        """The next acquire after saturation does NOT raise — it
        blocks until a slot frees. Queued mode contract."""
        limiter = ProfileRateLimiter(per_profile=1, mode="queued")
        release = asyncio.Event()
        b_done = asyncio.Event()

        async def hold_a() -> None:
            async with limiter.acquire(profile="tier1"):
                await release.wait()  # hold until released

        async def take_b() -> None:
            async with limiter.acquire(profile="tier1"):
                b_done.set()

        a = asyncio.create_task(hold_a())
        await asyncio.sleep(0.05)  # let A take the slot
        b = asyncio.create_task(take_b())
        await asyncio.sleep(0.05)  # let B queue
        assert not b_done.is_set(), "B must be blocked while A holds"
        release.set()
        await asyncio.gather(a, b)
        assert b_done.is_set()


# ---------------------------------------------------------------------------
# TestFailFastMode — raise immediately on saturation.
# ---------------------------------------------------------------------------


class TestFailFastMode:
    async def test_first_acquire_succeeds(self) -> None:
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        async with limiter.acquire(profile="tier1"):
            pass

    async def test_saturated_acquire_raises_immediately(self) -> None:
        """Per ``mode="fail_fast"``: if saturated, raise — do NOT
        block. Inverse of queued mode."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        async with limiter.acquire(profile="tier1"):
            with pytest.raises(LLMConcurrencyExceeded):
                async with limiter.acquire(profile="tier1"):
                    pytest.fail("nested acquire must have raised, not entered")

    async def test_releases_after_fail_fast_does_not_double_count(self) -> None:
        """A fail_fast denial doesn't take a slot — after the rejected
        attempt, a fresh acquire still works."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        async with limiter.acquire(profile="tier1"):
            try:
                async with limiter.acquire(profile="tier1"):
                    pass
            except LLMConcurrencyExceeded:
                pass
        # First slot now released; another fail_fast acquire succeeds.
        async with limiter.acquire(profile="tier1"):
            pass

    async def test_error_carries_profile_name(self) -> None:
        """Operator-friendly diagnostic — the error message lists the
        profile that's saturated (Plan T6 logs this on the
        ``concurrency_exhausted`` ledger row)."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        async with limiter.acquire(profile="tier2"):
            with pytest.raises(LLMConcurrencyExceeded, match="tier2"):
                async with limiter.acquire(profile="tier2"):
                    pass


# ---------------------------------------------------------------------------
# TestPerProfileIsolation — tier1 saturation does NOT block tier2.
# ---------------------------------------------------------------------------


class TestPerProfileIsolation:
    async def test_tier1_saturation_does_not_block_tier2(self) -> None:
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        # tier1 saturated — but tier2 is independent. Both held
        # simultaneously to prove the per-profile isolation contract.
        async with (
            limiter.acquire(profile="tier1"),
            limiter.acquire(profile="tier2"),
        ):
            pass

    async def test_per_profile_capacity_is_independent(self) -> None:
        """``per_profile=2`` means each profile gets 2 slots, not 2
        slots shared."""
        limiter = ProfileRateLimiter(per_profile=2, mode="fail_fast")
        # Both tier1 slots taken — saturated. tier2 still has 2 slots,
        # both of which we'll also hold to exercise the independent
        # per-profile capacity. The third tier2 acquire then raises.
        async with (
            limiter.acquire(profile="tier1"),
            limiter.acquire(profile="tier1"),
            limiter.acquire(profile="tier2"),
            limiter.acquire(profile="tier2"),
        ):
            # tier2 saturated. tier3-on-tier2 raises.
            with pytest.raises(LLMConcurrencyExceeded):
                async with limiter.acquire(profile="tier2"):
                    pass


# ---------------------------------------------------------------------------
# TestExceptionReleasesSlot — async-with body exception still releases.
# ---------------------------------------------------------------------------


class TestExceptionReleasesSlot:
    async def test_exception_in_body_releases_slot(self) -> None:
        """If the gateway raises mid-flow (e.g. LedgerWriteFailed,
        guardrail trip, post-response policy denial), the slot must
        release. Otherwise saturated profiles would never recover."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")

        with pytest.raises(RuntimeError, match="boom"):
            async with limiter.acquire(profile="tier1"):
                raise RuntimeError("boom")

        # Slot released — fresh acquire succeeds.
        async with limiter.acquire(profile="tier1"):
            pass

    async def test_cancellation_releases_slot(self) -> None:
        """``asyncio.CancelledError`` inside the body propagates AND
        releases the slot."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        release = asyncio.Event()

        async def hold() -> None:
            async with limiter.acquire(profile="tier1"):
                await release.wait()

        task = asyncio.create_task(hold())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # Slot released — fresh acquire succeeds.
        async with limiter.acquire(profile="tier1"):
            pass


# ---------------------------------------------------------------------------
# TestFailFastIsAtomic — Round-8 reviewer-P2 load-bearing tests.
# ---------------------------------------------------------------------------


class TestFailFastIsAtomic:
    """Round-8 reviewer-P2 rewrite: two complementary tests that prove
    fail_fast never blocks on slot availability. Replaces the prior
    ``_PausingLimiter`` test which paused before the lock and could
    not pass as written."""

    async def test_fail_fast_raises_immediately_when_saturated(self) -> None:
        """Pre-fill the slot via the public ``acquire()`` context, then
        prove a nested fail_fast acquire raises immediately rather
        than blocking on the saturated slot.

        With a buggy check-then-await implementation this would
        block forever and pytest's test-level timeout would catch
        it. With the atomic shape it raises in microseconds."""
        limiter = ProfileRateLimiter(per_profile=1, mode="fail_fast")
        async with limiter.acquire(profile="tier1"):
            # Slot saturated. Worker B must raise immediately — NOT block.
            with pytest.raises(LLMConcurrencyExceeded):
                await limiter._take_slot_or_raise("tier1")
        # Slot released; a fresh acquire should now succeed.
        async with limiter.acquire(profile="tier1"):
            pass

    async def test_fail_fast_no_race_under_concurrent_arrival(self) -> None:
        """Two contenders released simultaneously through a barrier;
        exactly one wins the slot, the other raises
        LLMConcurrencyExceeded. The atomic per-profile Lock
        serialises the (check, increment) critical section; the
        loser sees in_flight == capacity and raises without blocking
        on slot availability (only a brief microsecond wait on the
        Lock itself)."""
        barrier = asyncio.Event()

        class _BarrierLimiter(ProfileRateLimiter):
            async def _take_slot_or_raise(self, profile: str) -> _ProfileState:
                await barrier.wait()  # both contenders queue here
                return await super()._take_slot_or_raise(profile)

        limiter = _BarrierLimiter(per_profile=1, mode="fail_fast")

        async def contend() -> None:
            async with limiter.acquire(profile="tier1"):
                await asyncio.sleep(0.05)  # hold briefly so the loser sees saturation

        a = asyncio.create_task(contend())
        b = asyncio.create_task(contend())
        await asyncio.sleep(0.05)  # let both queue at the barrier
        barrier.set()  # release both simultaneously

        results = await asyncio.gather(a, b, return_exceptions=True)
        succeeded = [r for r in results if r is None]
        raised = [r for r in results if isinstance(r, LLMConcurrencyExceeded)]
        assert len(succeeded) == 1, f"expected exactly one winner; got {results}"
        assert len(raised) == 1, f"expected exactly one fail_fast denial; got {results}"


# ---------------------------------------------------------------------------
# TestConstructorContract — mode + per_profile validation.
# ---------------------------------------------------------------------------


class TestConstructorContract:
    @pytest.mark.parametrize("mode", ["queued", "fail_fast"])
    async def test_both_modes_accepted(self, mode: Literal["queued", "fail_fast"]) -> None:
        limiter = ProfileRateLimiter(per_profile=1, mode=mode)
        async with limiter.acquire(profile="tier1"):
            pass

    # T7 review reviewer-P1: constructor must enforce both invariants.
    # Without these guards, per_profile=0 deadlocks queued acquires
    # forever (the ``while in_flight >= capacity`` loop with capacity=0
    # never exits) and an invalid mode silently falls through to queued
    # behaviour because ``_take_slot_or_raise`` only special-cases
    # ``"fail_fast"``.

    def test_per_profile_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="per_profile must be >= 1"):
            ProfileRateLimiter(per_profile=0, mode="fail_fast")

    def test_per_profile_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="per_profile must be >= 1"):
            ProfileRateLimiter(per_profile=-1, mode="fail_fast")

    def test_unknown_mode_rejected(self) -> None:
        """An unknown mode must raise at construction, not silently
        behave as queued. The ``# type: ignore`` bypasses mypy's
        Literal narrowing — runtime callers passing through
        ``cast``/``Settings`` aren't always typed-strict, and the
        constructor must reject the bad input regardless of how it
        slipped past static checking."""
        with pytest.raises(ValueError, match="mode must be"):
            ProfileRateLimiter(per_profile=1, mode="spinwait")  # type: ignore[arg-type]

    def test_empty_mode_rejected(self) -> None:
        with pytest.raises(ValueError, match="mode must be"):
            ProfileRateLimiter(per_profile=1, mode="")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestExceptionType — LLMConcurrencyExceeded shape.
# ---------------------------------------------------------------------------


class TestLLMConcurrencyExceeded:
    def test_subclasses_runtime_error(self) -> None:
        """Generic 500-handlers + the gateway's outer-catch path both
        depend on this — RuntimeError parentage means the gateway's
        ``except LLMConcurrencyExceeded:`` matches before the
        catch-all ``except Exception``."""
        assert issubclass(LLMConcurrencyExceeded, RuntimeError)

    def test_construction_carries_message(self) -> None:
        err = LLMConcurrencyExceeded("tier1 saturated")
        assert "tier1 saturated" in str(err)

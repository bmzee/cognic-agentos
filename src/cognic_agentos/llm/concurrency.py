"""Per-profile concurrency primitive (Sprint 3 T7).

Layer classification: **platform primitive** (operational; feeds
into the gateway's saturation-exit path per AGENTS.md §"LLM gateway").

Two modes:

- ``queued``: the next acquire after saturation BLOCKS via an
  ``asyncio.Condition`` until a slot frees. ``release`` calls
  ``cond.notify(1)`` which wakes ONE waiter; the wake order is
  implementation-defined (CPython's ``asyncio.Condition`` happens to
  use a ``deque`` for waiters today, but the contract is "eventually
  wakes one waiter" — NOT a hard FIFO promise).
- ``fail_fast``: the next acquire after saturation RAISES
  :class:`LLMConcurrencyExceeded` immediately, without blocking.

Atomicity (Round-8 reviewer-P2 of the Sprint-3 plan): a per-profile
``asyncio.Lock`` guards the ``(in_flight, capacity)`` pair so the
"is there a slot?" check + "take a slot" mutation are a single
critical section. A naive ``asyncio.Semaphore.locked()`` check
plus ``await acquire()`` has a race window where another
coroutine takes the last slot between the check and the await,
causing fail_fast to block instead of raising — the exact bug the
plan's Round-1 review caught.

Per-profile isolation: tier1 saturation does NOT block tier2.
``per_profile=N`` means each profile gets its own N-slot pool, not
N slots shared.

References:
- Plan Decision-Locking §3 (gateway flow integrates this primitive
  via ``async with self._rate_limiter.acquire(profile=tier):``).
- Plan T7 Step 3 (atomic check-and-take per Round-8 reviewer-P2
  rewrite).
- ADR-007 (Provider-Honesty Enforcement — saturation evidence
  flows into the ``concurrency_exhausted`` ledger row).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import Literal


class LLMConcurrencyExceeded(RuntimeError):
    """Raised when a fail_fast ``acquire`` finds no slot available.

    Subclass of :class:`RuntimeError` so generic 500-handlers still
    trip on it. The gateway's outer ``except LLMConcurrencyExceeded:``
    matches before the catch-all ``except Exception:`` so the
    saturation path lands the right ledger outcome
    (``concurrency_exhausted``).
    """


class _ProfileState:
    """Per-profile slot accounting + the lock that guards it.

    ``__slots__`` keeps the per-profile memory footprint tight; the
    limiter creates one of these per distinct profile name on first
    use.
    """

    __slots__ = ("capacity", "cond", "in_flight", "lock")

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.in_flight = 0
        self.lock = asyncio.Lock()
        # Condition shares ``self.lock`` — when a queued waiter wakes
        # up via ``cond.wait()``, it holds the lock + can re-check
        # the predicate atomically before incrementing in_flight.
        self.cond = asyncio.Condition(self.lock)


class ProfileRateLimiter:
    """Per-profile concurrency primitive.

    Constructor takes ``per_profile`` (slot count, ≥1) and
    ``mode`` (``"queued"`` | ``"fail_fast"``). Profile names are
    arbitrary strings; the gateway uses ``"tier1"`` / ``"tier2"``
    matching the :class:`Tier` literal in :mod:`cognic_agentos.llm.gateway`.
    """

    def __init__(
        self,
        *,
        per_profile: int,
        mode: Literal["queued", "fail_fast"],
    ) -> None:
        # T7 review reviewer-P1: validate at construction. ``Settings``
        # already constrains the production path (``ge=1`` on the
        # capacity field; Literal-typed mode), but this primitive is
        # also constructable directly by tests + future callers, so
        # the guard belongs here too. Without it, ``per_profile=0``
        # would make queued acquires wait forever (the
        # ``while in_flight >= capacity`` loop never exits because
        # capacity is 0); an invalid ``mode`` would silently fall
        # through to queued behaviour because ``_take_slot_or_raise``
        # only special-cases ``"fail_fast"``.
        if per_profile < 1:
            raise ValueError(f"per_profile must be >= 1; got {per_profile!r}")
        if mode not in ("queued", "fail_fast"):
            raise ValueError(f"mode must be 'queued' or 'fail_fast'; got {mode!r}")
        self._capacity = per_profile
        self._mode = mode
        self._state: dict[str, _ProfileState] = {}
        # Guards ``_state`` dict membership — the dict insertion on
        # first-seen profile is the only place we have a non-per-
        # profile critical section.
        self._table_lock = asyncio.Lock()

    async def _state_for(self, profile: str) -> _ProfileState:
        async with self._table_lock:
            if profile not in self._state:
                self._state[profile] = _ProfileState(self._capacity)
            return self._state[profile]

    async def _take_slot_or_raise(self, profile: str) -> _ProfileState:
        """Acquire a slot for ``profile``. Atomically checks +
        increments ``in_flight`` under the per-profile lock so a
        fail_fast caller cannot block on slot availability."""
        st = await self._state_for(profile)
        async with st.lock:
            if self._mode == "fail_fast":
                if st.in_flight >= st.capacity:
                    raise LLMConcurrencyExceeded(
                        f"profile {profile!r} saturated (in_flight={st.in_flight}/{st.capacity})"
                    )
                st.in_flight += 1
                return st
            # queued mode: wait via condition until a slot frees.
            # ``cond.wait()`` releases the lock while waiting + re-
            # acquires it on wake; the ``while`` loop guards against
            # spurious wake-ups + the case where a different waiter
            # took the slot first.
            while st.in_flight >= st.capacity:
                await st.cond.wait()
            st.in_flight += 1
            return st

    async def _release_slot(self, st: _ProfileState) -> None:
        """Decrement ``in_flight`` + notify one waiter. Must run
        under ``st.lock`` so the decrement + notify are atomic with
        respect to any concurrent ``_take_slot_or_raise`` call.
        ``cond.notify(1)`` is a no-op when no waiters are queued —
        fail_fast mode never queues waiters, so this just decrements."""
        async with st.lock:
            st.in_flight -= 1
            st.cond.notify(1)

    @contextlib.asynccontextmanager
    async def acquire(self, *, profile: str) -> AsyncIterator[None]:
        """Acquire one slot for ``profile``; release on context exit.

        Raises :class:`LLMConcurrencyExceeded` in ``fail_fast`` mode
        when saturated. Blocks in ``queued`` mode. The slot is
        released even when the body raises (including
        :class:`asyncio.CancelledError`) — the gateway's mid-flow
        exceptions (LedgerWriteFailed, GuardrailViolationError, etc.)
        all rely on this.
        """
        st = await self._take_slot_or_raise(profile)
        try:
            yield
        finally:
            await self._release_slot(st)


__all__ = ("LLMConcurrencyExceeded", "ProfileRateLimiter")

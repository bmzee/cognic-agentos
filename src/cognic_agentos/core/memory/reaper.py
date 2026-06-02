"""Sprint 11.5b T7 — MemoryTombstoneReaper background sweep loop.

NOT-CC per Doctrine F (thin orchestration; the substantive retention
enforcement lives in the on-gate ``MemoryAdapter.purge_expired()``
from T4). This module wraps the adapter's per-sweep behaviour with
the asyncio loop semantics that the AgentOS app lifespan needs:

* ``run_once()`` — single sweep; delegates to
  ``MemoryAdapter.purge_expired(tombstone_window_s=settings.memory_tombstone_window_s)``
  + returns its purge count. Exceptions are caught + logged at ERROR
  and the method returns 0 so the loop survives a flaky DB blip
  without taking the reaper down for the process lifetime.
  ``asyncio.CancelledError`` is NOT caught — it MUST propagate so
  ``run_forever`` can shut down cleanly.
* ``run_forever()`` — asyncio loop calling ``run_once()`` every
  ``settings.memory_reaper_interval_s`` (default 300 s per ADR-019
  / Sprint 11.5b). Started by the AgentOS app lifespan (T7); cancelled
  cleanly on shutdown via ``asyncio.CancelledError`` propagating
  through ``asyncio.sleep``.

Mirrors ``sandbox/reaper.CheckpointReaper`` exactly. The pattern is:
CancelledError propagates; any other sweep error is logged + the loop
continues. Bank-grade consecutive-failure alerting lives at the
observability layer (future sprint).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cognic_agentos.core.memory.storage import MemoryAdapter

logger = logging.getLogger(__name__)


class _MemoryReaperSettings(Protocol):
    """Narrow structural Protocol — the reaper reads exactly two fields."""

    memory_tombstone_window_s: int
    memory_reaper_interval_s: int


class MemoryTombstoneReaper:
    """Single-instance asyncio reaper over the on-gate
    ``MemoryAdapter.purge_expired()``.

    Lifecycle owned by the AgentOS app lifespan (opt-in)::

        reaper = MemoryTombstoneReaper(adapter=..., settings=...)
        task = asyncio.create_task(reaper.run_forever())
        try:
            yield  # app lifetime
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    Construction is keyword-only because both args are required + the
    positional shape would silently swap on a future refactor.
    Mirrors ``CheckpointReaper`` from ``sandbox/reaper.py``.
    """

    def __init__(
        self,
        *,
        adapter: MemoryAdapter,
        settings: _MemoryReaperSettings,
    ) -> None:
        self._adapter = adapter
        self._settings = settings

    async def run_once(self) -> int:
        """Single sweep — delegates to ``MemoryAdapter.purge_expired()``.

        Returns the count of purged tombstones. Exceptions are caught
        + logged at ERROR + return 0 — the loop continues per the
        module docstring's flaky-DB-blip rationale. The
        ``asyncio.CancelledError`` path is NOT caught (it MUST
        propagate so ``run_forever`` can shut down cleanly).
        """
        try:
            return await self._adapter.purge_expired(
                tombstone_window_s=self._settings.memory_tombstone_window_s
            )
        except asyncio.CancelledError:
            # NEVER swallow cancellation — the loop owner needs the
            # signal to short-circuit the sweep + shut down.
            raise
        except Exception:
            logger.exception(
                "MemoryTombstoneReaper sweep failed; loop continues to the next interval."
            )
            return 0

    async def run_forever(self) -> None:
        """Asyncio loop calling ``run_once()`` every
        ``settings.memory_reaper_interval_s``.

        Started by the AgentOS app lifespan (T7); cancelled on
        shutdown. The ``asyncio.sleep`` inside the loop is the
        cancellation point — propagating ``asyncio.CancelledError``
        out of ``run_forever`` lets the app lifespan confirm clean
        shutdown (no zombie task lingering past process exit).
        """
        interval = self._settings.memory_reaper_interval_s
        while True:
            await self.run_once()
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                logger.info("MemoryTombstoneReaper.run_forever cancelled — clean shutdown")
                raise


__all__ = ["MemoryTombstoneReaper"]

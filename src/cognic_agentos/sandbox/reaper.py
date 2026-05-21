"""Sprint 8.5 T4 — CheckpointReaper background sweep loop.

NOT-CC per Doctrine F (thin orchestration; substantive enforcement
lives in the on-gate ``CheckpointStore.purge_expired()`` from T3).
This module wraps the store's per-sweep behaviour with the asyncio
loop semantics that the AgentOS app lifespan needs:

* ``run_once()`` — single sweep; delegates to
  ``CheckpointStore.purge_expired()`` + returns its purge count.
  Surfaces in observability metrics so operators can see how many
  checkpoints each sweep cleaned up.
* ``run_forever()`` — asyncio loop calling ``run_once()`` every
  ``settings.sandbox_reaper_interval_s`` (default 300 s = 5 min per
  spec §6). Started by the AgentOS app lifespan at T10; cancelled
  cleanly on shutdown via ``asyncio.CancelledError`` propagating
  through ``asyncio.sleep``.

Per spec §13: Sprint 8.5 ships a SINGLE-INSTANCE background reaper
(asyncio task) per AgentOS process. Multi-instance AgentOS
deployments running parallel reapers without coordination would
race:

* **Storage-delete is idempotent.** The underlying
  ``ObjectStoreAdapter.delete`` no-ops (or raises a typed
  ``RetentionWindowActiveError`` that the store catches) on a
  second delete of the same key. Bytes-level correctness is
  preserved — no half-deleted state, no orphaned snapshots.
* **Audit-row dedup is NOT enforced** by
  ``DecisionHistoryStore.append_with_precondition``. The
  precondition serialises chain writes via the chain-head ``FOR
  UPDATE`` lock — it guarantees ORDERING + hash-chain integrity,
  but it does NOT dedupe by content. Two reapers racing on the
  same listed ``checkpoint_id`` will produce TWO ``sandbox.lifecycle.
  checkpoint_purged`` chain rows (different ``record_id``s, same
  ``checkpoint_id`` + ``purge_reason``) — the chain stays valid
  + verifiable, but examiners see duplicate purge events for the
  same operator-meaningful action.

The pre-T4-r1 docstring in this module overclaimed full audit
idempotency. The same overclaim appears in spec §1 ("audit row
idempotency is achieved via per-checkpoint-id
append-with-precondition") and is a known spec drift; a later
spec amendment should correct it. For Sprint 8.5: deployments
SHOULD run exactly one reaper per shared object-store backend.
Cross-instance leader election is deferred to Sprint 10.5 (the
scheduler primitive is the natural coordination point); a tighter
in-store idempotency-key precondition on ``purge_by_id`` is an
alternative future path.

Exception handling: a sweep raising any exception is logged at
ERROR + the loop continues. This is the deliberate trade-off — a
flaky filesystem / network blip should NOT take the reaper down for
the lifetime of the AgentOS process. Bank-grade fail-loud reporting
for repeated reaper failures lives at the observability layer
(future sprint adds a ``sandbox_reaper_consecutive_failures``
metric); operators see structured exception logs in the meantime.

The asyncio.CancelledError path is NOT swallowed — it propagates
out of ``run_forever`` so the app lifespan can confirm clean
shutdown (no zombie reaper task lingering past the process boundary).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.sandbox.checkpoint_store import (
        CheckpointStore,
        _CheckpointSettings,
    )


logger = logging.getLogger(__name__)


class CheckpointReaper:
    """Single-instance asyncio reaper around ``CheckpointStore.purge_expired()``.

    Per spec §4.2 — the reaper IS the retention-floor enforcement
    point (NOT the WORM ``ObjectStoreAdapter.retention_seconds``
    lock, which has incompatible semantics per spec §4.1 P1.r3). The
    store's ``purge_expired()`` reads each checkpoint's
    ``metadata.retention_window_s`` + compares against
    ``now - metadata.created_at``; this loop just drives the schedule.

    Lifecycle is owned by the AgentOS app lifespan (T10):

        reaper = CheckpointReaper(checkpoint_store=..., settings=...)
        task = asyncio.create_task(reaper.run_forever())
        try:
            yield  # app lifetime
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    Construction is keyword-only because both args are required + the
    positional shape would silently swap on a future refactor that
    reorders the Settings + Store fields. Same convention as the
    Sprint 8A backends (see ``DockerSiblingSandboxBackend.__init__``).
    """

    def __init__(
        self,
        *,
        checkpoint_store: CheckpointStore,
        settings: _CheckpointSettings,
    ) -> None:
        self._store = checkpoint_store
        self._settings = settings

    async def run_once(self) -> int:
        """Single sweep — delegates to ``CheckpointStore.purge_expired()``.

        Returns the count of purged checkpoints. Exceptions are caught
        + logged at ERROR + return 0 — the loop continues per the
        module docstring's flaky-filesystem rationale. The
        ``asyncio.CancelledError`` path is NOT caught (it MUST
        propagate so ``run_forever`` can shut down cleanly).
        """
        try:
            return await self._store.purge_expired()
        except asyncio.CancelledError:
            # NEVER swallow cancellation — the loop owner needs the
            # signal to short-circuit the sweep + shut down.
            raise
        except Exception:
            logger.exception(
                "CheckpointReaper sweep failed; loop continues to next "
                "interval. Bank-grade consecutive-failure alerting "
                "lives at the observability layer (future sprint)."
            )
            return 0

    async def run_forever(self) -> None:
        """Asyncio loop calling ``run_once()`` every
        ``settings.sandbox_reaper_interval_s``.

        Started by the AgentOS app lifespan (T10); cancelled on
        shutdown. The ``asyncio.sleep`` inside the loop is the
        cancellation point — propagating ``asyncio.CancelledError``
        out of ``run_forever`` lets the app lifespan confirm clean
        shutdown (no zombie task lingering past process exit).
        """
        interval = self._settings.sandbox_reaper_interval_s
        while True:
            await self.run_once()
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                logger.info("CheckpointReaper.run_forever cancelled — clean shutdown")
                raise


__all__ = ["CheckpointReaper"]

"""Sprint 8.5 T4 — CheckpointReaper orchestration tests.

The substantive retention-floor enforcement lives in the on-gate
``CheckpointStore.purge_expired()`` (T3); these tests pin ONLY the
thin orchestration surface T4 adds:

* ``run_once()`` correctly delegates to
  ``CheckpointStore.purge_expired()`` + returns its count.
* ``run_once()`` catches non-cancellation exceptions + returns 0
  (loop survives flaky-filesystem blips per the module docstring).
* ``run_once()`` re-raises ``asyncio.CancelledError`` (NEVER
  swallow — loop owner needs the signal).
* ``run_forever()`` loops with ``settings.sandbox_reaper_interval_s``
  cadence between sweeps.
* ``run_forever()`` is cancellable (clean ``asyncio.CancelledError``
  propagation; no zombie task).
* Idempotency: a second sweep with no new state purges zero.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox.reaper import CheckpointReaper

# ---------------------------------------------------------------------------
# Test helpers — mock CheckpointStore + Settings stub.
# ---------------------------------------------------------------------------


def _make_store_mock(*, purge_returns: int | BaseException = 0) -> AsyncMock:
    """Mock CheckpointStore exposing ``purge_expired`` only — the only
    method the reaper touches. ``purge_returns`` is either an int
    (return value) or a ``BaseException`` instance (side_effect).

    Note: the type is ``BaseException`` NOT ``Exception`` so the
    helper handles ``asyncio.CancelledError`` correctly. In Python
    3.8+, ``CancelledError`` inherits from ``BaseException`` directly
    (intentional design — async cancellation MUST not be swallowed by
    generic ``except Exception`` blocks); without the BaseException
    check, ``isinstance(CancelledError(), Exception)`` is False and
    the mock would silently store the exception as a return value
    instead of raising it as a side effect.
    """
    store = AsyncMock()
    if isinstance(purge_returns, BaseException):
        store.purge_expired.side_effect = purge_returns
    else:
        store.purge_expired.return_value = purge_returns
    return store


def _make_settings(interval_s: int = 300) -> MagicMock:
    """Stub object structurally conforming to ``_CheckpointSettings``
    Protocol — only the field the reaper reads is exposed."""
    settings = MagicMock()
    settings.sandbox_reaper_interval_s = interval_s
    return settings


# ---------------------------------------------------------------------------
# run_once() — delegation + exception handling
# ---------------------------------------------------------------------------


class TestRunOnceDelegatesToStore:
    """The thin orchestration contract: run_once just forwards to the
    store's purge_expired() + returns its count."""

    async def test_run_once_returns_purge_expired_count(self) -> None:
        store = _make_store_mock(purge_returns=7)
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings())

        result = await reaper.run_once()

        assert result == 7
        store.purge_expired.assert_awaited_once_with()

    async def test_run_once_returns_zero_when_nothing_purged(self) -> None:
        """Idempotency: a sweep with nothing to purge returns 0
        cleanly; subsequent sweeps remain stable.
        """
        store = _make_store_mock(purge_returns=0)
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings())

        first = await reaper.run_once()
        second = await reaper.run_once()

        assert first == 0
        assert second == 0
        assert store.purge_expired.await_count == 2


class TestRunOnceHandlesExceptions:
    """Per the module docstring: a sweep raising any exception (NOT
    CancelledError) is logged at ERROR + the loop continues. The
    loop-survives-flaky-filesystem trade-off is deliberate; this
    class pins it."""

    async def test_run_once_catches_runtime_exception_and_returns_zero(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        store = _make_store_mock(purge_returns=RuntimeError("flaky FS"))
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings())

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.sandbox.reaper"):
            result = await reaper.run_once()

        assert result == 0
        # Exception logged at ERROR with structured context.
        assert any("CheckpointReaper sweep failed" in rec.message for rec in caplog.records)

    @pytest.mark.parametrize(
        "exc",
        [
            ValueError("malformed payload at sweep time"),
            OSError("disk read failed"),
            KeyError("missing metadata key"),
        ],
    )
    async def test_run_once_catches_diverse_exception_types(
        self, exc: Exception, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Catch-all is intentional per the module docstring — the
        loop MUST survive any underlying-store failure mode (the
        observability-layer aggregator at a future sprint surfaces
        consecutive-failure alerting).
        """
        store = _make_store_mock(purge_returns=exc)
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings())

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.sandbox.reaper"):
            result = await reaper.run_once()

        assert result == 0

    async def test_run_once_does_not_swallow_cancelled_error(self) -> None:
        """``asyncio.CancelledError`` MUST propagate so ``run_forever``
        can shut down cleanly. Loop owner needs the signal to short-
        circuit the sweep + exit the loop.
        """
        store = _make_store_mock(purge_returns=asyncio.CancelledError())
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings())

        with pytest.raises(asyncio.CancelledError):
            await reaper.run_once()


# ---------------------------------------------------------------------------
# run_forever() — loop semantics + cancellation
# ---------------------------------------------------------------------------


class TestRunForeverLoopSemantics:
    """Pin that run_forever drives the schedule correctly + responds
    to cancellation."""

    async def test_run_forever_calls_run_once_repeatedly(self) -> None:
        """The loop fires sweeps on the configured interval.

        We use a very short interval (1 ms) + cancel after a brief
        delay so the loop has time to execute multiple sweeps;
        asserting `await_count >= 2` proves the loop drives the
        cadence rather than firing once and returning.
        """
        store = _make_store_mock(purge_returns=0)
        # 0.001 s = 1 ms so the loop fires many sweeps in ~50 ms.
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings(interval_s=0))

        task = asyncio.create_task(reaper.run_forever())
        # Let the loop run a few iterations.
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # At interval=0 the loop should fire many sweeps in 50 ms —
        # assert >= 2 conservatively (CI scheduling jitter).
        assert store.purge_expired.await_count >= 2

    async def test_run_forever_propagates_cancellation_cleanly(self) -> None:
        """Cancellation MUST propagate as ``asyncio.CancelledError``
        out of ``run_forever`` so the app lifespan can confirm the
        reaper task ended cleanly (no zombie task lingering past
        process exit).
        """
        store = _make_store_mock(purge_returns=0)
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings(interval_s=300))

        task = asyncio.create_task(reaper.run_forever())
        # Let the first sweep complete + loop hit asyncio.sleep().
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    async def test_run_forever_logs_cancellation_at_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Clean shutdown is INFO-logged per the module docstring."""
        store = _make_store_mock(purge_returns=0)
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings(interval_s=300))

        with caplog.at_level(logging.INFO, logger="cognic_agentos.sandbox.reaper"):
            task = asyncio.create_task(reaper.run_forever())
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert any("clean shutdown" in rec.message for rec in caplog.records)

    async def test_run_forever_uses_configured_interval(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pin that the loop reads ``settings.sandbox_reaper_interval_s``
        rather than hard-coding the interval. A regression that
        hard-coded 300s would let an operator-configured tighter
        cadence (e.g. 30s for testing) silently fall back to 300s.

        Patches ``asyncio.sleep`` (scoped to the reaper module via
        ``monkeypatch`` so it auto-reverts) to capture the interval
        value + raise ``CancelledError`` to terminate the loop after
        one iteration.
        """
        store = _make_store_mock(purge_returns=0)
        settings = _make_settings(interval_s=42)
        reaper = CheckpointReaper(checkpoint_store=store, settings=settings)

        captured_intervals: list[float] = []

        async def capture_then_cancel(delay: float) -> None:
            captured_intervals.append(delay)
            raise asyncio.CancelledError()

        # ``monkeypatch`` reverts at test teardown — no manual restore
        # needed, no zombie patch leaking into adjacent tests. Patches
        # the ``asyncio`` module attribute the reaper module uses; the
        # reaper imports asyncio at module top so this affects exactly
        # the call site we want to instrument.
        monkeypatch.setattr(asyncio, "sleep", capture_then_cancel)

        with pytest.raises(asyncio.CancelledError):
            await reaper.run_forever()

        assert captured_intervals == [42], (
            f"reaper MUST read settings.sandbox_reaper_interval_s; "
            f"captured intervals: {captured_intervals}"
        )

    async def test_run_forever_continues_loop_after_sweep_exception(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """If a sweep raises, the loop MUST continue to the next
        interval (per the module docstring's flaky-filesystem trade-
        off). A regression that lets the exception escape would take
        the reaper down for the rest of the process lifetime.
        """
        # Side-effect sequence: 1st sweep raises; subsequent sweeps
        # succeed (mimics a transient filesystem blip).
        store = AsyncMock()
        store.purge_expired.side_effect = [
            RuntimeError("transient FS blip"),
            3,
            5,
        ]
        reaper = CheckpointReaper(checkpoint_store=store, settings=_make_settings(interval_s=0))

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.sandbox.reaper"):
            task = asyncio.create_task(reaper.run_forever())
            await asyncio.sleep(0.05)  # ~50 ms; 3 sweeps fire
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        # All 3 side_effect entries were consumed — loop survived the
        # first exception + executed the 2nd + 3rd sweeps.
        assert store.purge_expired.await_count >= 3

"""Sprint 11.5b T7 — MemoryTombstoneReaper orchestration + lifespan wiring.

The substantive retention enforcement lives in the on-gate
``MemoryAdapter.purge_expired()`` (T4); these tests pin ONLY the thin
orchestration surface T7 adds:

* ``run_once()`` correctly delegates to ``MemoryAdapter.purge_expired()``
  + returns its count; tombstone_window_s is read from settings.
* ``run_once()`` catches non-cancellation exceptions + returns 0
  (loop survives flaky-DB blips per the module docstring).
* ``run_once()`` re-raises ``asyncio.CancelledError`` (NEVER swallow —
  loop owner needs the signal).
* ``run_forever()`` survives a failed sweep and continues to the next.
* ``run_forever()`` is cancellable (clean ``asyncio.CancelledError``
  propagation; no zombie task).
* App-lifespan wiring: when ``memory_reaper`` is provided to
  ``create_app``, the reaper starts as a background task + is
  cancelled cleanly on shutdown; when absent, no task is created and
  startup is silent.

Mirrors ``tests/unit/sandbox/test_reaper.py`` + the lifespan wiring
contract in ``tests/unit/sandbox/test_reaper_lifespan_wiring.py``.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.core.memory.reaper import MemoryTombstoneReaper

# ---------------------------------------------------------------------------
# Test helpers — stub adapter + settings
# ---------------------------------------------------------------------------


def _make_adapter(*, purge_returns: int | BaseException = 0) -> AsyncMock:
    """Minimal stub MemoryAdapter exposing ``purge_expired`` only —
    the only method the reaper touches. ``purge_returns`` is either
    an int (return value) or a ``BaseException`` instance (side_effect).

    Note: type is ``BaseException`` NOT ``Exception`` so the helper
    handles ``asyncio.CancelledError`` correctly (inherits BaseException
    in Python 3.8+; pure ``Exception`` check misses it)."""
    adapter = AsyncMock()
    if isinstance(purge_returns, BaseException):
        adapter.purge_expired.side_effect = purge_returns
    else:
        adapter.purge_expired.return_value = purge_returns
    return adapter


def _make_settings(
    *, tombstone_window_s: int = 2_592_000, interval_s: int = 300
) -> SimpleNamespace:
    """Stub conforming to ``_MemoryReaperSettings`` Protocol — only the
    two fields the reaper reads are exposed."""
    return SimpleNamespace(
        memory_tombstone_window_s=tombstone_window_s,
        memory_reaper_interval_s=interval_s,
    )


# ---------------------------------------------------------------------------
# Pin 1 — run_once delegates exactly once + returns count + correct kwarg
# ---------------------------------------------------------------------------


class TestRunOnceDelegates:
    """run_once() is a thin forwarding layer: delegate once, return count,
    pass tombstone_window_s from settings."""

    async def test_run_once_returns_purge_count(self) -> None:
        adapter = _make_adapter(purge_returns=7)
        settings = _make_settings(tombstone_window_s=86400)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=settings)

        result = await reaper.run_once()

        assert result == 7

    async def test_run_once_calls_adapter_exactly_once(self) -> None:
        adapter = _make_adapter(purge_returns=3)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings())

        await reaper.run_once()

        adapter.purge_expired.assert_awaited_once()

    async def test_run_once_passes_correct_tombstone_window_s(self) -> None:
        """tombstone_window_s is read from settings, not hard-coded."""
        adapter = _make_adapter(purge_returns=0)
        settings = _make_settings(tombstone_window_s=777)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=settings)

        await reaper.run_once()

        adapter.purge_expired.assert_awaited_once_with(tombstone_window_s=777)

    async def test_run_once_returns_zero_when_nothing_purged(self) -> None:
        adapter = _make_adapter(purge_returns=0)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings())

        result = await reaper.run_once()

        assert result == 0


# ---------------------------------------------------------------------------
# Pin 2 — run_once swallows ordinary errors → returns 0
# ---------------------------------------------------------------------------


class TestRunOnceHandlesExceptions:
    """Per the module docstring: any non-cancellation exception is logged
    at ERROR + run_once returns 0 so the loop survives DB blips."""

    async def test_run_once_catches_runtime_error_returns_zero(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        adapter = _make_adapter(purge_returns=RuntimeError("flaky DB"))
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings())

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.core.memory.reaper"):
            result = await reaper.run_once()

        assert result == 0
        assert any("MemoryTombstoneReaper sweep failed" in rec.message for rec in caplog.records)

    @pytest.mark.parametrize(
        "exc",
        [
            ValueError("bad payload"),
            OSError("connection refused"),
            KeyError("missing field"),
        ],
    )
    async def test_run_once_catches_diverse_exception_types(
        self, exc: Exception, caplog: pytest.LogCaptureFixture
    ) -> None:
        adapter = _make_adapter(purge_returns=exc)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings())

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.core.memory.reaper"):
            result = await reaper.run_once()

        assert result == 0


# ---------------------------------------------------------------------------
# Pin 3 — CancelledError is NOT swallowed
# ---------------------------------------------------------------------------


class TestRunOnceCancelledError:
    """asyncio.CancelledError MUST propagate — the loop owner needs the
    signal to shut down cleanly."""

    async def test_run_once_reraises_cancelled_error(self) -> None:
        adapter = _make_adapter(purge_returns=asyncio.CancelledError())
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings())

        with pytest.raises(asyncio.CancelledError):
            await reaper.run_once()


# ---------------------------------------------------------------------------
# Pin 4 — run_forever survives one failed sweep and continues
# ---------------------------------------------------------------------------


class TestRunForeverSurvivesSweepFailure:
    """The loop MUST NOT die on a sweep exception — that would take the
    reaper down for the lifetime of the process on a transient DB blip."""

    async def test_run_forever_continues_after_failed_sweep(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """STATEFUL: drives the real loop.

        Side-effect sequence: 1st sweep raises RuntimeError (simulates
        transient DB blip); 2nd + 3rd sweeps succeed. Interval=0 so the
        loop fires fast in a test context. Assert ≥ 2 adapter calls
        so we KNOW the loop survived the 1st failure and fired again."""
        adapter = AsyncMock()
        adapter.purge_expired.side_effect = [
            RuntimeError("transient DB blip"),
            5,
            3,
        ]
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings(interval_s=0))

        with caplog.at_level(logging.ERROR, logger="cognic_agentos.core.memory.reaper"):
            task = asyncio.create_task(reaper.run_forever())
            await asyncio.sleep(0.05)  # ~50 ms — 3 sweeps fire at interval=0
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        # All 3 side_effect entries consumed — loop survived 1st failure + fired 2nd + 3rd
        assert adapter.purge_expired.await_count >= 2
        # The failed sweep was logged
        assert any("MemoryTombstoneReaper sweep failed" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Pin 5 — cancellation stops cleanly without leaking
# ---------------------------------------------------------------------------


class TestRunForeverCancellation:
    """Cancellation MUST propagate as asyncio.CancelledError; task MUST be
    done after awaiting (no zombie)."""

    async def test_run_forever_propagates_cancellation_cleanly(self) -> None:
        adapter = _make_adapter(purge_returns=0)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings(interval_s=300))

        task = asyncio.create_task(reaper.run_forever())
        # Let the first sweep complete + loop hit asyncio.sleep
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert task.done(), "No zombie task must survive cancellation"

    async def test_run_forever_logs_cancellation_at_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        adapter = _make_adapter(purge_returns=0)
        reaper = MemoryTombstoneReaper(adapter=adapter, settings=_make_settings(interval_s=300))

        with caplog.at_level(logging.INFO, logger="cognic_agentos.core.memory.reaper"):
            task = asyncio.create_task(reaper.run_forever())
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert any("clean shutdown" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# Pin 6 — app-lifespan opt-in (REAL lifespan test)
# ---------------------------------------------------------------------------


class _StubMemoryAdapter:
    """Minimal MemoryAdapter stub — the reaper only calls purge_expired().
    Records sweeps + sets an asyncio.Event so the test can prove the
    reaper genuinely STARTED (a task created but never run is a silent
    wiring regression)."""

    def __init__(self) -> None:
        self.sweep_count = 0
        self.swept = asyncio.Event()

    async def purge_expired(self, *, tombstone_window_s: int) -> int:
        self.sweep_count += 1
        self.swept.set()
        return 0


class TestAppLifespanOptIn:
    """Pin the lifespan wiring contract:

    * when ``memory_reaper`` is provided to ``create_app``, the reaper
      starts as a background asyncio task AND actually begins sweeping;
    * on app shutdown the task is cancelled + awaited cleanly (no zombie);
    * when ``memory_reaper`` is absent (None), NO memory-reaper task is
      created, startup succeeds, and the app is SILENT (no warning emitted).
    """

    def _build_reaper(self) -> tuple[MemoryTombstoneReaper, _StubMemoryAdapter]:
        from cognic_agentos.core.config import Settings

        adapter = _StubMemoryAdapter()
        settings = Settings(_env_file=None, runtime_profile="prod")  # type: ignore[call-arg]
        reaper = MemoryTombstoneReaper(
            adapter=cast("object", adapter),  # type: ignore[arg-type]
            settings=settings,
        )
        return reaper, adapter

    async def test_lifespan_starts_reaper_when_provided(self) -> None:
        """When memory_reaper kwarg is supplied, startup creates EXACTLY
        ONE memory-reaper background task and the reaper begins sweeping."""
        from cognic_agentos.core.config import Settings
        from cognic_agentos.portal.api.app import create_app

        reaper, adapter = self._build_reaper()
        settings = Settings(_env_file=None, runtime_profile="prod")  # type: ignore[call-arg]
        app = create_app(settings, memory_reaper=reaper)

        async with app.router.lifespan_context(app):
            task = app.state.memory_reaper_task
            assert isinstance(task, asyncio.Task)
            assert not task.done()
            # Prove the reaper genuinely began sweeping — not just that a task was created
            await asyncio.wait_for(adapter.swept.wait(), timeout=2.0)
            assert adapter.sweep_count >= 1

    async def test_lifespan_cancels_reaper_on_shutdown(self) -> None:
        """Shutdown cancels + awaits the reaper task. A cancelled task
        proves CancelledError propagated to the task boundary cleanly —
        no zombie task lingers past the lifespan."""
        from cognic_agentos.core.config import Settings
        from cognic_agentos.portal.api.app import create_app

        reaper, _ = self._build_reaper()
        settings = Settings(_env_file=None, runtime_profile="prod")  # type: ignore[call-arg]
        app = create_app(settings, memory_reaper=reaper)

        async with app.router.lifespan_context(app):
            task = app.state.memory_reaper_task
            assert isinstance(task, asyncio.Task)

        assert task.done()
        assert task.cancelled()

    async def test_no_reaper_task_when_absent(self, caplog: pytest.LogCaptureFixture) -> None:
        """The dev / test / pack-only path — create_app without memory_reaper.
        Startup MUST NOT fail, MUST NOT create a memory-reaper task, and
        MUST be SILENT (no warning log)."""
        from cognic_agentos.core.config import Settings
        from cognic_agentos.portal.api.app import create_app

        settings = Settings(_env_file=None, runtime_profile="prod")  # type: ignore[call-arg]
        app = create_app(settings)

        with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
            async with app.router.lifespan_context(app):
                task = app.state.memory_reaper_task
                assert task is None

        # NO warning emitted for absent memory_reaper (opt-in; pack-only deployments legitimate)
        memory_warnings = [r for r in caplog.records if "memory_reaper" in r.message.lower()]
        assert memory_warnings == [], (
            f"create_app without memory_reaper MUST be silent; "
            f"got: {[r.message for r in memory_warnings]}"
        )

    async def test_reaper_task_not_created_before_lifespan_startup(self) -> None:
        """The reaper task is created INSIDE the one-shot lifespan —
        never at app-construction time. Pre-startup app.state.memory_reaper_task
        is None even when a reaper IS wired."""
        from cognic_agentos.core.config import Settings
        from cognic_agentos.portal.api.app import create_app

        reaper, _ = self._build_reaper()
        settings = Settings(_env_file=None, runtime_profile="prod")  # type: ignore[call-arg]
        app = create_app(settings, memory_reaper=reaper)

        # No lifespan entered yet
        assert app.state.memory_reaper_task is None

        async with app.router.lifespan_context(app):
            assert isinstance(app.state.memory_reaper_task, asyncio.Task)

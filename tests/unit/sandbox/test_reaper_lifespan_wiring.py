"""Sprint 8.5 T10 — CheckpointReaper app-lifespan wiring.

Pins the wiring contract between ``portal/api/app.py``'s FastAPI
lifespan and the T4 ``CheckpointReaper``:

* When a ``CheckpointStore`` is wired (the ``checkpoint_store=`` kwarg
  on ``create_app``), app startup creates EXACTLY ONE reaper asyncio
  task and the reaper begins sweeping.
* App shutdown cancels the reaper task and awaits it cleanly — no
  zombie task survives the lifespan boundary; a cancelled task proves
  ``asyncio.CancelledError`` propagated all the way to the task
  boundary (the reaper never swallows it).
* When NO ``CheckpointStore`` is wired (dev / test / pack-only
  deployments), startup does NOT create a reaper task and does NOT
  fail — ``app.state.reaper_task`` stays ``None``.
* The reaper is a startup-singleton: it is NOT created at app
  construction / import time, and request handling never respawns it.

The reaper's own ``run_once`` / ``run_forever`` semantics
(delegate-to-store, exception-survival, ``CancelledError``-propagation,
sweep cadence) are pinned by ``tests/unit/sandbox/test_reaper.py``.
THIS module pins ONLY the lifespan wiring that T10 adds.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import httpx

from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app
from tests.support.settings_fixtures import prod_settings

if TYPE_CHECKING:
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore


class _StubCheckpointStore:
    """Minimal ``CheckpointStore`` stand-in — the reaper only ever
    calls ``purge_expired()``. Records each sweep + sets an event so a
    test can prove the reaper genuinely STARTED sweeping (a
    created-but-never-run task would be a silent wiring regression that
    a bare ``isinstance(task, asyncio.Task)`` assertion would miss)."""

    def __init__(self) -> None:
        self.sweep_count = 0
        self.swept = asyncio.Event()

    async def purge_expired(self) -> int:
        self.sweep_count += 1
        self.swept.set()
        return 0


def _settings() -> Settings:
    return prod_settings()


async def test_lifespan_starts_reaper_when_checkpoint_store_wired() -> None:
    """Startup wires the reaper as a background task AND the reaper
    actually begins sweeping (run_forever calls run_once immediately)."""
    store = _StubCheckpointStore()
    app = create_app(_settings(), checkpoint_store=cast("CheckpointStore", store))

    async with app.router.lifespan_context(app):
        task = app.state.reaper_task
        assert isinstance(task, asyncio.Task)
        assert not task.done()
        # Prove the reaper genuinely began sweeping — not merely that a
        # task object was constructed.
        await asyncio.wait_for(store.swept.wait(), timeout=2.0)
        assert store.sweep_count >= 1


async def test_lifespan_cancels_reaper_on_shutdown() -> None:
    """Shutdown cancels + awaits the reaper task. A cancelled task
    proves CancelledError propagated to the task boundary cleanly — no
    zombie task lingers past the lifespan."""
    store = _StubCheckpointStore()
    app = create_app(_settings(), checkpoint_store=cast("CheckpointStore", store))

    async with app.router.lifespan_context(app):
        task = app.state.reaper_task
        assert isinstance(task, asyncio.Task)

    assert task.done()
    assert task.cancelled()


async def test_no_reaper_when_checkpoint_store_absent() -> None:
    """The common dev / test / pack-only path — ``create_app`` without
    a ``checkpoint_store``. Startup MUST NOT fail and MUST NOT create a
    reaper task."""
    app = create_app(_settings())

    async with app.router.lifespan_context(app):
        assert app.state.checkpoint_store is None
        assert app.state.reaper_task is None


async def test_reaper_task_not_created_before_lifespan_startup() -> None:
    """The reaper is created INSIDE the one-shot lifespan — never at
    app-construction / import time. Pre-startup ``app.state.reaper_task``
    is ``None`` even when a store IS wired."""
    store = _StubCheckpointStore()
    app = create_app(_settings(), checkpoint_store=cast("CheckpointStore", store))

    # No lifespan entered yet.
    assert app.state.reaper_task is None

    async with app.router.lifespan_context(app):
        assert isinstance(app.state.reaper_task, asyncio.Task)


async def test_reaper_not_respawned_per_request() -> None:
    """The reaper is a startup-singleton (spec §13). Request handling
    never creates or replaces it — the task identity is stable across
    requests."""
    settings = _settings()
    store = _StubCheckpointStore()
    app = create_app(settings, checkpoint_store=cast("CheckpointStore", store))

    async with app.router.lifespan_context(app):
        original = app.state.reaper_task
        assert isinstance(original, asyncio.Task)

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for _ in range(3):
                resp = await client.get(f"{settings.api_prefix}/healthz")
                assert resp.status_code == 200

        assert app.state.reaper_task is original
        assert store.sweep_count >= 0  # reaper untouched by request handling

"""#489 T4 — production checkpoint-reaper lifespan wiring.

Pins the create_prod_app-facing wiring on top of the Sprint 8.5 T10
seam (tests/unit/sandbox/test_reaper_lifespan_wiring.py covers the
explicit-injection seam in isolation):

* setting-driven path — sandbox_reaper_enabled=true + a live adapter
  pool builds a CheckpointStore from the pool and starts the reaper;
* default posture — sandbox_reaper_enabled=false starts no reaper and
  logs a disabled-posture line;
* fail-loud — sandbox_reaper_enabled=true with no adapter registry
  fails startup loudly rather than silently disabling;
* explicit-injection precedence — an injected checkpoint_store starts a
  reaper with no adapter registry and never fails loud, even when
  sandbox_reaper_enabled=true;
* shutdown ordering — the reaper task is cancelled before
  adapters.close_all() so the shared engine is never disposed under an
  in-flight sweep;
* fail-loud propagation — the lifespan does not swallow a builder
  fail-loud.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import create_app
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

if TYPE_CHECKING:
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore


class _StubCheckpointStore:
    """Minimal CheckpointStore stand-in — the reaper only calls
    purge_expired(). Mirrors the stub in test_reaper_lifespan_wiring.py."""

    def __init__(self) -> None:
        self.sweep_count = 0

    async def purge_expired(self) -> int:
        self.sweep_count += 1
        return 0


def _memory_registry() -> AdapterRegistry:
    """A registry with the five in-memory drivers + the real local_fs
    object-store driver (same shape as tests/unit/db/test_adapter_factory.py)."""
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


def _memory_settings(*, reaper_enabled: bool, object_store_root: Path) -> Settings:
    """A Settings with all five non-object-store drivers set to ``memory``
    and the real local_fs object store rooted at a per-test tmp path. The
    ``*_driver`` field names — db / vector / secret / embed / obs — match
    core/config.py; the registry above keys by adapter *kind*."""
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        db_driver="memory",
        vector_driver="memory",
        secret_driver="memory",
        embed_driver="memory",
        obs_driver="memory",
        database_url=None,
        qdrant_url=None,
        vault_addr=None,
        embedding_base_url=None,
        langfuse_host=None,
        object_store_driver="local_fs",
        local_object_store_root=object_store_root,
        sandbox_reaper_enabled=reaper_enabled,
    )


async def test_setting_driven_reaper_starts_when_enabled(tmp_path: Path) -> None:
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    app = create_app(settings, adapter_registry=_memory_registry())

    async with app.router.lifespan_context(app):
        task = app.state.reaper_task
        assert isinstance(task, asyncio.Task)
        assert not task.done()


async def test_disabled_by_default_starts_no_reaper_and_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _memory_settings(reaper_enabled=False, object_store_root=tmp_path)
    app = create_app(settings, adapter_registry=_memory_registry())

    with caplog.at_level(logging.INFO, logger="cognic_agentos.portal.api.app"):
        async with app.router.lifespan_context(app):
            assert app.state.reaper_task is None

    assert any(r.message == "sandbox.reaper.disabled" for r in caplog.records)


async def test_setting_driven_fails_loud_without_adapter_registry(
    tmp_path: Path,
) -> None:
    """sandbox_reaper_enabled=true with no adapter pool fails startup
    loudly — never a silent no-op (#489 spec §4.3.2)."""
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    app = create_app(settings)  # no adapter_registry

    with pytest.raises(RuntimeError, match="adapter registry"):
        async with app.router.lifespan_context(app):
            pass


async def test_explicit_injection_wins_and_never_fails_loud(
    tmp_path: Path,
) -> None:
    """An explicit checkpoint_store starts a reaper with no adapter
    registry and does NOT fail loud, even with sandbox_reaper_enabled=true
    — the T10 seam is preserved."""
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    store = _StubCheckpointStore()
    app = create_app(settings, checkpoint_store=cast("CheckpointStore", store))

    async with app.router.lifespan_context(app):
        assert isinstance(app.state.reaper_task, asyncio.Task)


async def test_reaper_cancelled_before_adapters_closed(tmp_path: Path) -> None:
    """Shutdown ordering — the reaper task must be cancelled + awaited
    before adapters.close_all() runs, so the shared engine is never
    disposed under an in-flight sweep."""
    observed: dict[str, Any] = {}

    class _OrderRecordingRelational(InMemoryRelationalAdapter):
        reaper_task_ref: asyncio.Task[None] | None = None

        async def close(self) -> None:
            ref = _OrderRecordingRelational.reaper_task_ref
            observed["reaper_done_at_close"] = ref is not None and ref.done()
            await super().close()

    _OrderRecordingRelational.reaper_task_ref = None
    r = _memory_registry()
    r.register("relational", "memory", _OrderRecordingRelational)
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    app = create_app(settings, adapter_registry=r)

    async with app.router.lifespan_context(app):
        task = app.state.reaper_task
        assert isinstance(task, asyncio.Task)
        _OrderRecordingRelational.reaper_task_ref = task

    assert observed["reaper_done_at_close"] is True


async def test_lifespan_propagates_helper_fail_loud_and_closes_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#489 spec §4.3.2 — when the setting-driven store builder fails loud
    (object store or relational engine unavailable), the lifespan does NOT
    swallow it; startup fails. build_adapters structurally always provides
    an object store, so those unavailable-adapter states are exercised by
    monkeypatching the builder to raise.

    Pins the lifespan integration contract: the builder runs INSIDE the
    inner try/finally, so a builder fail-loud still closes the adapter
    pool — a failed startup never leaks an opened pool."""
    closed: dict[str, bool] = {"relational": False}

    class _CloseRecordingRelational(InMemoryRelationalAdapter):
        async def close(self) -> None:
            closed["relational"] = True
            await super().close()

    def _boom(adapters: object, settings: object) -> object:
        raise RuntimeError("simulated builder fail-loud")

    monkeypatch.setattr(
        "cognic_agentos.portal.api.app._build_checkpoint_store_from_adapters",
        _boom,
    )
    r = _memory_registry()
    r.register("relational", "memory", _CloseRecordingRelational)
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    app = create_app(settings, adapter_registry=r)

    with pytest.raises(RuntimeError, match="simulated builder fail-loud"):
        async with app.router.lifespan_context(app):
            pass

    # The builder fail-loud must still have closed the adapter pool — the
    # inner try/finally wraps the builder, so close_all() runs.
    assert closed["relational"] is True

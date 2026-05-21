# #489 — Production Checkpoint-Reaper Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the Sprint 8.5 resumable-session checkpoint reaper into the production app so it runs under `create_prod_app`, gated by a default-OFF operator setting.

**Architecture:** Approach A — add a read-only `engine` accessor to the `RelationalAdapter` protocol so the FastAPI lifespan can build a real `CheckpointStore` (`AuditStore` + `DecisionHistoryStore` + the object-store adapter) from the live adapter pool. A new default-OFF `Settings.sandbox_reaper_enabled` gates a setting-driven path that constructs the store after `open_all()` and starts the single-instance `CheckpointReaper`. The explicit `create_app(checkpoint_store=...)` injection seam (Sprint 8.5 T10) is preserved unchanged and never requires an adapter registry.

**Tech Stack:** Python 3.12, FastAPI lifespan, SQLAlchemy `AsyncEngine`, pydantic-settings, pytest + pytest-asyncio, `uv`.

**Source spec:** `docs/superpowers/specs/2026-05-21-489-prod-checkpoint-reaper-wiring-design.md` (committed at `18be47f`).

---

## Commit discipline

This repository operates under per-action commit authorization (see the project's
operating doctrine). Each task below ends with a **Commit** step showing the exact
`git commit` command, but the executor MUST produce a halt-before-commit summary and
wait for the human's explicit token before running it — do not auto-commit. Stage files
by **explicit path only** (never `git add -A`). Git identity is `bmzee`. No push / PR /
merge without a separate explicit token.

T0 (the design spec) is already committed at `18be47f` on branch
`feat/489-prod-checkpoint-store`. This plan covers T1–T6.

## File Structure

| File | Created / Modified | Responsibility |
|---|---|---|
| `src/cognic_agentos/core/config.py` | Modified | New `sandbox_reaper_enabled` bool setting (default `False`). |
| `src/cognic_agentos/db/adapters/protocols.py` | Modified | `engine` property added to the `RelationalAdapter` Protocol. |
| `src/cognic_agentos/db/adapters/postgres_adapter.py` | Modified | `engine` property implementation. |
| `src/cognic_agentos/db/adapters/oracle_adapter.py` | Modified | `engine` property implementation. |
| `tests/support/adapter_fixtures.py` | Modified | `engine` property on `InMemoryRelationalAdapter`. |
| `src/cognic_agentos/portal/api/app.py` | Modified | `_build_checkpoint_store_from_adapters` helper + lifespan reaper-wiring restructure. |
| `docs/operator-runbooks/checkpoint-reaper.md` | Created | Operator runbook for enabling/operating the reaper. |
| `tests/unit/test_config.py` | Modified | `sandbox_reaper_enabled` default test. |
| `tests/unit/db/test_relational_adapter_engine.py` | Created | `RelationalAdapter.engine` conformance across all three implementations. |
| `tests/unit/portal/api/test_checkpoint_store_builder.py` | Created | `_build_checkpoint_store_from_adapters` helper unit tests. |
| `tests/unit/portal/api/test_reaper_prod_wiring.py` | Created | Lifespan integration tests: setting-driven path, fail-loud, disabled posture, shutdown ordering, injection-preserved. |

No critical-controls module's contract changes: `sandbox/checkpoint_store.py`,
`sandbox/reaper.py`, `core/audit.py`, `core/decision_history.py` are **not** modified.

---

## Task 1: `sandbox_reaper_enabled` setting

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (after the `sandbox_reaper_interval_s` field, which currently ends at line 1236)
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_config.py` (near the other sandbox-settings tests):

```python
def test_sandbox_reaper_enabled_defaults_false() -> None:
    """#489 — the production checkpoint reaper is OFF by default. AgentOS
    production runs multiple Kubernetes replicas and the Sprint 8.5 reaper
    is single-instance by design; an operator must explicitly enable it on
    exactly one instance."""
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.sandbox_reaper_enabled is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_config.py::test_sandbox_reaper_enabled_defaults_false -v`
Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'sandbox_reaper_enabled'`.

- [ ] **Step 3: Write minimal implementation**

In `src/cognic_agentos/core/config.py`, immediately after the `sandbox_reaper_interval_s`
field's closing `)` (line 1236), add:

```python
    sandbox_reaper_enabled: bool = Field(
        default=False,
        description=(
            "#489 — gates the production checkpoint-retention reaper. "
            "Default OFF: AgentOS production runs multiple Kubernetes "
            "replicas, and the Sprint 8.5 reaper is single-instance by "
            "design (N replicas => N reapers => duplicate "
            "sandbox.lifecycle.checkpoint_purged audit rows; byte-level "
            "deletes stay idempotent). Operators set this true on EXACTLY "
            "ONE instance (or a dedicated single-replica reaper "
            "Deployment). Cross-instance leader election is deferred to "
            "Sprint 10.5. When false, create_prod_app starts no reaper and "
            "logs a disabled-posture line at startup."
        ),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_config.py::test_sandbox_reaper_enabled_defaults_false -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/core/config.py tests/unit/test_config.py
git commit -m "feat(489): T1 — sandbox_reaper_enabled setting (default OFF)"
```

---

## Task 2: `RelationalAdapter.engine` accessor

**Files:**
- Modify: `src/cognic_agentos/db/adapters/protocols.py:93-101` (the `RelationalAdapter` Protocol)
- Modify: `src/cognic_agentos/db/adapters/postgres_adapter.py` (after `session()`, line 47)
- Modify: `src/cognic_agentos/db/adapters/oracle_adapter.py` (after `session()`, line 49)
- Modify: `tests/support/adapter_fixtures.py` (after `InMemoryRelationalAdapter.session()`, line 55)
- Test: `tests/unit/db/test_relational_adapter_engine.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/db/test_relational_adapter_engine.py`:

```python
"""#489 T2 — RelationalAdapter.engine accessor conformance.

Every relational adapter implementation must expose its live
SQLAlchemy AsyncEngine via the read-only `engine` property after
connect(), and fail loud (RuntimeError) before connect(). The #489
lifespan builds AuditStore + DecisionHistoryStore from this accessor.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.db.adapters.oracle_adapter import OracleAdapter
from cognic_agentos.db.adapters.postgres_adapter import PostgresAdapter
from cognic_agentos.db.adapters.protocols import RelationalAdapter
from tests.support.adapter_fixtures import InMemoryRelationalAdapter

_SQLITE_URL = "sqlite+aiosqlite:///:memory:"


def _adapters() -> list[RelationalAdapter]:
    # All three relational adapter implementations. PostgresAdapter and
    # OracleAdapter are constructed against the sqlite URL — neither
    # branches on URL shape; SQLAlchemy picks the driver, so connect()
    # builds a real AsyncEngine without a live Postgres / Oracle process.
    return [
        PostgresAdapter(_SQLITE_URL),
        OracleAdapter(_SQLITE_URL),
        InMemoryRelationalAdapter(),
    ]


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda a: type(a).__name__)
def test_engine_raises_before_connect(adapter: RelationalAdapter) -> None:
    """Pre-connect access fails loud rather than yielding a half-live
    handle (#489 spec §4.2)."""
    with pytest.raises(RuntimeError, match="connect"):
        _ = adapter.engine


@pytest.mark.parametrize("adapter", _adapters(), ids=lambda a: type(a).__name__)
async def test_engine_yields_async_engine_after_connect(
    adapter: RelationalAdapter,
) -> None:
    """After connect() the accessor yields the adapter's live AsyncEngine."""
    await adapter.connect()
    try:
        assert isinstance(adapter.engine, AsyncEngine)
    finally:
        await adapter.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/db/test_relational_adapter_engine.py -v`
Expected: FAIL — `AttributeError: 'PostgresAdapter' object has no attribute 'engine'`.

- [ ] **Step 3: Write minimal implementation — protocol**

In `src/cognic_agentos/db/adapters/protocols.py`, add the import at the top of the
import block (after line 28's `from typing import ...`):

```python
from sqlalchemy.ext.asyncio import AsyncEngine
```

Then replace the `RelationalAdapter` Protocol body (lines 93-101) with:

```python
@runtime_checkable
class RelationalAdapter(Protocol):
    """RDBMS adapter — Sprint 1C ships postgres; Sprint 1D adds oracle."""

    async def connect(self) -> None: ...
    def session(self) -> Any: ...

    @property
    def engine(self) -> AsyncEngine:
        """The live SQLAlchemy AsyncEngine, owned and lifecycle-managed by
        the adapter — created by connect(), disposed by close().

        Read-only: consumers (e.g. the #489 checkpoint stores that build
        AuditStore / DecisionHistoryStore) use it but MUST NOT dispose it.
        Accessed before connect() it raises RuntimeError — fail loud
        rather than yield a half-live handle.
        """
        ...

    async def run_migrations(self, dir: str) -> None: ...
    async def close(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
```

- [ ] **Step 4: Write minimal implementation — three adapters**

In `src/cognic_agentos/db/adapters/postgres_adapter.py`, immediately after `session()`
(line 47, before `run_migrations`), add:

```python
    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("connect() must be awaited first")
        return self._engine
```

In `src/cognic_agentos/db/adapters/oracle_adapter.py`, immediately after `session()`
(line 49, before `run_migrations`), add the identical block:

```python
    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("connect() must be awaited first")
        return self._engine
```

In `tests/support/adapter_fixtures.py`, immediately after
`InMemoryRelationalAdapter.session()` (line 55, before `run_migrations`), add the
identical block:

```python
    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("connect() must be awaited first")
        return self._engine
```

(`AsyncEngine` is already imported in all three files.)

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/unit/db/test_relational_adapter_engine.py -v`
Expected: PASS — 6 tests (3 adapters × 2 cases).

Then confirm no existing adapter-protocol conformance test regressed:
Run: `uv run pytest tests/unit/db/ -q`
Expected: PASS — `@runtime_checkable` isinstance checks only verify attribute presence,
and all three adapters now have `engine`.

- [ ] **Step 6: Commit**

```bash
git add src/cognic_agentos/db/adapters/protocols.py src/cognic_agentos/db/adapters/postgres_adapter.py src/cognic_agentos/db/adapters/oracle_adapter.py tests/support/adapter_fixtures.py tests/unit/db/test_relational_adapter_engine.py
git commit -m "feat(489): T2 — RelationalAdapter.engine accessor"
```

---

## Task 3: `_build_checkpoint_store_from_adapters` lifespan helper

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (add a module-level helper near `_adapter_components`, around line 108)
- Test: `tests/unit/portal/api/test_checkpoint_store_builder.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/portal/api/test_checkpoint_store_builder.py`:

```python
"""#489 T3 — _build_checkpoint_store_from_adapters lifespan helper.

The helper constructs a production CheckpointStore from the live adapter
pool: AuditStore + DecisionHistoryStore from the relational adapter's own
engine, plus the bundled object-store adapter. It fails loud when the
object store is unavailable (#489 spec §4.3.2).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters.factory import Adapters
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.portal.api.app import _build_checkpoint_store_from_adapters
from cognic_agentos.sandbox.checkpoint_store import CheckpointStore
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


def _settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def _adapters(*, object_store: object) -> Adapters:
    return Adapters(
        relational=InMemoryRelationalAdapter(),
        vector=InMemoryVectorAdapter(),
        secret=InMemorySecretAdapter(),
        embedding=InMemoryEmbeddingAdapter(),
        observability=InMemoryObservabilityAdapter(),
        object_store=object_store,  # type: ignore[arg-type]
    )


async def test_builds_checkpoint_store_from_live_pool(tmp_path: Path) -> None:
    """Happy path — a connected relational adapter + an object store
    yields a real CheckpointStore."""
    adapters = _adapters(object_store=LocalObjectStoreAdapter(tmp_path))
    await adapters.relational.connect()
    try:
        store = _build_checkpoint_store_from_adapters(adapters, _settings())
        assert isinstance(store, CheckpointStore)
    finally:
        await adapters.relational.close()


def test_fails_loud_when_object_store_missing() -> None:
    """#489 spec §4.3.2 — a setting-driven reaper an operator explicitly
    enabled must never be silently disabled; a missing object store fails
    startup loudly."""
    adapters = _adapters(object_store=None)
    with pytest.raises(RuntimeError, match="object-store"):
        _build_checkpoint_store_from_adapters(adapters, _settings())


async def test_fails_loud_when_relational_engine_unavailable(tmp_path: Path) -> None:
    """#489 spec §4.3.2 / AC4 — a relational adapter that was never
    connected has no live engine; the helper fails loud with a
    dependency-naming RuntimeError rather than constructing a half-wired
    store. The relational adapter here is deliberately NOT connected."""
    adapters = _adapters(object_store=LocalObjectStoreAdapter(tmp_path))
    with pytest.raises(RuntimeError, match="relational adapter engine"):
        _build_checkpoint_store_from_adapters(adapters, _settings())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/portal/api/test_checkpoint_store_builder.py -v`
Expected: FAIL — `ImportError: cannot import name '_build_checkpoint_store_from_adapters'`.

- [ ] **Step 3: Write minimal implementation**

In `src/cognic_agentos/portal/api/app.py`, add this module-level function immediately
before `def create_app(` (line 189):

```python
def _build_checkpoint_store_from_adapters(
    adapters: Adapters,
    settings: Settings,
) -> CheckpointStore:
    """#489 — construct a production CheckpointStore from the live adapter pool.

    The checkpoint stores reuse the relational adapter's own AsyncEngine
    (read-only — they never dispose it; the adapter owns its lifecycle)
    and the bundled object-store adapter. Called by the lifespan ONLY
    after build_adapters() + open_all(), so adapters.relational.engine is
    connected.

    Fails loud — naming the missing dependency — when the object store
    OR the relational engine is unavailable. A setting-driven reaper an
    operator explicitly enabled must never be silently disabled (#489 spec
    §4.3.2 / AC4). The relational-engine-unavailable RuntimeError (raised
    by the RelationalAdapter.engine property when the adapter is not
    connected) is caught and re-raised with a dependency-naming message so
    both fail-loud paths are symmetric.
    """
    from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

    if adapters.object_store is None:
        raise RuntimeError(
            "sandbox_reaper_enabled=true but no object-store adapter is "
            "configured — the checkpoint reaper cannot run without "
            "persistent checkpoint storage."
        )
    try:
        engine = adapters.relational.engine
    except RuntimeError as exc:
        raise RuntimeError(
            "sandbox_reaper_enabled=true but the relational adapter "
            "engine is unavailable — the checkpoint reaper cannot run "
            "without a database connection."
        ) from exc
    return CheckpointStore(
        object_store=adapters.object_store,
        audit_store=AuditStore(engine),
        decision_history_store=DecisionHistoryStore(engine),
        settings=settings,
    )
```

(`Adapters` is imported at app.py line 48; `AuditStore` at line 43;
`DecisionHistoryStore` at line 45; `Settings` is already imported. `CheckpointStore` is
imported locally inside the function so the portal import graph stays sandbox-free until
a reaper is actually wired — same doctrine as the Sprint 8.5 T10 local
`CheckpointReaper` import.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/portal/api/test_checkpoint_store_builder.py -v`
Expected: PASS — 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_checkpoint_store_builder.py
git commit -m "feat(489): T3 — _build_checkpoint_store_from_adapters lifespan helper"
```

---

## Task 4: Production checkpoint-reaper lifespan wiring

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` — the `lifespan` function inside `create_app` (lines 298-388)
- Test: `tests/unit/portal/api/test_reaper_prod_wiring.py` (create)

This task restructures the FastAPI lifespan so that, in addition to the existing
explicit `checkpoint_store=` injection path, a default-OFF `sandbox_reaper_enabled`
setting drives construction of a real `CheckpointStore` from the live adapter pool. It
also moves reaper cancellation ahead of `adapters.close_all()`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/portal/api/test_reaper_prod_wiring.py`:

```python
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
  in-flight sweep.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.db.adapters.registry import AdapterRegistry
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
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        runtime_profile="prod",
        db_driver="memory",
        vector_driver="memory",
        secret_driver="memory",
        embedding_driver="memory",
        observability_driver="memory",
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


async def test_lifespan_propagates_helper_fail_loud(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#489 spec §4.3.2 — when the setting-driven store builder fails loud
    (object store or relational engine unavailable), the lifespan does NOT
    swallow it; startup fails. build_adapters structurally always provides
    an object store (factory.py resolves it unconditionally), so those
    unavailable-adapter states cannot be reached through the lifespan's
    own build path — they are exercised by monkeypatching the builder to
    raise. This pins the lifespan integration contract: there is no
    try/except around _build_checkpoint_store_from_adapters, so any builder
    fail-loud surfaces as a startup failure."""

    def _boom(adapters: object, settings: object) -> object:
        raise RuntimeError("simulated builder fail-loud")

    monkeypatch.setattr(
        "cognic_agentos.portal.api.app._build_checkpoint_store_from_adapters",
        _boom,
    )
    settings = _memory_settings(reaper_enabled=True, object_store_root=tmp_path)
    app = create_app(settings, adapter_registry=_memory_registry())

    with pytest.raises(RuntimeError, match="simulated builder fail-loud"):
        async with app.router.lifespan_context(app):
            pass
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/portal/api/test_reaper_prod_wiring.py -v`
Expected: FAIL — `test_setting_driven_reaper_starts_when_enabled` finds
`app.state.reaper_task is None` (the lifespan does not yet build a setting-driven
reaper); `test_setting_driven_fails_loud_without_adapter_registry` does not raise;
`test_disabled_by_default_starts_no_reaper_and_logs` finds no `sandbox.reaper.disabled`
log record; `test_lifespan_propagates_helper_fail_loud` does not raise (the lifespan
does not yet call the builder).

- [ ] **Step 3: Write the implementation — restructure the lifespan**

In `src/cognic_agentos/portal/api/app.py`, replace the entire `lifespan` function body
from line 298 (`@asynccontextmanager`) through the end of the outer `finally` block
(line 388) with:

```python
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Sprint-7B.4 T6: SSE-subscriber reap task. Unchanged by #489.
        reap_task: asyncio.Task[None] | None = None
        broker_for_lifespan = app.state.ui_event_broker
        if broker_for_lifespan is not None and settings is not None:
            _idle_s = settings.ui_event_stream_idle_timeout_s

            async def _reap_loop() -> None:
                """Periodic SSE-subscriber reaper. Runs at 1/3 the idle
                timeout so a stale subscriber is detected within one reap
                window; logs + swallows any per-iteration exception so a
                single failure does NOT kill the loop for the whole
                process lifetime."""
                while True:
                    await asyncio.sleep(_idle_s / 3)
                    try:
                        broker_for_lifespan.reap_idle(datetime.now(UTC))
                    except Exception:
                        logger.exception("ui.broker.reap_idle_failed")

            reap_task = asyncio.create_task(_reap_loop())

        # --- Checkpoint reaper (Sprint 8.5 T10 + #489) ---------------------
        # Precedence: an explicit create_app(checkpoint_store=...) injection
        # wins and needs NO adapter pool (preserves the T10 test seam,
        # including the adapter_registry-None path). Otherwise the #489
        # setting-driven path builds the store from the live adapter pool
        # AFTER open_all() when sandbox_reaper_enabled is set.
        reaper_task: asyncio.Task[None] | None = None
        injected_store = app.state.checkpoint_store
        setting_driven_reaper = (
            injected_store is None and settings.sandbox_reaper_enabled
        )

        # #489 spec §4.3.2 — fail loud. An operator who set
        # sandbox_reaper_enabled=true on a deployment with no adapter pool
        # gets a startup failure, never a silent no-op. Scoped to the
        # setting-driven path only: the explicit-injection path below never
        # reaches here, so injecting a store never fails for adapter reasons.
        if setting_driven_reaper and adapter_registry is None:
            raise RuntimeError(
                "sandbox_reaper_enabled=true but no adapter registry is "
                "configured. The setting-driven checkpoint reaper requires "
                "the production adapter pool — launch via create_prod_app, "
                "or inject create_app(checkpoint_store=...)."
            )

        def _start_checkpoint_reaper(store: CheckpointStore) -> asyncio.Task[None]:
            # Local import keeps the portal import graph sandbox-free until
            # a reaper is actually wired (Sprint 8.5 T10 doctrine).
            from cognic_agentos.sandbox.reaper import CheckpointReaper

            reaper = CheckpointReaper(checkpoint_store=store, settings=settings)
            return asyncio.create_task(reaper.run_forever())

        async def _shutdown_checkpoint_reaper() -> None:
            # cancel() then await so CancelledError propagates cleanly to
            # the task boundary — the reaper re-raises it out of
            # run_forever (it NEVER swallows cancellation). Idempotent via
            # the done() guard so the inner + outer finally can both call
            # it safely.
            if reaper_task is not None and not reaper_task.done():
                reaper_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reaper_task

        # Explicit-injection reaper starts immediately — the injected store
        # is self-contained (its own engine + object store), no adapter
        # pool needed.
        if injected_store is not None:
            reaper_task = _start_checkpoint_reaper(injected_store)
            app.state.reaper_task = reaper_task
            logger.info("sandbox.reaper.started", extra={"source": "explicit_injection"})

        try:
            if adapter_registry is None:
                app.state.adapters = None
                yield
                return

            # Trigger bundled-adapter registration side-effects. In the
            # default-adapters image this loads all five drivers; in the
            # kernel image (no `adapters` extras installed) every module
            # ImportErrors quietly per its allowlist and any configured
            # driver fails fast at build_adapters().
            if adapter_registry is bundled_registry:
                load_bundled_adapters()

            adapters = build_adapters(settings, registry=adapter_registry)
            await adapters.open_all()
            app.state.adapters = adapters

            # #489 — setting-driven reaper: build the CheckpointStore from
            # the live adapter pool AFTER open_all() so the relational
            # adapter's engine is connected.
            if setting_driven_reaper:
                store = _build_checkpoint_store_from_adapters(adapters, settings)
                reaper_task = _start_checkpoint_reaper(store)
                app.state.reaper_task = reaper_task
                logger.info(
                    "sandbox.reaper.started",
                    extra={
                        "source": "settings",
                        "interval_s": settings.sandbox_reaper_interval_s,
                    },
                )
            elif injected_store is None:
                # Default posture — no reaper. Loud log so an operator who
                # never enabled it sees why checkpoint retention is not
                # sweeping.
                logger.info(
                    "sandbox.reaper.disabled",
                    extra={
                        "remediation": (
                            "set sandbox_reaper_enabled=true on EXACTLY ONE "
                            "instance to run the resumable-session "
                            "retention sweep (single-instance posture per "
                            "spec §13; Sprint 10.5 adds leader election)"
                        ),
                    },
                )

            try:
                yield
            finally:
                # #489 — cancel the reaper BEFORE close_all() so the shared
                # adapter-owned engine is never disposed under an in-flight
                # sweep.
                await _shutdown_checkpoint_reaper()
                await adapters.close_all()
                app.state.adapters = None
        finally:
            # Sprint-7B.4 T6: SSE reap-task cleanup. Always runs, even on
            # the adapter-registry-None early-return path.
            if reap_task is not None:
                reap_task.cancel()
                with suppress(asyncio.CancelledError):
                    await reap_task
            # Catch-all for the adapter_registry-None early-return path,
            # where the inner finally never ran. _shutdown_checkpoint_reaper
            # is idempotent (done() guard), so the main path's double call
            # is a safe no-op.
            await _shutdown_checkpoint_reaper()
```

Notes for the implementer:
- `settings` is non-`None` for the whole function — line 291 (`settings = settings or
  get_settings()`) runs before `lifespan` is defined, and the closure captures the
  narrowed `Settings`. The pre-#489 SSE block keeps its redundant `settings is not None`
  check; leave it as-is to minimise the diff.
- The pre-startup `app.state.reaper_task = None` seed at line 472 is unchanged — it
  still guarantees the attribute exists before startup.
- `CheckpointStore` in the `_start_checkpoint_reaper` type annotation resolves via the
  existing `TYPE_CHECKING` import at app.py line 88 (`from __future__ import
  annotations` makes the annotation a string).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/portal/api/test_reaper_prod_wiring.py -v`
Expected: PASS — 6 tests.

Then confirm the Sprint 8.5 T10 seam still holds:
Run: `uv run pytest tests/unit/sandbox/test_reaper_lifespan_wiring.py -v`
Expected: PASS — 5 tests (the explicit-injection path is unchanged).

Then confirm no portal lifespan regression:
Run: `uv run pytest tests/unit/portal/ -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_reaper_prod_wiring.py
git commit -m "feat(489): T4 — production checkpoint-reaper lifespan wiring"
```

---

## Task 5: Checkpoint-reaper operator runbook

**Files:**
- Create: `docs/operator-runbooks/checkpoint-reaper.md`

- [ ] **Step 1: Write the runbook**

Create `docs/operator-runbooks/checkpoint-reaper.md`:

```markdown
# Operator runbook — checkpoint-retention reaper

## What the reaper does

The checkpoint reaper enforces the resumable-session retention floor
(ADR-004). It sweeps every `sandbox_reaper_interval_s` seconds and purges
checkpoints whose `retention_window_s` has elapsed, emitting a
`sandbox.lifecycle.checkpoint_purged` audit-chain row per purge. Without
the reaper running, expired checkpoints accumulate indefinitely.

## Enabling the reaper

The reaper is **OFF by default**. Set `sandbox_reaper_enabled=true`
(env var `COGNIC_SANDBOX_REAPER_ENABLED=true`) to enable it.

**Enable it on EXACTLY ONE instance.** AgentOS production runs multiple
Kubernetes replicas. The Sprint 8.5 reaper is single-instance by design:
if N replicas each enable it, N reapers sweep the same shared object-store
backend and produce N duplicate `checkpoint_purged` audit rows per purge.
The byte-level deletes stay idempotent and safe — the cost is
examiner-facing audit noise. Cross-instance leader election is deferred to
Sprint 10.5; until then, run exactly one reaper.

Recommended deployment: a dedicated single-replica reaper Deployment with
`sandbox_reaper_enabled=true`, while the request-serving Deployment leaves
it `false`.

## Preconditions

1. **Persistent object-store root.** The `local_fs` object-store driver
   (`local_object_store_root`) must point at a persistent path. In
   Kubernetes that is a PersistentVolume, mounted by whichever instance
   runs the reaper. A reaper on an ephemeral path sees an empty store and
   purges nothing.
2. **Database migrations.** The `decision_history` and `audit_event`
   tables must exist — run `uv run alembic upgrade head` (or the migration
   Job) before rolling out the reaper instance. Migrations are not run by
   the app at startup.

## Confirming the posture at startup

The app logs its reaper posture once at startup, on logger
`cognic_agentos.portal.api.app`:

- `sandbox.reaper.started` with `source=settings` — the setting-driven
  reaper is running on this instance.
- `sandbox.reaper.started` with `source=explicit_injection` — a reaper was
  started from an injected `CheckpointStore` (test / embedding scenarios).
- `sandbox.reaper.disabled` — no reaper on this instance; the log carries
  a `remediation` field. Expected on every instance except the designated
  reaper one.

## Fail-loud behaviour

If `sandbox_reaper_enabled=true` but the production adapters are missing or
unusable — no adapter registry, or no object-store adapter — the process
**fails to start** with a `RuntimeError` naming the missing dependency.
This is intentional: an operator who explicitly asked for the reaper is
never silently given a no-op. Fix the adapter configuration and restart.
```

- [ ] **Step 2: Verify the doc has no whitespace errors**

Run: `git add -N docs/operator-runbooks/checkpoint-reaper.md && git diff --check docs/operator-runbooks/checkpoint-reaper.md`
Expected: exit 0, no output (a plain `git diff --check` on an untracked file is
vacuous — the `git add -N` intent-to-add marker makes the check real).

- [ ] **Step 3: Commit**

```bash
git add docs/operator-runbooks/checkpoint-reaper.md
git commit -m "docs(489): T5 — checkpoint-reaper operator runbook"
```

---

## Task 6: Gate ladder + #489 acceptance verification

No code changes. This task verifies the whole #489 arc against the spec's acceptance
criteria and the project gate ladder.

- [ ] **Step 1: Run the full lint + type gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
Expected: all clean. Fix any issue in the owning task's files and fold the fix into a
follow-up commit (`fix(489): ...`).

- [ ] **Step 2: Run the full test suite AND produce fresh coverage data**

Run: `uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -m "not postgres and not oracle" -q`
Expected: PASS — the prior suite count plus the new #489 tests
(`test_sandbox_reaper_enabled_defaults_false`; 6 in `test_relational_adapter_engine.py`;
3 in `test_checkpoint_store_builder.py`; 6 in `test_reaper_prod_wiring.py`); no
regressions.

This command — not a bare `pytest -q` — is mandatory: `tools/check_critical_coverage.py`
(Step 3) reads `coverage.json`, which is produced ONLY by `--cov-report=json`. A bare
`pytest -q` leaves `coverage.json` stale (from an earlier run) or absent, so Step 3
would validate stale data or fail for the wrong reason. `--cov-branch` matches the
gate's 90% branch floor; `-m "not postgres and not oracle"` deselects the env-gated
live-DB integration tests — the critical-controls floor is mocked-unit coverage
(env-gated live tests are extra proof only, per `feedback_verify_promotion_meets_floor_at_promotion_time`).

- [ ] **Step 3: Verify the critical-controls coverage gate is unaffected**

Run: `uv run python tools/check_critical_coverage.py`
Expected: PASS — #489 modifies no critical-controls module
(`sandbox/checkpoint_store.py`, `sandbox/reaper.py`, `core/audit.py`,
`core/decision_history.py` are untouched; the on-gate module set and floors are
unchanged).

- [ ] **Step 4: Verify acceptance criteria AC1–AC9**

Confirm against the spec
(`docs/superpowers/specs/2026-05-21-489-prod-checkpoint-reaper-wiring-design.md` §5),
each backed by a passing test or a gate result:
- AC1 — `sandbox_reaper_enabled` defaults `False` → `test_sandbox_reaper_enabled_defaults_false`.
- AC2 — `RelationalAdapter.engine` on all three adapters → `test_relational_adapter_engine.py`.
- AC3 — setting-driven reaper runs → `test_setting_driven_reaper_starts_when_enabled`.
- AC4 — fail-loud on missing adapters → `test_setting_driven_fails_loud_without_adapter_registry` (lifespan, no registry) + `test_fails_loud_when_object_store_missing` + `test_fails_loud_when_relational_engine_unavailable` (helper — both unavailable-dependency paths, each raising a dependency-naming RuntimeError) + `test_lifespan_propagates_helper_fail_loud` (lifespan does not swallow a builder fail-loud). build_adapters resolves the object store unconditionally, so the object-store / engine unavailable states are unreachable through the lifespan's own build path and are pinned at the helper unit-test level plus the monkeypatch propagation test.
- AC5 — explicit-injection seam intact → `test_explicit_injection_wins_and_never_fails_loud` + `test_reaper_lifespan_wiring.py` still green.
- AC6 — reaper cancelled before `close_all()` → `test_reaper_cancelled_before_adapters_closed`.
- AC7 — default path: no reaper + disabled log → `test_disabled_by_default_starts_no_reaper_and_logs`.
- AC8 — operator runbook exists → `docs/operator-runbooks/checkpoint-reaper.md`.
- AC9 — full gate ladder green → Steps 1-3 above.

- [ ] **Step 5: Halt-before-commit summary**

Produce a halt-before-commit summary listing files modified, tests run + results, the
gate-ladder outcome, and the AC1–AC9 status. This task produces no commit of its own
unless Step 1/2 surfaced a fix.

---

## Self-Review

**1. Spec coverage.** Every spec section maps to a task: §4.1 setting → T1; §4.2 engine
seam → T2; §4.3 lifespan wiring (precedence, fail-loud, ordering, logs) → T3 (helper) +
T4 (lifespan); §4.4 operator runbook → T5; §4.5 testing → tests embedded in T1-T4 +
verified in T6; §5 acceptance criteria → T6 Step 4; §3 non-goals → respected (no K8s
manifests, no leader election, no migrations, alternatives B/C not built). No gaps.

**2. Placeholder scan.** No `TBD` / `TODO` / "handle edge cases" / "similar to Task N".
Every code step contains complete code; every command has an expected result.

**3. Type consistency.** `_build_checkpoint_store_from_adapters(adapters: Adapters,
settings: Settings) -> CheckpointStore` is defined identically in T3 and called with
that signature in T4. `RelationalAdapter.engine` is declared as a `@property` returning
`AsyncEngine` in T2's protocol step and implemented as a `@property` returning
`AsyncEngine` in all three adapters. `_start_checkpoint_reaper` /
`_shutdown_checkpoint_reaper` / `setting_driven_reaper` / `injected_store` /
`reaper_task` names are consistent within the T4 lifespan body. The log event names
`sandbox.reaper.started` / `sandbox.reaper.disabled` match between T4's implementation
and the T4 tests and the T5 runbook.

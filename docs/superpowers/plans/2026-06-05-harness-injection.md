# Harness Injection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the canonical OS composition root `harness/` — `async build_runtime(settings, adapters) -> Runtime` — that constructs the real `LLMGateway` and (when `cache_driver != "none"`) the governed-memory API factory from `Settings` + the adapter pool, and wire it into `create_prod_app`'s lifespan. This activates the Wave-1 T3 gateway `vault://` seam.

**Architecture:** New `harness/` package (OS runtime wiring only, never Layer-C behaviour). `build_runtime` runs async inside the FastAPI lifespan after `adapters.open_all()`, builds a minimal spine (engine→`AuditStore`/`DecisionHistoryStore`), the gateway, and — only when a cache adapter is present — the memory factory (two `OPAEngine`s behind a harness-owned `MemoryPolicyRouter`, the routing memory adapter, DLP, consent, the Redis write-freeze kill switch, optional object-store + vector index). Redis/cache becomes a first-class optional adapter-pool member. `/memory` mounts at construction time gated on config; its handlers resolve the factory from `app.state` at request time.

**Tech Stack:** Python 3.12, `uv`, FastAPI, SQLAlchemy async, Pydantic v2 Settings, `redis>=5.3` (in the `adapters` extra), OPA (`opa` binary) for Rego. Tests: pytest, `respx` (gateway HTTP), in-memory adapter fixtures.

**Source spec:** `docs/superpowers/specs/2026-06-05-harness-injection-design.md` (committed `11a12e1` + `d1d683c`).

---

## Locked design decisions (from the spec — do not re-litigate)

- **B1 fence.** `Runtime` public members are exactly `{llm_gateway, memory_api_factory}`. Do **not** wire `ParentBudgetResolver`, `VaultCredentialAdapter`, scheduler/quota/pack-state (Bucket 3), or any Bucket-1 bank-overlay default. Do **not** modify `core/memory/*` (stop-rule), `llm/gateway.py`, or `core/emergency/kill_switches.py` — they are **constructed, not edited**. No managed-agent substrate / tool palette / `base_agent.py`.
- **No harness-local Redis client.** `build_runtime` consumes `adapters.cache.client`; it must **never** call `redis.asyncio.Redis(...)`. Pinned by an architecture test.
- **`cache_driver` default `"none"`** — preserves today's bare-`create_app()` no-`/memory` behaviour (zero OpenAPI churn) and keeps memory opt-in. `"memory"` is a **test-only** driver; `"redis"` is the real one (in the `adapters` extra). Strict profiles forbid `cache_driver="memory"`.
- **Two-bundle memory policy.** `OPAEngine` is a single-**file** loader. `MemoryGate` spans two bundles. `build_runtime` builds two `OPAEngine`s + a harness-owned `MemoryPolicyRouter` (conforms to `OPAEngine.evaluate(...)`), passed to `MemoryAPI` with `# type: ignore[arg-type]` (mirrors the `_build_api` test precedent). **No `core/memory/` change.** If mypy ever forces widening `gate.py`/`api.py` to a Protocol → **HALT and surface** (do not do it silently).
- **`/memory` mount strategy.** Mount decision is construction-time (`cache_driver != "none"` OR a `memory_api_factory` kwarg); the factory is resolved per-request from `request.app.state.memory_api_factory`; absent → `503 memory_unavailable`.

## New Settings (added in T4)

| Field | Type | Default | Purpose |
|---|---|---|---|
| `cache_driver` | `Literal["none","redis","memory"]` | `"none"` | cache adapter selection (`none` = no cache, memory off) |
| `redis_url` | `str \| None` | `None` | required when `cache_driver="redis"` |
| `litellm_config_path` | `Path` | `Path("infra/litellm/config.yaml")` | `PreflightResolver.from_yaml` source |
| `llm_sla_total_budget_s` | `float` | `30.0` | `SLAPolicy.total_budget` |
| `llm_sla_warning_threshold_s` | `float` | `20.0` | `SLAPolicy.warning_threshold` |
| `memory_policy_bundle` | `Path` | `Path("policies/_default/memory.rego")` | memory `OPAEngine` bundle |
| `memory_purpose_matrix_policy_bundle` | `Path` | `Path("policies/_default/memory_purpose_matrix.rego")` | purpose-matrix `OPAEngine` bundle |

The SLA policy **name** is a harness constant `_SLA_POLICY_NAME = "llm-gateway"` (audit label — no Setting).

## Halt-before-commit gates (per `feedback_strict_review_off_gate`)

Every task touching these is **halt-before-commit** (produce a halt summary; wait for the `commit` token): **T3** (`db/adapters/factory.py` — adapter factory), **T4** (`core/config.py` — stop-rule + deploy-safety guard), **T7** (`portal/api/memory/routes.py` — governance-adjacent surface), **T8** (`portal/api/app.py` — composition root), and **T1/T2** (adapter Protocol + registry typing + the real `RedisAdapter`). T5/T6 (the `harness/` composition root) and T9 (arch fences) are also halt-before-commit (security-adjacent). T10 is the Z-gate.

Run `uv run` for all Python. Pre-commit ladder: targeted tests + affected slice + `ruff check .` + `ruff format --check .` + `uv run mypy src tests` (full-tree at HALT) + the focused regressions. Full suite at the `commit` token (per `feedback_gate_ladder_per_microfix`).

## Execution order

**Run the tasks T1 → T2 → T4 → T3 → T5 → T6 → T7 → T8 → T9 → T10.** T4 (config Settings) lands **before** T3 (factory) because `build_adapters` reads `settings.cache_driver` — the field must exist first. The task *numbers* are kept (T3 = factory, T4 = config); only the execution sequence swaps those two. Every other task is in numeric order.

---

## File Structure

**New files**
- `src/cognic_agentos/harness/__init__.py` — re-exports `build_runtime`, `Runtime`
- `src/cognic_agentos/harness/runtime.py` — `Runtime` dataclass + `async build_runtime`
- `src/cognic_agentos/harness/memory_policy.py` — `MemoryPolicyRouter`
- `src/cognic_agentos/db/adapters/redis_adapter.py` — `RedisAdapter` (optional, `adapters` extra)
- `tests/unit/db/test_cache_adapter_protocol.py`, `tests/unit/db/test_redis_adapter.py`, `tests/unit/db/test_cache_factory.py`
- `tests/unit/core/test_config_cache_guards.py`
- `tests/unit/harness/test_runtime.py`, `tests/unit/harness/test_memory_policy.py`
- `tests/unit/portal/api/memory/test_routes_app_state.py`
- `tests/unit/portal/api/test_app_harness_wiring.py`
- `tests/unit/architecture/test_harness_fences.py`

**Modified files**
- `src/cognic_agentos/db/adapters/protocols.py` — add `_AsyncKVClient` + `CacheAdapter` Protocols
- `src/cognic_agentos/db/adapters/registry.py` — add `"cache"` to `AdapterKind` + `PROTOCOL_FOR_KIND`
- `src/cognic_agentos/db/adapters/factory.py` — `Adapters.cache` field + `_cache_args` + resolve with `"none"` skip
- `src/cognic_agentos/db/adapters/__init__.py` — add `redis_adapter` to `_BUNDLED_ADAPTER_OPTIONAL_DEPS`
- `src/cognic_agentos/core/config.py` — the 8 new Settings + the strict-profile cache guard
- `tests/support/adapter_fixtures.py` — `InMemoryCacheAdapter`
- `tests/conftest.py` — register `("cache","memory")`
- `src/cognic_agentos/portal/api/memory/routes.py` — resolve factory from `app.state` + `503`
- `src/cognic_agentos/portal/api/app.py` — `llm_gateway` kwarg + construction-time mount gate + lifespan `build_runtime`

---

## Task 1: Cache adapter Protocol + registry typing + in-memory fixture

**Files:**
- Modify: `src/cognic_agentos/db/adapters/protocols.py` (add Protocols)
- Modify: `src/cognic_agentos/db/adapters/registry.py:22-37` (`AdapterKind` + `PROTOCOL_FOR_KIND`)
- Modify: `tests/support/adapter_fixtures.py` (add `InMemoryCacheAdapter`)
- Modify: `tests/conftest.py:35-48` (register cache/memory)
- Test: `tests/unit/db/test_cache_adapter_protocol.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/db/test_cache_adapter_protocol.py
from __future__ import annotations

import typing

from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import AdapterKind, PROTOCOL_FOR_KIND
from tests.support.adapter_fixtures import InMemoryCacheAdapter


def test_cache_kind_in_adapter_kind_literal() -> None:
    assert "cache" in typing.get_args(AdapterKind)


def test_cache_kind_in_protocol_for_kind() -> None:
    assert PROTOCOL_FOR_KIND["cache"] is P.CacheAdapter


def test_in_memory_cache_adapter_satisfies_protocol() -> None:
    adapter = InMemoryCacheAdapter()
    assert isinstance(adapter, P.CacheAdapter)


async def test_in_memory_cache_client_roundtrip() -> None:
    adapter = InMemoryCacheAdapter()
    await adapter.connect()
    await adapter.client.set("k", "v")
    assert await adapter.client.get("k") == "v"
    assert await adapter.client.get("missing") is None
    health = await adapter.health_check()
    assert health.status == "ok"
    assert health.driver == "memory"
    await adapter.close()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/db/test_cache_adapter_protocol.py -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'CacheAdapter'` / `KeyError: 'cache'`.

- [ ] **Step 3: Add the Protocols to `protocols.py`**

Add after the `VectorAdapter` Protocol (`protocols.py:132`):

```python
@runtime_checkable
class _AsyncKVClient(Protocol):
    """Minimal async key-value client the cache adapter exposes via ``.client``.

    Deliberately permissive (``set(*args, **kwargs)``) so the value is assignable
    at BOTH memory consumers without friction —
    ``core/memory/storage._AsyncRedisLike`` (scratch tier) and
    ``core/emergency/kill_switches._AsyncRedisKVLike`` (write-freeze). The real
    ``redis.asyncio.Redis`` and the in-memory test client both satisfy it.
    """

    async def get(self, key: str) -> Any: ...
    async def set(self, *args: Any, **kwargs: Any) -> Any: ...


@runtime_checkable
class CacheAdapter(Protocol):
    """Cache / ephemeral async-KV adapter — the harness ships ``redis``.

    ``.client`` is the live async KV client the memory subsystem injects into
    ``RedisMemoryAdapter`` (scratch) + ``RedisMemoryWriteFreezeKillSwitch``
    (ADR-018). It mirrors ``RelationalAdapter.engine``: owned + lifecycle-managed
    by the adapter (created by ``connect()``, closed by ``close()``); consumers
    use it but MUST NOT close it. Accessed before ``connect()`` it raises
    ``RuntimeError`` — fail loud rather than yield a half-live handle.
    """

    async def connect(self) -> None: ...

    @property
    def client(self) -> _AsyncKVClient: ...

    async def close(self) -> None: ...
    async def health_check(self) -> AdapterHealth: ...
```

- [ ] **Step 4: Add `"cache"` to the registry typing (`registry.py`)**

Modify `registry.py:22-24`:

```python
AdapterKind = Literal[
    "relational", "vector", "secret", "embedding", "object_store", "observability", "cache"
]
```

Modify `PROTOCOL_FOR_KIND` (`registry.py:30-37`) — add the `"cache"` entry:

```python
PROTOCOL_FOR_KIND: dict[str, type] = {
    "relational": P.RelationalAdapter,
    "vector": P.VectorAdapter,
    "secret": P.SecretAdapter,
    "embedding": P.EmbeddingAdapter,
    "object_store": P.ObjectStoreAdapter,
    "observability": P.ObservabilityAdapter,
    "cache": P.CacheAdapter,
}
```

- [ ] **Step 5: Add `InMemoryCacheAdapter` to the test fixtures + register it**

Add to `tests/support/adapter_fixtures.py` (after `InMemoryVectorAdapter`, with the needed imports — `from cognic_agentos.db.adapters.protocols import AdapterHealth` is already imported there):

```python
class _InMemoryKVClient:
    """Dict-backed async KV satisfying ``_AsyncKVClient`` (get/set).

    TTL (``ex=`` kwarg) is accepted-and-ignored: scratch reads in tests are
    immediate; real TTL eviction is the redis driver's concern. Mirrors the
    other in-memory adapters' "defer the hard part, keep the contract" shape.
    """

    def __init__(self) -> None:
        self._store: dict[str, object] = {}

    async def get(self, key: str) -> object | None:
        return self._store.get(key)

    async def set(self, *args: object, **kwargs: object) -> bool:
        # redis-style positional ``set(name, value, ...)``.
        key, value = args[0], args[1]
        self._store[str(key)] = value
        return True


class InMemoryCacheAdapter:
    """Test-only in-memory cache adapter (``driver="memory"``), mirroring the
    sibling in-memory adapters. Hand-rolled dict-backed async KV — NOT fakeredis
    (not a project dep)."""

    driver = "memory"

    def __init__(self) -> None:
        self._client = _InMemoryKVClient()

    async def connect(self) -> None:
        return None

    @property
    def client(self) -> _InMemoryKVClient:
        return self._client

    async def close(self) -> None:
        return None

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)
```

Register it in the `memory_registry` fixture (`tests/conftest.py:35-48`) — add the import (`from tests.support.adapter_fixtures import InMemoryCacheAdapter`) and the line:

```python
    r.register("cache", "memory", InMemoryCacheAdapter)
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/unit/db/test_cache_adapter_protocol.py -v`
Expected: PASS (4 tests).

- [ ] **Step 7: HALT-before-commit, then commit**

Pre-commit ladder: `uv run pytest tests/unit/db/test_cache_adapter_protocol.py` + `uv run ruff check .` + `uv run ruff format --check .` + `uv run mypy src tests`. Produce the halt summary (files modified, the registry-typing change, the new Protocols), wait for `commit`.

```bash
git add src/cognic_agentos/db/adapters/protocols.py src/cognic_agentos/db/adapters/registry.py tests/support/adapter_fixtures.py tests/conftest.py tests/unit/db/test_cache_adapter_protocol.py
git commit -m "feat(harness): CacheAdapter protocol + cache registry typing + in-memory fixture"
```

---

## Task 2: Real `RedisAdapter` (optional `adapters`-extra driver)

**Files:**
- Create: `src/cognic_agentos/db/adapters/redis_adapter.py`
- Modify: `src/cognic_agentos/db/adapters/__init__.py:35-59` (`_BUNDLED_ADAPTER_OPTIONAL_DEPS`)
- Test: `tests/unit/db/test_redis_adapter.py`

**Pattern note:** mirror `qdrant_adapter.py` exactly — top-level driver import (kernel-image resilience is in `load_bundled_adapters`'s allowlist + try/except, NOT a lazy import), `driver = "redis"` class attr, `connect()` sets the client, `client` property + `close()` + `health_check()`, and a module-bottom `bundled_registry.register("cache", "redis", RedisAdapter)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/db/test_redis_adapter.py
from __future__ import annotations

import pytest

from cognic_agentos.db.adapters import protocols as P
from cognic_agentos.db.adapters.registry import bundled_registry


def test_redis_adapter_registered_on_import() -> None:
    # Importing the module self-registers the driver (mirrors qdrant_adapter).
    import cognic_agentos.db.adapters.redis_adapter  # noqa: F401

    assert bundled_registry.has("cache", "redis")
    cls = bundled_registry.resolve("cache", "redis")
    assert cls.driver == "redis"


def test_redis_adapter_satisfies_cache_protocol() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    adapter = RedisAdapter("redis://localhost:6379/0")
    assert isinstance(adapter, P.CacheAdapter)


def test_redis_adapter_requires_url() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    with pytest.raises(ValueError, match="redis_url"):
        RedisAdapter(None)


def test_client_before_connect_raises() -> None:
    from cognic_agentos.db.adapters.redis_adapter import RedisAdapter

    adapter = RedisAdapter("redis://localhost:6379/0")
    with pytest.raises(RuntimeError, match="not connected"):
        _ = adapter.client
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/db/test_redis_adapter.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Create `redis_adapter.py`**

```python
"""Redis cache adapter — the harness's first-class ``cache`` driver (ADR-009).

Optional ``adapters``-extra driver. ``redis`` is imported at module top level
(mirroring qdrant_adapter); kernel-image resilience lives in
``load_bundled_adapters``'s allowlist + try/except, not a lazy import. Exposes
the live ``redis.asyncio.Redis`` client via ``.client`` for the memory
subsystem (scratch tier + ADR-018 write-freeze kill switch).
"""

from __future__ import annotations

import time

import redis.asyncio as _redis

from cognic_agentos.db.adapters.protocols import AdapterHealth, _AsyncKVClient
from cognic_agentos.db.adapters.registry import bundled_registry


class RedisAdapter:
    driver = "redis"

    def __init__(self, url: str | None) -> None:
        if not url:
            raise ValueError("RedisAdapter requires redis_url; got empty/None")
        self._url = url
        self._client: _redis.Redis | None = None

    async def connect(self) -> None:
        # decode_responses=True so get() returns str (matches the in-memory
        # fixture + the memory scratch/kill-switch consumers' str handling).
        self._client = _redis.Redis.from_url(self._url, decode_responses=True)

    @property
    def client(self) -> _AsyncKVClient:
        if self._client is None:
            raise RuntimeError("RedisAdapter.client accessed before connect(): not connected")
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> AdapterHealth:
        if self._client is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="not connected")
        start = time.perf_counter()
        try:
            await self._client.ping()
        except Exception as exc:  # noqa: BLE001 — health probe must not raise
            return AdapterHealth(status="unreachable", driver=self.driver, detail=type(exc).__name__)
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("cache", "redis", RedisAdapter)
```

- [ ] **Step 4: Add to the optional-deps allowlist (`__init__.py`)**

Add to `_BUNDLED_ADAPTER_OPTIONAL_DEPS` (`__init__.py:35-59`):

```python
    "cognic_agentos.db.adapters.redis_adapter": frozenset({"redis"}),
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/db/test_redis_adapter.py -v`
Expected: PASS (4 tests). (No live Redis needed — these test construction + registration + the fail-loud guards. A live-Redis health/roundtrip test is env-gated integration, out of this task.)

- [ ] **Step 6: HALT-before-commit, then commit**

Ladder + halt summary (note: real adapter, optional-extra path, optional-import skip behavior via the allowlist). Wait for `commit`.

```bash
git add src/cognic_agentos/db/adapters/redis_adapter.py src/cognic_agentos/db/adapters/__init__.py tests/unit/db/test_redis_adapter.py
git commit -m "feat(harness): real RedisAdapter cache driver (optional adapters extra)"
```

---

## Task 3: `Adapters.cache` field + factory wiring + `"none"` skip

**Files:**
- Modify: `src/cognic_agentos/db/adapters/factory.py` (`Adapters` dataclass `:32-87`, `build_adapters` `:90-142`, `_cache_args` helper `:189+`)
- Test: `tests/unit/db/test_cache_factory.py`

**HALT-before-commit** (adapter factory).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/db/test_cache_factory.py
from __future__ import annotations

import pytest

from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.db.adapters.registry import AdapterNotInstalled


def test_cache_none_yields_none(memory_registry, memory_settings) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "none"})
    adapters = build_adapters(s, registry=memory_registry)
    assert adapters.cache is None


def test_cache_memory_driver_resolves(memory_registry, memory_settings) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "memory"})
    adapters = build_adapters(s, registry=memory_registry)
    assert adapters.cache is not None
    assert adapters.cache.driver == "memory"


def test_cache_redis_unregistered_fails_loud(memory_registry, memory_settings) -> None:
    # memory_registry has no ("cache","redis") — must fail loud, never None.
    s = memory_settings.model_copy(update={"cache_driver": "redis", "redis_url": "redis://x:6379/0"})
    with pytest.raises(AdapterNotInstalled):
        build_adapters(s, registry=memory_registry)


async def test_cache_in_open_all_lifecycle(memory_registry, memory_settings) -> None:
    s = memory_settings.model_copy(update={"cache_driver": "memory"})
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()  # must not raise; cache has connect()
    await adapters.close_all()
```

> **Execution order:** run **T4 (config Settings) before this task** — `build_adapters` reads `settings.cache_driver`, so the field must exist first (canonical order in the header: T1 → T2 → T4 → T3 → …). `memory_settings` (`tests/conftest.py`) sets the other drivers to `"memory"`; this task drives cache resolution via `cache_driver` overrides. `model_copy` is fine here — these are **factory** tests (they read `settings.cache_driver`), not validator tests.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/db/test_cache_factory.py -v`
Expected: FAIL — `Adapters` has no `cache` field / `cache_driver` unknown.

- [ ] **Step 3: Add the `cache` field to `Adapters`**

In `factory.py`, add `cache` after `observability` and append it in `__post_init__`:

```python
    observability: P.ObservabilityAdapter
    cache: P.CacheAdapter | None = None
    object_store: P.ObjectStoreAdapter | None = None
    _all: list[Any] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._all = [
            self.relational,
            self.vector,
            self.secret,
            self.embedding,
            self.observability,
        ]
        if self.cache is not None:
            self._all.append(self.cache)
        if self.object_store is not None:
            self._all.append(self.object_store)
```

- [ ] **Step 4: Resolve the cache driver in `build_adapters` + add `_cache_args`**

In `build_adapters` (after the `observability_cls` line, before the `object_store` block), add the **`"none"` skip-branch**:

```python
    # Cache adapter — the ONLY optional-with-opt-out adapter. ``none`` means the
    # operator runs no cache (pack-only deploys without governed memory). Any
    # other driver resolves through the registry (fail-loud if unregistered).
    cache_instance: P.CacheAdapter | None = None
    if settings.cache_driver != "none":
        cache_cls = reg.resolve("cache", settings.cache_driver)
        cache_instance = cache_cls(*_cache_args(settings))
```

Pass it into the `Adapters(...)` return:

```python
    return Adapters(
        relational=relational_cls(*_relational_args(settings)),
        vector=vector_cls(*_vector_args(settings)),
        secret=secret_cls(*_secret_args(settings)),
        embedding=embedding_cls(*_embedding_args(settings)),
        observability=observability_cls(*_observability_args(settings)),
        cache=cache_instance,
        object_store=object_store_instance,
    )
```

Add the `_cache_args` helper alongside the others (`factory.py:189+`):

```python
def _cache_args(s: Settings) -> tuple[Any, ...]:
    if s.cache_driver == "memory":
        return ()
    if s.cache_driver == "redis":
        return (s.redis_url,)
    return ()
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/db/test_cache_factory.py -v`
Expected: PASS (4 tests). Also run the existing factory suite: `uv run pytest tests/unit/db/test_adapter_factory.py -v` (the new optional field must not break existing construction).

- [ ] **Step 6: HALT-before-commit, then commit**

Full-tree mypy/ruff + halt summary (the `"none"` skip-branch is the new control path; note the `Adapters` field is optional for direct-construction ergonomics but `build_adapters` always sets it). Wait for `commit`.

```bash
git add src/cognic_agentos/db/adapters/factory.py tests/unit/db/test_cache_factory.py
git commit -m "feat(harness): wire cache adapter into the pool with a none-opt-out skip"
```

## Task 4: `core/config.py` — Settings + strict-profile cache guard

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (8 new Settings + 2 new guard clauses in `_validate_wave1_deploy_safety_guards` `:1266-1401`)
- Test: `tests/unit/core/test_config_cache_guards.py`

**HALT-before-commit** (`core/` stop-rule + deploy-safety guard). `Path` is already imported in `config.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_config_cache_guards.py
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cognic_agentos.core.config import Settings, build_settings_without_env_file


def _settings(**overrides) -> Settings:
    # Fresh construction RUNS the model validators. Pydantic v2 model_copy(update=...)
    # does NOT re-validate — NEVER use it for validator tests. _env_file=None
    # suppresses .env (mirror tests/unit/core/test_config_wave1_guards.py).
    return Settings(_env_file=None, **overrides)


def _prod_compliant(**overrides) -> Settings:
    # Strict (prod) Settings that passes G1-G8 so only the cache guard is exercised.
    from tests.unit.core.test_config_wave1_guards import prod_compliant_settings_kwargs  # type: ignore[attr-defined]

    return Settings(_env_file=None, **{**prod_compliant_settings_kwargs(), **overrides})


def test_cache_driver_defaults_to_none() -> None:
    assert _settings().cache_driver == "none"


def test_new_gateway_memory_setting_defaults() -> None:
    s = _settings()
    assert s.litellm_config_path == Path("infra/litellm/config.yaml")
    assert s.llm_sla_total_budget_s == 30.0
    assert s.llm_sla_warning_threshold_s == 20.0
    assert s.memory_policy_bundle == Path("policies/_default/memory.rego")
    assert s.memory_purpose_matrix_policy_bundle == Path(
        "policies/_default/memory_purpose_matrix.rego"
    )
    assert s.memory_vector_recall_enabled is False


def test_redis_without_url_fails_loud_any_profile() -> None:
    with pytest.raises(ValidationError, match="redis_url_unset_for_redis_cache_driver"):
        _settings(cache_driver="redis", redis_url=None)


def test_dev_allows_memory_cache_driver() -> None:
    assert _settings(cache_driver="memory").cache_driver == "memory"


def test_strict_forbids_memory_cache_driver() -> None:
    with pytest.raises(ValidationError, match="cache_driver_memory_forbidden_in_strict_profile"):
        _prod_compliant(cache_driver="memory")


def test_strict_allows_redis_with_url() -> None:
    assert _prod_compliant(cache_driver="redis", redis_url="redis://r:6379/0").cache_driver == "redis"


def test_strict_allows_none() -> None:
    assert _prod_compliant(cache_driver="none").cache_driver == "none"
```

> **Implementer note:** validator tests MUST construct fresh via `Settings(_env_file=None, **overrides)` — Pydantic v2 `model_copy(update=...)` does **not** re-run validators, so the guards would never fire (the tests would be vacuous/red). If `tests/unit/core/test_config_wave1_guards.py` has no reusable `prod_compliant_settings_kwargs()` helper, extract one (the file already builds a prod Settings passing G1-G8). The strict tests cannot use `build_settings_without_env_file()` (dev-profile).

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/test_config_cache_guards.py -v`
Expected: FAIL — unknown fields / guard not present.

- [ ] **Step 3: Add the 8 Settings**

Add `cache_driver` + `redis_url` near the other `*_driver` fields (after `obs_driver`, `config.py:400`):

```python
    cache_driver: Literal["none", "redis", "memory"] = Field(
        default="none",
        description=(
            "Cache/Redis adapter driver. 'none' (default) = no cache, governed "
            "memory disabled (pack-only deploys need no Redis). 'redis' = the real "
            "adapter (requires redis_url). 'memory' = TEST-ONLY in-memory fixture "
            "(forbidden in strict profiles)."
        ),
    )
    redis_url: str | None = Field(
        default=None,
        description="Redis URL (e.g. redis://localhost:6379/0). Required when cache_driver='redis'.",
    )
```

Add the gateway settings near the LLM block (after `llm_concurrency_mode`, `config.py:560`):

```python
    litellm_config_path: Path = Field(
        default=Path("infra/litellm/config.yaml"),
        description=(
            "Path to the LiteLLM model_list YAML consumed by PreflightResolver at "
            "gateway construction. Must exist when the harness builds the gateway "
            "(deploy artifact, like the rego bundles)."
        ),
    )
    llm_sla_total_budget_s: float = Field(
        default=30.0, gt=0.0, description="Gateway SLAPolicy total budget (seconds)."
    )
    llm_sla_warning_threshold_s: float = Field(
        default=20.0,
        ge=0.0,
        description=(
            "Gateway SLAPolicy soft-warning threshold (seconds). MUST be < "
            "llm_sla_total_budget_s — SLAPolicy enforces this at construction "
            "(build_runtime), so a bad pair fails loud at startup."
        ),
    )
```

Add the memory bundle settings near `memory_kill_switch_cache_ttl_s` (`config.py:1773`):

```python
    memory_policy_bundle: Path = Field(
        default=Path("policies/_default/memory.rego"),
        description=(
            "Rego bundle for the memory governance OPAEngine (long_term / "
            "cross_subject / restricted_class_write). Single FILE (OPAEngine is a "
            "single-file loader)."
        ),
    )
    memory_purpose_matrix_policy_bundle: Path = Field(
        default=Path("policies/_default/memory_purpose_matrix.rego"),
        description=(
            "Rego bundle for the purpose-compatibility OPAEngine "
            "(recall.purpose_compatible). Separate file — the harness "
            "MemoryPolicyRouter routes between the two."
        ),
    )
    memory_vector_recall_enabled: bool = Field(
        default=False,
        description=(
            "Opt-in (default OFF): when true AND cache_driver != 'none', the harness "
            "wires MemoryVectorIndex (episodic recall) + calls ensure_collection() at "
            "startup — coupling /memory startup to the vector backend (qdrant). Default "
            "false keeps /memory decoupled; the 4 portal endpoints don't use vector recall."
        ),
    )
```

- [ ] **Step 4: Add the two guard clauses**

In `_validate_wave1_deploy_safety_guards` (`config.py:1266-1401`), before the final `return self`:

```python
        # G9 — cache_driver="memory" forbidden in strict profiles. An in-memory
        # write-freeze kill switch cannot propagate the ADR-018 <=30s freeze
        # across instances; a strict /memory must be Redis-backed. (The driver is
        # also unregistered in src/ runtime, so it would fail at resolve anyway —
        # this is the legible deploy-safety refusal.)
        if strict and self.cache_driver == "memory":
            raise ValueError(
                "cache_driver_memory_forbidden_in_strict_profile: cache_driver='memory' "
                "is the test-only in-memory driver; stage/prod must use 'redis' (governed "
                "memory enabled) or 'none' (disabled)"
            )

        # G10 — redis_url required when cache_driver='redis' (EVERY profile: the
        # RedisAdapter cannot construct without a URL).
        if self.cache_driver == "redis" and self.redis_url is None:
            raise ValueError(
                "redis_url_unset_for_redis_cache_driver: cache_driver='redis' requires "
                "redis_url to be set"
            )
```

Update the validator docstring's guard list (G1-G8 → add G9/G10).

- [ ] **Step 5: Run to verify it passes + the existing guard suite**

Run: `uv run pytest tests/unit/core/test_config_cache_guards.py tests/unit/core/test_config_wave1_guards.py -v`
Expected: PASS.

- [ ] **Step 6: TM-revert proof (per `feedback_security_regression_hardening`)**

Temporarily neutralise the G9 clause (comment the `raise`), run `test_strict_forbids_memory_cache_driver` → it MUST FAIL; restore → PASS. Do the same for G10. Record both in the halt summary.

- [ ] **Step 7: HALT-before-commit, then commit**

Full-tree `uv run mypy src tests` + `uv run ruff check .` + `uv run ruff format --check .` + halt summary (map G9/G10 to their pinning tests + the TM-revert results). Wait for `commit`.

```bash
git add src/cognic_agentos/core/config.py tests/unit/core/test_config_cache_guards.py
git commit -m "feat(harness): cache/gateway/memory Settings + strict-profile cache guards (G9/G10)"
```

---

## Task 5: `harness/` package — `Runtime` + `build_runtime` (gateway path)

**Files:**
- Create: `src/cognic_agentos/harness/__init__.py`, `src/cognic_agentos/harness/runtime.py`
- Test: `tests/unit/harness/test_runtime.py`

**HALT-before-commit** (composition root). This task builds the gateway path only; the memory path is a stub branch filled in T6.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/harness/test_runtime.py
from __future__ import annotations

import pytest

from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.harness import Runtime, build_runtime
from cognic_agentos.llm.gateway import LLMGateway


def _litellm_yaml(tmp_path):
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


async def test_build_runtime_yields_usable_gateway(memory_registry, memory_settings, tmp_path):
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert isinstance(runtime, Runtime)
        assert isinstance(runtime.llm_gateway, LLMGateway)
        # cache_driver="none" → memory not wired.
        assert runtime.memory_api_factory is None
        assert runtime.memory_policy is None
        await runtime.aclose()  # must not raise
    finally:
        await adapters.close_all()


async def test_build_runtime_resolves_vault_master_key(memory_registry, memory_settings, tmp_path):
    """A vault:// litellm_master_key is RESOLVED at build time — the gateway holds
    the PLAIN value, never the URI (an unresolved URI would put 'Bearer vault://...'
    on the wire). 'No raise' is NOT sufficient: build_runtime passes a non-None key,
    so the gateway ctor's None-guard would not catch an unresolved URI — we assert
    the resolved value directly."""
    s = memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "none",
            "litellm_master_key": "vault://secret/llm",
            "vault_addr": "http://vault:8200",
            "vault_token": "dev-token",
        }
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    # Seed the in-memory secret store so resolve_secret_field returns the plain
    # value. The secret at the path is a {"key": "<value>"} dict (the _VAULT_KEY_FIELD
    # contract); mirror tests/unit/db/test_secret_resolution.py for the exact
    # in-memory-adapter seed call.
    _seed_in_memory_secret(adapters.secret, path="secret/llm", value={"key": "sk-resolved"})
    try:
        runtime = await build_runtime(s, adapters)
        assert runtime.llm_gateway._litellm_master_key == "sk-resolved"
        await runtime.aclose()
    finally:
        await adapters.close_all()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/harness/test_runtime.py::test_build_runtime_yields_usable_gateway -v`
Expected: FAIL — `harness` package does not exist.

- [ ] **Step 3: Create `harness/__init__.py`**

```python
"""AgentOS runtime composition root (Workstream #2 — Harness Injection).

OS runtime wiring ONLY — never Layer-C agent behaviour. ``build_runtime``
constructs the real kernel runtime (LLMGateway + governed-memory factory) from
Settings + the adapter pool; ``create_prod_app`` calls it from the lifespan.
"""

from __future__ import annotations

from cognic_agentos.harness.runtime import Runtime, build_runtime

__all__ = ("Runtime", "build_runtime")
```

- [ ] **Step 4: Create `harness/runtime.py` (gateway path; memory branch stubbed)**

```python
"""``build_runtime(settings, adapters) -> Runtime`` — the canonical composition root.

Builds a minimal spine (engine→AuditStore/DecisionHistoryStore), the LLMGateway,
and — only when a cache adapter is present (cache_driver != "none") — the
governed-memory API factory (T6). Runs async inside the FastAPI lifespan after
``adapters.open_all()`` (the engine + any vault:// resolution are async).
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import TYPE_CHECKING

import httpx as _httpx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.secret_resolution import resolve_secret_field
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.memory.api import MemoryApiFactory
    from cognic_agentos.db.adapters.factory import Adapters
    from cognic_agentos.harness.memory_policy import MemoryPolicyRouter

#: SLA policy audit-label (NOT operator-tunable — a name, not a budget; per the
#: locked decision, no name Setting).
_SLA_POLICY_NAME = "llm-gateway"


@dataclasses.dataclass(frozen=True, slots=True)
class Runtime:
    """Constructed kernel runtime. Public members are the two Bucket-2 seams;
    the spine is exposed for future reuse (broker / packs / UI) but nothing new
    consumes it this workstream."""

    llm_gateway: LLMGateway
    memory_api_factory: MemoryApiFactory | None
    audit_store: AuditStore
    decision_history_store: DecisionHistoryStore
    memory_policy: MemoryPolicyRouter | None
    _http_client: _httpx.AsyncClient

    async def aclose(self) -> None:
        """Close runtime-owned resources (the gateway's HTTP client). The
        adapter pool's lifecycle (relational engine, cache client) is owned by
        ``Adapters.close_all`` — NOT here."""
        await self._http_client.aclose()


async def build_runtime(settings: Settings, adapters: Adapters) -> Runtime:
    engine = adapters.relational.engine
    audit_store = AuditStore(engine)
    decision_history_store = DecisionHistoryStore(engine)

    # --- Gateway ----------------------------------------------------------
    ledger = GatewayCallLedger(engine)
    rate_limiter = ProfileRateLimiter(
        per_profile=settings.llm_concurrency_per_profile,
        mode=settings.llm_concurrency_mode,
    )
    preflight = PreflightResolver.from_yaml(settings.litellm_config_path)
    sla_policy = SLAPolicy(
        name=_SLA_POLICY_NAME,
        total_budget=timedelta(seconds=settings.llm_sla_total_budget_s),
        warning_threshold=timedelta(seconds=settings.llm_sla_warning_threshold_s),
    )
    litellm_key = settings.litellm_master_key
    if litellm_key is not None and litellm_key.startswith("vault://"):
        litellm_key = await resolve_secret_field(
            litellm_key, secret_adapter=adapters.secret, field_name="litellm_master_key"
        )
    http_client = _httpx.AsyncClient(timeout=settings.llm_timeout_s)
    gateway = LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        http_client=http_client,
        litellm_master_key=litellm_key,
    )

    # --- Memory factory (T6 fills this branch) ----------------------------
    memory_api_factory: MemoryApiFactory | None = None
    memory_policy: MemoryPolicyRouter | None = None
    # if adapters.cache is not None: ... (T6)

    return Runtime(
        llm_gateway=gateway,
        memory_api_factory=memory_api_factory,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        memory_policy=memory_policy,
        _http_client=http_client,
    )
```

> **Resolved:** `LLMGateway` has **no** `close()`/`aclose()` method (confirmed), so `Runtime` owns the `http_client` (passed via `http_client=`) and closes it in `aclose` — as coded above. No `gateway.py` change (it stays construct-not-edit). (`from __future__ import annotations` is present — `harness/runtime.py` is not a FastAPI closure-local-`Depends` module, so PEP-563 is safe here.)

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/unit/harness/test_runtime.py::test_build_runtime_yields_usable_gateway -v`
Expected: PASS. (Implement `test_build_runtime_resolves_vault_master_key` per the secret_resolution fixture pattern and make it pass too.)

- [ ] **Step 6: HALT-before-commit, then commit**

Full-tree mypy/ruff + halt summary (the new composition root; the spine; the vault:// resolve seam; aclose lifecycle). Wait for `commit`.

```bash
git add src/cognic_agentos/harness/__init__.py src/cognic_agentos/harness/runtime.py tests/unit/harness/test_runtime.py
git commit -m "feat(harness): build_runtime composition root — gateway path"
```

---

## Task 6: `MemoryPolicyRouter` + `build_runtime` memory path

**Files:**
- Create: `src/cognic_agentos/harness/memory_policy.py`
- Modify: `src/cognic_agentos/harness/runtime.py` (fill the memory branch)
- Test: `tests/unit/harness/test_memory_policy.py`, extend `tests/unit/harness/test_runtime.py`

**HALT-before-commit** (composition root + memory wiring).

- [ ] **Step 1: Write the failing test for the router**

```python
# tests/unit/harness/test_memory_policy.py
from __future__ import annotations

import pytest

from cognic_agentos.harness.memory_policy import MemoryPolicyRouter


class _RecordingEngine:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.calls: list[str] = []

    async def evaluate(self, *, decision_point: str, input: dict):
        self.calls.append(decision_point)
        return _Decision(tag=self.tag)


class _Decision:
    def __init__(self, tag: str) -> None:
        self.allow = True
        self.tag = tag


@pytest.mark.parametrize(
    "decision_point,expected_tag",
    [
        ("data.cognic.memory.long_term.allow", "memory"),
        ("data.cognic.memory.cross_subject.allow", "memory"),
        ("data.cognic.memory.restricted_class_write.allow", "memory"),
        ("data.cognic.memory.recall.purpose_compatible.allow", "purpose_matrix"),
    ],
)
async def test_router_dispatches_decision_point(decision_point, expected_tag) -> None:
    mem = _RecordingEngine("memory")
    pm = _RecordingEngine("purpose_matrix")
    router = MemoryPolicyRouter(memory_engine=mem, purpose_matrix_engine=pm)  # type: ignore[arg-type]
    result = await router.evaluate(decision_point=decision_point, input={})
    assert result.tag == expected_tag


async def test_router_raises_on_unknown_decision_point() -> None:
    from cognic_agentos.harness.memory_policy import MemoryPolicyDecisionPointUnknown

    mem = _RecordingEngine("memory")
    pm = _RecordingEngine("purpose_matrix")
    router = MemoryPolicyRouter(memory_engine=mem, purpose_matrix_engine=pm)  # type: ignore[arg-type]
    with pytest.raises(MemoryPolicyDecisionPointUnknown, match="memory_policy_decision_point_unknown"):
        await router.evaluate(decision_point="data.cognic.memory.bogus.allow", input={})
    assert mem.calls == [] and pm.calls == []  # never delegated on the unknown path
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/harness/test_memory_policy.py -v`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Create `harness/memory_policy.py`**

```python
"""``MemoryPolicyRouter`` — routes memory Rego decision points across the TWO
single-file OPAEngines MemoryGate needs.

``OPAEngine`` loads exactly one ``.rego`` file (``engine.py:204`` —
``bundle_path.is_file()``), but ``MemoryGate`` queries four decision points
spanning ``memory.rego`` (long_term / cross_subject / restricted_class_write)
and ``memory_purpose_matrix.rego`` (recall.purpose_compatible). This router
presents the exact ``OPAEngine.evaluate(...)`` interface MemoryGate calls and
delegates — the per-point fail-closed (OpaNotInstalledError / RegoEvaluationError)
stays in MemoryGate. Harness-owned (NOT core/memory) per the locked design;
``build_runtime`` passes it as MemoryAPI's ``policy`` with ``# type: ignore[arg-type]``
(MemoryGate types ``policy: OPAEngine``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cognic_agentos.core.policy.engine import Decision, OPAEngine

#: The ONLY decision point served by memory_purpose_matrix.rego (gate.py:93).
_PURPOSE_MATRIX_DECISION_POINT = "data.cognic.memory.recall.purpose_compatible.allow"

#: The decision points served by memory.rego (gate.py:90-92). A test-only drift
#: detector pins this set + _PURPOSE_MATRIX_DECISION_POINT against the gate.py
#: constants (per feedback_drift_detector_test_only_no_runtime_import).
_MEMORY_DECISION_POINTS: frozenset[str] = frozenset(
    {
        "data.cognic.memory.long_term.allow",
        "data.cognic.memory.cross_subject.allow",
        "data.cognic.memory.restricted_class_write.allow",
    }
)


class MemoryPolicyDecisionPointUnknown(ValueError):
    """The router was asked to evaluate a decision point outside the known memory
    set — fail loud (a programming error: the gate queried an unexpected point)
    rather than silently routing it to memory.rego."""


class MemoryPolicyRouter:
    def __init__(self, *, memory_engine: OPAEngine, purpose_matrix_engine: OPAEngine) -> None:
        self._memory = memory_engine
        self._purpose_matrix = purpose_matrix_engine

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        if decision_point == _PURPOSE_MATRIX_DECISION_POINT:
            return await self._purpose_matrix.evaluate(decision_point=decision_point, input=input)
        if decision_point in _MEMORY_DECISION_POINTS:
            return await self._memory.evaluate(decision_point=decision_point, input=input)
        raise MemoryPolicyDecisionPointUnknown(
            f"memory_policy_decision_point_unknown: {decision_point!r}"
        )
```

- [ ] **Step 4: Fill the memory branch in `build_runtime`**

Replace the `# if adapters.cache is not None: ... (T6)` placeholder in `runtime.py` with (memory imports are **function-local** so the gateway-only path stays import-light):

```python
    if adapters.cache is not None:
        # Function-local imports: only loaded when memory is actually wired.
        from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
        from cognic_agentos.core.emergency.kill_switches import RedisMemoryWriteFreezeKillSwitch
        from cognic_agentos.core.memory._routing import RoutingMemoryAdapter
        from cognic_agentos.core.memory.api import MemoryAPI, MemoryCallerContext
        from cognic_agentos.core.memory.consent import ConsentValidator
        from cognic_agentos.core.memory.storage import PostgresMemoryAdapter, RedisMemoryAdapter
        from cognic_agentos.core.memory.vector import MemoryVectorIndex
        from cognic_agentos.core.policy.engine import OPAEngine
        from cognic_agentos.harness.memory_policy import MemoryPolicyRouter as _Router

        memory_engine = await OPAEngine.create(
            bundle_path=settings.memory_policy_bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        purpose_matrix_engine = await OPAEngine.create(
            bundle_path=settings.memory_purpose_matrix_policy_bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        memory_policy = _Router(
            memory_engine=memory_engine, purpose_matrix_engine=purpose_matrix_engine
        )

        cache_client = adapters.cache.client
        routing_adapter = RoutingMemoryAdapter(
            redis_adapter=RedisMemoryAdapter(
                redis_client=cache_client, scratch_ttl_s=settings.memory_scratch_ttl_s
            ),
            pg_adapter=PostgresMemoryAdapter(engine=engine, dh_store=decision_history_store),
            scratch_ttl_s=settings.memory_scratch_ttl_s,
        )
        dlp = ChecksumRegexGazetteerScanner()
        consent = ConsentValidator(audit=decision_history_store)
        kill_switch = RedisMemoryWriteFreezeKillSwitch(
            redis_client=cache_client, cache_ttl_s=settings.memory_kill_switch_cache_ttl_s
        )

        # vector_index — opt-in episodic recall (default OFF). Gated on
        # memory_vector_recall_enabled so /memory startup is NOT coupled to the
        # vector backend (qdrant) reachability by default; the 4 portal endpoints
        # don't use vector recall. When enabled, ensure_collection() runs once.
        vector_index = None
        if settings.memory_vector_recall_enabled:
            vector_index = MemoryVectorIndex(
                embedder=adapters.embedding,
                client=adapters.vector,
                collection=settings.memory_vector_collection,
            )
            await vector_index.ensure_collection()
        object_store = adapters.object_store

        def _factory(ctx: MemoryCallerContext) -> MemoryAPI:
            return MemoryAPI(
                context=ctx,
                adapter=routing_adapter,
                dlp=dlp,
                consent=consent,
                policy=memory_policy,  # type: ignore[arg-type]  # router conforms structurally (mirrors _build_api)
                kill_switch=kill_switch,
                audit=decision_history_store,
                settings=settings,
                object_store=object_store,
                vector_index=vector_index,
            )

        memory_api_factory = _factory
```

- [ ] **Step 5: Extend the runtime test (memory path)**

Add to `tests/unit/harness/test_runtime.py` (needs a **migrated** relational DB — `OPAEngine.create` emits a `policy.bundle_loaded` decision-history row; reuse the migrated-DB fixture pattern from `tests/unit/core/memory/conftest.py`). The rego files exist in-repo, so construction is `opa`-binary-free:

```python
async def test_build_runtime_wires_memory_when_cache_present(
    migrated_memory_settings, migrated_memory_registry, tmp_path
):
    """With cache_driver='memory' the factory + router are wired. Construction is
    opa-binary-free (engines construct + warn without the binary); end-to-end
    ALLOW is env-gated, out of this test."""
    s = migrated_memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=migrated_memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert runtime.memory_api_factory is not None
        assert runtime.memory_policy is not None
        # The factory mints a MemoryAPI for a caller context.
        from cognic_agentos.core.memory.api import MemoryAPI
        ctx = _a_memory_caller_context()  # build per core/memory test helpers
        assert isinstance(runtime.memory_api_factory(ctx), MemoryAPI)
        await runtime.aclose()
    finally:
        await adapters.close_all()
```

> **Implementer note:** `migrated_memory_settings`/`migrated_memory_registry` + `_a_memory_caller_context` come from the existing `tests/unit/core/memory/conftest.py` patterns (the migrated SQLite DB + a `MemoryCallerContext` builder). If those fixtures are package-scoped, lift the shared bits into `tests/support/` or a conftest reachable from `tests/unit/harness/`.

- [ ] **Step 6: Run to verify it passes**

Run: `uv run pytest tests/unit/harness/test_memory_policy.py tests/unit/harness/test_runtime.py -v`
Expected: PASS.

- [ ] **Step 7: HALT-before-commit, then commit**

Full-tree mypy/ruff (the `# type: ignore[arg-type]` must be the ONLY one + justified) + halt summary (the two-engine router; the function-local memory imports keeping the gateway path clean; the vector_index opt-in decoupling via `memory_vector_recall_enabled`). Wait for `commit`.

```bash
git add src/cognic_agentos/harness/memory_policy.py src/cognic_agentos/harness/runtime.py tests/unit/harness/test_memory_policy.py tests/unit/harness/test_runtime.py
git commit -m "feat(harness): two-bundle MemoryPolicyRouter + build_runtime memory factory"
```

## Task 7: `portal/api/memory/routes.py` — request-time factory resolution

**Files:**
- Modify: `src/cognic_agentos/portal/api/memory/routes.py` (`build_memory_routes` `:99` + the 4 handlers)
- Modify: `src/cognic_agentos/portal/api/app.py` (the ONE caller line in the memory-mount block — `build_memory_routes(memory_api_factory=...)` → `build_memory_routes()`; the `if memory_api_factory is not None:` gate STAYS unchanged — T8 reworks it to `cache_driver != "none"`)
- Test: `tests/unit/portal/api/memory/test_memory_routes.py` (append the mounted-but-unwired 503 class, reusing the existing `_build_app` / `_make_memory_actor` / `_CapturingFactory` harness)

**Option B (locked 2026-06-05):** a signature change moves with its direct caller, so T7 includes the one-line `app.py` caller update. Option A (keep the closure param as a dead-but-accepted kwarg for one task) was rejected as compatibility-surface cruft. The construction-time mount-gate rework, the lifespan `build_runtime`, and the `llm_gateway` kwarg all stay in **T8**.

**HALT-before-commit** (governance-adjacent surface + composition root). `routes.py` intentionally omits `from __future__ import annotations` (PEP-563/closure-local-`Depends` rule) — the new dependency is **module-level**, so this is unaffected. **Do not** add the future-import. **Full suite at the commit gate** (T7 touches the portal route surface + `app.py` — broader than the harness-only commits).

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/unit/portal/api/memory/test_memory_routes.py — reuse the
# file's existing harness (_build_app / _make_memory_actor / _CapturingFactory
# / _FakeMemoryAPI; _StubBinder returns the actor directly, no auth headers).


class TestRequestTimeFactoryResolution:
    """Mounted-but-unwired /memory route fails closed 503 memory_unavailable.

    Regression for the closure->app.state migration: with the pre-T7 closure
    code, nulling app.state.memory_api_factory has NO effect (the handler used
    the captured kwarg) -> 200 -> this test FAILS. It passes only when the
    handler reads app.state per request."""

    def test_mounted_but_unwired_factory_returns_503(self) -> None:
        # Mount via a supplied factory (satisfies the UNCHANGED
        # `if memory_api_factory is not None` gate), then null app.state to
        # simulate the prod lifespan not yet populating the factory. RBAC MUST
        # pass (default actor holds memory.read) so the FACTORY dep is what
        # fires — the load-bearing assertion is the exact 503 memory_unavailable.
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        app = _build_app(actor=actor, factory=factory)
        assert getattr(app.state, "memory_router_mounted", False) is True
        app.state.memory_api_factory = None  # mounted, but unwired
        client = TestClient(app)
        resp = client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": "agent-1"},
        )
        assert resp.status_code == 503
        assert resp.json()["detail"]["reason"] == "memory_unavailable"
        assert factory.last_context is None  # dep fired before the handler body
```

> **Why this shape (not a `cache_driver=redis` construction-mount):** under Option B the T7 mount gate is STILL `if memory_api_factory is not None:`, so redis-without-a-factory would NOT mount (→ 404, not 503). The construction-time `cache_driver != "none"` mount is a **T8** change. Mounting via a supplied factory + nulling `app.state.memory_api_factory` is the Option-B way to reach "mounted but unwired" — and is a STRONGER regression: it passes only once the handler reads `app.state` per request (the old closure ignores the null → 200). RBAC MUST pass (the default `_make_memory_actor()` holds `memory.read`) so the **factory** dep is what fires — the load-bearing assertion is the **exact** `503 memory_unavailable` (never 403-masked, never 500).

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/portal/api/memory/test_routes_app_state.py -v`
Expected: FAIL — `build_memory_routes()` still requires the `memory_api_factory` kwarg.

- [ ] **Step 3: Add the module-level resolver + drop the closure param**

Add to `routes.py` imports: `from fastapi import Request` (extend the existing `from fastapi import ...` line). Add the module-level dependency (after the `_MEMORY_RECORD_NOT_FOUND` constant, `routes.py:70`):

```python
def _require_memory_api_factory(request: Request) -> MemoryApiFactory:
    """Resolve the memory API factory from ``app.state`` at request time.

    The factory is populated at app construction (test path) or by
    ``build_runtime`` in the lifespan (prod path). A mounted route whose factory
    is still absent fails closed ``503 memory_unavailable`` — never 500."""
    factory = getattr(request.app.state, "memory_api_factory", None)
    if factory is None:
        raise HTTPException(status_code=503, detail={"reason": "memory_unavailable"})
    return factory
```

Change the factory signature (`routes.py:99`) from `def build_memory_routes(*, memory_api_factory: MemoryApiFactory) -> APIRouter:` to `def build_memory_routes() -> APIRouter:` and update its docstring (the factory is resolved per-request from `app.state`, not closure-captured).

In each of the 4 handlers (`list_records` / `forget` / `redact` / `export`), add the dependency param and use it:

```python
        factory: Annotated[MemoryApiFactory, Depends(_require_memory_api_factory)],
```

and replace each `api: MemoryAPI = memory_api_factory(ctx)` with `api: MemoryAPI = factory(ctx)`.

Then update the ONE caller in `app.py`'s memory-mount block (Option B — the signature change moves with its caller): `build_memory_routes(memory_api_factory=memory_api_factory)` → `build_memory_routes()`. Leave the `if memory_api_factory is not None:` gate AND the `app.state.memory_api_factory = memory_api_factory` seed (`app.py:675`) UNCHANGED.

- [ ] **Step 4: Run to verify it passes + the existing memory-route suite**

Run: `uv run pytest tests/unit/portal/api/memory/ tests/unit/portal/test_app_factory_actor_binder_wiring.py -v`
Expected: PASS. The existing endpoint tests reach the factory via `app.state.memory_api_factory` (already seeded at `app.py:675` on the `create_app(memory_api_factory=...)` path) — NO existing test edits needed (none call `build_memory_routes` directly; the only call sites are the `app.py` caller + the `memory/__init__.py` re-export).

- [ ] **Step 5: HALT-before-commit, then commit**

Full-tree mypy/ruff + **full suite** + halt summary (the closure→`app.state` resolution; the one-line `app.py` caller; the 503 fail-closed; the future-import-omission invariant preserved). Wait for `commit`.

```bash
git add src/cognic_agentos/portal/api/memory/routes.py \
        src/cognic_agentos/portal/api/app.py \
        tests/unit/portal/api/memory/test_memory_routes.py \
        docs/superpowers/plans/2026-06-05-harness-injection.md
git commit -m "feat(harness): /memory handlers resolve factory from app.state + 503 fail-closed"
```

---

## Task 8: `portal/api/app.py` — `llm_gateway` kwarg + construction-time mount gate + lifespan `build_runtime`

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (`create_app` signature; the memory-mount block `:912-928`; the lifespan adapter path `:510-560`; `app.state` `:675`)
- Test: `tests/unit/portal/api/test_app_harness_wiring.py`

**HALT-before-commit** (composition root). `app.py` omits `from __future__ import annotations` (FastAPI closure-local `Depends`) — **do not** add it.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/portal/api/test_app_harness_wiring.py
from __future__ import annotations

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.portal.api.app import create_app


def _compiled_paths(app) -> set[str]:
    return {getattr(r, "path", None) for r in app.routes}


def test_llm_gateway_kwarg_stored_on_state() -> None:
    sentinel = object()
    app = create_app(llm_gateway=sentinel)  # type: ignore[arg-type]
    assert app.state.llm_gateway is sentinel


def test_memory_router_mounted_when_cache_configured() -> None:
    s = build_settings_without_env_file().model_copy(
        update={"cache_driver": "redis", "redis_url": "redis://x:6379/0"}
    )
    app = create_app(s)
    assert any(p and p.startswith("/api/v1/memory") for p in _compiled_paths(app))
    assert app.state.memory_router_mounted is True


def test_memory_router_absent_when_cache_none() -> None:
    s = build_settings_without_env_file().model_copy(update={"cache_driver": "none"})
    app = create_app(s)
    assert not any(p and p.startswith("/api/v1/memory") for p in _compiled_paths(app))
    assert app.state.memory_router_mounted is False
```

> **Added during execution (2026-06-05):** a 4th async test
> `test_lifespan_build_runtime_populates_state` reuses the root-conftest
> `memory_registry` / `memory_settings` fixtures + enters the lifespan
> (`async with app.router.lifespan_context(app)`) to assert build_runtime
> populates `app.state.{runtime, llm_gateway, memory_api_factory}` on the adapter
> path. `cache_driver="none"` → gateway-only (memory_api_factory stays None); the
> pre-startup `app.state.runtime is None` pre-seed confirms the LIFESPAN (not
> construction) does the population — directly pinning the deliverable the 3
> construction-time tests only exercise indirectly.

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/portal/api/test_app_harness_wiring.py -v`
Expected: FAIL — no `llm_gateway` kwarg; mount gate still only checks `memory_api_factory`.

- [ ] **Step 3: Add the `llm_gateway` kwarg + store on state**

Add to `create_app`'s signature (alongside the other optional deps), with the import `from cognic_agentos.llm.gateway import LLMGateway` (guard under `TYPE_CHECKING` if needed to avoid import bloat — `llm_gateway` is type-only in the signature):

```python
    llm_gateway: LLMGateway | None = None,
```

Store it on `app.state` (near the other `app.state.*` assignments, `app.py:~657`):

```python
    app.state.llm_gateway = llm_gateway
```

- [ ] **Step 4: Change the construction-time mount gate**

Replace the memory-mount block (`app.py:912-928`):

```python
    # Harness Injection: mount /memory at CONSTRUCTION time, gated on config
    # (cache_driver != "none") OR a directly-injected factory (test path). The
    # factory itself is populated at request time from app.state — by the kwarg
    # here (test) or by build_runtime in the lifespan (prod). See the spec §3.4
    # mount strategy.
    app.state.memory_router_mounted = False
    if memory_api_factory is not None or settings.cache_driver != "none":
        from cognic_agentos.portal.api.memory import build_memory_routes

        app.include_router(
            build_memory_routes(),
            prefix="/api/v1/memory",
            tags=["memory"],
        )
        app.state.memory_router_mounted = True
```

(Keep `app.state.memory_api_factory = memory_api_factory` at `app.py:675` — it seeds the test path; the lifespan overwrites it on the prod path.)

- [ ] **Step 5: Call `build_runtime` in the lifespan adapter path**

Inside the lifespan, right after `app.state.adapters = adapters` and inside the existing `try:` (so a failure runs `close_all`), add (lazy import keeps the harness out of the module import graph until the adapter path runs):

```python
            try:
                # Harness Injection: build the real kernel runtime from the live
                # adapter pool (gateway + governed-memory factory). Fail-loud — a
                # misconfigured gateway/memory must abort startup, not degrade.
                from cognic_agentos.harness import build_runtime

                runtime = await build_runtime(settings, adapters)
                app.state.runtime = runtime
                app.state.llm_gateway = runtime.llm_gateway
                app.state.memory_api_factory = runtime.memory_api_factory
                # ... existing checkpoint-reaper block stays here ...
```

In the inner `finally:`, close the runtime **before** `adapters.close_all()`
(user-locked runtime-first ordering, 2026-06-05 — the runtime's
`memory_api_factory` closes over adapter-backed clients, so close it first in
case a future runtime resource depends on them; today it owns only the gateway
HTTP client, so either order is correct but runtime-first is future-safe):

```python
            finally:
                await _shutdown_memory_reaper()
                await _shutdown_checkpoint_reaper()
                # T8: runtime-first close (getattr-guarded — a build_runtime
                # failure never set app.state.runtime, and T6's leak-fix means no
                # http client was allocated if it raised before Runtime existed).
                _runtime = getattr(app.state, "runtime", None)
                if _runtime is not None:
                    await _runtime.aclose()
                await adapters.close_all()
                app.state.adapters = None
```

> **Deploy artifact (confirmed present):** `build_runtime` reads `settings.litellm_config_path` (default `infra/litellm/config.yaml`) at construction. That file **exists in-repo** (the LiteLLM `model_list`), so the default is valid for the adapter-registry startup path — no creation needed. Integration tests that pass an `adapter_registry` rely on that file (or override `litellm_config_path` to a tmp YAML, as the harness unit tests do).

- [ ] **Step 6: Run to verify it passes**

Run: `uv run pytest tests/unit/portal/api/test_app_harness_wiring.py -v`
Expected: PASS. Then the broader portal app suite: `uv run pytest tests/unit/portal/api/test_app*.py -v` (the new kwarg + mount gate must not break existing factory tests).

- [ ] **Step 7: HALT-before-commit, then commit**

Full-tree mypy/ruff + halt summary (the construction-time mount gate; the lifespan `build_runtime` + `aclose`; the litellm-config deploy-artifact note; confirm no existing app test regressed). Wait for `commit`.

```bash
git add src/cognic_agentos/portal/api/app.py tests/unit/portal/api/test_app_harness_wiring.py
git commit -m "feat(harness): wire build_runtime into create_prod_app lifespan + construction-time /memory gate"
```

---

## Task 9: Architecture fences (the 5 pins)

**Files:**
- Test: `tests/unit/architecture/test_harness_fences.py`

**HALT-before-commit** (these pin the security fences per `feedback_security_regression_hardening`). AST-scan tests over `harness/*.py` source + one behavioural pin.

- [ ] **Step 1: Write the fence tests**

> **As-built (2026-06-05):** `_HARNESS_DIR` uses absolute `parents[3]` (NOT the
> CWD-relative path shown below — matches `test_memory_layer_c_no_direct_storage.py`),
> and a non-vacuous `test_harness_dir_has_expected_sources` guard pins the exact
> `{__init__, memory_policy, runtime}.py` set so a vanished glob cannot make the
> fences pass trivially. The kill-switch behavioural pin was FOLDED into the
> existing `test_build_runtime_wires_memory_when_cache_present` (the `migrated_*`
> fixtures + `_a_memory_caller_context()` in the snippet below DO NOT exist; the
> existing test already builds the migrated tables + mints the api) as a single
> `assert isinstance(api._gate._kill_switch, RedisMemoryWriteFreezeKillSwitch)`,
> TM-revert-proven (kill_switch=None → gate binds `_NullMemoryKillSwitchInterrogator`
> → the isinstance FAILS).

```python
# tests/unit/architecture/test_harness_fences.py
from __future__ import annotations

import ast
import pathlib

import pytest

_HARNESS_DIR = pathlib.Path("src/cognic_agentos/harness")


def _harness_sources() -> list[pathlib.Path]:
    return sorted(_HARNESS_DIR.glob("*.py"))


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text())
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_harness_imports_no_layer_c() -> None:
    for path in _harness_sources():
        for mod in _imported_modules(path):
            assert not mod.startswith("cognic_agentos.agents"), f"{path}: Layer-C import {mod}"


def test_harness_has_no_redis_import_or_client() -> None:
    # The "no harness-local Redis client" fence: build_runtime must consume
    # adapters.cache.client, never open its own Redis.
    for path in _harness_sources():
        src = path.read_text()
        for mod in _imported_modules(path):
            assert not (mod == "redis" or mod.startswith("redis.")), f"{path}: redis import {mod}"
        assert "redis.asyncio" not in src, f"{path}: references redis.asyncio"
        assert "Redis(" not in src and "Redis.from_url" not in src, f"{path}: constructs a Redis client"


def test_harness_opens_no_second_engine() -> None:
    # build_runtime must reuse adapters.relational.engine, never create_async_engine.
    for path in _harness_sources():
        for mod in _imported_modules(path):
            assert "create_async_engine" not in mod
        assert "create_async_engine" not in path.read_text(), f"{path}: opens a second engine"


def test_harness_constructs_no_bucket1_default() -> None:
    # The harness must invent no bank-overlay default (ActorBinder /
    # TrustRootResolver / ElicitationAdapter / KernelDefaultCredentialAdapter).
    forbidden = ("KernelDefaultActorBinder", "KernelDefaultTrustRootResolver",
                 "KernelDefaultElicitationAdapter", "KernelDefaultCredentialAdapter")
    for path in _harness_sources():
        src = path.read_text()
        for name in forbidden:
            assert name not in src, f"{path}: constructs Bucket-1 default {name}"
```

For the **kill-switch-never-`_Null`** pin (behavioural — when memory mounts, the kill switch is the real Redis impl), add to `tests/unit/harness/test_runtime.py`:

```python
async def test_wired_memory_kill_switch_is_real_redis_never_null(
    migrated_memory_settings, migrated_memory_registry, tmp_path
):
    """When build_runtime wires memory, the MemoryAPI's kill switch is a real
    RedisMemoryWriteFreezeKillSwitch — never the _Null fail-loud sentinel."""
    from cognic_agentos.core.emergency.kill_switches import RedisMemoryWriteFreezeKillSwitch

    s = migrated_memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=migrated_memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        api = runtime.memory_api_factory(_a_memory_caller_context())  # type: ignore[misc]
        # MemoryAPI binds the gate; assert the bound kill switch type via the gate.
        assert isinstance(api._gate._kill_switch, RedisMemoryWriteFreezeKillSwitch)
        await runtime.aclose()
    finally:
        await adapters.close_all()
```

> **TM-revert proof:** temporarily change `build_runtime` to pass `kill_switch=None` → this test (and `_NullMemoryKillSwitchInterrogator` binding) must FAIL the assertion; restore. Record in the halt summary. (Reaching into `api._gate._kill_switch` is acceptable in a test pin; if a public accessor is preferred, note it but do not add one to `core/memory` — stop-rule.)

- [ ] **Step 2: Run to verify behaviour**

Run: `uv run pytest tests/unit/architecture/test_harness_fences.py tests/unit/harness/test_runtime.py -v`
Expected: PASS (fences green against the real `harness/` tree).

- [ ] **Step 3: HALT-before-commit, then commit**

Halt summary mapping each of the 5 fences → its test + the kill-switch TM-revert result. Wait for `commit`.

```bash
git add tests/unit/architecture/test_harness_fences.py \
        tests/unit/harness/test_runtime.py \
        docs/superpowers/plans/2026-06-05-harness-injection.md
git commit -m "test(harness): architecture fences (no Layer-C / no local Redis / no 2nd engine / no Bucket-1 default / real kill switch)"
```

---

## Task 10: Z-gate — full suite, lint/type, CC-gate verify, closeout

**Files:**
- Create: `docs/closeouts/2026-06-05-harness-injection.md`
- Verify only (no production code)

- [ ] **Step 1: Full unit suite**

Run: `uv run pytest -q`
Expected: all green (record passed/skipped counts).

- [ ] **Step 2: Full-tree lint + types**

Run: `uv run ruff check .` · `uv run ruff format --check .` · `uv run mypy src tests`
Expected: clean. The **only** `# type: ignore[arg-type]` introduced is the `MemoryAPI(policy=router)` one (T6) — grep to confirm: `rg -n "type: ignore" src/cognic_agentos/harness/`.

- [ ] **Step 3: Critical-controls coverage gate (verify NO regression)**

Run: `uv run python tools/check_critical_coverage.py` (against a fresh `--cov-branch coverage.json` if the tool requires it).
Expected: PASS, `_EXPECTED_ENTRY_COUNT` **unchanged**. The harness is OFF the per-file gate (Doctrine F — enforcement lives in the wired CC modules: `llm/gateway.py`, the memory gate, `OPAEngine`). **No on-gate module was modified** (config/app/routes/factory are off-gate; `gateway.py`/`kill_switches.py` were constructed-not-edited). If the tool reports a delta, STOP and surface — it means an on-gate module changed unexpectedly.

- [ ] **Step 4: Write the closeout**

`docs/closeouts/2026-06-05-harness-injection.md` — the commit table (T1-T9), the locked decisions, the 8 new Settings, the two-bundle router + the single `# type: ignore`, the mount strategy, gate evidence (suite counts, lint/type clean, CC-gate unchanged), and the honest-scope markers: gateway is **primitive-wired, consumption-deferred** (no in-repo consumer of `app.state.llm_gateway` yet); memory is a **live portal consumer**; `vector_index` is **opt-in, default OFF** via `memory_vector_recall_enabled` (decoupled from the vector backend); `ParentBudgetResolver`/`VaultCredentialAdapter`/Bucket-3 remain **not wired**.

- [ ] **Step 5: HALT-before-commit (READY FOR GATE), then commit**

```bash
git add docs/closeouts/2026-06-05-harness-injection.md
git commit -m "docs(harness): Workstream #2 closeout — harness injection (gateway + governed memory wired)"
```

- [ ] **Step 6: Finish the branch**

Announce: "I'm using the finishing-a-development-branch skill." Present merge/PR options on the human's tokens (push + PR are separate explicit authorizations; never `gh pr merge --auto`).

---

## Self-review notes (controller)

- **Spec coverage:** every §7 file in the spec maps to a task (T1 protocols+registry+fixture, T2 redis_adapter, T3 factory, T4 config, T5 runtime, T6 memory_policy+memory path, T7 routes, T8 app, T9 fences, T10 Z-gate). ✓
- **Cross-task type consistency:** `_AsyncKVClient` (T1) is the `.client` return type consumed in T2/T6; `MemoryPolicyRouter.evaluate(... ) -> Decision` (T6) matches `OPAEngine.evaluate` (verified `engine.py:269`); `Runtime.memory_policy` (T5) is filled in T6; `cache_driver`/`redis_url` (T4) are read by T3's `_cache_args` + T8's mount gate. ✓
- **Execution order (header-pinned, not a caveat):** **T1 → T2 → T4 → T3 → T5 → T6 → T7 → T8 → T9 → T10.** T4 (config) before T3 (factory) because `build_adapters` reads `settings.cache_driver`. Numbers kept; sequence swaps those two.
- **Open items carried into execution:** (a) extract `prod_compliant_settings_kwargs` from the Wave-1 guard tests if absent (T4 step 1); (b) migrated-DB + `MemoryCallerContext` fixtures for the memory-path tests (T6 + T9 notes); (c) the in-memory secret seed for the T5 vault test (mirror `test_secret_resolution.py`). **Resolved during planning:** `LLMGateway` has no close method (Runtime owns the http client); `infra/litellm/config.yaml` exists; the `vector_index` coupling is decoupled via `memory_vector_recall_enabled` (default OFF).



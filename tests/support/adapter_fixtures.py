"""In-memory adapter implementations — TEST FIXTURES ONLY.

Lives under ``tests/support/`` per AGENTS.md "test-only mocks, fixtures,
and demo-safe sample data are allowed only under clearly separated
test/demo paths." Never wired as a default driver; the bundled registry
uses the real adapters (postgres / qdrant / vault / ollama / langfuse_otel).

The relational variant uses ``aiosqlite`` so SQLAlchemy machinery can
exercise the adapter contract without a live Postgres. The other variants
are dict-backed.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from cognic_agentos.db.adapters.protocols import (
    AdapterHealth,
    SecretLease,
    VectorHit,
    VectorItem,
)


class InMemoryRelationalAdapter:
    """SQLite-backed relational adapter for tests.

    Driver name: ``memory``. Database URL fixed to in-memory SQLite.
    """

    driver = "memory"

    def __init__(self) -> None:
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[Any] | None = None
        self._closed = False

    async def connect(self) -> None:
        self._engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            echo=False,
            future=True,
        )
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._closed = False
        await self._create_chain_schema(self._engine)

    @staticmethod
    async def _create_chain_schema(engine: AsyncEngine) -> None:
        """Create the Sprint-1 chain tables + seed the two chain heads.

        Sprint 13.5b1: ``build_runtime`` constructs the approval trio
        UNCONDITIONALLY, and ``OPAEngine.create`` emits ``policy.bundle_loaded``
        into decision history at startup — so every test that drives
        ``build_runtime`` (directly or via the app lifespan) needs the chain
        schema present BEFORE the lifespan runs. The adapter is the only hook
        that runs early enough for lifespan-driven tests. Idempotent: create_all
        is checkfirst, and the head seed skips chain_ids that already exist
        (tests that seed heads themselves stay green).
        """
        from datetime import UTC, datetime

        from sqlalchemy import select

        from cognic_agentos.core.audit import _chain_heads, _metadata
        from cognic_agentos.core.canonical import ZERO_HASH
        from cognic_agentos.core.decision_history import (  # noqa: F401  (registers table in _metadata)
            _decision_history,
        )

        async with engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)
            existing = set((await conn.execute(select(_chain_heads.c.chain_id))).scalars().all())
            for chain_id in ("audit_event", "decision_history"):
                if chain_id not in existing:
                    await conn.execute(
                        _chain_heads.insert().values(
                            chain_id=chain_id,
                            latest_sequence=0,
                            latest_hash=ZERO_HASH,
                            updated_at=datetime.now(UTC),
                        )
                    )

    def session(self) -> Any:
        if self._session_factory is None:
            raise RuntimeError("connect() must be awaited first")
        return self._session_factory()

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("connect() must be awaited first")
        return self._engine

    async def run_migrations(self, dir: str) -> None:
        # Tests don't need real migrations; presence of method satisfies
        # protocol structural conformance. Test-fixture path may legitimately
        # no-op (the production fail-loud rule lives in postgres_adapter.py).
        return None

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
        self._closed = True

    async def health_check(self) -> AdapterHealth:
        if self._closed or self._engine is None:
            return AdapterHealth(status="unreachable", driver=self.driver, detail="closed")
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryVectorAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self._collections: dict[str, list[VectorItem]] = {}

    async def ensure_collection(self, name: str, dim: int, metric: str = "cosine") -> None:
        self._collections.setdefault(name, [])

    async def upsert(self, items: list[VectorItem]) -> None:
        # Single default collection for test convenience.
        col = self._collections.setdefault("default", [])
        existing_ids = {it.id for it in col}
        for it in items:
            if it.id in existing_ids:
                col[:] = [c for c in col if c.id != it.id]
        col.extend(items)

    async def search(
        self,
        vector: list[float],
        k: int = 10,
        filter: dict[str, Any] | None = None,
    ) -> list[VectorHit]:
        if filter is not None:
            raise NotImplementedError(
                "InMemoryVectorAdapter.search filter is deferred to "
                "Sprint 11.5 + ADR-017 — same fail-loud rule as the bundled "
                "Qdrant adapter."
            )
        col = self._collections.get("default", [])
        scored = [(self._cosine(vector, it.vector), it) for it in col]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [VectorHit(id=it.id, score=score, payload=it.payload) for score, it in scored[:k]]

    async def delete(self, ids: list[str]) -> None:
        for col in self._collections.values():
            col[:] = [it for it in col if it.id not in ids]

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b, strict=True))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


class InMemorySecretAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._leases: dict[str, str] = {}

    async def read(self, path: str) -> dict[str, Any]:
        if path not in self._store:
            raise KeyError(path)
        return dict(self._store[path])

    async def write(self, path: str, value: dict[str, Any]) -> None:
        self._store[path] = dict(value)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        lease_id = uuid.uuid4().hex
        self._leases[lease_id] = path
        return SecretLease(lease_id=lease_id, ttl_s=ttl_s, value=dict(self._store[path]))

    async def revoke(self, lease_id: str) -> None:
        self._leases.pop(lease_id, None)

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryEmbeddingAdapter:
    driver = "memory"

    def __init__(self, dimensions: int = 8) -> None:
        self._dimensions = dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        # Deterministic pseudo-embedding: hash → float per dim. Hash output
        # varies per process (PYTHONHASHSEED) but is stable within a single
        # test run, which is all the tests assert.
        out: list[list[float]] = []
        for t in texts:
            seed = abs(hash(t)) or 1
            row = [((seed >> (i * 3)) & 0xFFFF) / 0xFFFF for i in range(self._dimensions)]
            out.append(row)
        return out

    @property
    def dimensions(self) -> int:
        return self._dimensions

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


class InMemoryObservabilityAdapter:
    driver = "memory"

    def __init__(self) -> None:
        self.traces: list[tuple[str, dict[str, Any]]] = []
        self.metrics: list[tuple[str, float, dict[str, Any]]] = []
        self._flushed = 0

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        self.traces.append((name, dict(attributes)))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None:
        self.metrics.append((name, value, dict(attributes)))

    async def flush(self) -> None:
        # Exercise the async flush boundary; idempotent.
        await asyncio.sleep(0)
        self._flushed += 1

    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver=self.driver, latency_ms=0.0)


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

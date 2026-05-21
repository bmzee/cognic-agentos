"""#489 T3 — _build_checkpoint_store_from_adapters lifespan helper.

The helper constructs a production CheckpointStore from the live adapter
pool: AuditStore + DecisionHistoryStore from the relational adapter's own
engine, plus the bundled object-store adapter. It fails loud — naming the
missing dependency — when the object store OR the relational engine is
unavailable (#489 spec §4.3.2 / AC4).
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

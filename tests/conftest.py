"""Shared test fixtures for Sprint 1C adapter-aware tests.

These fixtures construct a memory-backed ``AdapterRegistry`` + a
``Settings`` instance whose driver fields all point at ``"memory"``,
so tests can exercise the full Sprint 1C lifespan + ``/readyz`` adapter
roll-up without standing up Postgres / Qdrant / Vault / Ollama / Langfuse.

Sprint 4 added the production ``LocalObjectStoreAdapter`` (driver
``local_fs``) and wired it unconditionally in ``build_adapters``. The
``memory_registry`` fixture now registers it too — bound to a per-test
tmp directory via ``memory_settings``'s ``local_object_store_root``.

The in-memory adapters live under ``tests/support/`` per AGENTS.md
test-fixture-placement rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


@pytest.fixture
def memory_registry() -> AdapterRegistry:
    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    # Sprint-4 P2-1 fix: object_store is resolved unconditionally in
    # build_adapters, so the test-time registry must include local_fs.
    # The real LocalObjectStoreAdapter is fine here — it points at the
    # per-test tmp_path supplied by ``memory_settings``.
    r.register("object_store", "local_fs", LocalObjectStoreAdapter)
    return r


@pytest.fixture
def memory_settings(tmp_path: Path) -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "local_object_store_root": tmp_path,
        }
    )

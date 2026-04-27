"""Shared test fixtures for Sprint 1C adapter-aware tests.

These fixtures construct a memory-backed ``AdapterRegistry`` + a
``Settings`` instance whose driver fields all point at ``"memory"``,
so tests can exercise the full Sprint 1C lifespan + ``/readyz`` adapter
roll-up without standing up Postgres / Qdrant / Vault / Ollama / Langfuse.

The in-memory adapters live under ``tests/support/`` per AGENTS.md
test-fixture-placement rule.
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.db.adapters import AdapterRegistry
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
    return r


@pytest.fixture
def memory_settings() -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
        }
    )

"""Sprint 1C — adapter registry + factory.

Exit criterion: ``COGNIC_DB_DRIVER=mssql`` (a planned plugin pack, not bundled
in Sprint 1C) raises ``AdapterNotInstalled`` at startup with the kind +
driver name in the message — no silent fallback.
"""

from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.db.adapters import (
    AdapterNotInstalled,
    AdapterRegistry,
    build_adapters,
    bundled_registry,
)
from cognic_agentos.db.adapters import protocols as P
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


def _memory_settings() -> Any:
    """Build a Settings-like with all drivers set to 'memory'."""

    from cognic_agentos.core.config import build_settings_without_env_file

    return build_settings_without_env_file().model_copy(
        update={
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "database_url": None,
            "qdrant_url": None,
            "vault_addr": None,
            "embedding_base_url": None,
            "langfuse_host": None,
        }
    )


def _memory_registry() -> AdapterRegistry:
    """A fresh registry with only the in-memory test impls."""

    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    return r


class TestRegistry:
    def test_register_and_resolve(self) -> None:
        r = AdapterRegistry()
        r.register("relational", "x", InMemoryRelationalAdapter)
        assert r.resolve("relational", "x") is InMemoryRelationalAdapter

    def test_unknown_driver_raises(self) -> None:
        r = AdapterRegistry()
        with pytest.raises(AdapterNotInstalled) as exc:
            r.resolve("relational", "mssql")
        assert "mssql" in str(exc.value)
        assert "relational" in str(exc.value)
        assert exc.value.kind == "relational"
        assert exc.value.driver == "mssql"

    def test_has_returns_false_for_missing(self) -> None:
        r = AdapterRegistry()
        assert r.has("relational", "missing") is False

    def test_kinds_returns_distinct_set(self) -> None:
        r = AdapterRegistry()
        r.register("relational", "x", InMemoryRelationalAdapter)
        r.register("relational", "y", InMemoryRelationalAdapter)
        r.register("vector", "x", InMemoryVectorAdapter)
        assert r.kinds() == {"relational", "vector"}

    def test_bundled_registry_lists_real_drivers(self) -> None:
        """``load_bundled_adapters()`` registers the five Sprint-1C drivers
        in any image where their optional deps are installed (test env =
        ``--all-extras`` so every module loads cleanly)."""

        from cognic_agentos.db.adapters import load_bundled_adapters

        results = load_bundled_adapters()
        for module_name in (
            "cognic_agentos.db.adapters.postgres_adapter",
            "cognic_agentos.db.adapters.qdrant_adapter",
            "cognic_agentos.db.adapters.vault_adapter",
            "cognic_agentos.db.adapters.ollama_embedding_adapter",
            "cognic_agentos.db.adapters.langfuse_otel_adapter",
        ):
            assert results[module_name] == "loaded", (
                f"{module_name} should load in the test env: {results[module_name]}"
            )

        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.has("observability", "langfuse_otel")

    def test_load_bundled_adapters_kernel_resilience(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Simulate kernel-image behaviour: one bundled module's optional
        dep is missing. ``ModuleNotFoundError.name`` matches the loader's
        per-adapter allowlist, so the loader logs + skips and the rest
        continue."""

        import importlib as _importlib

        from cognic_agentos.db.adapters import load_bundled_adapters

        real_import = _importlib.import_module

        def fake_import(name: str, package: str | None = None) -> object:
            if name == "cognic_agentos.db.adapters.qdrant_adapter":
                raise ModuleNotFoundError("No module named 'qdrant_client'", name="qdrant_client")
            return real_import(name, package)

        monkeypatch.setattr(_importlib, "import_module", fake_import)

        results = load_bundled_adapters()

        assert "skipped" in results["cognic_agentos.db.adapters.qdrant_adapter"]
        assert "qdrant_client" in results["cognic_agentos.db.adapters.qdrant_adapter"]
        assert results["cognic_agentos.db.adapters.postgres_adapter"] == "loaded"

    def test_load_bundled_adapters_reraises_unexpected_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the missing module is NOT on the adapter's allowlist (e.g.
        a typo bug inside the adapter's own code), the loader must re-raise
        so the bug is visible — never bury it as 'skipped'."""

        import importlib as _importlib

        from cognic_agentos.db.adapters import load_bundled_adapters

        real_import = _importlib.import_module

        def fake_import(name: str, package: str | None = None) -> object:
            if name == "cognic_agentos.db.adapters.qdrant_adapter":
                raise ModuleNotFoundError(
                    "No module named 'definitely_a_typo'",
                    name="definitely_a_typo",
                )
            return real_import(name, package)

        monkeypatch.setattr(_importlib, "import_module", fake_import)

        with pytest.raises(ModuleNotFoundError, match="definitely_a_typo"):
            load_bundled_adapters()


class TestFactory:
    async def test_build_with_memory_drivers(self) -> None:
        s = _memory_settings()
        adapters = build_adapters(s, registry=_memory_registry())

        assert isinstance(adapters.relational, P.RelationalAdapter)
        assert isinstance(adapters.vector, P.VectorAdapter)
        assert isinstance(adapters.secret, P.SecretAdapter)
        assert isinstance(adapters.embedding, P.EmbeddingAdapter)
        assert isinstance(adapters.observability, P.ObservabilityAdapter)

        # ObjectStore remains unset in Sprint 1C (Sprint 8 fills it).
        # MemoryAdapter is ADR-019 / Sprint 11.5 — no slot in this sprint.
        assert adapters.object_store is None
        assert not hasattr(adapters, "memory")

    async def test_unknown_driver_fails_fast(self) -> None:
        s = _memory_settings().model_copy(update={"db_driver": "mssql"})
        with pytest.raises(AdapterNotInstalled) as exc:
            build_adapters(s, registry=_memory_registry())
        assert "mssql" in str(exc.value)
        assert "relational" in str(exc.value)

    async def test_open_close_lifecycle(self) -> None:
        s = _memory_settings()
        adapters = build_adapters(s, registry=_memory_registry())

        await adapters.open_all()
        for name in ("relational", "vector", "secret", "embedding", "observability"):
            adapter = getattr(adapters, name)
            h = await adapter.health_check()
            assert h.status == "ok", f"{name} not ok: {h}"

        await adapters.close_all()
        # Relational adapter flips to unreachable after close
        h = await adapters.relational.health_check()
        assert h.status == "unreachable"

    async def test_bundled_registry_default_used_when_registry_none(self) -> None:
        """Smoke: when ``registry`` is None, the factory falls back to the
        process-wide ``bundled_registry``. Bundled drivers won't be present
        in this T5 run (T6-T10 land them), so the default-postgres lookup
        raises AdapterNotInstalled — proving the fallback path runs."""

        s = _memory_settings().model_copy(update={"db_driver": "postgres"})
        with pytest.raises(AdapterNotInstalled):
            build_adapters(s)  # no registry kwarg → uses bundled_registry

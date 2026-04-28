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
        """``load_bundled_adapters()`` registers all eight Sprint-1C+1D
        drivers in any image where their optional deps are installed
        (test env = ``--all-extras`` so every module loads cleanly)."""

        from cognic_agentos.db.adapters import load_bundled_adapters

        results = load_bundled_adapters()
        for module_name in (
            # Sprint 1C
            "cognic_agentos.db.adapters.postgres_adapter",
            "cognic_agentos.db.adapters.qdrant_adapter",
            "cognic_agentos.db.adapters.vault_adapter",
            "cognic_agentos.db.adapters.ollama_embedding_adapter",
            "cognic_agentos.db.adapters.langfuse_otel_adapter",
            # Sprint 1D
            "cognic_agentos.db.adapters.oracle_adapter",
            "cognic_agentos.db.adapters.dynatrace_adapter",
            "cognic_agentos.db.adapters.openai_compat_embedding_adapter",
        ):
            assert results[module_name] == "loaded", (
                f"{module_name} should load in the test env: {results[module_name]}"
            )

        # Sprint 1C drivers
        assert bundled_registry.has("relational", "postgres")
        assert bundled_registry.has("vector", "qdrant")
        assert bundled_registry.has("secret", "vault")
        assert bundled_registry.has("embedding", "ollama")
        assert bundled_registry.has("observability", "langfuse_otel")
        # Sprint 1D drivers
        assert bundled_registry.has("relational", "oracle")
        assert bundled_registry.has("observability", "dynatrace")
        assert bundled_registry.has("embedding", "openai_compat")

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
        """Smoke: when ``registry`` is None the factory falls back to the
        process-wide ``bundled_registry``. ``vector_driver=memory`` is not
        registered there → AdapterNotInstalled — proving the fallback path
        runs (rather than silently picking up some other registry)."""

        s = _memory_settings()  # vector_driver="memory" is not bundled
        with pytest.raises(AdapterNotInstalled):
            build_adapters(s)  # no registry kwarg → uses bundled_registry


class TestPerDriverArgs:
    """Coverage for the private per-driver argument helpers.

    The factory's ``_relational_args`` / ``_vector_args`` / ``_secret_args``
    / ``_embedding_args`` / ``_observability_args`` helpers translate
    Settings fields into adapter constructor positional args. They're
    private but worth direct coverage so the bundled-driver branches
    (postgres / qdrant / vault / ollama / langfuse_otel) are exercised
    independently of the live builders, and so the unknown-driver
    fallback path (returning empty tuple, letting the registry surface
    AdapterNotInstalled) is locked in.
    """

    @pytest.fixture
    def base_settings(self) -> Any:
        """Settings with all per-driver paths populated."""

        from cognic_agentos.core.config import build_settings_without_env_file

        return build_settings_without_env_file().model_copy(
            update={
                "database_url": "postgresql+asyncpg://u:p@h/d",
                "qdrant_url": "http://q:6333",
                "qdrant_collection": "mycol",
                "vault_addr": "http://v:8200",
                "vault_token": "tok",
                "vault_namespace": "ns",
                "embedding_base_url": "http://o:11434",
                "embedding_model": "qwen3-embedding:8b",
                "embedding_dimensions": 1024,
                "langfuse_host": "http://l:3000",
                "langfuse_public_key": "pk",
                "langfuse_secret_key": "sk",
            }
        )

    def test_relational_postgres_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _relational_args

        assert _relational_args(base_settings) == ("postgresql+asyncpg://u:p@h/d",)

    def test_relational_memory_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _relational_args

        s = base_settings.model_copy(update={"db_driver": "memory"})
        assert _relational_args(s) == ()

    def test_relational_unknown_returns_empty(self, base_settings: Any) -> None:
        """Plugin-pack drivers (e.g. mssql) return empty here — their own
        helper or pack-supplied factory provides the args."""

        from cognic_agentos.db.adapters.factory import _relational_args

        s = base_settings.model_copy(update={"db_driver": "mssql"})
        assert _relational_args(s) == ()

    def test_vector_qdrant_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _vector_args

        s = base_settings.model_copy(update={"vector_driver": "qdrant"})
        assert _vector_args(s) == ("http://q:6333", "mycol")

    def test_vector_memory_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _vector_args

        s = base_settings.model_copy(update={"vector_driver": "memory"})
        assert _vector_args(s) == ()

    def test_vector_unknown_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _vector_args

        s = base_settings.model_copy(update={"vector_driver": "chroma"})
        assert _vector_args(s) == ()

    def test_secret_vault_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _secret_args

        s = base_settings.model_copy(update={"secret_driver": "vault"})
        assert _secret_args(s) == ("http://v:8200", "tok", "ns")

    def test_secret_memory_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _secret_args

        s = base_settings.model_copy(update={"secret_driver": "memory"})
        assert _secret_args(s) == ()

    def test_secret_unknown_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _secret_args

        s = base_settings.model_copy(update={"secret_driver": "aws"})
        assert _secret_args(s) == ()

    def test_embedding_ollama_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(update={"embed_driver": "ollama"})
        assert _embedding_args(s) == ("http://o:11434", "qwen3-embedding:8b", 1024)

    def test_embedding_memory_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(update={"embed_driver": "memory"})
        assert _embedding_args(s) == ()

    def test_embedding_unknown_returns_empty(self, base_settings: Any) -> None:
        """Use a placeholder name that's truly not bundled (Sprint 1D
        added openai_compat to bundled). ``cohere_native`` represents a
        future Cohere-native (non-OpenAI-shape) plugin pack per ADR-009
        alternative-adapter list."""

        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(update={"embed_driver": "cohere_native"})
        assert _embedding_args(s) == ()

    def test_observability_langfuse_otel_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(update={"obs_driver": "langfuse_otel"})
        assert _observability_args(s) == ("http://l:3000", "pk", "sk")

    def test_observability_memory_returns_empty(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(update={"obs_driver": "memory"})
        assert _observability_args(s) == ()

    def test_observability_unknown_returns_empty(self, base_settings: Any) -> None:
        """Use a placeholder name that's truly not bundled (Sprint 1D
        added dynatrace to bundled). ``splunk`` is a future plugin-pack
        candidate per ADR-009 alternative-adapter list."""

        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(update={"obs_driver": "splunk"})
        assert _observability_args(s) == ()

    # --- Sprint 1D enterprise-driver branches -----------------------

    def test_relational_oracle_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _relational_args

        s = base_settings.model_copy(
            update={
                "db_driver": "oracle",
                "database_url": "oracle+oracledb://u:p@h:1521/?service_name=XEPDB1",
            }
        )
        assert _relational_args(s) == ("oracle+oracledb://u:p@h:1521/?service_name=XEPDB1",)

    def test_observability_dynatrace_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _observability_args

        s = base_settings.model_copy(
            update={
                "obs_driver": "dynatrace",
                "dynatrace_tenant_url": "https://abc.live.dynatrace.com",
                "dynatrace_api_token": "dt0c01.tok",
            }
        )
        assert _observability_args(s) == (
            "https://abc.live.dynatrace.com",
            "dt0c01.tok",
        )

    def test_embedding_openai_compat_args(self, base_settings: Any) -> None:
        from cognic_agentos.db.adapters.factory import _embedding_args

        s = base_settings.model_copy(
            update={
                "embed_driver": "openai_compat",
                "embedding_base_url": "http://vllm:8000",
                "embedding_model": "BAAI/bge-large-en-v1.5",
                "embedding_dimensions": 1024,
                "embed_provider_label": "vllm",
                "embedding_api_key": "sk-test",
                "embedding_api_key_header": "Authorization",
                "embedding_extra_headers": {"x-trace": "abc"},
            }
        )
        assert _embedding_args(s) == (
            "http://vllm:8000",
            "BAAI/bge-large-en-v1.5",
            1024,
            "vllm",
            "sk-test",
            "Authorization",
            {"x-trace": "abc"},
        )

    async def test_close_all_swallows_per_adapter_errors(self, base_settings: Any) -> None:
        """``close_all`` uses contextlib.suppress so one adapter raising
        on close cannot prevent the others from closing. This locks the
        behaviour against future regressions."""

        from cognic_agentos.db.adapters.factory import Adapters

        class FlakyClose:
            driver = "flaky"
            closed = False

            async def connect(self) -> None: ...

            async def close(self) -> None:
                raise RuntimeError("flaky close")

            async def health_check(self) -> Any:
                from cognic_agentos.db.adapters.protocols import AdapterHealth

                return AdapterHealth(status="ok", driver=self.driver)

        class CleanClose:
            driver = "clean"
            closed = False

            async def connect(self) -> None: ...

            async def close(self) -> None:
                self.__class__.closed = True

            async def health_check(self) -> Any:
                from cognic_agentos.db.adapters.protocols import AdapterHealth

                return AdapterHealth(status="ok", driver=self.driver)

        flaky = FlakyClose()
        clean = CleanClose()
        adapters = Adapters(
            relational=clean,  # type: ignore[arg-type]
            vector=flaky,  # type: ignore[arg-type]
            secret=clean,  # type: ignore[arg-type]
            embedding=clean,  # type: ignore[arg-type]
            observability=clean,  # type: ignore[arg-type]
        )

        # Must not raise; flaky's close() error is swallowed
        await adapters.close_all()
        assert CleanClose.closed is True

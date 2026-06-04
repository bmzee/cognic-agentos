from typing import Any

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.db.adapters import build_adapters, build_adapters_async
from cognic_agentos.db.adapters.registry import AdapterRegistry
from cognic_agentos.db.adapters.secret_resolution import (
    SecretFieldResolutionError,
    resolve_secret_field,
)
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter as _InMemoryEmbeddingAdapter,
)
from tests.support.adapter_fixtures import (
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

# These stubs intentionally implement ONLY ``read`` — the single method the
# resolver calls. They are partial ``SecretAdapter`` Protocols, so each call
# site carries ``# type: ignore[arg-type]`` (the established partial-stub
# convention in ``test_adapter_factory.py``). Methods ARE annotated so mypy's
# ``no-untyped-call`` does not fire.


class _StubAdapter:
    def __init__(self, mapping: dict[str, Any]) -> None:
        self._m = mapping

    async def read(self, path: str) -> Any:
        return self._m[path]  # raises KeyError if absent


@pytest.mark.asyncio
async def test_none_passthrough() -> None:
    assert (
        await resolve_secret_field(None, secret_adapter=_StubAdapter({}), field_name="x") is None  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_plain_identity() -> None:
    assert (
        await resolve_secret_field("plain", secret_adapter=_StubAdapter({}), field_name="x")  # type: ignore[arg-type]
        == "plain"
    )


@pytest.mark.asyncio
async def test_vault_uri_reads_key_field() -> None:
    a = _StubAdapter({"secret/cognic/litellm": {"key": "resolved-master-key"}})
    out = await resolve_secret_field(
        "vault://secret/cognic/litellm",
        secret_adapter=a,  # type: ignore[arg-type]
        field_name="litellm_master_key",
    )
    assert out == "resolved-master-key"


@pytest.mark.asyncio
async def test_missing_key_field_fails_loud() -> None:
    a = _StubAdapter({"secret/x": {"not_key": "v"}})
    with pytest.raises(SecretFieldResolutionError, match="secret_field_resolution_failed"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_vault_unreachable_fails_loud() -> None:
    class _Boom:
        async def read(self, path: str) -> Any:
            raise RuntimeError("vault down")

    with pytest.raises(SecretFieldResolutionError, match="secret_field_resolution_failed"):
        await resolve_secret_field("vault://secret/x", secret_adapter=_Boom(), field_name="x")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_non_dict_payload_fails_loud() -> None:
    class _BadShape:
        async def read(self, path: str) -> Any:
            return "not-a-dict"

    with pytest.raises(SecretFieldResolutionError, match="not a dict"):
        await resolve_secret_field("vault://secret/x", secret_adapter=_BadShape(), field_name="x")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_empty_string_key_fails_loud() -> None:
    a = _StubAdapter({"secret/x": {"key": ""}})
    with pytest.raises(SecretFieldResolutionError, match="non-empty str"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_non_str_key_value_fails_loud() -> None:
    a = _StubAdapter({"secret/x": {"key": 12345}})
    with pytest.raises(SecretFieldResolutionError, match="non-empty str"):
        await resolve_secret_field("vault://secret/x", secret_adapter=a, field_name="x")  # type: ignore[arg-type]


# --- Step 6: factory wiring + sync-preflight (end-to-end seam) ----------------


class _CapturingAdapter:
    """Records the positional args its constructor receives so a test can assert
    the resolved (plain) secret — NOT the ``vault://`` URI — reached the adapter.
    Registered under the kind+driver of the field under test; the per-field
    positional index it lands at is pinned by ``_E2E_SECRET_CASES``."""

    def __init__(self, *args: Any) -> None:
        self.args = args


class _StubObjectStore:
    """``build_adapters`` resolves object_store unconditionally; this stub
    satisfies that resolve without touching the filesystem."""

    driver = "local_fs"

    def __init__(self, *args: Any) -> None:
        self.args = args


def _wiring_registry(*, embedding_cls: type, embed_driver_name: str = "memory") -> AdapterRegistry:
    """A registry with in-memory stubs for every kind + a per-test embedding
    class registered under ``embed_driver_name`` + a no-op object_store."""

    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", embed_driver_name, embedding_cls)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", _StubObjectStore)
    return r


def _dev_base() -> Any:
    """Dev-profile Settings with all non-object_store drivers = memory and
    bootstrap (vault_addr/vault_token) set so T1's G3 is satisfied whenever a
    ``vault://`` secret is present. ``model_copy`` does NOT re-run validators,
    so individual tests overlay the vault:// secret + driver here."""

    return build_settings_without_env_file().model_copy(
        update={
            "runtime_profile": "dev",
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "database_url": None,
            "qdrant_url": None,
            "vault_addr": "http://v:8200",
            "vault_token": "boot-token",
            "embedding_base_url": None,
            "langfuse_host": None,
        }
    )


# --- All-three-adapter-secret end-to-end matrix (P2 coverage) -----------------
# Each adapter service secret flows into a DIFFERENT adapter at a DIFFERENT
# positional index. Parametrizing over all three guards against a future edit
# dropping one from ``factory._ADAPTER_SECRET_FIELDS`` — which would silently let
# a ``vault://`` value reach an observability adapter while an embedding-only
# test still passed. The index map mirrors ``factory._embedding_args`` /
# ``factory._observability_args``.
_E2E_SECRET_CASES = [
    pytest.param(
        "embedding_api_key",
        {
            "embed_driver": "openai_compat",
            "embedding_base_url": "http://vllm:8000",
            "embedding_model": "BAAI/bge-large-en-v1.5",
            "embedding_dimensions": 1024,
        },
        "embedding",
        "openai_compat",
        "embedding",
        4,  # (base_url, model, dims, label, api_key, header, extra)
        id="embedding_api_key",
    ),
    pytest.param(
        "langfuse_secret_key",
        {
            "obs_driver": "langfuse_otel",
            "langfuse_host": "http://lf:3000",
            "langfuse_public_key": "pk-test",
        },
        "observability",
        "langfuse_otel",
        "observability",
        2,  # (langfuse_host, langfuse_public_key, langfuse_secret_key)
        id="langfuse_secret_key",
    ),
    pytest.param(
        "dynatrace_api_token",
        {
            "obs_driver": "dynatrace",
            "dynatrace_tenant_url": "https://abc12345.live.dynatrace.com",
        },
        "observability",
        "dynatrace",
        "observability",
        1,  # (dynatrace_tenant_url, dynatrace_api_token)
        id="dynatrace_api_token",
    ),
]


def _capturing_registry(kind: str, driver_name: str) -> AdapterRegistry:
    """All-memory-stub registry with the kind-under-test's driver overridden by
    the arg-capturing adapter, so a test can inspect the value that reached it."""

    r = AdapterRegistry()
    r.register("relational", "memory", InMemoryRelationalAdapter)
    r.register("vector", "memory", InMemoryVectorAdapter)
    r.register("secret", "memory", InMemorySecretAdapter)
    r.register("embedding", "memory", _InMemoryEmbeddingAdapter)
    r.register("observability", "memory", InMemoryObservabilityAdapter)
    r.register("object_store", "local_fs", _StubObjectStore)
    r.register(kind, driver_name, _CapturingAdapter)
    return r


@pytest.mark.parametrize(
    "field, driver_overlay, kind, driver_name, adapter_attr, arg_index", _E2E_SECRET_CASES
)
@pytest.mark.asyncio
async def test_build_adapters_async_resolves_each_adapter_secret(
    field: str,
    driver_overlay: dict[str, Any],
    kind: str,
    driver_name: str,
    adapter_attr: str,
    arg_index: int,
) -> None:
    """End-to-end for ALL three adapter secrets: a ``vault://`` value is resolved
    ONCE via the injected secret adapter and the PLAIN value reaches the adapter
    constructor at the expected positional index (NOT the ``vault://`` URI)."""

    vault_path = f"secret/{field}"
    seed = InMemorySecretAdapter()
    await seed.write(vault_path, {"key": f"resolved-{field}"})

    settings = _dev_base().model_copy(update={**driver_overlay, field: f"vault://{vault_path}"})
    registry = _capturing_registry(kind, driver_name)

    adapters = await build_adapters_async(settings, registry=registry, secret_adapter=seed)

    captured = getattr(adapters, adapter_attr)
    assert isinstance(captured, _CapturingAdapter)
    assert captured.args[arg_index] == f"resolved-{field}"
    assert captured.args[arg_index] != f"vault://{vault_path}"


@pytest.mark.asyncio
async def test_build_adapters_async_no_vault_fast_path() -> None:
    """All 3 adapter secrets None/plain → delegates straight to the sync
    builder with NO secret adapter needed (``secret_adapter=None`` + a
    registry that has no vault driver)."""

    settings = _dev_base()  # embedding_api_key/langfuse_secret_key/dynatrace_api_token all None
    registry = _wiring_registry(embedding_cls=_InMemoryEmbeddingAdapter)

    adapters = await build_adapters_async(settings, registry=registry, secret_adapter=None)

    assert adapters.embedding is not None
    assert adapters.relational is not None


@pytest.mark.parametrize(
    "field, driver_overlay, kind, driver_name, adapter_attr, arg_index", _E2E_SECRET_CASES
)
@pytest.mark.asyncio
async def test_sync_build_adapters_preflight_fires_for_each_adapter_secret(
    field: str,
    driver_overlay: dict[str, Any],
    kind: str,
    driver_name: str,
    adapter_attr: str,
    arg_index: int,
) -> None:
    """For ALL three adapter secrets: the sync ``build_adapters`` refuses a
    still-``vault://`` value (closed-reason RuntimeError); the SAME settings
    through ``build_adapters_async`` (with a seeded adapter) resolves + succeeds."""

    vault_path = f"secret/{field}"
    seed = InMemorySecretAdapter()
    await seed.write(vault_path, {"key": f"resolved-{field}"})

    settings = _dev_base().model_copy(update={**driver_overlay, field: f"vault://{vault_path}"})
    registry = _capturing_registry(kind, driver_name)

    with pytest.raises(RuntimeError, match="build_adapters_sync_unresolved_vault_secret"):
        build_adapters(settings, registry=registry)

    adapters = await build_adapters_async(settings, registry=registry, secret_adapter=seed)
    assert getattr(adapters, adapter_attr).args[arg_index] == f"resolved-{field}"

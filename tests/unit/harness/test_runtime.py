"""Harness Injection T5 — build_runtime composition root (gateway path)."""

from __future__ import annotations

from pathlib import Path

from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.harness import Runtime, build_runtime
from cognic_agentos.llm.gateway import LLMGateway
from tests.support.adapter_fixtures import InMemorySecretAdapter


def _litellm_yaml(tmp_path: Path) -> Path:
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
        assert runtime.memory_api_factory is None  # cache_driver="none" → memory not wired (T6)
        assert runtime.memory_policy is None
        await runtime.aclose()  # must not raise
    finally:
        await adapters.close_all()


async def test_build_runtime_resolves_vault_master_key(memory_registry, memory_settings, tmp_path):
    """A vault:// litellm_master_key is RESOLVED at build time — the gateway holds the
    PLAIN value, never the URI. 'No raise' is NOT enough (build_runtime passes a non-None
    key, so the gateway ctor's None-guard wouldn't catch an unresolved URI) — assert the
    resolved value directly."""
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
    # Seed the in-memory secret store so resolve_secret_field returns the plain value.
    # The secret at the path is a {"key": "<value>"} dict (the _VAULT_KEY_FIELD contract).
    # InMemorySecretAdapter exposes ``async write(path, value)`` (the same seed the
    # secret_resolution e2e tests use); the resolver strips the ``vault://`` prefix, so
    # ``vault://secret/llm`` reads path ``secret/llm``.
    assert isinstance(adapters.secret, InMemorySecretAdapter)
    await adapters.secret.write("secret/llm", {"key": "sk-resolved"})
    try:
        runtime = await build_runtime(s, adapters)
        # white-box: no public accessor; proves the vault:// URI actually resolved.
        assert runtime.llm_gateway._litellm_master_key == "sk-resolved"
        await runtime.aclose()
    finally:
        await adapters.close_all()

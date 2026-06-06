"""Harness Injection T5 — build_runtime composition root (gateway path)."""

from __future__ import annotations

from pathlib import Path

import pytest

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


async def test_build_runtime_wires_memory_when_cache_present(
    memory_registry, memory_settings, tmp_path
):
    """cache_driver='memory' -> build_runtime wires the factory + the two-bundle router.
    Construction is opa-binary-free (engines warn+defer without the binary); the rego
    FILES must exist (they do). End-to-end memory ALLOW is env-gated, out of T6."""
    from datetime import UTC, datetime

    from cognic_agentos.core.audit import _chain_heads, _metadata
    from cognic_agentos.core.canonical import ZERO_HASH
    from cognic_agentos.core.decision_history import (  # noqa: F401  (ensures table in _metadata)
        _decision_history,
    )
    from cognic_agentos.core.emergency.kill_switches import RedisMemoryWriteFreezeKillSwitch
    from cognic_agentos.core.memory._context import MemoryCallerContext
    from cognic_agentos.core.memory.api import MemoryAPI
    from cognic_agentos.core.memory.storage import _memory_records
    from cognic_agentos.core.memory.tiers import SubjectRef

    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    # Create the chain + memory tables on the pool's relational engine + seed chain heads
    # (mirrors tests/unit/core/memory/conftest.py::_mem_engine), so OPAEngine.create's
    # policy.bundle_loaded emit works.
    eng = adapters.relational.engine
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.run_sync(_memory_records.metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    try:
        runtime = await build_runtime(s, adapters)
        assert runtime.memory_api_factory is not None
        assert runtime.memory_policy is not None
        ctx = MemoryCallerContext(
            tenant_id="t1",
            agent_id="a",
            actor_id="svc",
            served_subject=SubjectRef(kind="human", id="u1"),
            is_subagent=False,
            long_term_writes_allowed=False,
            cross_subject_recall=False,
            memory_read_capabilities=frozenset({"memory_read.task"}),
            declared_purposes=frozenset(),
            declared_data_classes=frozenset(),
            risk_tier="read_only",
        )
        api = runtime.memory_api_factory(ctx)
        assert isinstance(api, MemoryAPI)
        # The minted API's gate enforces with the SAME router exposed on
        # Runtime.memory_policy. id() identity sidesteps the nominal-type mismatch
        # (MemoryGate types policy: OPAEngine; at runtime the gate's policy IS the
        # harness MemoryPolicyRouter, passed via the build_runtime arg-type cast).
        assert id(api._gate._policy) == id(runtime.memory_policy)
        # T9 fence (behavioural): the wired kill switch is the REAL Redis impl,
        # NEVER the _Null fail-loud sentinel. TM-revert-proven load-bearing —
        # build_runtime passing kill_switch=None makes the gate bind _Null and
        # this isinstance FAILS.
        assert isinstance(api._gate._kill_switch, RedisMemoryWriteFreezeKillSwitch)
        await runtime.aclose()
    finally:
        await adapters.close_all()


async def test_http_client_not_constructed_when_memory_construction_fails(
    memory_registry, memory_settings, tmp_path, monkeypatch
):
    """Leak guard: the http_client is allocated LAST — after ALL fallible construction
    (vault-resolve + the memory branch's OPAEngine.create / ensure_collection). If memory
    construction fails, build_runtime raises BEFORE the client exists, so the client is
    never constructed — no leak (Runtime.aclose, the only path that closes it, is never
    reachable). Regression for the ordering bug: with the client allocated before the
    memory branch, this test FAILS (the client is constructed, then orphaned by the raise)."""
    import httpx

    from cognic_agentos.core.policy.engine import RegoBundleNotFoundError

    # build_runtime does ``import httpx as _httpx`` — ``_httpx is httpx`` (same module),
    # so patching httpx.AsyncClient patches exactly what build_runtime allocates.
    constructed: list[int] = []
    real_cls = httpx.AsyncClient

    def _spy_async_client(*args: object, **kwargs: object) -> httpx.AsyncClient:
        constructed.append(1)
        # A default client suffices — the spy only records that AsyncClient was called;
        # the returned client is never used on the (passing) no-leak path.
        return real_cls()

    monkeypatch.setattr(httpx, "AsyncClient", _spy_async_client)

    s = memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "memory",
            "memory_policy_bundle": tmp_path / "missing.rego",  # forces OPAEngine.create to fail
        }
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        with pytest.raises(RegoBundleNotFoundError):
            await build_runtime(s, adapters)
        # The client was NEVER allocated — build_runtime raised in the memory branch first.
        assert constructed == []
    finally:
        await adapters.close_all()


async def test_build_runtime_threads_observability_into_gateway(
    memory_registry, memory_settings, tmp_path
):
    """build_runtime threads adapters.observability into the gateway (the
    gateway-observability seam). White-box on the private attr — mirrors the
    _litellm_master_key assertion: proves the wiring, not just 'no raise'."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "none"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    try:
        runtime = await build_runtime(s, adapters)
        assert runtime.llm_gateway._observability is adapters.observability
        await runtime.aclose()
    finally:
        await adapters.close_all()

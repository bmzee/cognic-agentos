"""Sprint 14A-A — lifespan sandbox-runtime wiring (pre-seed + fail-soft).

Mirrors the 13.8 tests/unit/portal/api/test_app_mcp_host_state.py harness:
``create_app(memory_settings, adapter_registry=memory_registry)`` + the
``app.router.lifespan_context`` driver. ``cache_driver="memory"`` makes
``runtime.scheduler`` non-None (the construction guard requires it). All paths
here are skip/fail-soft (both ``app.state`` slots stay None) — the HAPPY backend
construction needs docker + OPA + images and is the env-gated e2e
(test_managed_run_e2e). asyncio_mode=auto, mixed sync/async, so no marker.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from cognic_agentos.portal.api.app import create_app

if TYPE_CHECKING:
    from pathlib import Path


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


def _settings(memory_settings: Any, tmp_path: Path, **extra: Any) -> Any:
    return memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory", **extra}
    )


def test_sandbox_state_preseeded_none_before_lifespan(
    memory_settings: Any, memory_registry: Any, tmp_path: Path
) -> None:
    app = create_app(_settings(memory_settings, tmp_path), adapter_registry=memory_registry)
    assert app.state.sandbox_backend is None
    assert app.state.managed_run_executor is None


async def test_disabled_skips_construction(
    memory_settings: Any, memory_registry: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sandbox_runtime_enabled defaults False -> build_sandbox_backend MUST NOT run.
    import cognic_agentos.harness.sandbox as hs

    async def _never(**kw: Any) -> Any:
        raise AssertionError("build_sandbox_backend ran while disabled")

    monkeypatch.setattr(hs, "build_sandbox_backend", _never)
    app = create_app(
        _settings(memory_settings, tmp_path, sandbox_runtime_enabled=False),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None


async def test_enabled_but_unavailable_fail_softs(
    memory_settings: Any, memory_registry: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_sandbox_available()==False (SDK-absent / kubernetes_pod) -> both None.
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: False)
    app = create_app(
        _settings(
            memory_settings, tmp_path, sandbox_runtime_enabled=True, vault_addr="http://vault:8200"
        ),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None


async def test_construction_failure_fail_softs(
    memory_settings: Any, memory_registry: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_sandbox_available True (aiodocker in venv) + enabled + scheduler present
    # (cache=memory), but build_sandbox_backend raises -> fail-soft: both None,
    # the app still boots (no unhandled exception escapes the lifespan).
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: True)
    import cognic_agentos.harness.sandbox as hs

    async def _boom(**kw: Any) -> Any:
        raise RuntimeError("simulated sandbox construction failure")

    monkeypatch.setattr(hs, "build_sandbox_backend", _boom)
    app = create_app(
        _settings(
            memory_settings, tmp_path, sandbox_runtime_enabled=True, vault_addr="http://vault:8200"
        ),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.runtime is not None  # build_runtime OK; only sandbox failed
        assert app.state.sandbox_backend is None
        assert app.state.managed_run_executor is None


async def test_construction_success_wires_executor_and_closes_client(
    memory_settings: Any, memory_registry: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GREEN path: is_sandbox_available True + enabled + scheduler present (cache=
    # memory), build_sandbox_backend returns (stub backend, fake client). The
    # lifespan must construct app.state.managed_run_executor wired to that backend
    # (PackRecordStore + scheduler + DH are the real memory infra), expose
    # app.state.sandbox_backend, and close the owned client on shutdown. No docker
    # / OPA needed — only the lifespan's executor-wiring + client-close is under
    # test (the real build_sandbox_backend is the env-gated e2e).
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: True)

    class _FakeClient:
        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    fake_client = _FakeClient()
    backend = object()  # the executor just stores it (no methods called at ctor)

    import cognic_agentos.harness.sandbox as hs

    async def _build(**kw: Any) -> Any:
        return backend, fake_client

    monkeypatch.setattr(hs, "build_sandbox_backend", _build)
    app = create_app(
        _settings(
            memory_settings, tmp_path, sandbox_runtime_enabled=True, vault_addr="http://vault:8200"
        ),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        assert app.state.sandbox_backend is backend
        executor = app.state.managed_run_executor
        assert executor is not None
        # the executor is wired to the SAME backend object (introspectable)
        assert executor._sandbox_backend is backend
        # Sprint 14A-A3b — the executor got the two new deps + the SAME
        # CheckpointStore is resolved onto app.state (shared with the reaper).
        from cognic_agentos.core.run.storage import RunRecordStore
        from cognic_agentos.sandbox.checkpoint_store import CheckpointStore

        assert isinstance(executor._runs, RunRecordStore)
        assert isinstance(executor._checkpoints, CheckpointStore)
        assert app.state.checkpoint_store is executor._checkpoints
        assert fake_client.closed is False  # not yet — closed on shutdown
    assert fake_client.closed is True  # the owned docker client is closed on shutdown


async def test_construction_shares_checkpoint_store_with_executor_and_backend(
    memory_settings: Any, memory_registry: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The lifespan resolves ONE CheckpointStore + threads it into BOTH
    # build_sandbox_backend(checkpoint_store=...) AND the executor's
    # checkpoint_store kwarg (so suspend() persists + load_latest reads the same
    # store). Capture the kwarg the builder received + assert it IS the executor's.
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_sandbox_available", lambda _s: True)

    class _FakeClient:
        async def close(self) -> None:
            return None

    captured: dict[str, Any] = {}
    backend = object()

    import cognic_agentos.harness.sandbox as hs

    async def _build(**kw: Any) -> Any:
        captured["checkpoint_store"] = kw.get("checkpoint_store")
        return backend, _FakeClient()

    monkeypatch.setattr(hs, "build_sandbox_backend", _build)
    app = create_app(
        _settings(
            memory_settings, tmp_path, sandbox_runtime_enabled=True, vault_addr="http://vault:8200"
        ),
        adapter_registry=memory_registry,
    )
    async with app.router.lifespan_context(app):
        executor = app.state.managed_run_executor
        assert executor is not None
        # the builder's checkpoint_store kwarg IS the executor's IS app.state's
        assert captured["checkpoint_store"] is executor._checkpoints
        assert app.state.checkpoint_store is executor._checkpoints

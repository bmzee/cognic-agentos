"""M8.5-D D2-C approval-executor composition and startup reconciliation."""

from __future__ import annotations

from typing import Any, cast

from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.portal.api.app import create_app

from .test_app_mcp_host_state import _litellm_yaml


class _Executor:
    def __init__(self, *, sweep_error: Exception | None = None) -> None:
        self.sweeps: list[float | None] = []
        self.sweep_error = sweep_error

    async def sweep_granted_unconsumed(self, grace_s: float | None = None) -> tuple[()]:
        self.sweeps.append(grace_s)
        if self.sweep_error is not None:
            raise self.sweep_error
        return ()


def test_explicit_executor_is_preseeded_for_request_time_route_resolution() -> None:
    executor = _Executor()
    app = create_app(approval_executor=cast("ApprovalExecutionService", executor))
    assert app.state.approval_executor is executor


async def test_lifespan_builds_and_sweeps_executor_after_host_and_conversation(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    monkeypatch: Any,
) -> None:
    built = _Executor()
    captured: dict[str, Any] = {}

    async def _build(**kwargs: Any) -> _Executor:
        captured.update(kwargs)
        return built

    monkeypatch.setattr(
        "cognic_agentos.harness.approval_executor.build_approval_executor",
        _build,
    )
    settings = memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "memory",
            "action_context_signing_key_path": str(tmp_path / "unused-by-spy.pem"),
            "approval_executor_grace_s": 47.0,
        }
    )
    app = create_app(settings, adapter_registry=memory_registry)

    async with app.router.lifespan_context(app):
        assert app.state.approval_executor is built
        assert captured["runtime"] is app.state.runtime
        assert captured["mcp_host"] is app.state.mcp_host
        assert captured["conversation_completer"] is app.state.conversation_executor
        assert built.sweeps == [47.0]


async def test_lifespan_executor_construction_failure_is_fail_soft(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    monkeypatch: Any,
    caplog: Any,
) -> None:
    async def _build(**_: Any) -> _Executor:
        raise RuntimeError("construction failed")

    monkeypatch.setattr(
        "cognic_agentos.harness.approval_executor.build_approval_executor",
        _build,
    )
    settings = memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "memory",
            "action_context_signing_key_path": str(tmp_path / "unused-by-spy.pem"),
        }
    )
    app = create_app(settings, adapter_registry=memory_registry)

    async with app.router.lifespan_context(app):
        assert app.state.approval_executor is None
    assert "approval.executor_construction_failed" in caplog.messages


async def test_lifespan_executor_sweep_failure_keeps_executor_for_later_retry(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    monkeypatch: Any,
    caplog: Any,
) -> None:
    built = _Executor(sweep_error=RuntimeError("sweep failed"))

    async def _build(**_: Any) -> _Executor:
        return built

    monkeypatch.setattr(
        "cognic_agentos.harness.approval_executor.build_approval_executor",
        _build,
    )
    settings = memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "memory",
            "action_context_signing_key_path": str(tmp_path / "unused-by-spy.pem"),
        }
    )
    app = create_app(settings, adapter_registry=memory_registry)

    async with app.router.lifespan_context(app):
        assert app.state.approval_executor is built
        assert built.sweeps == [settings.approval_executor_grace_s]
    assert "approval.executor_startup_sweep_failed" in caplog.messages

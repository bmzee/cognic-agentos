"""M8.5-D D2-C production builder for approved-action execution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.db.adapters.protocols import SecretAdapter
from cognic_agentos.harness.approval_executor import build_approval_executor


class _Secret:
    def __init__(self, value: object) -> None:
        self.value = value
        self.paths: list[str] = []

    async def read(self, path: str) -> Any:
        self.paths.append(path)
        return self.value


def _runtime() -> Any:
    return SimpleNamespace(
        approval_engine=object(),
        decision_history_store=object(),
    )


@pytest.mark.asyncio
async def test_builder_reads_plain_file_and_wires_runtime_instances(tmp_path: Any) -> None:
    key_path = tmp_path / "action.pem"
    key_path.write_bytes(b"PRIVATE-KEY")
    runtime = _runtime()
    host = object()
    completer = object()

    service = await build_approval_executor(
        runtime=runtime,
        settings=SimpleNamespace(
            action_context_signing_key_path=str(key_path),
            action_context_ttl_s=120.0,
            approval_executor_grace_s=30.0,
        ),
        engine=cast("AsyncEngine", object()),
        secret_adapter=cast("SecretAdapter", _Secret({})),
        mcp_host=host,
        conversation_completer=completer,
    )

    assert isinstance(service, ApprovalExecutionService)
    assert service._engine is runtime.approval_engine
    assert service._history is runtime.decision_history_store
    assert service._tool_proxy is host
    assert service._completer is completer
    assert service._signing_key == b"PRIVATE-KEY"


@pytest.mark.asyncio
async def test_builder_resolves_vault_key_material_without_treating_it_as_a_path() -> None:
    secret = _Secret({"key": "VAULT-PRIVATE-KEY"})
    service = await build_approval_executor(
        runtime=_runtime(),
        settings=SimpleNamespace(
            action_context_signing_key_path="vault://agentos/action-context",
            action_context_ttl_s=120.0,
            approval_executor_grace_s=30.0,
        ),
        engine=cast("AsyncEngine", object()),
        secret_adapter=cast("SecretAdapter", secret),
        mcp_host=object(),
        conversation_completer=object(),
    )

    assert service is not None
    assert service._signing_key == b"VAULT-PRIVATE-KEY"
    assert secret.paths == ["agentos/action-context"]


@pytest.mark.asyncio
async def test_builder_is_none_when_key_or_runtime_collaborators_are_absent() -> None:
    secret = _Secret({"key": "must-not-be-read"})
    common = {
        "runtime": _runtime(),
        "engine": cast("AsyncEngine", object()),
        "secret_adapter": cast("SecretAdapter", secret),
        "mcp_host": object(),
        "conversation_completer": object(),
    }
    settings = SimpleNamespace(
        action_context_signing_key_path=None,
        action_context_ttl_s=120.0,
        approval_executor_grace_s=30.0,
    )
    assert await build_approval_executor(settings=settings, **common) is None

    settings.action_context_signing_key_path = "vault://agentos/action-context"
    common["mcp_host"] = None
    assert await build_approval_executor(settings=settings, **common) is None
    assert secret.paths == []


@pytest.mark.asyncio
async def test_builder_refuses_an_empty_plain_key_file(tmp_path: Any) -> None:
    key_path = tmp_path / "empty.pem"
    key_path.write_bytes(b"")
    with pytest.raises(ValueError, match="must not be empty"):
        await build_approval_executor(
            runtime=_runtime(),
            settings=SimpleNamespace(
                action_context_signing_key_path=str(key_path),
                action_context_ttl_s=120.0,
                approval_executor_grace_s=30.0,
            ),
            engine=cast("AsyncEngine", object()),
            secret_adapter=cast("SecretAdapter", _Secret({})),
            mcp_host=object(),
            conversation_completer=object(),
        )

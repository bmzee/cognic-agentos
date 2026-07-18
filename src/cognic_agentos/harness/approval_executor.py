"""Compose the M8.5-D approved-action executor from live runtime seams."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.core.approval.replay import ApprovalReplayStore
from cognic_agentos.db.adapters.secret_resolution import resolve_secret_field

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from cognic_agentos.db.adapters.protocols import SecretAdapter


class _RuntimeLike(Protocol):
    @property
    def approval_engine(self) -> Any: ...

    @property
    def decision_history_store(self) -> Any: ...


class _SettingsLike(Protocol):
    action_context_signing_key_path: str | None
    action_context_ttl_s: float
    approval_executor_grace_s: float


async def build_approval_executor(
    *,
    runtime: _RuntimeLike,
    settings: _SettingsLike,
    engine: AsyncEngine,
    secret_adapter: SecretAdapter,
    mcp_host: Any | None,
    conversation_completer: Any | None,
) -> ApprovalExecutionService | None:
    """Build only when the key and both execution collaborators are present."""

    key_reference = settings.action_context_signing_key_path
    if key_reference is None or mcp_host is None or conversation_completer is None:
        return None
    if key_reference.startswith("vault://"):
        resolved = await resolve_secret_field(
            key_reference,
            secret_adapter=secret_adapter,
            field_name="action_context_signing_key_path",
        )
        if resolved is None:  # pragma: no cover - guarded by key_reference
            raise RuntimeError("action-context signing key resolution returned None")
        signing_key = resolved.encode("utf-8")
    else:
        signing_key = Path(key_reference).read_bytes()
    if not signing_key:
        raise ValueError("action-context signing key must not be empty")

    return ApprovalExecutionService(
        engine=runtime.approval_engine,
        replay_store=ApprovalReplayStore(engine),
        tool_proxy=mcp_host,
        conversation_completer=conversation_completer,
        decision_history=runtime.decision_history_store,
        signing_key=signing_key,
        settings=settings,
    )


__all__ = ("build_approval_executor",)

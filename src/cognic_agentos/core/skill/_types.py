"""M6 Task A3 (ADR-025) — broker-side types for the governed skill executor.

Off the durable coverage gate (pure type module, mirroring
``core/scheduler/_types.py`` / ``core/run/_types.py``): the substantive
enforcement lives in the on-gate ``core/skill/broker.py`` consumer.

``SkillCallProxy`` is the consumer-owned narrow seam over
``MCPHost.call_tool`` (per the consumer-owned-Protocol doctrine): the
broker unit-tests against a spy conformer without a full MCP host, and
the Task-A5 executor wires the real host through a thin adapter. The
broker NEVER imports ``protocol.*`` — the seam is the only coupling.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "SkillCallProxy",
    "_BrokerHandle",
]


@runtime_checkable
class SkillCallProxy(Protocol):
    """Narrow seam over ``MCPHost.call_tool`` (ADR-025 §"Security model").

    The broker routes every DECLARED tool request through this seam with
    the skill's bound tenant/actor and a fresh per-call ``request_id``,
    so OAuth / approval / DLP / audit apply automatically downstream.
    Implementations surface failures as exceptions — the broker maps
    them to the ``skill_tool_invocation_failed`` wire arm.
    """

    async def call(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class _BrokerHandle:
    """Handle for one served broker session (one skill invocation).

    Carries the socket path the executor mounts into the sandbox, the
    per-invocation session token the runner must present (invariant
    #4), and the idempotent ``close()`` that tears the session down
    (invariant #5 — socket + ``0700`` dir removed on success AND
    failure).
    """

    sock_path: str
    session_token: str
    _closer: Callable[[], Awaitable[None]]

    async def close(self) -> None:
        """Tear down the served session; safe to call more than once."""
        await self._closer()

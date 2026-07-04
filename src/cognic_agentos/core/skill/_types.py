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
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "LoadedSkillRecord",
    "SkillCallProxy",
    "SkillInvokeRefusalReason",
    "SkillInvokeResult",
    "SkillInvokeTerminalState",
    "SkillRecordLoader",
    "_BrokerHandle",
]

#: M6 Task A5 (ADR-025) — the executor-side pre-flight / infra refusal
#: vocabulary. DISTINCT from the broker's ``SkillBrokerReason`` (which the
#: executor surfaces as a PASSTHROUGH string, e.g. ``skill_tool_not_declared``):
#: these three are the reasons the executor itself mints —
#:
#:   * ``skill_not_found``       — the loader has no record for ``skill_id``
#:     (absent / not hosted). Route → 404.
#:   * ``skill_not_registered``  — a record exists but is not in an invokable
#:     registered state (executor-side defence in depth over the loader's
#:     admission, mirroring ``core/run``'s ``pack_record_not_installed``).
#:     Route → 409.
#:   * ``skill_runtime_error``   — the sandboxed runner crashed, timed out,
#:     produced no parseable result frame, or ``create``/``exec`` raised.
#:     Route → 502.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias`` annotation) to match
#: the repo convention at ``packs/lifecycle.py:111`` + the RBAC scope families.
SkillInvokeRefusalReason = Literal[
    "skill_not_found",
    "skill_not_registered",
    "skill_runtime_error",
]

#: The three invoke outcomes. ``completed`` carries a result dict; ``refused``
#: carries a refusal reason (a broker PASSTHROUGH string OR a pre-flight
#: :data:`SkillInvokeRefusalReason`); ``failed`` carries ``skill_runtime_error``.
SkillInvokeTerminalState = Literal["completed", "refused", "failed"]


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


@dataclass(frozen=True, slots=True)
class SkillInvokeResult:
    """Outcome of one :meth:`SkillExecutor.invoke`.

    ``terminal_state == "completed"`` → ``result`` is the runner's fixed-shape
    result dict and ``refusal_reason`` is ``None``. Otherwise ``result`` is
    ``None`` and ``refusal_reason`` carries the surfaced reason: a broker
    PASSTHROUGH string on the ``refused`` path (e.g. ``skill_tool_not_declared``
    — the load-bearing declared-tools refusal the broker minted; the executor
    NEVER re-implements the check, it surfaces the broker's frame verbatim), a
    pre-flight :data:`SkillInvokeRefusalReason` on the pre-submit ``refused``
    path (``skill_not_found`` / ``skill_not_registered``), or
    ``skill_runtime_error`` on the ``failed`` path. The route (A6) maps the
    reason string to an HTTP status.
    """

    terminal_state: SkillInvokeTerminalState
    result: dict[str, Any] | None
    refusal_reason: str | None


@dataclass(frozen=True, slots=True)
class LoadedSkillRecord:
    """Core-owned projection of a trust-registered, ``SKILL.md``-validated skill
    pack — ``core/skill`` cannot import ``protocol`` / ``packs`` / ``harness``.
    Built by the :class:`SkillRecordLoader` conformer in ``harness/skill_host.py``.

    ``entry_point_name`` is the ``cognic.skills`` entry-point the in-sandbox
    runner resolves; ``declared_tools`` are the ``<server_id>/<tool_name>`` MCP
    identities the broker is bound to (invariant #11); ``runtime_image`` is the
    immutable, cosign-verified skill-runtime image the sandbox session runs;
    ``registered`` is the executor-side invokable-state gate (False → the
    executor refuses ``skill_not_registered``).
    """

    skill_id: str
    entry_point_name: str
    declared_tools: tuple[str, ...]
    runtime_image: str
    registered: bool = True
    pack_version: str = ""
    signed_artefact_digest: bytes = field(default=b"")


@runtime_checkable
class SkillRecordLoader(Protocol):
    """Consumer-owned read seam (mirrors ``core/run``'s ``PackRecordLoader``).

    The conformer ``harness.skill_host._RegistrySkillRecordLoader`` resolves the
    ``skill_id`` (the ``SKILL.md`` frontmatter ``name``) against the boot-built
    set of trust-registered, validated skill packs and projects to
    :class:`LoadedSkillRecord`; ``None`` when the id is not a hosted skill.
    """

    async def load_for_skill(self, *, skill_id: str, tenant_id: str) -> LoadedSkillRecord | None:
        """Load + project the hosted skill record by id; None when absent."""

"""Sprint-7B.1 T6b — fixture factories for harness per-kind dispatch tests.

Per plan-of-record T6b §361-364: the harness's dispatch dry-run path
needs synthetic ``ToolRegistry`` + ``TaskRecord`` + ``HookContext``
shapes to feed Skill / Agent / Hook per-kind dispatch. These factories
construct minimal SDK-shape instances for test consumption. The
HARNESS module ``cli/test_harness.py`` has its own production builders
that produce structurally-equivalent shapes — the two surfaces are
independently maintained.

AGENTS.md test-fixture-placement rule (Sprint-1C R-round): test-only
fixtures live under ``tests/support/`` so production imports cannot
accidentally pull them in. ``tests/support/`` is on the import path
only when pytest is running.

Factories:

  - :func:`make_tool_registry_fixture` — returns a strict-membership
    ``ToolRegistry``: each declared name resolves to a distinct
    :class:`Tool` subclass whose ``.name`` ClassVar matches the
    registered key EXACTLY (R1 reviewer P3 fix — earlier draft
    returned a singleton whose name was a constant regardless of
    key). Default empty tuple yields a registry that exposes no
    tools (suitable for skill packs with empty ``declared_tools``);
    non-declared names raise ``KeyError`` on ``get``.
  - :func:`make_task_record_fixture` — returns a Wave-1 inert
    :class:`TaskRecord` with all 8 required fields populated;
    ``payload_digest`` is derived from the ``payload`` arg via
    ``hashlib.sha256(payload).hexdigest()`` to match the A2A
    source-of-truth contract (R1 reviewer P2 fix — earlier draft
    accepted ``payload`` then dropped it via ``del`` and pinned the
    digest to ``""`` regardless).
  - :func:`make_hook_context_fixture` — returns a frozen Wave-1 inert
    :class:`HookContext` with all 9 required fields populated.

Per ADR-017 + Doctrine Lock E + Sprint-7A2 T7 payload-never-logged
invariant: NO factory in this module PERSISTS OR CARRIES raw payload
bytes downstream. :func:`make_task_record_fixture` accepts a
``payload`` arg but hashes it inline (``hashlib.sha256(payload).
hexdigest()``) and persists only the digest string — the raw bytes
never leave the function scope. Default ``b""`` keeps the inert path
trivially safe; pack-author tests that pass non-trivial payload
bytes get a correct digest without leaking bytes onto the
:class:`TaskRecord` carrier. The AST-walk regression at
``tests/architecture/test_hook_payload_never_logged.py`` pins the
invariant on the runtime dispatcher; this module's contract is the
fixture-surface equivalent — digest-only persistence, no carrier-
field leak.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final

from cognic_agentos.protocol.a2a_endpoint import TaskRecord, TaskState
from cognic_agentos.sdk.hook import HookContext
from cognic_agentos.sdk.registry import ToolRegistry
from cognic_agentos.sdk.tool import Tool

# ---------------------------------------------------------------------------
# Per-name no-op Tool subclass factory + strict-membership registry
# ---------------------------------------------------------------------------


#: Permissive input schema shared by every dynamically-constructed
#: fixture no-op Tool subclass. Mirrors the harness's production
#: surface at ``cli/test_harness.py::_HARNESS_NO_OP_TOOL_INPUT_SCHEMA``
#: — the two surfaces are independently maintained.
_FIXTURE_NO_OP_TOOL_INPUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": True,
}


_FIXTURE_NO_OP_TOOL_OUTPUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": True,
}


async def _fixture_no_op_invoke(self: Tool, **kwargs: Any) -> dict[str, Any]:
    """Permissive no-op ``_invoke`` body bound to every dynamically-
    constructed fixture no-op Tool subclass. Ignores ``self`` + any
    kwargs + returns the empty dict so the SDK's output-schema
    validation seam clears."""
    del self, kwargs
    return {}


def _make_fixture_no_op_tool_class(tool_name: str) -> type[Tool]:
    """Construct a :class:`Tool` subclass whose ``name`` ClassVar
    matches ``tool_name`` EXACTLY. Mirrors the harness's production
    factory at
    ``cli/test_harness.py::_make_harness_no_op_tool_class`` so a
    skill that reads ``self._tools.get(name).name`` sees the
    registered key as the tool's identity (every real
    :class:`ToolRegistry` honors this contract — each registered
    tool's ``name`` matches the key it was registered under).
    """
    return type(
        f"_FixtureNoOpTool__{tool_name}",
        (Tool,),
        {
            "name": tool_name,
            "input_schema": _FIXTURE_NO_OP_TOOL_INPUT_SCHEMA,
            "output_schema": _FIXTURE_NO_OP_TOOL_OUTPUT_SCHEMA,
            "_invoke": _fixture_no_op_invoke,
        },
    )


class _FixtureNoOpToolRegistry:
    """Strict-membership ``ToolRegistry`` implementation. Pre-builds
    one :class:`Tool` subclass per declared name in ``__init__`` so
    ``get(name)`` returns a Tool whose ``.name`` matches the
    requested key EXACTLY.

    Strict-membership semantics: ``get(name)`` for any name outside
    ``declared`` raises ``KeyError``. Prevents future multi-tool
    skill pack drift from silently succeeding against a registry
    with FEWER tools than declared — that drift would mask a real
    :class:`Skill`.__init__`` cross-check failure.
    """

    def __init__(self, *, declared: tuple[str, ...]) -> None:
        self._declared: frozenset[str] = frozenset(declared)
        self._tools: dict[str, Tool] = {
            tool_name: _make_fixture_no_op_tool_class(tool_name)() for tool_name in declared
        }

    def list_tools(self) -> list[str]:
        return sorted(self._declared)

    def get(self, name: str) -> Tool:
        if name not in self._declared:
            raise KeyError(
                f"tool {name!r} is not registered; the harness's no-op "
                f"registry exposes only the declared_tools tuple. Declared: "
                f"{sorted(self._declared)!r}."
            )
        return self._tools[name]


# ---------------------------------------------------------------------------
# Public factory functions
# ---------------------------------------------------------------------------


def make_tool_registry_fixture(declared_tools: tuple[str, ...] = ()) -> ToolRegistry:
    """Return a strict-membership ``ToolRegistry`` exposing exactly the
    names in ``declared_tools``. Each declared name resolves to a
    distinct no-op :class:`Tool` subclass whose ``.name`` ClassVar
    matches the registered key EXACTLY (R1 reviewer P3 fix); non-
    declared names raise ``KeyError`` on ``get``.

    Used by harness dispatch dry-run for skill packs: the harness reads
    the skill class's ``declared_tools`` ClassVar + passes it here so
    ``Skill.__init__`` (R5 P2 #3 cross-check seam) sees a registry
    that exactly matches the declared set + so a skill that asserts
    ``self._tools.get(name).name == name`` for any declared name sees
    the registered key as the tool's identity.
    """
    return _FixtureNoOpToolRegistry(declared=declared_tools)


def make_task_record_fixture(payload: bytes = b"") -> TaskRecord:
    """Return a Wave-1 inert :class:`TaskRecord` with all 8 required
    fields populated. ``payload_digest`` is derived from ``payload``
    via ``hashlib.sha256(payload).hexdigest()`` to match the A2A
    source-of-truth contract at
    ``protocol/a2a_endpoint.py:436`` + ``:662`` (where the inbound
    endpoint mints the digest from the same payload bytes it routes
    to ``agent.handle``).

    Defaults match the harness's own internal builder so a test
    that constructs an expected TaskRecord through this fixture
    compares cleanly against the dispatch path. The payload bytes
    themselves are NOT persisted in the dataclass — only the digest
    string — so this fixture does NOT violate the payload-never-
    logged invariant.
    """
    return TaskRecord(
        task_id="harness-dispatch-dry-run-task",
        target_agent="harness-dispatch",
        parent_trace_id="harness-dispatch-parent",
        child_trace_id="harness-dispatch-child",
        state=TaskState.CREATED,
        created_at=0.0,
        updated_at=0.0,
        payload_digest=hashlib.sha256(payload).hexdigest(),
    )


def make_hook_context_fixture() -> HookContext:
    """Return a frozen Wave-1 inert :class:`HookContext` with all 9
    required fields populated. The phase is fixed to ``"dlp_pre"``
    (canonical Wave-1 starter phase); pack authors writing a
    ``"dlp_post"`` hook receive the same context shape from the
    harness — phase is informational, not a routing key in the
    SDK validator.
    """
    return HookContext(
        hook_id="harness_dispatch_dry_run",
        phase="dlp_pre",
        pack_id="harness_dispatch",
        tenant_id="harness",
        request_id="harness-dispatch-dry-run",
        trace_id=None,
        parent_trace_id=None,
        manifest_data_classes=(),
        manifest_purpose="harness_dispatch_dry_run",
    )


__all__ = [
    "make_hook_context_fixture",
    "make_task_record_fixture",
    "make_tool_registry_fixture",
]

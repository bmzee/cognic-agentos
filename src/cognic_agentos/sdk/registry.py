"""Sprint-7A T2 — `ToolRegistry` Protocol (R3 P2 #4).

Public type bound on every Skill instance via ``Skill.__init__(*, tools:
ToolRegistry)`` (R5 P2 #3 cross-check seam) and exposed inside skill
code as ``self._tools`` for tool resolution at run time. The
``fixture_tool_registry()`` helper produces fixture-only registries
that conform structurally without inheritance coupling — PEP 544
structural typing lets the runtime registry (eventually owned by the
MCP host or a future ``protocol/tool_registry.py``) and fixture
registries share the same wire shape.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cognic_agentos.sdk.tool import Tool


@runtime_checkable
class ToolRegistry(Protocol):
    """Runtime + fixture tool-registry contract.

    Used by:

    - ``Skill.__init__(*, tools: ToolRegistry)`` for the
      instantiation-time ``declared_tools`` cross-check (R5 P2 #3).
      The supplied registry is bound to ``self._tools`` BEFORE the
      base ``__init__`` calls the subclass ``setup()`` hook.
    - Skill code (via ``self._tools``) for tool resolution at run
      time inside ``execute()`` and any helper methods.
    - ``agentos_sdk.testing.fixture_tool_registry()`` for pack-author
      tests against fixture-only adapters.
    """

    def get(self, name: str) -> Tool:
        """Return the registered Tool by pack_id; raise KeyError if
        not registered (mirrors ``dict[str, Tool].__getitem__`` for
        predictable error semantics)."""
        ...

    def list_tools(self) -> list[str]:
        """Return the pack_ids of every registered tool. Used by
        ``Skill.__init__(*, tools)`` (R5 P2 #3 — instantiation-time
        cross-check seam) to validate ``declared_tools`` against the
        supplied registry BEFORE any ``execute()`` call."""
        ...


__all__ = ["ToolRegistry"]

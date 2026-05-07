"""Sprint-7A T2 — ToolRegistry Protocol smoke (R3 P2 #4).

Public type bound on every Skill via ``Skill.__init__(*, tools:
ToolRegistry)`` (R5 P2 #3 cross-check seam) and exposed inside skill
code as ``self._tools`` for tool resolution at run time. The
``fixture_tool_registry()`` helper produces fixture-only registries
that conform structurally. PEP 544 structural typing — runtime
registry (eventually owned by the MCP host or a future
``protocol/tool_registry.py``) AND the fixture registry conform
without inheritance coupling.
"""

from __future__ import annotations


def test_tool_registry_imports_cleanly() -> None:
    """The Protocol class is importable from the sdk package."""
    from cognic_agentos.sdk.registry import ToolRegistry  # noqa: F401


def test_tool_registry_is_a_protocol() -> None:
    """``ToolRegistry`` is declared as a ``typing.Protocol`` so
    structural typing applies. Verified via the ``runtime_checkable``
    machinery: any class with ``get(name) -> Tool`` and
    ``list_tools() -> list[str]`` should satisfy the type."""

    from cognic_agentos.sdk.registry import ToolRegistry

    # Protocol classes inherit from typing.Protocol; the metaclass is
    # _ProtocolMeta. We don't assert the exact class object because
    # typing internals shift across Python versions; instead, check
    # the Protocol-conformance flag.
    assert getattr(ToolRegistry, "_is_protocol", False) is True


def test_tool_registry_declares_get() -> None:
    """``ToolRegistry.get(name)`` is part of the Protocol surface."""
    from cognic_agentos.sdk.registry import ToolRegistry

    assert hasattr(ToolRegistry, "get")


def test_tool_registry_declares_list_tools() -> None:
    """``ToolRegistry.list_tools()`` is part of the Protocol surface."""
    from cognic_agentos.sdk.registry import ToolRegistry

    assert hasattr(ToolRegistry, "list_tools")

"""{{ class_name }} — AUTHOR-FILL: short description of what this skill does.

The pack-author contract:

  - Override ``execute`` (the public abstract). NO LLM calls in skill
    code per ADR-001 three-pool rule.
  - Declare ``declared_tools`` as a ClassVar tuple of MCP tool
    identities in ``"<server_id>/<tool_name>"`` form (M6, ADR-025 —
    ``server_id`` is the registered tool pack's distribution name).
    The list MUST mirror the manifest's ``[skill].declared_tools``;
    at runtime the kernel-side broker refuses any identity outside
    the declared set. The SDK validates ``declared_tools`` against
    the supplied ``ToolRegistry`` at instantiation time + raises
    ``SkillUnregisteredToolError`` BEFORE any ``execute()`` call if
    a declared identity is missing.
  - Override ``setup()`` (NOT ``__init__``). The SDK's
    ``Skill.__init_subclass__`` rejects subclasses that define their
    own constructor (R6 P2 #1). The base ``__init__`` calls
    ``setup()`` AFTER binding ``self._tools``, so subclass setup
    logic can reference the registry safely.
"""

from __future__ import annotations

from typing import Any, ClassVar

from cognic_agentos.sdk.skill import Skill


class {{ class_name }}(Skill):
    """AUTHOR-FILL: docstring describing what this skill orchestrates."""

    name: ClassVar[str] = "{{ pack_name }}"

    declared_tools: ClassVar[tuple[str, ...]] = (
        # AUTHOR-FILL: every MCP tool identity this skill calls, in
        # "<server_id>/<tool_name>" form — e.g.
        # "cognic-tool-oracle-schema/describe_table". MUST mirror the
        # manifest's [skill].declared_tools list.
    )

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """AUTHOR-FILL: compose tools deterministically here.

        Use ``self._tools.get("<server_id>/<tool_name>")`` to resolve a
        declared tool; the SDK's instantiation-time cross-check
        guarantees every identity in ``declared_tools`` is present in
        the supplied registry by the time ``execute()`` is called, and
        the kernel-side broker enforces the declared set on every call
        at runtime.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}.execute"
        )

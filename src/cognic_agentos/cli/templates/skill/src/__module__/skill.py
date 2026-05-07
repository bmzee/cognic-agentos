"""{{ class_name }} — AUTHOR-FILL: short description of what this skill does.

The pack-author contract:

  - Override ``execute`` (the public abstract). NO LLM calls in skill
    code per ADR-001 three-pool rule.
  - Declare ``declared_tools`` as a ClassVar tuple of tool names. The
    SDK validates ``declared_tools`` against the supplied
    ``ToolRegistry`` at instantiation time + raises
    ``SkillUnregisteredToolError`` BEFORE any ``execute()`` call if
    a declared tool is missing.
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
        # AUTHOR-FILL: list every tool name your skill calls into.
    )

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """AUTHOR-FILL: compose tools deterministically here.

        Use ``self._tools.get("<name>")`` to resolve a registered tool;
        the SDK's instantiation-time cross-check guarantees every
        name in ``declared_tools`` is present in the supplied
        registry by the time ``execute()`` is called.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}.execute"
        )

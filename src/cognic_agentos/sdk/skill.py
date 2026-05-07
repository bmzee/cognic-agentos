"""Sprint-7A T2 — `agentos_sdk.Skill` composition base class (no LLM).

Skills compose tools deterministically — no LLM call in skill code per
ADR-001 three-pool rule. The SDK enforces:

  - ``declared_tools`` instantiation-time cross-check against the
    supplied ``ToolRegistry`` (R5 P2 #3) — raises
    ``SkillUnregisteredToolError`` if any name is missing BEFORE any
    ``execute()`` call.
  - ``__init__`` is final at runtime (R6 P2 #1 + R8 P2 #1 MRO walk) —
    pack-specific construction logic lives in the ``setup()`` hook,
    which the base ``__init__`` calls AFTER the cross-check.
  - ``execute()`` is the abstract method subclasses override.
"""

from __future__ import annotations

import abc
from typing import Any, ClassVar, final

from cognic_agentos.sdk.registry import ToolRegistry


class SkillError(Exception):
    """Base class for all SDK Skill errors. The runtime harness
    catches this single class to refuse a skill at admission time."""


class SkillUnregisteredToolError(SkillError):
    """A name in ``declared_tools`` was missing from the
    ``ToolRegistry`` supplied at instantiation. R5 P2 #3 — pinned
    BEFORE any ``execute()`` call."""


class Skill(abc.ABC):
    """Base class for ``cognic.skills`` entry-point implementations.

    Subclasses declare ``name`` + ``declared_tools`` as ClassVar
    fields, override ``execute`` (and optionally ``setup``), and let
    the SDK's template-method ``__init__`` handle the registry
    cross-check.
    """

    name: ClassVar[str]
    declared_tools: ClassVar[tuple[str, ...]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """R6 P2 #1 + R8 P2 #1 — runtime enforcement of the
        ``__init__`` cross-check seam.

        Walk ``cls.__mro__`` and refuse any ancestor (other than
        ``Skill`` itself and ``object``) that defines ``__init__``
        directly. Subclasses use ``setup()`` for pack-specific
        construction; the base's ``__init__`` calls ``setup()``
        AFTER the cross-check, so subclass-side state lands without
        bypassing the registry guard.
        """
        super().__init_subclass__(**kwargs)
        for ancestor in cls.__mro__:
            if ancestor is Skill or ancestor is object:
                continue
            if "__init__" in ancestor.__dict__:
                raise TypeError(
                    f"{cls.__qualname__} resolves Skill.__init__() to a non-base "
                    f"override defined in {ancestor.__qualname__} (in MRO before "
                    "Skill). The Skill template-method contract pins ``__init__`` "
                    "as final; the only allowed owner is the SDK's Skill base. "
                    "Override Skill.setup() instead so the SDK's declared_tools "
                    "cross-check seam cannot be bypassed via mixin smuggling."
                )

    @final
    def __init__(self, *, tools: ToolRegistry) -> None:
        """Bind a tool registry at instantiation; cross-check
        ``declared_tools`` against ``tools.list_tools()`` BEFORE any
        ``execute()`` call. Subclasses MUST NOT override this method
        — pinned via ``@typing.final`` (mypy) AND ``__init_subclass__``
        (runtime). For pack-specific construction logic, override
        ``setup()`` instead.

        Raises ``SkillUnregisteredToolError`` if any name in
        ``declared_tools`` is missing from the registry. Pinned by
        the T2 Step-1 instantiation-time regression in
        ``test_skill_base.py``.
        """
        registered = set(tools.list_tools())
        missing = [name for name in self.declared_tools if name not in registered]
        if missing:
            raise SkillUnregisteredToolError(
                f"{type(self).__qualname__} declares tools {missing!r} "
                f"that are not in the supplied ToolRegistry. Either "
                f"register the missing tools before instantiating the "
                f"skill, or remove them from declared_tools."
            )
        self._tools: ToolRegistry = tools
        self.setup()

    def setup(self) -> None:  # noqa: B027 — intentional override-or-no-op hook
        """Subclass hook for pack-specific construction logic.
        Called by the base ``__init__`` AFTER the registry
        cross-check has passed. Default is a no-op; subclasses
        override as needed.

        ``self._tools`` is bound by the time this is called, so
        subclass setup logic can reference it (e.g., to pre-resolve
        a Tool instance and cache it on ``self``).
        """

    @abc.abstractmethod
    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Skill-specific composition. ``self._tools`` (bound at
        ``__init__`` time per R5 P2 #3) is the runtime registry the
        skill calls into; subclasses use
        ``self._tools.get(<pack_id>)`` to resolve a Tool, then
        ``await tool.invoke(**...)`` to call it."""
        raise NotImplementedError


__all__ = [
    "Skill",
    "SkillError",
    "SkillUnregisteredToolError",
]

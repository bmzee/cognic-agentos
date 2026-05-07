# mypy: disable-error-code="misc,override,unused-ignore,arg-type,assignment,truthy-bool"
"""Sprint-7A T2 — `agentos_sdk.Skill` base-class contract tests.

Skills compose tools deterministically — NO LLM call in skill code per
ADR-001 three-pool rule. The SDK enforces:

  - Abstract method `execute` (subclasses override).
  - ClassVar declarations (`name`, `declared_tools`).
  - **Instantiation-time `declared_tools` cross-check** (R5 P2 #3) —
    `Skill(tools=registry)` raises `SkillUnregisteredToolError` BEFORE
    any `execute()` call if any name in `declared_tools` is missing
    from the registry.
  - **`__init__` runtime override-rejection** (R6 P2 #1) — defining a
    subclass with its own `__init__` raises `TypeError` at
    class-creation time. Subclasses use the `setup()` hook for
    pack-specific init.
  - **Mixin-bypass rejection** (R8 P2 #1) — same MRO-walk pattern as
    Tool's `invoke` guard.
"""

from __future__ import annotations

import pytest


def _make_fixture_registry(tool_names: tuple[str, ...]) -> object:
    """Build a minimal fixture ToolRegistry exposing the supplied
    tool names. Structural typing means we don't need to import the
    Protocol — any object with `get(name) -> Tool` and
    `list_tools() -> list[str]` satisfies the contract."""

    class _FixtureRegistry:
        def get(self, name: str) -> object:
            raise NotImplementedError

        def list_tools(self) -> list[str]:
            return list(tool_names)

    return _FixtureRegistry()


# ---------------------------------------------------------------------------
# (a) Abstract method enforcement on `execute`
# ---------------------------------------------------------------------------


def test_skill_execute_is_abstract() -> None:
    from cognic_agentos.sdk.skill import Skill

    class IncompleteSkill(Skill):
        name = "incomplete"
        declared_tools: tuple[str, ...] = ()

    with pytest.raises(TypeError, match="abstract"):
        IncompleteSkill(tools=_make_fixture_registry(()))  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# (b) ClassVar declarations
# ---------------------------------------------------------------------------


def test_skill_classvar_name_declared() -> None:
    from cognic_agentos.sdk.skill import Skill

    assert "name" in Skill.__annotations__


def test_skill_classvar_declared_tools_declared() -> None:
    from cognic_agentos.sdk.skill import Skill

    assert "declared_tools" in Skill.__annotations__


# ---------------------------------------------------------------------------
# (c) declared_tools instantiation-time cross-check (R5 P2 #3)
# ---------------------------------------------------------------------------


def test_skill_instantiation_with_missing_tool_raises() -> None:
    """`Skill(tools=registry_missing_a_declared_tool)` raises
    `SkillUnregisteredToolError` BEFORE any `execute()` call.
    `affects_exit_code` here is "subclass-of-SkillError" — the
    runtime harness catches SkillError to refuse the skill."""
    from cognic_agentos.sdk.skill import Skill, SkillUnregisteredToolError

    class GoodSkill(Skill):
        name = "good"
        declared_tools: tuple[str, ...] = ("alpha", "beta")

        async def execute(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {}

    # Registry missing "beta".
    registry = _make_fixture_registry(("alpha",))

    with pytest.raises(SkillUnregisteredToolError, match="beta"):
        GoodSkill(tools=registry)


def test_skill_unregistered_tool_error_subclasses_skill_error() -> None:
    from cognic_agentos.sdk.skill import SkillError, SkillUnregisteredToolError

    assert issubclass(SkillUnregisteredToolError, SkillError)


def test_skill_instantiation_with_full_registry_succeeds() -> None:
    """Happy path: registry has every declared tool → instantiation
    succeeds, `self._tools` is bound."""
    from cognic_agentos.sdk.skill import Skill

    class GoodSkill(Skill):
        name = "good"
        declared_tools: tuple[str, ...] = ("alpha", "beta")

        async def execute(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {}

    registry = _make_fixture_registry(("alpha", "beta", "gamma"))
    s = GoodSkill(tools=registry)
    assert s._tools is registry


# ---------------------------------------------------------------------------
# (d) __init__ runtime override-rejection (R6 P2 #1)
# ---------------------------------------------------------------------------


def test_subclass_overriding_init_raises_at_class_creation() -> None:
    """R6 P2 #1: defining a subclass with its own `__init__` raises
    `TypeError` at class-creation time. Pack-specific construction
    logic goes in `setup()` instead."""
    from cognic_agentos.sdk.skill import Skill

    with pytest.raises(TypeError, match="__init__"):

        class BadSkill(Skill):
            name = "bad"
            declared_tools: tuple[str, ...] = ()

            def __init__(self, *, tools: object) -> None:
                # Subclass attempts to bypass the cross-check.
                self._tools = tools

            async def execute(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
                return {}


def test_subclass_overriding_only_setup_succeeds() -> None:
    """Subclass overrides `setup()` (NOT `__init__`); the base
    `__init__` calls `setup()` AFTER the registry cross-check, so
    subclass setup logic can reference `self._tools`."""
    from cognic_agentos.sdk.skill import Skill

    class SetupSkill(Skill):
        name = "setup_skill"
        declared_tools: tuple[str, ...] = ("alpha",)
        setup_ran: bool = False
        tools_visible_at_setup: bool = False

        def setup(self) -> None:
            type(self).setup_ran = True
            type(self).tools_visible_at_setup = self._tools is not None  # type: ignore[truthy-bool]

        async def execute(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
            return {}

    s = SetupSkill(tools=_make_fixture_registry(("alpha",)))
    assert SetupSkill.setup_ran is True
    assert SetupSkill.tools_visible_at_setup is True
    assert s._tools is not None  # type: ignore[truthy-bool]


# ---------------------------------------------------------------------------
# (e) Mixin-bypass rejection (R8 P2 #1)
# ---------------------------------------------------------------------------


def test_mixin_smuggled_init_raises_at_class_creation() -> None:
    """R8 P2 #1: `class Bypass: __init__; class Sub(Bypass, Skill):
    pass` raises at `Sub`'s class-creation time."""
    from cognic_agentos.sdk.skill import Skill

    class Bypass:
        def __init__(self, *, tools: object) -> None:
            self._tools = tools

    with pytest.raises(TypeError, match="Bypass"):

        class Sub(Bypass, Skill):
            name = "sub"
            declared_tools: tuple[str, ...] = ()

            async def execute(self, **kwargs: object) -> dict:  # type: ignore[type-arg, override]
                return {}

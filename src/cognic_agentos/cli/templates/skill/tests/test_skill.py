"""{{ class_name }} smoke tests."""

from __future__ import annotations

import pytest

from {{ module_name }}.{{ kind }} import {{ class_name }}


def test_skill_class_creation_passes_sdk_init_subclass() -> None:
    """Importing the {{ class_name }} module + class-creating the
    subclass passes without tripping the SDK's
    ``Skill.__init_subclass__`` runtime guards (no ``__init__``
    override on the subclass MRO)."""
    assert {{ class_name }}.name == "{{ pack_name }}"


@pytest.mark.skip(reason="AUTHOR-FILL: replace with real test once execute() is implemented")
async def test_skill_execute_with_fixture_registry(
    fixture_tool_registry: object,
) -> None:
    skill = {{ class_name }}(tools=fixture_tool_registry)
    result = await skill.execute()
    assert result is not None

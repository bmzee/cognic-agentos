"""{{ class_name }} smoke tests.

The default scaffold ships one passing class-creation arm + one
``@pytest.mark.skip`` invoke arm pack authors enable as they implement
``_invoke``.
"""

from __future__ import annotations

import pytest

from {{ module_name }}.{{ kind }} import {{ class_name }}


def test_tool_class_creation_passes_sdk_init_subclass() -> None:
    """Importing the {{ class_name }} module + class-creating the
    subclass passes without tripping the SDK's
    ``Tool.__init_subclass__`` runtime guards (no ``invoke`` override
    on the subclass MRO)."""
    assert {{ class_name }}.name == "{{ pack_name }}"


@pytest.mark.skip(reason="AUTHOR-FILL: replace with real assertion once _invoke is implemented")
async def test_tool_invoke_happy_path() -> None:
    tool = {{ class_name }}()
    result = await tool.invoke()
    assert result is not None

"""{{ class_name }} smoke tests."""

from __future__ import annotations

import pytest

from {{ module_name }}.{{ kind }} import {{ class_name }}


def test_agent_class_creation_passes_sdk_init_subclass() -> None:
    """Importing the {{ class_name }} module + class-creating the
    subclass passes; the ``handle`` signature matches the shipped
    Sprint-6 A2AEndpoint dispatch contract."""
    assert {{ class_name }}.name == "{{ pack_name }}"


@pytest.mark.skip(reason="AUTHOR-FILL: implement handle() then enable this arm")
async def test_agent_handle_dispatches() -> None:
    pass

"""Pytest config for {{ pack_id }} — re-exports the SDK testing fixtures.

Importing the fixtures here makes them available to every test in the
``tests/`` tree as plain pytest fixture parameters (pytest discovers
them via this conftest at collection time).
"""

# noqa: F401  — pytest fixture-discovery imports
from cognic_agentos.sdk.testing import (  # noqa: F401
    fixture_audit_capture,
    fixture_settings,
    fixture_tool_registry,
)

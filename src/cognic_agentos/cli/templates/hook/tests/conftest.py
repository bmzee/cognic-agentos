"""pytest fixtures for {{ pack_id }} hook-pack tests.

The cognic-agentos SDK's testing helpers ship as pytest fixtures
(see ``cognic_agentos.sdk.testing``); this conftest registers the
plugin so test files can declare ``fixture_settings`` /
``fixture_tool_registry`` / ``fixture_audit_capture`` as test args
without per-file imports.
"""

from __future__ import annotations

pytest_plugins = ("cognic_agentos.sdk.testing",)

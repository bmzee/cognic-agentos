"""M5 (ADR-017) — MCPHost DLP wiring contract tests.

Critical-controls module (``protocol/mcp_host.py``). Task 3 pins the optional
``dlp_guard`` construction seam; later tasks add the ``_dlp_pre_scan`` behaviour
tests. Deps are self-contained (there is no ``conftest.py`` in
``tests/unit/protocol/``); ``require_mcp`` is monkeypatched so the host
constructs without the SDK check firing, and ``servers``/``transports`` are
empty so no per-server transport validation runs.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from cognic_agentos.core.config import build_settings_without_env_file


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


def _host(host_module: Any, **kwargs: Any) -> Any:
    return host_module.MCPHost(
        servers={},
        transports={},
        authz=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=build_settings_without_env_file(),
        **kwargs,
    )


class TestMCPHostDLPGuardConstruction:
    """M5: ``MCPHost`` accepts an optional ``dlp_guard``. ``None`` (the default)
    keeps the pre-M5 construction byte-for-byte; a wired guard is stored for
    ``call_tool``'s dlp_pre scan (Task 4)."""

    def test_dlp_guard_defaults_none(self, host_module: Any) -> None:
        host = _host(host_module)
        assert host._dlp_guard is None

    def test_dlp_guard_is_stored(self, host_module: Any) -> None:
        guard = MagicMock()
        host = _host(host_module, dlp_guard=guard)
        assert host._dlp_guard is guard

"""Sprint-4 fixture entry-point target.

The class shape is deliberately minimal — Sprint 4's deferred-load
contract means this module is only imported when an explicit
``PluginRegistry.load("tools", "cognic_test_pack")`` call fires after
admission. Operators / tests that exercise that path see a Plugin
class with stable identity attributes; they don't get a real Tool
implementation (that's Sprint 5+ territory).
"""

from __future__ import annotations


class Plugin:
    """Minimal Sprint-4-fixture Plugin marker.

    Real Cognic tool packs would declare an MCP-conformant interface
    here per ADR-002. The fixture only needs identity attributes so
    deferred-load tests can assert ``Plugin.name`` /
    ``Plugin.version`` round-trip through the registry.
    """

    name: str = "cognic_test_pack"
    version: str = "0.1.0"

    def __repr__(self) -> str:
        return f"<Plugin name={self.name!r} version={self.version!r}>"

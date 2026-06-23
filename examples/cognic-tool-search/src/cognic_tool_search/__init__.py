"""cognic-tool-search - Proof 1a example MCP tool pack.

SERVER_DESCRIPTOR is the importable entry-point object PluginRegistry.discover()
resolves the distribution from. The runtime MCP invocation path runs the tool
behind a real HTTP server (see server.py) and NEVER EntryPoint.load()s this
object; it exists only for discovery + the optional `agentos verify` load-probe.
Do NOT import-poison this module - `agentos verify`'s load-probe must succeed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _ServerDescriptor:
    """Inert marker. The real server lives in cognic_tool_search.server."""

    pack_id: str = "cognic-tool-search"
    tool_name: str = "search_policy_docs"


SERVER_DESCRIPTOR = _ServerDescriptor()

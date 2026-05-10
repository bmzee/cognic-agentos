"""Sprint-7A2 — :mod:`cognic_agentos.packs` runtime pack subsystems.

The ``packs`` namespace is the runtime-side counterpart of the
``cognic_agentos.cli`` authoring-side surface. Sprint-7A authored the
pack-manifest validator stack at ``cli/validators/``; Sprint-7A2 ships
the runtime registries that consume verified-pack output (hooks first,
per ADR-008 + ADR-017). Future sprints add per-kind runtime modules
(MCP-host pack registry, A2A pack registry) under this namespace.

This package does NOT host plugin packs themselves — those ship as
separate distributions (``cognic-hook-<name>``, ``cognic-tool-<name>``,
etc.) per the OS / pack boundary in AGENTS.md. ``packs`` here is OS
runtime infrastructure that admits + dispatches verified packs.
"""

from __future__ import annotations

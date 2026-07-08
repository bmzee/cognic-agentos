"""protocol/agent_manifest.py — M8 A8 (ADR-027) AGENT.md persona reader.

Reads an agent pack's ``AGENT.md`` (the persona document the governed agent
loop hosts) as package data WITHOUT importing pack code — the same
``Distribution.locate_file()`` deferred-load discipline as
:mod:`cognic_agentos.protocol.skill_manifest` / ``mcp_manifest`` (ADR-002
§gate 1): the hosting layer validates + hosts the persona but agent-pack
Python NEVER loads into the kernel process.

The frontmatter contract is REUSED from :mod:`cognic_agentos.protocol.
skill_manifest` — ``parse_skill_md`` + ``validate_skill_md`` are re-exported
here (the same objects, NOT a fork): an AGENT.md is the same
``---``-fenced YAML frontmatter (``name`` label + ``description`` ≤ 1024)
over a non-empty instructions body, so the wire contract is shared and a
malformed persona surfaces the same closed-enum
:data:`~cognic_agentos.protocol.skill_manifest.SkillMdValidationReason` via
:class:`~cognic_agentos.protocol.skill_manifest.SkillManifestInvalid`. The
loader in ``harness/agent_host.py`` warn-skips a pack that fails (a bad agent
pack is not hosted, never crashes the boot — the M5 mapper doctrine).

Off the durable coverage gate (small reader; trust is upstream in the plugin
registry's cosign gate + the CLI agents validator's build-time checks). NO SDK
import; the kernel image reads this module cleanly.
"""

from __future__ import annotations

import importlib.metadata as _im
import re as _re
from pathlib import Path

# REUSED frontmatter contract (same wire contract, do not fork) — re-exported
# for agent-side consumers so the persona pipeline imports from one place.
from cognic_agentos.protocol.skill_manifest import (
    SkillManifestInvalid,
    parse_skill_md,
    validate_skill_md,
)

#: The persona artifact filename inside the agent pack's package data.
_AGENT_MD_FILENAME = "AGENT.md"

#: Defence-in-depth: the ``package_name`` interpolated into the AGENT.md path
#: must be a single Python identifier segment (mirrors skill_manifest /
#: mcp_manifest — path-shaped values are rejected before
#: ``Distribution.locate_file`` resolves anything).
_PACKAGE_NAME_RE: _re.Pattern[str] = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AgentManifestError(Exception):
    """Base for AGENT.md read failures."""


class AgentManifestNotFound(AgentManifestError):
    """Raised when ``AGENT.md`` cannot be located as package data in the
    installed agent distribution (distribution absent, RECORD does not list
    the file, file missing on disk, or ``package_name`` fails the identifier
    guard)."""


def extract_agent_md(*, distribution_name: str, package_name: str) -> str:
    """Read ``<package_name>/AGENT.md`` from an installed agent distribution
    WITHOUT importing pack code (``Distribution.locate_file`` — the
    deferred-load invariant; see the module docstring). Returns the raw text.

    :raises AgentManifestNotFound: distribution not installed OR AGENT.md not
        in RECORD OR file missing on disk OR ``package_name`` fails the
        identifier guard.
    """
    if not isinstance(package_name, str) or not _PACKAGE_NAME_RE.fullmatch(package_name):
        raise AgentManifestNotFound(
            f"package_name must be a single Python identifier segment "
            f"(got {package_name!r}); path-shaped values are rejected before "
            f"Distribution.locate_file resolves the AGENT.md path."
        )
    try:
        dist = _im.distribution(distribution_name)
    except _im.PackageNotFoundError as exc:
        raise AgentManifestNotFound(
            f"Agent distribution {distribution_name!r} is not installed."
        ) from exc
    relative_path = f"{package_name}/{_AGENT_MD_FILENAME}"
    located = dist.locate_file(relative_path)
    if located is None:
        raise AgentManifestNotFound(
            f"Agent pack {distribution_name!r} does not declare {relative_path!r} "
            f"in its RECORD / installed-files metadata. Ship AGENT.md as package "
            f"data (force-include) so the hosting layer can validate it without "
            f"importing pack code."
        )
    manifest_path = Path(str(located))
    if not manifest_path.is_file():
        raise AgentManifestNotFound(
            f"Agent pack {distribution_name!r} declares {relative_path!r} in RECORD "
            f"but the file does not exist on disk at {manifest_path!s}."
        )
    return manifest_path.read_text(encoding="utf-8")


__all__ = (
    "AgentManifestError",
    "AgentManifestNotFound",
    "SkillManifestInvalid",
    "extract_agent_md",
    "parse_skill_md",
    "validate_skill_md",
)

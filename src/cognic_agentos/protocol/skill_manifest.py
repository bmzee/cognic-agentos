"""protocol/skill_manifest.py — M6 (ADR-025) SKILL.md frontmatter reader + validator.

Reads a skill pack's ``SKILL.md`` (the agentskills.io standard artifact) as
package data WITHOUT importing pack code — same ``Distribution.locate_file()``
deferred-load discipline as :mod:`cognic_agentos.protocol.mcp_manifest` (ADR-002
§gate 1): the hosting layer validates + hosts the ``SKILL.md`` but the executable
action's Python NEVER loads into the kernel process (that is the M5 hook pattern,
which ADR-025 D1 forbids for skills — the action runs ONLY inside the sandbox).

The validator enforces the agentskills.io shape the AgentOS hosting layer governs
without replacing: a ``name`` matching the reverse-DNS-safe label regex, a
``description`` ≤ 1024 chars, and a non-empty instructions body. Malformed
frontmatter / bad shape surfaces as a closed-enum
:data:`SkillMdValidationReason`; the loader in ``harness/skill_host.py`` warn-skips
a pack that fails (mirroring the M5 mapper doctrine — a bad skill pack is not
hosted, never crashes the boot).

Off the durable coverage gate (small validator; trust is upstream in the plugin
registry's cosign gate + the CLI skill validator's build-time checks). NO SDK
import; the kernel image reads this module cleanly.
"""

from __future__ import annotations

import importlib.metadata as _im
import re as _re
from pathlib import Path
from typing import Any, Literal

import yaml

#: The agentskills.io ``name`` shape — a reverse-DNS-safe label: lowercase
#: alphanumerics + internal hyphens, 1-64 chars, no leading/trailing hyphen.
_NAME_RE: _re.Pattern[str] = _re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")

#: ``description`` length ceiling (agentskills.io).
_MAX_DESCRIPTION_LEN = 1024

#: Defence-in-depth: the ``package_name`` interpolated into the SKILL.md path
#: must be a single Python identifier segment (mirrors mcp_manifest).
_PACKAGE_NAME_RE: _re.Pattern[str] = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Closed-enum SKILL.md validation-failure vocabulary. Wire-adjacent — the loader
#: logs the reason on warn-skip so operators can debug why a pack was not hosted.
SkillMdValidationReason = Literal[
    "skill_md_frontmatter_malformed",
    "skill_md_name_invalid",
    "skill_md_description_invalid",
    "skill_md_description_too_long",
    "skill_md_body_empty",
]


class SkillManifestError(Exception):
    """Base for SKILL.md read/validation failures."""


class SkillManifestNotFound(SkillManifestError):
    """Raised when ``SKILL.md`` cannot be located as package data in the
    installed skill distribution (distribution absent, RECORD does not list the
    file, file missing on disk, or ``package_name`` fails the identifier guard)."""


class SkillManifestInvalid(SkillManifestError):
    """Raised when ``SKILL.md`` frontmatter/body fails the agentskills.io shape.

    Carries the closed-enum :data:`SkillMdValidationReason` so the loader can log
    a precise warn-skip reason.
    """

    def __init__(self, reason: SkillMdValidationReason) -> None:
        self.reason: SkillMdValidationReason = reason
        super().__init__(reason)


def parse_skill_md(text: str) -> tuple[dict[str, Any], str]:
    """Split a ``SKILL.md`` into ``(frontmatter, body)``.

    The frontmatter is a leading ``---``-delimited YAML mapping (agentskills.io);
    the body is everything after the closing ``---``. Raises
    :class:`SkillManifestInvalid` with ``skill_md_frontmatter_malformed`` on a
    missing delimiter block, a YAML parse error, or a non-mapping frontmatter.
    """
    stripped = text.lstrip("﻿")  # tolerate a BOM
    if not stripped.startswith("---"):
        raise SkillManifestInvalid("skill_md_frontmatter_malformed")
    # Consume the opening fence line, then find the closing fence.
    rest = stripped[3:]
    if rest.startswith("\r\n"):
        rest = rest[2:]
    elif rest.startswith("\n"):
        rest = rest[1:]
    else:
        raise SkillManifestInvalid("skill_md_frontmatter_malformed")
    end = _find_closing_fence(rest)
    if end is None:
        raise SkillManifestInvalid("skill_md_frontmatter_malformed")
    fm_text, body = rest[: end[0]], rest[end[1] :]
    try:
        loaded = yaml.safe_load(fm_text) if fm_text.strip() else {}
    except yaml.YAMLError as exc:
        raise SkillManifestInvalid("skill_md_frontmatter_malformed") from exc
    if not isinstance(loaded, dict):
        raise SkillManifestInvalid("skill_md_frontmatter_malformed")
    return loaded, body


def _find_closing_fence(text: str) -> tuple[int, int] | None:
    """Return ``(fence_start, after_fence)`` offsets of the first line that is
    exactly ``---`` (agentskills.io closing fence), or ``None`` when absent."""
    idx = 0
    for line in text.splitlines(keepends=True):
        if line.rstrip("\r\n") == "---":
            after = idx + len(line)
            return idx, after
        idx += len(line)
    return None


def validate_skill_md(frontmatter: dict[str, Any], *, body: str) -> None:
    """Validate the agentskills.io shape. Raises :class:`SkillManifestInvalid`
    with the matching closed-enum reason on the first failure; returns ``None``
    when valid.

    * ``name`` — must be a string matching :data:`_NAME_RE`
      (``skill_md_name_invalid``; also covers missing / non-string).
    * ``description`` — must be a string (``skill_md_description_invalid``) ≤ 1024
      chars (``skill_md_description_too_long``).
    * ``body`` — the instructions body must be non-blank (``skill_md_body_empty``).
    """
    name = frontmatter.get("name")
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise SkillManifestInvalid("skill_md_name_invalid")
    description = frontmatter.get("description")
    if not isinstance(description, str):
        raise SkillManifestInvalid("skill_md_description_invalid")
    if len(description) > _MAX_DESCRIPTION_LEN:
        raise SkillManifestInvalid("skill_md_description_too_long")
    if not body.strip():
        raise SkillManifestInvalid("skill_md_body_empty")


def extract_skill_md(*, distribution_name: str, package_name: str) -> str:
    """Read ``<package_name>/SKILL.md`` from an installed skill distribution
    WITHOUT importing pack code (``Distribution.locate_file`` — the deferred-load
    invariant; see the module docstring). Returns the raw text.

    :raises SkillManifestNotFound: distribution not installed OR SKILL.md not in
        RECORD OR file missing on disk OR ``package_name`` fails the identifier
        guard.
    """
    if not isinstance(package_name, str) or not _PACKAGE_NAME_RE.fullmatch(package_name):
        raise SkillManifestNotFound(
            f"package_name must be a single Python identifier segment "
            f"(got {package_name!r}); path-shaped values are rejected before "
            f"Distribution.locate_file resolves the SKILL.md path."
        )
    try:
        dist = _im.distribution(distribution_name)
    except _im.PackageNotFoundError as exc:
        raise SkillManifestNotFound(
            f"Skill distribution {distribution_name!r} is not installed."
        ) from exc
    relative_path = f"{package_name}/SKILL.md"
    located = dist.locate_file(relative_path)
    if located is None:
        raise SkillManifestNotFound(
            f"Skill pack {distribution_name!r} does not declare {relative_path!r} "
            f"in its RECORD / installed-files metadata. Ship SKILL.md as package "
            f"data (force-include) so the hosting layer can validate it without "
            f"importing pack code."
        )
    manifest_path = Path(str(located))
    if not manifest_path.is_file():
        raise SkillManifestNotFound(
            f"Skill pack {distribution_name!r} declares {relative_path!r} in RECORD "
            f"but the file does not exist on disk at {manifest_path!s}."
        )
    return manifest_path.read_text(encoding="utf-8")


__all__ = (
    "SkillManifestError",
    "SkillManifestInvalid",
    "SkillManifestNotFound",
    "SkillMdValidationReason",
    "extract_skill_md",
    "parse_skill_md",
    "validate_skill_md",
)

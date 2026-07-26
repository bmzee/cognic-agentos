"""Synthetic agent-pack fixtures for the kernel conformance suite.

The pack is deliberately BORING: one requested skill, one requested tool (a real
``<server_id>/<tool_name>`` identity), a
two-line persona. Its only job is to be trivially correct so that any failure
in a conformance run is attributable to the KERNEL and never to pack quality.

What is REAL here (versus the unit suite's stubs):

* the manifest and ``AGENT.md`` are real bytes on disk, read by the real
  ``extract_pack_manifest`` / ``extract_agent_md`` through the real
  ``Distribution.locate_file`` resolution path — only distribution *lookup* is
  redirected, so the deferred-load invariant is exercised, not bypassed;
* the record loader is the real :func:`_build_agent_records` walk.

What is necessarily scripted: the model (no LLM in CI) and the MCP tool proxy
(no MCP server in CI). Both are the *inputs* to the governed decisions under
test, never the decisions themselves.
"""

from __future__ import annotations

import importlib.metadata as _im
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

MANIFEST_BASENAME = "cognic-pack-manifest.toml"
AGENT_MD_BASENAME = "AGENT.md"

DEFAULT_DIST = "cognic-agent-conformance"
DEFAULT_PACKAGE = "cognic_agent_conformance"
DEFAULT_AGENT_ID = "conformance-agent"
DEFAULT_VERSION = "0.1.0"


class FakeDist:
    """An ``importlib.metadata.Distribution``-shaped stand-in whose
    ``locate_file`` resolves against a real tmp-path root.

    Mirrors the shape used by
    ``tests/unit/protocol/test_plugin_registry_manifest_discovery.py`` so both
    suites exercise the same resolution contract.
    """

    def __init__(
        self,
        *,
        name: str,
        version: str,
        root: Path,
        files: list[str] | None,
    ) -> None:
        self._name = name
        self.version = version
        self._root = root
        self._files = files

    @property
    def metadata(self) -> dict[str, Any]:
        return {"Name": self._name}

    @property
    def entry_points(self) -> tuple[Any, ...]:
        return ()

    @property
    def files(self) -> list[_im.PackagePath] | None:
        if self._files is None:
            return None
        return [_im.PackagePath(f) for f in self._files]

    def locate_file(self, relative: Any) -> Path:
        return self._root / str(relative)


def agent_manifest_toml(
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    requested_skills: tuple[str, ...] = ("conformance-skill",),
    requested_tools: tuple[str, ...] = ("conformance-server/conformance_query",),
    max_steps: int | None = 4,
    risk_tier: str = "read_only",
) -> str:
    """Canonical-path ``[agent]`` manifest for a synthetic agent pack.

    ``agent_id`` is accepted for symmetry with the AGENT.md builder but is NOT
    written here: the kernel derives the agent id from the AGENT.md frontmatter
    ``name``, and duplicating it in the manifest would let a fixture drift from
    the contract it is meant to pin.
    """
    del agent_id
    lines = [
        "[pack]",
        f'pack_id = "{DEFAULT_DIST}"',
        'kind = "agent"',
        "",
        "[risk_tier]",
        f'tier = "{risk_tier}"',
        "",
        "[agent]",
        f"requested_skills = {list(requested_skills)!r}".replace("'", '"'),
        f"requested_tools = {list(requested_tools)!r}".replace("'", '"'),
    ]
    if max_steps is not None:
        lines.append(f"max_steps = {max_steps}")
    return "\n".join(lines) + "\n"


def agent_md(
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    description: str = "Synthetic conformance agent. Not a product pack.",
    body: str = "Answer using only assigned capabilities.",
) -> str:
    """Minimal valid agentskills.io frontmatter + non-blank body.

    ``name`` becomes the kernel-side agent id (``_build_agent_records``).
    """
    return f"---\nname: {agent_id}\ndescription: {description}\n---\n\n{body}\n"


def write_agent_pack(
    root: Path,
    *,
    package: str = DEFAULT_PACKAGE,
    agent_id: str = DEFAULT_AGENT_ID,
    requested_skills: tuple[str, ...] = ("conformance-skill",),
    requested_tools: tuple[str, ...] = ("conformance-server/conformance_query",),
    max_steps: int | None = 4,
    risk_tier: str = "read_only",
    write_agent_md: bool = True,
) -> Path:
    """Write a real synthetic agent pack under ``root`` and return its package dir.

    ``write_agent_md=False`` produces the negative fixture for the
    ``agent.agent_md_not_found`` warn-skip arm.
    """
    pkg_dir = root / package
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / MANIFEST_BASENAME).write_text(
        agent_manifest_toml(
            agent_id=agent_id,
            requested_skills=requested_skills,
            requested_tools=requested_tools,
            max_steps=max_steps,
            risk_tier=risk_tier,
        ),
        encoding="utf-8",
    )
    if write_agent_md:
        (pkg_dir / AGENT_MD_BASENAME).write_text(agent_md(agent_id=agent_id), encoding="utf-8")
    return pkg_dir


def pack_record_files(package: str = DEFAULT_PACKAGE) -> list[str]:
    """RECORD-style file list for a synthetic agent pack."""
    return [
        f"{package}/{MANIFEST_BASENAME}",
        f"{package}/{AGENT_MD_BASENAME}",
        f"{package}/__init__.py",
    ]


def candidate(
    *,
    distribution_name: str = DEFAULT_DIST,
    package_name: str = DEFAULT_PACKAGE,
    signature_digest: str | None = "0" * 64,
) -> RegisteredPackCandidate:
    """A registered-pack row for the loader walk.

    Deliberately builds the REAL :class:`RegisteredPackCandidate` rather than a
    look-alike: if the projection gains or renames a field, this suite fails
    loudly instead of passing against a stale shape.
    """
    return RegisteredPackCandidate(
        distribution_name=distribution_name,
        package_name=package_name,
        signature_digest=signature_digest,
    )


class Registry:
    """``_RegistryCandidates`` conformer over a fixed candidate list."""

    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._candidates = list(candidates)

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(list(self._candidates))

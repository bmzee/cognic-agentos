"""M8 A8 (ADR-027) — AGENT.md persona reader for agent packs.

``extract_agent_md`` mirrors ``extract_skill_md``'s deferred-load / not-found
contract (``Distribution.locate_file`` — pack code is NEVER imported); the
frontmatter contract is REUSED from ``protocol.skill_manifest`` (the same
``parse_skill_md`` / ``validate_skill_md`` objects — same wire contract, not a
fork).
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cognic_agentos.protocol import agent_manifest, skill_manifest
from cognic_agentos.protocol.agent_manifest import (
    AgentManifestError,
    AgentManifestNotFound,
    extract_agent_md,
)

_VALID_AGENT_MD = """---
name: schema-advisor
description: Answers schema questions through governed skills and tools.
---
You are a schema advisor. Use read_skill before invoking any skill.
"""


# ============================ reuse (do-not-fork) =============================
def test_frontmatter_contract_is_reused_not_forked() -> None:
    """The parse/validate callables re-exported by agent_manifest ARE the
    skill_manifest objects — identity-pinned so a future fork trips here."""
    assert agent_manifest.parse_skill_md is skill_manifest.parse_skill_md
    assert agent_manifest.validate_skill_md is skill_manifest.validate_skill_md
    assert agent_manifest.SkillManifestInvalid is skill_manifest.SkillManifestInvalid


def test_valid_agent_md_parses_and_validates() -> None:
    fm, body = agent_manifest.parse_skill_md(_VALID_AGENT_MD)
    agent_manifest.validate_skill_md(fm, body=body)  # no raise
    assert fm["name"] == "schema-advisor"
    assert "schema advisor" in body


# ============================ extract (deferred-load) ========================
def test_extract_not_found_for_absent_distribution() -> None:
    with pytest.raises(AgentManifestNotFound):
        extract_agent_md(
            distribution_name="cognic-agent-nonexistent-xyz",
            package_name="cognic_agent_nonexistent",
        )


def test_extract_rejects_path_shaped_package_name() -> None:
    # defence-in-depth: a path-shaped package_name is rejected BEFORE any
    # locate_file resolution (mirrors extract_skill_md's identifier guard).
    with pytest.raises(AgentManifestNotFound):
        extract_agent_md(distribution_name="whatever", package_name="../etc/passwd")


def test_not_found_is_an_agent_manifest_error() -> None:
    assert issubclass(AgentManifestNotFound, AgentManifestError)


def _patch_distribution(monkeypatch: pytest.MonkeyPatch, dist: Any) -> None:
    """Swap agent_manifest's module-local ``_im`` binding for a stub namespace
    (string-path setattr; reverted by monkeypatch — the REAL
    ``importlib.metadata`` module is never mutated). The stub keeps the real
    ``PackageNotFoundError`` so the extractor's except clause still resolves."""
    stub = SimpleNamespace(
        distribution=lambda name: dist,
        PackageNotFoundError=importlib.metadata.PackageNotFoundError,
    )
    monkeypatch.setattr("cognic_agentos.protocol.agent_manifest._im", stub)


def test_extract_reads_package_data_agent_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive extraction against a stub Distribution: the resolved relative
    path is ``<package_name>/AGENT.md`` and the raw text is returned."""
    agent_md = tmp_path / "AGENT.md"
    agent_md.write_text(_VALID_AGENT_MD, encoding="utf-8")
    seen: dict[str, Any] = {}

    class _Dist:
        def locate_file(self, relative_path: str) -> Path:
            seen["relative_path"] = relative_path
            return agent_md

    _patch_distribution(monkeypatch, _Dist())
    text = extract_agent_md(
        distribution_name="cognic-agent-advisor", package_name="cognic_agent_advisor"
    )
    assert text == _VALID_AGENT_MD
    assert seen["relative_path"] == "cognic_agent_advisor/AGENT.md"


def test_extract_not_found_when_file_missing_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Dist:
        def locate_file(self, relative_path: str) -> Path:
            return tmp_path / "missing" / "AGENT.md"

    _patch_distribution(monkeypatch, _Dist())
    with pytest.raises(AgentManifestNotFound):
        extract_agent_md(
            distribution_name="cognic-agent-advisor", package_name="cognic_agent_advisor"
        )


def test_extract_not_found_when_locate_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Dist:
        def locate_file(self, relative_path: str) -> None:
            return None

    _patch_distribution(monkeypatch, _Dist())
    with pytest.raises(AgentManifestNotFound):
        extract_agent_md(
            distribution_name="cognic-agent-advisor", package_name="cognic_agent_advisor"
        )

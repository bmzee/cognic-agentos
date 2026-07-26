"""Kernel conformance for the governed agent loop (ADR-027).

WHY THIS SUITE EXISTS
---------------------
Every kernel claim about the agent loop has, until now, been provable only two
ways: unit tests over eleven stubbed seams, or a composed live proof (BAR I)
that needs Oracle, Keycloak, kind, a cloud model, and forty-five minutes. The
first proves logic but never wiring; the second cannot distinguish a kernel
defect from a pack defect, which is exactly how a fixture's ambiguous goldens
came to block a kernel milestone.

This suite closes that gap. It drives the REAL composition — real manifest
extraction through ``Distribution.locate_file``, the real ``_build_agent_records``
walk, real ``AssignmentStore`` / ``EntitlementStore`` over a migrated database,
the real Rego bundle — against a synthetic pack that is trivially correct by
construction.

THE ATTRIBUTION RULE THIS BUYS
------------------------------
* fails here                      -> KERNEL defect (the pack cannot be at fault)
* passes here, fails a real pack  -> PACK defect, or an underspecified boundary
                                     contract (a kernel *docs* defect)
* passes both, answer still wrong -> model/skill quality; never a kernel milestone

The scripted model is a FEATURE, not a compromise: it removes the
non-determinism that makes model-driven bars unreliable as gates.
"""

from __future__ import annotations

import importlib.metadata as _im
from pathlib import Path
from typing import Any

import pytest

import cognic_agentos.harness.agent_host as agent_host

from ._synthetic import (
    DEFAULT_AGENT_ID,
    DEFAULT_DIST,
    DEFAULT_PACKAGE,
    DEFAULT_VERSION,
    FakeDist,
    Registry,
    candidate,
    pack_record_files,
    write_agent_pack,
)


@pytest.fixture
def metadata_env(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Redirect distribution LOOKUP to a mutable fake list.

    Only resolution is redirected — ``locate_file`` still reads real bytes from
    disk, so the real extractors and the deferred-load invariant are exercised.
    Both ``agent_manifest`` and ``mcp_manifest`` bind the same
    ``importlib.metadata`` module object, so one patch site covers both.
    """
    dists: list[Any] = []

    def _distribution(name: str) -> Any:
        for dist in dists:
            if dist.metadata["Name"] == name:
                return dist
        raise _im.PackageNotFoundError(name)

    def _distributions() -> Any:
        return iter(list(dists))

    monkeypatch.setattr(_im, "distribution", _distribution)
    monkeypatch.setattr(_im, "distributions", _distributions)
    return dists


def _install_pack(dists: list[Any], tmp_path: Path, **kwargs: Any) -> Path:
    """Write a synthetic pack and register it in the fake distribution list."""
    root = tmp_path / "site-packages"
    package = kwargs.pop("package", DEFAULT_PACKAGE)
    write_agent_pack(root, package=package, **kwargs)
    dists.append(
        FakeDist(
            name=DEFAULT_DIST,
            version=DEFAULT_VERSION,
            root=root,
            files=pack_record_files(package),
        )
    )
    return root


class TestSyntheticPackIsAdmissible:
    """The fixture itself must load through the REAL loader.

    If these fail, every downstream conformance assertion is meaningless — so
    they run first and assert the fixture's own validity, not kernel policy.
    """

    def test_real_loader_admits_the_synthetic_pack(
        self, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        _install_pack(metadata_env, tmp_path)

        records = agent_host._build_agent_records(
            registry=Registry([candidate()]), settings=object()
        )

        assert set(records) == {DEFAULT_AGENT_ID}
        record = records[DEFAULT_AGENT_ID]
        assert record.agent_id == DEFAULT_AGENT_ID
        assert record.requested_skills == ("conformance-skill",)
        # NOTE: entries are ``<server_id>/<tool_name>`` identities, not bare
        # names — the first-``/``-partition rule at ``agent_host._requested_tools``.
        assert record.requested_tools == ("conformance-server/conformance_query",)
        assert record.max_steps == 4
        assert record.risk_tier == "read_only"
        assert record.persona_body.strip()
        assert len(record.persona_sha256) == 64

    def test_missing_agent_md_warn_skips_rather_than_raising(
        self, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """Fail-closed per-pack: a malformed pack is skipped, never fatal, and
        never silently admitted."""
        _install_pack(metadata_env, tmp_path, write_agent_md=False)

        records = agent_host._build_agent_records(
            registry=Registry([candidate()]), settings=object()
        )

        assert records == {}

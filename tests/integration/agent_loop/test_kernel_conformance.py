"""Kernel conformance for the governed agent loop (ADR-027).

WHY THIS SUITE EXISTS
---------------------
Every kernel claim about the agent loop has, until now, been provable only two
ways: unit tests over eleven stubbed seams, or a composed live proof (BAR I)
that needs Oracle, Keycloak, kind, a cloud model, and forty-five minutes. The
first proves logic but never wiring; the second cannot distinguish a kernel
defect from a pack defect, which is exactly how a fixture's ambiguous goldens
came to block a kernel milestone.

This suite is being built to close that gap. Read the scope statement below
before citing it as evidence of anything.

WHAT THIS FILE PROVES TODAY — and what it does NOT
--------------------------------------------------
PROVEN (real code, not stubs):

* the real ``extract_pack_manifest`` / ``extract_agent_md`` — their
  ``package_name`` identifier guard, path resolution, filesystem existence
  check and read, TOML parse and frontmatter validation, all against real bytes
  on disk, with no pack code imported (the deferred-load invariant). They do
  NOT walk ``dist.files``: neither extractor consults RECORD despite
  documenting that it does. That mismatch is a separately-recorded production
  forward item for authorized critical-control review — do not restate the
  RECORD claim here, and do not fix it from a test packet;
* the real ``agent_host._build_agent_records`` admission walk, including its
  per-pack fail-closed warn-skip arm;
* the real ``RegisteredPackCandidate`` TYPE (constructed, not imitated, so a
  field rename fails this suite instead of passing against a stale shape).

DELIBERATELY SUBSTITUTED — these are seams, and naming them is the point:

* **distribution lookup** — ``importlib.metadata.distribution`` is redirected to
  a fake list;
* **``locate_file``** — supplied by ``FakeDist``, a two-line ``root / relative``
  join. The stdlib ``Distribution.locate_file`` is NOT exercised; what is real
  is the extractors' logic around it and the bytes it lands on;
* **the registry** — ``Registry`` / ``candidate()`` hand-construct candidates.
  This proves the candidate SHAPE, not ``PluginRegistry``'s projection
  SEMANTICS (which derives ``package_name`` from ``record.entry_point_value``
  at ``plugin_registry.py:867``). The real registry and ``registry_boot`` trust
  registration are NOT exercised here — that path is cosign-gated and proven by
  ``tests/integration/pack_loop/test_proof_1a_inprocess.py``.

NOT YET PROVEN — do not cite this file for any of it:

* ``build_agent_loop`` production composition;
* ``AssignmentStore`` / ``EntitlementStore`` against a migrated database;
* the Rego dispatch gate, refusal feedback to the model, or digest-only
  chain-valid dispatch evidence.

Those land in the dispatch-conformance packet. Until then this file proves
pack-load wiring only.

THE ATTRIBUTION RULE THIS IS BEING BUILT FOR
--------------------------------------------
* fails here                      -> KERNEL defect (the pack cannot be at fault)
* passes here, fails a real pack  -> PACK defect, or an underspecified boundary
                                     contract (a kernel *docs* defect)
* passes both, answer still wrong -> model/skill quality; never a kernel milestone
"""

from __future__ import annotations

import hashlib
import importlib.metadata as _im
import logging
from pathlib import Path
from typing import Any

import pytest

import cognic_agentos.harness.agent_host as agent_host

from ._synthetic import (
    DEFAULT_AGENT_ID,
    DEFAULT_DIST,
    DEFAULT_PACKAGE,
    DEFAULT_PERSONA_BODY,
    DEFAULT_PERSONA_SHA256,
    DEFAULT_SIGNATURE_DIGEST,
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

        # EVERY field of the projection is pinned. A shape-only check (e.g.
        # ``len(persona_sha256) == 64``) would pass against a wrong digest, and
        # unpinned fields are how a loader regression ships green.
        assert record.agent_id == DEFAULT_AGENT_ID
        assert record.requested_skills == ("conformance-skill",)
        # Entries are ``<server_id>/<tool_name>`` identities, not bare names —
        # the first-``/``-partition rule at ``agent_host._requested_tools``.
        assert record.requested_tools == ("conformance-server/conformance_query",)
        assert record.max_steps == 4
        assert record.risk_tier == "read_only"

        # Byte-exact persona custody. The body keeps its leading newline (the
        # frontmatter delimiter is not stripped), and the digest is taken over
        # those exact bytes — change the fixture body and this MUST fail.
        assert record.persona_body == DEFAULT_PERSONA_BODY
        assert record.persona_sha256 == DEFAULT_PERSONA_SHA256
        assert (
            hashlib.sha256(record.persona_body.encode("utf-8")).hexdigest() == record.persona_sha256
        )

        # Provenance carried from the distribution + the registered candidate.
        assert record.pack_version == DEFAULT_VERSION
        assert record.signed_artefact_digest == DEFAULT_SIGNATURE_DIGEST
        assert record.registered is True

    def test_missing_agent_md_warn_skips_rather_than_raising(
        self,
        metadata_env: list[Any],
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail-closed per-pack: skipped, never fatal, never silently admitted.

        The WARNING is asserted, not just the empty result. Without it a silent
        drop would pass this test identically — and silent-drop vs warn-skip is
        precisely the operational difference an operator needs to see.
        """
        _install_pack(metadata_env, tmp_path, write_agent_md=False)

        with caplog.at_level(logging.WARNING, logger="cognic_agentos.harness.agent_host"):
            records = agent_host._build_agent_records(
                registry=Registry([candidate()]), settings=object()
            )

        assert records == {}

        # Assert on EVERY agent-host warning, not merely the matching one.
        # Filtering by message before counting would hide any additional
        # warn-skip — a pack failing for several reasons must not be
        # indistinguishable from one skipping cleanly for the named reason.
        emitted = [
            rec
            for rec in caplog.records
            if rec.name == "cognic_agentos.harness.agent_host" and rec.levelno >= logging.WARNING
        ]
        assert [rec.message for rec in emitted] == ["agent.agent_md_not_found"], (
            f"expected exactly one loader warning, saw {[r.message for r in emitted]}"
        )
        assert getattr(emitted[0], "distribution_name", None) == DEFAULT_DIST

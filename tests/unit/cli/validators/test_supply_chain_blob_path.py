"""Sprint 7B.3 T2 Slice G — ``cli/validators/supply_chain.py`` blob_path
field validation per R6 P2 #4 + R7 P2 #4 contract.

The ``[supply_chain].blob_path`` field is OPTIONAL (additive; legacy
packs without it still validate cleanly) but when present MUST satisfy:

1. Type — must be a string
2. Non-empty — not empty / not whitespace-only
3. Relative — must NOT be absolute (no leading ``/``)
4. Path-traversal-safe — no ``..`` segments
5. Not AUTHOR-FILL — must not start with the placeholder prefix

Field-absent green path is critical for legacy compat: packs that
predate R6 P2 #4 still pass ``agentos validate``; they'll just hit
``signature_blob_path_not_declared_in_manifest`` at the 7B.3 approve
gate (forcing the author to re-sign with `agentos sign --bundle-root`).

All findings use the NEW closed-enum reason
``supply_chain_blob_path_unresolvable`` with a ``payload.failure_mode``
discriminator (mirrors the existing
``supply_chain_attestation_path_unresolvable`` pattern at the
attestation_paths surface). Closed-enum membership pinned via a drift
detector.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _well_formed_block_without_blob_path() -> dict[str, Any]:
    """Baseline well-formed [supply_chain] block — has attestation_paths
    but NO blob_path field (legacy / pre-R6 shape)."""
    return {
        "attestation_paths": ["attestations/cosign.sig", "attestations/sbom.cdx.json"],
    }


def _baseline_manifest(supply_chain: dict[str, Any]) -> dict[str, Any]:
    """Compose a minimal manifest body the validator can process."""
    return {
        "pack": {"name": "ex", "version": "1.0.0", "kind": "tool"},
        "supply_chain": supply_chain,
    }


# ===========================================================================
# Section A — field-absent green path (backward-compat per R6 P2 #4)
# ===========================================================================


class TestSprint7B3T2SliceGBlobPathFieldAbsent:
    """Field-absent → no findings. Legacy packs without blob_path
    validate cleanly per the additive-only contract."""

    def test_block_without_blob_path_produces_no_blob_path_findings(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.validators.supply_chain import validate

        # Create the attestation files the existing validator probes.
        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")
        (tmp_path / "attestations" / "sbom.cdx.json").write_bytes(b"sbom")

        manifest = _baseline_manifest(_well_formed_block_without_blob_path())
        findings = validate(manifest, pack_path=tmp_path)

        # Filter for blob_path-specific findings only.
        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert blob_findings == [], (
            f"Field-absent must produce zero blob_path findings; got "
            f"{[(f.message, f.payload) for f in blob_findings]}"
        )


# ===========================================================================
# Section B — happy path: relative + non-empty + traversal-safe
# ===========================================================================


class TestSprint7B3T2SliceGBlobPathHappyPath:
    """Well-formed blob_path → no findings."""

    def test_relative_posix_path_validates_clean(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "dist/example-1.0.0-py3-none-any.whl"
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert blob_findings == [], blob_findings

    def test_bare_filename_in_bundle_root_validates_clean(self, tmp_path: Path) -> None:
        """Wheel directly in bundle root (no subdirectory) → bare basename."""
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "example.whl"
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert blob_findings == [], blob_findings


# ===========================================================================
# Section C — refusal paths
# ===========================================================================


class TestSprint7B3T2SliceGBlobPathRefusals:
    """Each invariant has a dedicated failure_mode discriminator."""

    def test_non_string_blob_path_refused(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = 42
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_not_string"

    def test_empty_blob_path_refused(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = ""
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_empty"

    def test_whitespace_only_blob_path_refused(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "   "
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_empty"

    def test_absolute_blob_path_refused(self, tmp_path: Path) -> None:
        """Absolute path → refused. R5 P2 #3 + R6 P2 #4 doctrine: paths
        in the manifest MUST be bundle-root-relative."""
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "/absolute/path/to/wheel.whl"
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_absolute_forbidden"

    def test_path_traversal_segments_refused(self, tmp_path: Path) -> None:
        """``..`` segments → refused. Defense in depth alongside the
        resolver's signature_path_traversal_rejected red-reason."""
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "dist/../escaping.whl"
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_traversal_rejected"

    def test_author_fill_blob_path_refused(self, tmp_path: Path) -> None:
        """AUTHOR-FILL placeholder → refused. Mirrors the existing
        attestation_paths AUTHOR-FILL refusal."""
        from cognic_agentos.cli.validators.supply_chain import validate

        (tmp_path / "attestations").mkdir()
        (tmp_path / "attestations" / "cosign.sig").write_bytes(b"sig")

        block = _well_formed_block_without_blob_path()
        block["blob_path"] = "AUTHOR-FILL: replace with wheel path"
        manifest = _baseline_manifest(block)
        findings = validate(manifest, pack_path=tmp_path)

        blob_findings = [f for f in findings if f.reason == "supply_chain_blob_path_unresolvable"]
        assert len(blob_findings) == 1, blob_findings
        assert blob_findings[0].payload["failure_mode"] == "blob_path_author_fill"


# ===========================================================================
# Section D — closed-enum vocabulary extension at cli/__init__.py
# ===========================================================================


class TestSprint7B3T2SliceGValidatorReasonExtension:
    """``supply_chain_blob_path_unresolvable`` is in the central
    ValidatorReason Literal + mapped to validators/supply_chain.py ownership."""

    def test_supply_chain_blob_path_unresolvable_in_validator_reason_literal(
        self,
    ) -> None:
        import typing

        from cognic_agentos.cli import ValidatorReason

        values = typing.get_args(ValidatorReason)
        assert "supply_chain_blob_path_unresolvable" in values

    def test_supply_chain_blob_path_unresolvable_owned_by_supply_chain_validator(
        self,
    ) -> None:
        from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP

        assert (
            _VALIDATOR_REASON_OWNERSHIP["supply_chain_blob_path_unresolvable"]
            == "validators/supply_chain.py"
        )

"""Sprint 2 — tests for the installed-pack attestation resolver.

The resolver is a TRUST-INPUT PRIMITIVE: it locates an installed pack's
signed attestation artefacts from a deployment-configured root and
returns a ``PackAttestations``. A wrong path or a wrong digest is a
wrong trust decision, so every refusal path is exercised with a
concrete negative test and the closed-enum reason is asserted.
"""

import hashlib
import importlib.metadata as importlib_metadata
import json
import typing
from pathlib import Path

import pytest

from cognic_agentos.protocol.pack_attestation_resolver import (
    AttestationResolutionReason,
    PackAttestationResolutionError,
    resolve_pack_attestations,
)
from cognic_agentos.protocol.plugin_registry import DiscoveredPack, PluginRecord


def _make_pack(dist_name: str = "cognic-tool-x", version: str = "1.0.0") -> DiscoveredPack:
    """Build a ``DiscoveredPack`` whose ``record.distribution_name`` /
    ``distribution_version`` are ``dist_name`` / ``version``.

    Uses a REAL ``importlib.metadata.EntryPoint`` (not a fake) — the
    resolver must never call ``EntryPoint.load()``, so no load-capable
    stub is required and the resolver is proven to work against the
    genuine discovered-pack shape.
    """
    record = PluginRecord(
        kind="tools",
        name="x",
        distribution_name=dist_name,
        distribution_version=version,
        entry_point_value="cognic_tool_x:Plugin",
    )
    entry_point = importlib_metadata.EntryPoint(
        name="x",
        value="cognic_tool_x:Plugin",
        group="cognic.tools",
    )
    return DiscoveredPack(record=record, entry_point=entry_point)


def _write_attestations(
    root: Path,
    *,
    dist: str = "cognic-tool-x",
    version: str = "1.0.0",
    sbom_digest: str | None = None,
) -> Path:
    base = root / dist / version
    base.mkdir(parents=True)
    (base / "cosign.sig").write_text("sig")
    (base / "bundle.sigstore").write_text("{}")
    sbom = b'{"bomFormat":"CycloneDX"}'
    (base / "sbom.cdx.json").write_bytes(sbom)
    digest = sbom_digest if sbom_digest is not None else hashlib.sha256(sbom).hexdigest()
    (base / "slsa-provenance.intoto.json").write_text(
        json.dumps(
            {
                "predicate": {
                    "buildDefinition": {"externalParameters": {"sbom_digest_sha256": digest}}
                }
            }
        )
    )
    (base / "cognic_tool_x-1.0.0-py3-none-any.whl").write_text("wheel-bytes")
    return base


def test_happy_path_resolves_required_and_digest(tmp_path: Path) -> None:
    root = tmp_path / "attestations"
    _write_attestations(root)
    att = resolve_pack_attestations(
        _make_pack(), pack_attestation_root=root, cosign_trust_root=tmp_path / "trust-root"
    )
    assert att.cosign_signature_path == root / "cognic-tool-x" / "1.0.0" / "cosign.sig"
    assert att.sbom_path.name == "sbom.cdx.json"
    assert att.sigstore_bundle_path.name == "bundle.sigstore"
    assert len(att.sbom_signed_digest) == 64
    assert att.cosign_trust_root == tmp_path / "trust-root"
    assert (
        att.cosign_blob_path
        == root / "cognic-tool-x" / "1.0.0" / "cognic_tool_x-1.0.0-py3-none-any.whl"
    )
    # SLSA provenance is a fixed-name required artefact -> always populated.
    expected_slsa = root / "cognic-tool-x" / "1.0.0" / "slsa-provenance.intoto.json"
    assert att.slsa_provenance_path == expected_slsa
    # The three grace-period optionals were not written -> None.
    assert att.intoto_layout_path is None
    assert att.vuln_scan_path is None
    assert att.license_audit_path is None


def test_optional_artefacts_present_populate_their_fields(tmp_path: Path) -> None:
    root = tmp_path / "attestations"
    base = _write_attestations(root)
    (base / "intoto-layout.json").write_text("{}")
    (base / "vuln-scan.json").write_text("[]")
    (base / "license-audit.json").write_text("[]")
    att = resolve_pack_attestations(
        _make_pack(), pack_attestation_root=root, cosign_trust_root=tmp_path / "trust-root"
    )
    assert att.intoto_layout_path == base / "intoto-layout.json"
    assert att.vuln_scan_path == base / "vuln-scan.json"
    assert att.license_audit_path == base / "license-audit.json"


def test_zero_wheels_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    next(base.glob("*.whl")).unlink()
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_required_artefact_missing"


def test_multiple_wheels_fails_closed_ambiguous(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cognic_tool_x-1.0.0-py3-none-any2.whl").write_text("wheel-2")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_wheel_ambiguous"


def test_empty_wheel_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    next(base.glob("*.whl")).write_text("")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_required_artefact_empty"


def test_missing_required_artefact_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cosign.sig").unlink()
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_required_artefact_missing"


def test_empty_required_artefact_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cosign.sig").write_text("")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_required_artefact_empty"


def test_path_traversal_escapes_root_fails_closed(tmp_path: Path) -> None:
    _write_attestations(tmp_path / "attestations")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(dist_name="../escape"),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_path_escapes_root"


def test_symlink_escape_fails_closed(tmp_path: Path) -> None:
    """A required artefact that is a SYMLINK to a file OUTSIDE
    ``pack_attestation_root`` must be caught by the ``realpath`` containment
    guard — a distinct attack from lexical ``../`` traversal — and fail closed
    with ``attestation_path_escapes_root``. ``cosign.sig`` is the first required
    artefact resolved, so it exercises the artefact-level containment check."""
    base = _write_attestations(tmp_path / "attestations")
    outside = tmp_path / "outside-attacker-controlled.sig"
    outside.write_text("attacker-controlled")
    sig = base / "cosign.sig"
    sig.unlink()
    sig.symlink_to(outside)
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_path_escapes_root"


def test_sbom_digest_unsourced_when_slsa_missing_field(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "slsa-provenance.intoto.json").write_text(
        json.dumps({"predicate": {"buildDefinition": {}}})
    )
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "sbom_digest_unsourced"


def test_sbom_digest_unsourced_when_slsa_malformed_json(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "slsa-provenance.intoto.json").write_text("{not-json")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "sbom_digest_unsourced"


def test_sbom_digest_unsourced_when_digest_not_a_string(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "slsa-provenance.intoto.json").write_text(
        json.dumps(
            {
                "predicate": {
                    "buildDefinition": {"externalParameters": {"sbom_digest_sha256": 12345}}
                }
            }
        )
    )
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "sbom_digest_unsourced"


def test_distribution_unidentified_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(
            _make_pack(dist_name="<unknown>"),
            pack_attestation_root=tmp_path / "attestations",
            cosign_trust_root=tmp_path,
        )
    assert ei.value.reason == "attestation_distribution_unidentified"


def test_resolution_reason_is_a_closed_six_value_enum() -> None:
    """Drift detector: the closed-enum refusal vocabulary is the
    consumer-facing wire contract for ``PackAttestationResolutionError``.
    A future add/drop must be deliberate."""
    assert set(typing.get_args(AttestationResolutionReason)) == {
        "attestation_distribution_unidentified",
        "attestation_path_escapes_root",
        "attestation_required_artefact_missing",
        "attestation_required_artefact_empty",
        "attestation_wheel_ambiguous",
        "sbom_digest_unsourced",
    }

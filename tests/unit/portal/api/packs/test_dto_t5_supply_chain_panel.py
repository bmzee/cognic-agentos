"""Sprint 7B.3 T5 Slice C — :class:`SupplyChainPanel` DTO drift detectors.

The DTO is the wire-protocol contract for ``GET /api/v1/packs/
{pack_id}/evidence/supply-chain``. Drift between the DTO field-set /
type annotations and the :class:`SupplyChainPanelData` projector
output (or the :data:`AttestationKind` Literal at the projector
module) is wire-protocol-public regression — caught here.

Mirrors the T4 :class:`RiskTierPanel` DTO test layout — vocab drift +
field-set drift + frozen / extra=forbid / from_attributes inherited
config + projector roundtrip.
"""

from __future__ import annotations

import dataclasses
import typing
from datetime import UTC, datetime
from typing import ClassVar

from cognic_agentos.packs.evidence.supply_chain import (
    AttestationKind,
    SupplyChainPanelData,
)
from cognic_agentos.portal.api.packs.dto import SupplyChainPanel


class TestSprint7B3T5SliceCSupplyChainPanelDTO:
    """Drift detectors + interop tests for the DTO."""

    _EXPECTED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "pack_kind",
            "declared_attestation_paths",
            "slsa_level_declared",
            "sbom_path_declared",
            "vuln_scan_path_declared",
            "license_audit_path_declared",
            "sigstore_bundle_path_declared",
            "in_toto_layout_declared",
            "sigstore_bundle_retention_expires_at",
        }
    )

    def test_exact_field_set(self) -> None:
        """Lock the exact 9-field shape per plan §334."""
        assert frozenset(SupplyChainPanel.model_fields.keys()) == self._EXPECTED_FIELDS

    def test_dto_field_count_matches_projector_field_count(self) -> None:
        """The DTO field count MUST equal the projector dataclass field
        count — a new projector field landing without a corresponding
        DTO field would silently drop on the wire."""
        projector_fields = {f.name for f in dataclasses.fields(SupplyChainPanelData)}
        assert frozenset(SupplyChainPanel.model_fields.keys()) == projector_fields

    def test_dto_is_frozen(self) -> None:
        """``frozen=True`` MUST be inherited from
        :class:`PackBaseModel` so the DTO matches every other pack-API
        response wire-shape (no in-flight mutation)."""
        assert SupplyChainPanel.model_config.get("frozen") is True

    def test_dto_rejects_extra_fields(self) -> None:
        """``extra="forbid"`` MUST be inherited — smuggled fields
        refuse at validation."""
        assert SupplyChainPanel.model_config.get("extra") == "forbid"

    def test_dto_supports_from_attributes(self) -> None:
        """``from_attributes=True`` lets the route handler call
        :meth:`SupplyChainPanel.model_validate` directly on the
        projector's :class:`SupplyChainPanelData` output without a
        :func:`dataclasses.asdict` step."""
        assert SupplyChainPanel.model_config.get("from_attributes") is True

    def test_panel_data_roundtrips_via_model_validate(self) -> None:
        """The interop contract: :meth:`model_validate` on the
        projector's :class:`SupplyChainPanelData` output produces a
        valid DTO with identical field values."""
        panel_data = SupplyChainPanelData(
            pack_kind="agent",
            declared_attestation_paths=("attestations/cosign.sig",),
            slsa_level_declared=3,
            sbom_path_declared="attestations/sbom.spdx.json",
            vuln_scan_path_declared="attestations/vuln-scan.json",
            license_audit_path_declared="attestations/license-audit.json",
            sigstore_bundle_path_declared="attestations/sigstore.bundle",
            in_toto_layout_declared="attestations/in-toto.layout",
            sigstore_bundle_retention_expires_at=datetime(2033, 5, 14, tzinfo=UTC),
        )
        dto = SupplyChainPanel.model_validate(panel_data)
        assert dto.pack_kind == "agent"
        assert dto.declared_attestation_paths == ("attestations/cosign.sig",)
        assert dto.slsa_level_declared == 3
        assert dto.sbom_path_declared == "attestations/sbom.spdx.json"
        assert dto.vuln_scan_path_declared == "attestations/vuln-scan.json"
        assert dto.license_audit_path_declared == "attestations/license-audit.json"
        assert dto.sigstore_bundle_path_declared == "attestations/sigstore.bundle"
        assert dto.in_toto_layout_declared == "attestations/in-toto.layout"
        assert dto.sigstore_bundle_retention_expires_at == datetime(2033, 5, 14, tzinfo=UTC)

    def test_panel_data_with_all_none_fields_roundtrips(self) -> None:
        """A maximally-empty projector output (every optional field None
        + empty attestation tuple + retention None) MUST round-trip
        through the DTO — covers the defensive-fallback wire path."""
        panel_data = SupplyChainPanelData(
            pack_kind="tool",
            declared_attestation_paths=(),
            slsa_level_declared=None,
            sbom_path_declared=None,
            vuln_scan_path_declared=None,
            license_audit_path_declared=None,
            sigstore_bundle_path_declared=None,
            in_toto_layout_declared=None,
            sigstore_bundle_retention_expires_at=None,
        )
        dto = SupplyChainPanel.model_validate(panel_data)
        assert dto.declared_attestation_paths == ()
        assert dto.slsa_level_declared is None
        assert dto.sigstore_bundle_path_declared is None
        assert dto.sigstore_bundle_retention_expires_at is None

    def test_attestation_kind_covers_seven_canonical_values(self) -> None:
        """Vacuous-test guard: pin :data:`AttestationKind` count + set
        independently of the projector module's drift detector. A
        future split between projector + DTO modules that lets
        :data:`AttestationKind` diverge would surface here."""
        assert frozenset(typing.get_args(AttestationKind)) == frozenset(
            {
                "cosign",
                "slsa",
                "sbom",
                "vuln_scan_baseline",
                "license_audit",
                "sigstore_bundle",
                "in_toto",
            }
        )
        assert len(typing.get_args(AttestationKind)) == 7

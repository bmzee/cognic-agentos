"""Sprint 7B.3 T6 Slice C — :class:`ConformanceMatrixPanel` DTO drift
detectors.

The DTO is the wire-protocol contract for ``GET /api/v1/packs/
{pack_id}/evidence/conformance``. Drift between the DTO field-set /
type annotations and the :class:`ConformanceMatrixPanelData` projector
output (or the :data:`MatrixComparisonFlag` Literal at the projector
module) is wire-protocol-public regression — caught here.

Mirrors the T5 :class:`SupplyChainPanel` DTO test layout — vocab drift
+ field-set drift + frozen / extra=forbid / from_attributes inherited
config + projector roundtrip, extended for the nested sub-models
(:class:`MatrixDeclarationPanel` / :class:`MatrixComparisonPanel` /
:class:`OwaspCheckResultPanel` / :class:`OwaspVerdictPanel`).
"""

from __future__ import annotations

import dataclasses
import typing
from typing import ClassVar

from cognic_agentos.packs.evidence.conformance_matrix import (
    ConformanceMatrixPanelData,
    MatrixComparison,
    MatrixComparisonFlag,
    MatrixDeclaration,
    OwaspCheckResultData,
    OwaspVerdictData,
)
from cognic_agentos.portal.api.packs.dto import (
    ConformanceMatrixPanel,
    MatrixComparisonPanel,
    MatrixDeclarationPanel,
    OwaspCheckResultPanel,
    OwaspVerdictPanel,
)


class TestSprint7B3T6SliceCConformanceMatrixPanelDTO:
    """Drift detectors + interop tests for the top-level DTO."""

    _EXPECTED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "pack_kind",
            "declarations",
            "comparisons",
            "flagged_mismatches",
            "owasp_verdict",
        }
    )

    def test_exact_field_set(self) -> None:
        assert frozenset(ConformanceMatrixPanel.model_fields.keys()) == self._EXPECTED_FIELDS

    def test_dto_field_count_matches_projector_field_count(self) -> None:
        projector_fields = {f.name for f in dataclasses.fields(ConformanceMatrixPanelData)}
        assert frozenset(ConformanceMatrixPanel.model_fields.keys()) == projector_fields

    def test_dto_inherited_config(self) -> None:
        assert ConformanceMatrixPanel.model_config.get("frozen") is True
        assert ConformanceMatrixPanel.model_config.get("extra") == "forbid"
        assert ConformanceMatrixPanel.model_config.get("from_attributes") is True


class TestSprint7B3T6SliceCNestedSubModelShapes:
    """The nested sub-model field sets MUST match their projector
    dataclass counterparts 1:1."""

    def test_matrix_declaration_panel_matches_projector(self) -> None:
        projector_fields = {f.name for f in dataclasses.fields(MatrixDeclaration)}
        assert frozenset(MatrixDeclarationPanel.model_fields.keys()) == projector_fields

    def test_matrix_comparison_panel_matches_projector(self) -> None:
        projector_fields = {f.name for f in dataclasses.fields(MatrixComparison)}
        assert frozenset(MatrixComparisonPanel.model_fields.keys()) == projector_fields

    def test_owasp_check_result_panel_matches_projector(self) -> None:
        projector_fields = {f.name for f in dataclasses.fields(OwaspCheckResultData)}
        assert frozenset(OwaspCheckResultPanel.model_fields.keys()) == projector_fields

    def test_owasp_verdict_panel_matches_projector(self) -> None:
        projector_fields = {f.name for f in dataclasses.fields(OwaspVerdictData)}
        assert frozenset(OwaspVerdictPanel.model_fields.keys()) == projector_fields

    def test_all_nested_models_inherit_strict_config(self) -> None:
        for model in (
            MatrixDeclarationPanel,
            MatrixComparisonPanel,
            OwaspCheckResultPanel,
            OwaspVerdictPanel,
        ):
            assert model.model_config.get("frozen") is True
            assert model.model_config.get("extra") == "forbid"
            assert model.model_config.get("from_attributes") is True


class TestSprint7B3T6SliceCMatrixComparisonFlagVocab:
    """Vacuous-test guard — pin :data:`MatrixComparisonFlag` count + set
    independently of the projector module's drift detector."""

    def test_flag_vocab_is_six_values(self) -> None:
        assert frozenset(typing.get_args(MatrixComparisonFlag)) == frozenset(
            {
                "mcp_capability_restricted",
                "mcp_capability_unknown",
                "a2a_feature_forbidden",
                "a2a_wave2_feature_declared",
                "a2a_feature_unknown",
                "oasf_capability_wave2_declared",
            }
        )
        assert len(typing.get_args(MatrixComparisonFlag)) == 6


class TestSprint7B3T6SliceCProjectorRoundtrip:
    """The interop contract: :meth:`model_validate` on the projector's
    :class:`ConformanceMatrixPanelData` output produces a valid DTO."""

    def test_full_panel_roundtrips_via_model_validate(self) -> None:
        panel_data = ConformanceMatrixPanelData(
            pack_kind="agent",
            declarations={
                "mcp": MatrixDeclaration(
                    applicable=True,
                    applicability_reason="applicable",
                    declared_features=("sampling",),
                ),
                "a2a": MatrixDeclaration(
                    applicable=True,
                    applicability_reason="applicable",
                    declared_features=("streaming_messages",),
                ),
                "oasf": MatrixDeclaration(
                    applicable=True,
                    applicability_reason="applicable",
                    declared_features=(),
                ),
            },
            comparisons=(
                MatrixComparison(
                    protocol="mcp",
                    feature="sampling",
                    matrix_wave_1="restricted",
                    matrix_wave_2_promoted=True,
                    flag="mcp_capability_restricted",
                ),
            ),
            flagged_mismatches=("mcp_capability_restricted",),
            owasp_verdict=OwaspVerdictData(
                overall_status="green",
                results=(OwaspCheckResultData(category="tool_misuse", status="pass", findings=()),),
                summary="9 pass / 0 fail / 1 not_applicable",
                errored_categories=(),
            ),
        )
        dto = ConformanceMatrixPanel.model_validate(panel_data)
        assert dto.pack_kind == "agent"
        assert dto.declarations["mcp"].declared_features == ("sampling",)
        assert dto.comparisons[0].flag == "mcp_capability_restricted"
        assert dto.flagged_mismatches == ("mcp_capability_restricted",)
        assert dto.owasp_verdict is not None
        assert dto.owasp_verdict.overall_status == "green"
        assert dto.owasp_verdict.results[0].category == "tool_misuse"

    def test_panel_with_none_verdict_roundtrips(self) -> None:
        panel_data = ConformanceMatrixPanelData(
            pack_kind="hook",
            declarations={
                "mcp": MatrixDeclaration(
                    applicable=False,
                    applicability_reason="MCP matrix does not apply to hook packs",
                    declared_features=(),
                ),
                "a2a": MatrixDeclaration(
                    applicable=False,
                    applicability_reason="A2A matrix applies to agent packs only, not hook packs",
                    declared_features=(),
                ),
                "oasf": MatrixDeclaration(
                    applicable=False,
                    applicability_reason=(
                        "AGNTCY/OASF identity applies to agent packs only, not hook packs"
                    ),
                    declared_features=(),
                ),
            },
            comparisons=(),
            flagged_mismatches=(),
            owasp_verdict=None,
        )
        dto = ConformanceMatrixPanel.model_validate(panel_data)
        assert dto.owasp_verdict is None
        assert dto.comparisons == ()
        assert dto.declarations["mcp"].applicable is False

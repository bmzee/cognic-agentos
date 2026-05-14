"""Sprint 7B.3 T6 — :mod:`packs.evidence.conformance_matrix` drift
detectors + projector contract tests (CRITICAL CONTROLS).

Pure-projector tests for ``project_conformance_matrix_panel``. No DB /
no FastAPI — these tests pin the projector contract independently of
the route handler at ``portal/api/packs/evidence_routes.py``. The
route-level integration tests (RBAC, tenant-isolation, kind-integrity,
full FastAPI stack with seeded submit row) ship in
``tests/unit/portal/api/packs/test_evidence_panel_routes.py`` at the
T6 Slice D extension classes.

Wire-protocol surfaces under test:

- :data:`MatrixComparisonFlag` — closed-enum 6-value Literal per plan
  §352. Drift breaks every reviewer evidence-pack consumer.
- :class:`MatrixDeclaration` / :class:`MatrixComparison` /
  :class:`OwaspVerdictData` / :class:`ConformanceMatrixPanelData` —
  the projector's frozen dataclass outputs; field sets +
  ``from_attributes`` interop with the :class:`ConformanceMatrixPanel`
  Pydantic DTO at ``portal/api/packs/dto.py``.
- :func:`project_conformance_matrix_panel` — pure projector contract:
  manifest dict + record kind + conformance payload → frozen
  dataclass. R9 kind-aware applicability (tool/skill/agent → MCP;
  agent → +A2A +OASF; hook → none). Defensive-shape fallback.

Mirrors the T5 :mod:`packs.evidence.supply_chain` test layout: vocab
drift-detector classes + shape drift-detector classes + projector-
contract classes.
"""

from __future__ import annotations

import dataclasses
import json
import typing
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.packs.evidence.conformance_matrix import (
    _CONFORMANCE_MATRIX,
    ConformanceMatrixPanelData,
    MatrixComparison,
    MatrixComparisonFlag,
    MatrixDeclaration,
    OwaspCheckResultData,
    OwaspVerdictData,
    _load_conformance_matrix,
    project_conformance_matrix_panel,
)

# ---------------------------------------------------------------------------
# Slice A — vocab + shape drift detectors
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceAMatrixComparisonFlagVocab:
    """Drift detectors for :data:`MatrixComparisonFlag` per plan §352."""

    _EXPECTED_VALUES: frozenset[str] = frozenset(
        {
            "mcp_capability_restricted",
            "mcp_capability_unknown",
            "a2a_feature_forbidden",
            "a2a_wave2_feature_declared",
            "a2a_feature_unknown",
            "oasf_capability_wave2_declared",
        }
    )

    def test_exact_value_set(self) -> None:
        assert frozenset(typing.get_args(MatrixComparisonFlag)) == self._EXPECTED_VALUES

    def test_exact_count(self) -> None:
        assert len(typing.get_args(MatrixComparisonFlag)) == 6


class TestSprint7B3T6SliceADataclassShapes:
    """Shape drift detectors for the projector output dataclasses."""

    def test_matrix_declaration_field_set(self) -> None:
        fields = {f.name for f in dataclasses.fields(MatrixDeclaration)}
        assert fields == {"applicable", "applicability_reason", "declared_features"}

    def test_matrix_comparison_field_set(self) -> None:
        fields = {f.name for f in dataclasses.fields(MatrixComparison)}
        assert fields == {
            "protocol",
            "feature",
            "matrix_wave_1",
            "matrix_wave_2_promoted",
            "flag",
        }

    def test_owasp_check_result_field_set(self) -> None:
        fields = {f.name for f in dataclasses.fields(OwaspCheckResultData)}
        assert fields == {"category", "status", "findings"}

    def test_owasp_verdict_field_set(self) -> None:
        fields = {f.name for f in dataclasses.fields(OwaspVerdictData)}
        assert fields == {"overall_status", "results", "summary", "errored_categories"}

    def test_panel_data_field_set(self) -> None:
        fields = {f.name for f in dataclasses.fields(ConformanceMatrixPanelData)}
        assert fields == {
            "pack_kind",
            "declarations",
            "comparisons",
            "flagged_mismatches",
            "owasp_verdict",
        }

    def test_panel_data_is_frozen(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest={"pack": {"kind": "tool"}},
            record_kind="tool",
            conformance_payload=None,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            panel.pack_kind = "agent"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Slice B — R9 kind-aware applicability
# ---------------------------------------------------------------------------


def _manifest(
    *,
    kind: str = "tool",
    mcp: dict[str, Any] | None = None,
    a2a: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"pack": {"kind": kind}}
    if mcp is not None:
        out["mcp"] = mcp
    if a2a is not None:
        out["a2a"] = a2a
    if identity is not None:
        out["identity"] = identity
    return out


class TestSprint7B3T6SliceBKindApplicability:
    """R9 kind-aware matrix applicability per plan §351."""

    @pytest.mark.parametrize("kind", ["tool", "skill", "agent"])
    def test_mcp_applicable_for_tool_skill_agent(self, kind: str) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind=kind),
            record_kind=kind,  # type: ignore[arg-type]
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].applicable is True

    def test_mcp_not_applicable_for_hook(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="hook"), record_kind="hook", conformance_payload=None
        )
        assert panel.declarations["mcp"].applicable is False
        assert panel.declarations["mcp"].declared_features == ()

    @pytest.mark.parametrize("kind", ["tool", "skill", "hook"])
    def test_a2a_and_oasf_only_applicable_for_agent(self, kind: str) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind=kind),
            record_kind=kind,  # type: ignore[arg-type]
            conformance_payload=None,
        )
        assert panel.declarations["a2a"].applicable is False
        assert panel.declarations["oasf"].applicable is False

    def test_a2a_and_oasf_applicable_for_agent(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent"), record_kind="agent", conformance_payload=None
        )
        assert panel.declarations["a2a"].applicable is True
        assert panel.declarations["oasf"].applicable is True

    def test_all_three_protocols_keyed_in_declarations(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent"), record_kind="agent", conformance_payload=None
        )
        assert set(panel.declarations.keys()) == {"mcp", "a2a", "oasf"}

    def test_non_applicable_protocol_produces_no_comparisons_even_if_block_present(
        self,
    ) -> None:
        # A hook pack that (wrongly) carries an [mcp] block: the panel
        # marks MCP not_applicable and emits NO comparisons for it
        # rather than failing the absent-protocol expectation.
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="hook", mcp={"sampling_supported": True}),
            record_kind="hook",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].applicable is False
        assert panel.comparisons == ()
        assert panel.flagged_mismatches == ()


# ---------------------------------------------------------------------------
# Slice C — MCP comparison flags
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceCMcpComparisons:
    def test_supported_capability_is_clean(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"resources_supported": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].declared_features == ("resources",)
        comparison = next(c for c in panel.comparisons if c.feature == "resources")
        assert comparison.protocol == "mcp"
        assert comparison.matrix_wave_1 == "supported"
        assert comparison.flag is None
        assert panel.flagged_mismatches == ()

    def test_restricted_capability_flags(self) -> None:
        # sampling is ⚠️ restricted in the shipped matrix.
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"sampling_supported": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "sampling")
        assert comparison.flag == "mcp_capability_restricted"
        assert "mcp_capability_restricted" in panel.flagged_mismatches

    def test_caching_strategy_declared_when_not_none(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching_strategy": "ttl"}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "caching" in panel.declarations["mcp"].declared_features

    def test_caching_strategy_none_is_not_declared(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching_strategy": "none"}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "caching" not in panel.declarations["mcp"].declared_features

    def test_elicitation_modes_declared_when_non_empty(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"elicitation_modes": ["url"]}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "elicitation" in panel.declarations["mcp"].declared_features
        comparison = next(c for c in panel.comparisons if c.feature == "elicitation")
        assert comparison.flag == "mcp_capability_restricted"

    def test_false_bool_field_is_not_declared(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"resources_supported": False}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].declared_features == ()

    def test_unknown_slug_flags_when_matrix_missing_entry(self) -> None:
        # Inject a matrix missing the "sampling" slug — exercises the
        # mcp_capability_unknown defensive path (JSON drift vs the
        # curated manifest-field → slug map).
        injected = {"mcp": {"resources": _CONFORMANCE_MATRIX["mcp"]["resources"]}, "a2a": {}}
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"sampling_supported": True}),
            record_kind="tool",
            conformance_payload=None,
            matrix=injected,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "sampling")
        assert comparison.flag == "mcp_capability_unknown"
        assert comparison.matrix_wave_1 is None


# ---------------------------------------------------------------------------
# Slice D — A2A comparison flags
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceDA2aComparisons:
    def test_supported_feature_is_clean(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", a2a={"streaming": True}),
            record_kind="agent",
            conformance_payload=None,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "streaming_messages")
        assert comparison.protocol == "a2a"
        assert comparison.matrix_wave_1 == "supported"
        assert comparison.flag is None

    def test_restricted_feature_flags_wave2_declared(self) -> None:
        # push_notification_config is ⚠️ restricted + Wave-2-promoted.
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", a2a={"push_notification_config": True}),
            record_kind="agent",
            conformance_payload=None,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "push_notification_config")
        assert comparison.flag == "a2a_wave2_feature_declared"
        assert comparison.matrix_wave_2_promoted is True
        assert "a2a_wave2_feature_declared" in panel.flagged_mismatches

    def test_artifacts_feature_is_clean(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", a2a={"artifacts_supported": True}),
            record_kind="agent",
            conformance_payload=None,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "artifacts")
        assert comparison.flag is None

    def test_unknown_a2a_feature_flags_when_matrix_missing_entry(self) -> None:
        injected = {
            "mcp": {},
            "a2a": {"streaming_messages": _CONFORMANCE_MATRIX["a2a"]["streaming_messages"]},
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", a2a={"artifacts_supported": True}),
            record_kind="agent",
            conformance_payload=None,
            matrix=injected,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "artifacts")
        assert comparison.flag == "a2a_feature_unknown"

    def test_forbidden_a2a_feature_flags(self) -> None:
        # No curated manifest field maps to a forbidden A2A feature in
        # the shipped matrix, so exercise the forbidden branch via an
        # injected matrix that marks `artifacts` forbidden.
        injected = {
            "mcp": {},
            "a2a": {"artifacts": {"wave_1": "forbidden", "wave_2_promoted": False}},
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", a2a={"artifacts_supported": True}),
            record_kind="agent",
            conformance_payload=None,
            matrix=injected,
        )
        comparison = next(c for c in panel.comparisons if c.feature == "artifacts")
        assert comparison.flag == "a2a_feature_forbidden"


# ---------------------------------------------------------------------------
# Slice E — OASF comparison flags
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceEOasfComparisons:
    def test_oasf_capability_set_flags_each_entry_wave2(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(
                kind="agent", identity={"oasf_capability_set": ["search.v1", "rag.v1"]}
            ),
            record_kind="agent",
            conformance_payload=None,
        )
        oasf_comparisons = [c for c in panel.comparisons if c.protocol == "oasf"]
        assert {c.feature for c in oasf_comparisons} == {"search.v1", "rag.v1"}
        assert all(c.flag == "oasf_capability_wave2_declared" for c in oasf_comparisons)
        assert panel.declarations["oasf"].declared_features == ("search.v1", "rag.v1")

    def test_empty_oasf_capability_set_produces_no_comparisons(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", identity={"oasf_capability_set": []}),
            record_kind="agent",
            conformance_payload=None,
        )
        assert [c for c in panel.comparisons if c.protocol == "oasf"] == []

    def test_oasf_not_projected_for_non_agent_even_when_block_present(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", identity={"oasf_capability_set": ["search.v1"]}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert panel.declarations["oasf"].applicable is False
        assert [c for c in panel.comparisons if c.protocol == "oasf"] == []


# ---------------------------------------------------------------------------
# Slice F — flagged_mismatches aggregation + defensive shapes
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceFAggregationAndDefensiveShapes:
    def test_flagged_mismatches_is_deduplicated_and_sorted(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(
                kind="agent",
                mcp={"sampling_supported": True, "elicitation_modes": ["url"]},
                a2a={"push_notification_config": True},
            ),
            record_kind="agent",
            conformance_payload=None,
        )
        # sampling + elicitation both flag mcp_capability_restricted →
        # deduplicated to one entry; sorted alphabetically.
        assert panel.flagged_mismatches == (
            "a2a_wave2_feature_declared",
            "mcp_capability_restricted",
        )

    def test_missing_blocks_produce_empty_declared_features(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent"),
            record_kind="agent",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].declared_features == ()
        assert panel.declarations["a2a"].declared_features == ()
        assert panel.declarations["oasf"].declared_features == ()
        assert panel.comparisons == ()
        assert panel.flagged_mismatches == ()

    def test_non_dict_block_is_defensively_ignored(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest={"pack": {"kind": "agent"}, "mcp": "not-a-dict", "a2a": 42},
            record_kind="agent",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].declared_features == ()
        assert panel.declarations["a2a"].declared_features == ()

    def test_non_list_oasf_capability_set_defensively_ignored(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent", identity={"oasf_capability_set": "search.v1"}),
            record_kind="agent",
            conformance_payload=None,
        )
        assert panel.declarations["oasf"].declared_features == ()

    def test_non_string_oasf_entries_filtered(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(
                kind="agent", identity={"oasf_capability_set": ["ok.v1", 123, None]}
            ),
            record_kind="agent",
            conformance_payload=None,
        )
        assert panel.declarations["oasf"].declared_features == ("ok.v1",)

    def test_pack_kind_echoed_from_record_not_manifest(self) -> None:
        # Manifest says "agent", record says "tool" — projector echoes
        # the authoritative record kind (the route layer owns the
        # kind-integrity cross-check; the projector trusts record_kind).
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="agent"),
            record_kind="tool",
            conformance_payload=None,
        )
        assert panel.pack_kind == "tool"


# ---------------------------------------------------------------------------
# Slice G — OWASP verdict projection
# ---------------------------------------------------------------------------


_GREEN_CONFORMANCE_PAYLOAD: dict[str, Any] = {
    "overall_status": "green",
    "results": {
        "tool_misuse": {"category": "tool_misuse", "status": "pass", "findings": []},
        "unsafe_network": {
            "category": "unsafe_network",
            "status": "not_applicable",
            "findings": [],
        },
    },
    "summary": "9 pass / 0 fail / 1 not_applicable",
    "errored_categories": [],
}


class TestSprint7B3T6SliceGOwaspVerdict:
    def test_none_payload_yields_none_verdict(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"), record_kind="tool", conformance_payload=None
        )
        assert panel.owasp_verdict is None

    def test_green_payload_reconstructs_verdict(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload=_GREEN_CONFORMANCE_PAYLOAD,
        )
        verdict = panel.owasp_verdict
        assert verdict is not None
        assert verdict.overall_status == "green"
        assert verdict.summary == "9 pass / 0 fail / 1 not_applicable"
        assert verdict.errored_categories == ()
        assert {r.category for r in verdict.results} == {"tool_misuse", "unsafe_network"}
        tool_misuse = next(r for r in verdict.results if r.category == "tool_misuse")
        assert tool_misuse.status == "pass"
        assert tool_misuse.findings == ()

    def test_red_payload_with_findings(self) -> None:
        payload: dict[str, Any] = {
            "overall_status": "red",
            "results": {
                "secret_exfiltration": {
                    "category": "secret_exfiltration",
                    "status": "fail",
                    "findings": ["manifest.egress: wildcard egress not allowed"],
                }
            },
            "summary": "9 pass / 1 fail / 0 not_applicable",
            "errored_categories": [],
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload=payload,
        )
        assert panel.owasp_verdict is not None
        assert panel.owasp_verdict.overall_status == "red"
        result = panel.owasp_verdict.results[0]
        assert result.findings == ("manifest.egress: wildcard egress not allowed",)

    def test_yellow_payload_with_errored_categories(self) -> None:
        payload: dict[str, Any] = {
            "overall_status": "yellow",
            "results": {},
            "summary": "incomplete (1 errored)",
            "errored_categories": ["goal_hijacking"],
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload=payload,
        )
        assert panel.owasp_verdict is not None
        assert panel.owasp_verdict.overall_status == "yellow"
        assert panel.owasp_verdict.errored_categories == ("goal_hijacking",)

    def test_malformed_overall_status_yields_none_verdict(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload={"overall_status": "purple", "results": {}},
        )
        assert panel.owasp_verdict is None

    def test_non_dict_payload_yields_none_verdict(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload="not-a-dict",  # type: ignore[arg-type]
        )
        assert panel.owasp_verdict is None

    def test_non_dict_results_field_skips_result_loop(self) -> None:
        """A payload with a valid ``overall_status`` but a non-dict
        ``results`` field reconstructs a verdict with an EMPTY results
        tuple — the projector skips the per-category loop entirely
        rather than crashing on the malformed field."""
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload={
                "overall_status": "green",
                "results": "not-a-dict",
                "summary": "ok",
                "errored_categories": [],
            },
        )
        assert panel.owasp_verdict is not None
        assert panel.owasp_verdict.overall_status == "green"
        assert panel.owasp_verdict.results == ()

    def test_unknown_category_in_results_is_filtered(self) -> None:
        payload: dict[str, Any] = {
            "overall_status": "green",
            "results": {
                "tool_misuse": {"category": "tool_misuse", "status": "pass", "findings": []},
                "not_a_real_category": {
                    "category": "not_a_real_category",
                    "status": "pass",
                    "findings": [],
                },
            },
            "summary": "ok",
            "errored_categories": [],
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload=payload,
        )
        assert panel.owasp_verdict is not None
        assert {r.category for r in panel.owasp_verdict.results} == {"tool_misuse"}

    def test_bad_status_in_result_filtered(self) -> None:
        payload: dict[str, Any] = {
            "overall_status": "green",
            "results": {
                "tool_misuse": {"category": "tool_misuse", "status": "bogus", "findings": []},
            },
            "summary": "ok",
            "errored_categories": [],
        }
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool"),
            record_kind="tool",
            conformance_payload=payload,
        )
        assert panel.owasp_verdict is not None
        assert panel.owasp_verdict.results == ()


# ---------------------------------------------------------------------------
# Slice H — shipped-matrix sanity
# ---------------------------------------------------------------------------


class TestSprint7B3T6SliceHShippedMatrix:
    """The module loads the static-shipped JSON at import time."""

    def test_module_loaded_matrix_has_both_protocols(self) -> None:
        assert set(_CONFORMANCE_MATRIX.keys()) == {"mcp", "a2a"}

    def test_every_curated_mcp_field_slug_resolves_in_shipped_matrix(self) -> None:
        from cognic_agentos.packs.evidence.conformance_matrix import _MCP_FIELD_TO_SLUG

        for slug in _MCP_FIELD_TO_SLUG.values():
            assert slug in _CONFORMANCE_MATRIX["mcp"], (
                f"curated MCP field slug {slug!r} missing from shipped matrix — "
                "regenerate conformance_matrix.json or fix the field map"
            )

    def test_every_curated_a2a_field_slug_resolves_in_shipped_matrix(self) -> None:
        from cognic_agentos.packs.evidence.conformance_matrix import _A2A_FIELD_TO_SLUG

        for slug in _A2A_FIELD_TO_SLUG.values():
            assert slug in _CONFORMANCE_MATRIX["a2a"], (
                f"curated A2A field slug {slug!r} missing from shipped matrix — "
                "regenerate conformance_matrix.json or fix the field map"
            )

    def test_load_conformance_matrix_fail_loud_on_bad_top_level_keys(self, tmp_path: Path) -> None:
        """The fail-loud guard fires when the JSON's top-level keys are
        not exactly ``{mcp, a2a}`` — a deployment-time error the
        operator must fix, NOT a silent empty-matrix fallback that
        would let every conformance comparison vacuously pass."""
        bad = tmp_path / "conformance_matrix.json"
        bad.write_text(json.dumps({"mcp": {}, "wrong_key": {}}), encoding="utf-8")
        with pytest.raises(ValueError, match="must carry exactly"):
            _load_conformance_matrix(bad)

    def test_load_conformance_matrix_accepts_well_formed_file(self, tmp_path: Path) -> None:
        """Sanity counterpart — a well-formed two-protocol JSON loads
        cleanly through the parameterised path."""
        good = tmp_path / "conformance_matrix.json"
        good.write_text(json.dumps({"mcp": {}, "a2a": {}}), encoding="utf-8")
        assert _load_conformance_matrix(good) == {"mcp": {}, "a2a": {}}


# ---------------------------------------------------------------------------
# Slice I — R-reviewer P2 #1 (canonical scaffold field families) +
#           P2 #2 (dual-path [tool.cognic.*] block resolution)
# ---------------------------------------------------------------------------


def _nested(
    *,
    kind: str = "tool",
    mcp: dict[str, Any] | None = None,
    a2a: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a legacy ``[tool.cognic.*]``-shaped manifest. The ``[pack]``
    block stays top-level (kind is route-layer-authoritative; the
    projector reads ``record_kind``, not the manifest)."""
    cognic: dict[str, Any] = {}
    if mcp is not None:
        cognic["mcp"] = mcp
    if a2a is not None:
        cognic["a2a"] = a2a
    if identity is not None:
        cognic["identity"] = identity
    return {"pack": {"kind": kind}, "tool": {"cognic": cognic}}


class TestSprint7B3T6SliceICanonicalScaffoldFieldFamilies:
    """R-reviewer P2 #1 — the canonical ``agentos init-tool`` /
    PACK-MANIFEST-SPEC.md ``[mcp]`` fields ``caching`` (bool) +
    ``elicitation_form`` (bool) MUST project, not just the runtime/docs
    alternative shapes ``caching_strategy`` / ``elicitation_modes``."""

    def test_scaffold_caching_bool_declares_caching_slug(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "caching" in panel.declarations["mcp"].declared_features
        comparison = next(c for c in panel.comparisons if c.feature == "caching")
        assert comparison.protocol == "mcp"
        assert comparison.matrix_wave_1 == "supported"
        assert comparison.flag is None

    def test_scaffold_caching_false_is_not_declared(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching": False}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert panel.declarations["mcp"].declared_features == ()

    def test_scaffold_elicitation_form_bool_declares_elicitation_slug(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"elicitation_form": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "elicitation" in panel.declarations["mcp"].declared_features
        comparison = next(c for c in panel.comparisons if c.feature == "elicitation")
        assert comparison.flag == "mcp_capability_restricted"

    def test_full_scaffold_mcp_block_projects_both_capabilities(self) -> None:
        """The shape ``agentos init-tool`` actually emits — both
        canonical bool fields present."""
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching": True, "elicitation_form": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert set(panel.declarations["mcp"].declared_features) == {"caching", "elicitation"}

    def test_both_caching_field_families_dedupe_to_one_comparison(self) -> None:
        """A pack declaring BOTH ``caching`` and ``caching_strategy``
        in one block produces exactly ONE ``caching`` comparison — the
        slug-dedup contract."""
        panel = project_conformance_matrix_panel(
            manifest=_manifest(kind="tool", mcp={"caching": True, "caching_strategy": "ttl"}),
            record_kind="tool",
            conformance_payload=None,
        )
        caching_comparisons = [c for c in panel.comparisons if c.feature == "caching"]
        assert len(caching_comparisons) == 1
        assert panel.declarations["mcp"].declared_features.count("caching") == 1

    def test_both_elicitation_field_families_dedupe_to_one_comparison(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_manifest(
                kind="tool", mcp={"elicitation_form": True, "elicitation_modes": ["url"]}
            ),
            record_kind="tool",
            conformance_payload=None,
        )
        elicitation_comparisons = [c for c in panel.comparisons if c.feature == "elicitation"]
        assert len(elicitation_comparisons) == 1


class TestSprint7B3T6SliceIDualPathBlockResolution:
    """R-reviewer P2 #2 — the projector MUST resolve protocol blocks
    from BOTH the canonical top-level path AND the legacy
    ``[tool.cognic.<block>]`` nested path (R23 dual-path doctrine). A
    docs-shaped submitted manifest would otherwise project empty."""

    def test_nested_mcp_block_resolves(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_nested(kind="tool", mcp={"sampling_supported": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "sampling" in panel.declarations["mcp"].declared_features
        comparison = next(c for c in panel.comparisons if c.feature == "sampling")
        assert comparison.flag == "mcp_capability_restricted"

    def test_nested_mcp_scaffold_caching_resolves(self) -> None:
        """P2 #1 + P2 #2 together — a docs-shaped manifest with the
        canonical scaffold bool field."""
        panel = project_conformance_matrix_panel(
            manifest=_nested(kind="tool", mcp={"caching": True}),
            record_kind="tool",
            conformance_payload=None,
        )
        assert "caching" in panel.declarations["mcp"].declared_features

    def test_nested_a2a_block_resolves(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_nested(kind="agent", a2a={"push_notification_config": True}),
            record_kind="agent",
            conformance_payload=None,
        )
        assert "push_notification_config" in panel.declarations["a2a"].declared_features
        comparison = next(c for c in panel.comparisons if c.feature == "push_notification_config")
        assert comparison.flag == "a2a_wave2_feature_declared"

    def test_nested_identity_oasf_block_resolves(self) -> None:
        panel = project_conformance_matrix_panel(
            manifest=_nested(kind="agent", identity={"oasf_capability_set": ["search.v1"]}),
            record_kind="agent",
            conformance_payload=None,
        )
        assert panel.declarations["oasf"].declared_features == ("search.v1",)
        oasf = [c for c in panel.comparisons if c.protocol == "oasf"]
        assert len(oasf) == 1
        assert oasf[0].flag == "oasf_capability_wave2_declared"

    def test_canonical_and_nested_mcp_union_dedupes_by_slug(self) -> None:
        """A pack declaring the SAME capability at both ``[mcp]`` and
        ``[tool.cognic.mcp]`` produces exactly ONE comparison — the
        dual-path union deduped by slug."""
        manifest: dict[str, Any] = {
            "pack": {"kind": "tool"},
            "mcp": {"sampling_supported": True},
            "tool": {"cognic": {"mcp": {"sampling_supported": True}}},
        }
        panel = project_conformance_matrix_panel(
            manifest=manifest, record_kind="tool", conformance_payload=None
        )
        sampling_comparisons = [c for c in panel.comparisons if c.feature == "sampling"]
        assert len(sampling_comparisons) == 1
        assert panel.declarations["mcp"].declared_features.count("sampling") == 1

    def test_canonical_and_nested_mcp_union_merges_distinct_features(self) -> None:
        """Distinct capabilities split across the two block paths are
        UNIONED — canonical ``[mcp]`` carries one, legacy carries the
        other; both surface."""
        manifest: dict[str, Any] = {
            "pack": {"kind": "tool"},
            "mcp": {"resources_supported": True},
            "tool": {"cognic": {"mcp": {"sampling_supported": True}}},
        }
        panel = project_conformance_matrix_panel(
            manifest=manifest, record_kind="tool", conformance_payload=None
        )
        assert set(panel.declarations["mcp"].declared_features) == {"resources", "sampling"}

    def test_non_dict_nested_intermediate_is_defensively_ignored(self) -> None:
        """``manifest["tool"]`` present but not a dict — the dual-path
        resolver returns no nested block rather than crashing."""
        manifest: dict[str, Any] = {
            "pack": {"kind": "tool"},
            "mcp": {"sampling_supported": True},
            "tool": "not-a-dict",
        }
        panel = project_conformance_matrix_panel(
            manifest=manifest, record_kind="tool", conformance_payload=None
        )
        assert panel.declarations["mcp"].declared_features == ("sampling",)

"""Sprint 7B.3 T5 — :mod:`packs.evidence.supply_chain` drift detectors +
projector contract tests (CRITICAL CONTROLS).

Pure-projector tests for ``project_supply_chain_panel``. No DB / no
FastAPI — these tests pin the projector contract independently of the
route handler at ``portal/api/packs/evidence_routes.py``. The route-
level integration tests (RBAC, tenant-isolation, kind-integrity, full
FastAPI stack with seeded submit row) ship in
``tests/unit/portal/api/packs/test_evidence_panel_routes.py`` at the
T5 Slice D extension classes.

Wire-protocol surfaces under test:

- :data:`AttestationKind` — closed-enum 7-value Literal per ADR-016
  §23-33. Drift breaks every reviewer evidence-pack consumer + the
  composer Gate 1 (signature) lookup.
- :class:`SupplyChainPanelData` — projector's frozen dataclass output;
  field set + ``from_attributes`` interop with the
  :class:`SupplyChainPanel` Pydantic DTO at ``portal/api/packs/dto.py``.
- :func:`project_supply_chain_panel` — pure projector contract:
  manifest dict → frozen dataclass. Defensive-shape fallback (missing
  / non-dict / malformed block) + the 7-year sigstore-bundle retention
  computation per ADR-016 §70-72.

Mirrors the T4 :mod:`packs.evidence.risk_tier` test layout: 3 vocab
drift-detector classes + 1 projector-contract class.
"""

from __future__ import annotations

import dataclasses
import typing
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cognic_agentos.packs.evidence.supply_chain import (
    AttestationKind,
    SupplyChainPanelData,
    project_supply_chain_panel,
)


class TestSprint7B3T5SliceAAttestationKindVocab:
    """Drift detectors for :data:`AttestationKind` per plan §335.

    The 7 values correspond 1:1 with ADR-016 §23-33's seven attestation
    kinds:

    - ``cosign``        — §23 cosign signature blob
    - ``slsa``          — §24 SLSA provenance attestation
    - ``sbom``          — §25 SPDX / CycloneDX SBOM
    - ``vuln_scan_baseline`` — §26 vuln-scan baseline (grype JSON)
    - ``license_audit``  — §27 license audit (pip-licenses JSON)
    - ``sigstore_bundle`` — §28 cosign --bundle Rekor-bound bundle
    - ``in_toto``       — §29 in-toto layout

    Wire-protocol-public — drift caught by typing.get_args round-trip.
    """

    _EXPECTED_VALUES: frozenset[str] = frozenset(
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

    def test_exact_value_set(self) -> None:
        """Lock the exact 7-value vocabulary per plan §335."""
        assert frozenset(typing.get_args(AttestationKind)) == self._EXPECTED_VALUES

    def test_exact_count(self) -> None:
        """Count guard pinned independently for crisp drift-diagnosis."""
        assert len(typing.get_args(AttestationKind)) == 7


class TestSprint7B3T5SliceASupplyChainPanelDataShape:
    """Shape drift detectors for the :class:`SupplyChainPanelData`
    projector output."""

    _EXPECTED_FIELDS: frozenset[str] = frozenset(
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

    def test_field_set_matches_plan(self) -> None:
        """Lock the exact 9-field set per plan §334."""
        names = {f.name for f in dataclasses.fields(SupplyChainPanelData)}
        assert names == self._EXPECTED_FIELDS

    def test_dataclass_is_frozen(self) -> None:
        """Projector output MUST be frozen — defends against handler-
        side mutation between projection and DTO validation.

        Pin via the actual frozen-behaviour contract (a frozen
        dataclass raises :class:`dataclasses.FrozenInstanceError` on
        attribute assignment) rather than the runtime-only
        ``__dataclass_params__`` attribute (which mypy doesn't expose
        on the dataclass type's surface)."""
        instance = SupplyChainPanelData(
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
        with pytest.raises(dataclasses.FrozenInstanceError):
            # mypy: ``frozen=True`` rejects attribute assignment at
            # type-check time too; ignore the misc rule here because
            # the test exists EXACTLY to pin the runtime refusal.
            instance.slsa_level_declared = 1  # type: ignore[misc]


class TestSprint7B3T5SliceAProjectorContract:
    """Pure-projector contract — happy path + per-attestation-kind
    declaration projection + defensive-shape fallback paths."""

    _SUBMIT_TIME = datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)

    def _full_supply_chain_block(self) -> dict[str, Any]:
        """A maximally-populated [supply_chain] block — every canonical
        attestation file declared in ``attestation_paths`` (the live
        signer contract per ``cli/verify.py:_REQUIRED_ATTESTATION_FILES``)
        plus the optional author-declared ``slsa_level``."""
        return {
            "attestation_paths": [
                "attestations/cosign.sig",
                "attestations/bundle.sigstore",
                "attestations/sbom.cdx.json",
                "attestations/vuln-scan.json",
                "attestations/license-audit.json",
                "attestations/slsa-provenance.intoto.json",
                "attestations/intoto-layout.json",
            ],
            "slsa_level": 3,
        }

    def test_full_manifest_projects_every_declared_field(self) -> None:
        """A maximally-populated manifest projects every field — the
        five named path fields DERIVED from ``attestation_paths`` by
        canonical-basename match + the optional author-declared
        ``slsa_level`` + the 7-year retention computed from the
        submit_created_at."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": self._full_supply_chain_block(),
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.pack_kind == "tool"
        assert result.declared_attestation_paths == (
            "attestations/cosign.sig",
            "attestations/bundle.sigstore",
            "attestations/sbom.cdx.json",
            "attestations/vuln-scan.json",
            "attestations/license-audit.json",
            "attestations/slsa-provenance.intoto.json",
            "attestations/intoto-layout.json",
        )
        assert result.slsa_level_declared == 3
        assert result.sbom_path_declared == "attestations/sbom.cdx.json"
        assert result.vuln_scan_path_declared == "attestations/vuln-scan.json"
        assert result.license_audit_path_declared == "attestations/license-audit.json"
        assert result.sigstore_bundle_path_declared == "attestations/bundle.sigstore"
        assert result.in_toto_layout_declared == "attestations/intoto-layout.json"
        # 7-year retention per ADR-016 §70-72 — mirror the constant at
        # protocol/supply_chain.py:99 (7 * 365 * 24 * 3600 seconds = no
        # leap-year adjustment; this is the regulator-floor window).
        assert result.sigstore_bundle_retention_expires_at == self._SUBMIT_TIME + timedelta(
            seconds=7 * 365 * 24 * 3600
        )

    def test_pack_kind_echoes_record_kind_not_manifest_kind(self) -> None:
        """Per the kind-integrity-route-layer doctrine: the route
        handler is the AUTHORITY on ``pack_kind``. The projector
        echoes ``record_kind`` verbatim, NOT the manifest's
        ``pack.kind`` value (the route handler cross-checks the two
        BEFORE invoking the projector)."""
        manifest = {
            "pack": {"kind": "agent"},  # manifest value (ignored by projector)
            "supply_chain": {"attestation_paths": ["x"]},
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",  # authoritative value from PackRecord
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.pack_kind == "tool"

    def test_missing_supply_chain_block_returns_all_none_or_empty(self) -> None:
        """Manifest without a ``supply_chain`` block surfaces all
        declared fields as None / empty tuple + retention=None per
        the defensive-shape doctrine."""
        manifest: dict[str, Any] = {"pack": {"kind": "tool"}}
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.declared_attestation_paths == ()
        assert result.slsa_level_declared is None
        assert result.sbom_path_declared is None
        assert result.vuln_scan_path_declared is None
        assert result.license_audit_path_declared is None
        assert result.sigstore_bundle_path_declared is None
        assert result.in_toto_layout_declared is None
        # Retention is None when sigstore_bundle_path is not declared —
        # even when a submit_created_at is supplied. The retention is
        # a property of the BUNDLE, not the submit row.
        assert result.sigstore_bundle_retention_expires_at is None

    def test_non_dict_supply_chain_block_falls_back_to_defensive_shape(self) -> None:
        """A manifest with a non-dict ``supply_chain`` value (e.g. a
        bare string from corrupted persistence) surfaces the defensive
        fallback — handler must NOT crash projecting against a
        malformed block."""
        manifest: dict[str, Any] = {
            "pack": {"kind": "tool"},
            "supply_chain": "not-a-dict",
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.declared_attestation_paths == ()
        assert result.slsa_level_declared is None
        assert result.sbom_path_declared is None
        assert result.sigstore_bundle_path_declared is None
        assert result.sigstore_bundle_retention_expires_at is None

    def test_retention_none_when_submit_created_at_is_none(self) -> None:
        """When the route handler cannot source a submit_created_at
        (e.g. pre-7B.3 chain row predates the seam, or storage returned
        None), retention surfaces None even when the bundle IS declared
        in ``attestation_paths``. The reviewer sees the gap on-panel."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": ["attestations/bundle.sigstore"],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.sigstore_bundle_path_declared == "attestations/bundle.sigstore"
        assert result.sigstore_bundle_retention_expires_at is None

    def test_retention_computed_only_when_both_conditions_met(self) -> None:
        """Retention computes ONLY when BOTH the bundle is derivable
        from ``attestation_paths`` AND submit_created_at is non-None.
        Mirror of the truth-table — only the (declared, non-None)
        combination produces a non-None retention value."""
        sigstore_block = {"attestation_paths": ["attestations/bundle.sigstore"]}
        empty_block: dict[str, Any] = {}

        # (declared, non-None) → computes retention.
        result_pos = project_supply_chain_panel(
            manifest={"pack": {"kind": "tool"}, "supply_chain": sigstore_block},
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result_pos.sigstore_bundle_retention_expires_at is not None

        # (not declared, non-None) → None.
        result_no_decl = project_supply_chain_panel(
            manifest={"pack": {"kind": "tool"}, "supply_chain": empty_block},
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result_no_decl.sigstore_bundle_retention_expires_at is None

        # (declared, None) → None.
        result_no_time = project_supply_chain_panel(
            manifest={"pack": {"kind": "tool"}, "supply_chain": sigstore_block},
            record_kind="tool",
            submit_created_at=None,
        )
        assert result_no_time.sigstore_bundle_retention_expires_at is None

        # (not declared, None) → None.
        result_neither = project_supply_chain_panel(
            manifest={"pack": {"kind": "tool"}, "supply_chain": empty_block},
            record_kind="tool",
            submit_created_at=None,
        )
        assert result_neither.sigstore_bundle_retention_expires_at is None

    def test_non_string_attestation_paths_entries_filtered_out(self) -> None:
        """The ``attestation_paths`` list MUST surface only string
        entries — non-string drift in the manifest is silently dropped
        rather than crashing or leaking non-string values onto the
        wire (the field type is ``tuple[str, ...]``)."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": [
                    "valid/path.sig",
                    42,  # int — silently filtered
                    None,  # None — silently filtered
                    ["nested"],  # list — silently filtered
                    "another/valid.bundle",
                ],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.declared_attestation_paths == (
            "valid/path.sig",
            "another/valid.bundle",
        )

    def test_non_list_attestation_paths_falls_back_to_empty_tuple(self) -> None:
        """If ``attestation_paths`` is a non-list value (e.g. a bare
        string), the defensive fallback surfaces an empty tuple."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {"attestation_paths": "not-a-list"},
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.declared_attestation_paths == ()

    def test_non_int_slsa_level_falls_back_to_none(self) -> None:
        """``slsa_level`` declared as a non-int (string / float / dict)
        surfaces as None — refuse to project a non-int to a typed
        ``int | None`` field."""
        for bad_value in ("3", 3.0, ["3"], {"value": 3}):
            manifest = {
                "pack": {"kind": "tool"},
                "supply_chain": {"slsa_level": bad_value},
            }
            result = project_supply_chain_panel(
                manifest=manifest,
                record_kind="tool",
                submit_created_at=None,
            )
            assert result.slsa_level_declared is None, f"failed for {bad_value!r}"

    def test_bool_slsa_level_excluded_despite_int_subclass(self) -> None:
        """``bool`` is a runtime subclass of :class:`int` in Python —
        an isinstance(int) check WOULD accept ``True`` and narrow it
        to SLSA level 1, which is a security-relevant misrepresentation
        on the reviewer panel.

        The projector pre-checks ``isinstance(raw, bool)`` and returns
        None first to defend against this; both ``True`` and ``False``
        must surface as ``slsa_level_declared = None``. Regression
        pinned to keep the bool-subclass guard load-bearing."""
        for bool_value in (True, False):
            manifest = {
                "pack": {"kind": "tool"},
                "supply_chain": {"slsa_level": bool_value},
            }
            result = project_supply_chain_panel(
                manifest=manifest,
                record_kind="tool",
                submit_created_at=None,
            )
            assert result.slsa_level_declared is None, f"failed for {bool_value!r}"

    @pytest.mark.parametrize(
        ("canonical_basename", "result_attr"),
        [
            ("sbom.cdx.json", "sbom_path_declared"),
            ("vuln-scan.json", "vuln_scan_path_declared"),
            ("license-audit.json", "license_audit_path_declared"),
            ("bundle.sigstore", "sigstore_bundle_path_declared"),
            ("intoto-layout.json", "in_toto_layout_declared"),
        ],
    )
    def test_named_path_field_independently_derives_from_attestation_paths(
        self, canonical_basename: str, result_attr: str
    ) -> None:
        """Each of the 5 named path fields independently DERIVES from an
        ``attestation_paths`` entry whose canonical basename matches.
        Mirrors the per-attestation-kind audit: a reviewer can confirm
        individual declaration presence; a pack that declares ONLY one
        canonical file has ONLY that field populated + the rest None."""
        declared = f"attestations/{canonical_basename}"
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {"attestation_paths": [declared]},
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert getattr(result, result_attr) == declared
        # Every OTHER named path field is None — only the one declared
        # canonical file derives a value.
        other_attrs = {
            "sbom_path_declared",
            "vuln_scan_path_declared",
            "license_audit_path_declared",
            "sigstore_bundle_path_declared",
            "in_toto_layout_declared",
        } - {result_attr}
        for attr in other_attrs:
            assert getattr(result, attr) is None, f"{attr} leaked"

    def test_non_canonical_basename_entries_derive_no_named_field(self) -> None:
        """An ``attestation_paths`` entry whose basename is NOT one of
        the canonical attestation filenames (e.g. a typo or a
        non-standard file) is surfaced verbatim in
        ``declared_attestation_paths`` but derives NO named path field.
        Defends against a fuzzy-match regression that would mis-derive
        a field from a near-miss filename."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": [
                    "attestations/sbom.spdx.json",  # SPDX, not the canonical .cdx.json
                    "attestations/my-custom-attestation.json",
                ],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.declared_attestation_paths == (
            "attestations/sbom.spdx.json",
            "attestations/my-custom-attestation.json",
        )
        assert result.sbom_path_declared is None
        assert result.vuln_scan_path_declared is None
        assert result.license_audit_path_declared is None
        assert result.sigstore_bundle_path_declared is None
        assert result.in_toto_layout_declared is None

    def test_duplicate_canonical_basename_takes_first_entry(self) -> None:
        """When ``attestation_paths`` carries two entries with the same
        canonical basename, the FIRST (in author-declared order) wins —
        deterministic, no last-write-wins ambiguity."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": [
                    "first/bundle.sigstore",
                    "second/bundle.sigstore",
                ],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.sigstore_bundle_path_declared == "first/bundle.sigstore"

    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    def test_projector_accepts_all_four_pack_kinds(self, kind: str) -> None:
        """All 4 PackKind values flow through the projector unchanged.
        Pinned independently — a future drift in PackKind would
        otherwise surface only at the DTO validation layer."""
        from cognic_agentos.packs.lifecycle import PackKind

        # Type narrow at runtime — every parametrised value is a member
        # of the PackKind Literal, so the runtime cast is sound.
        narrow_kind: PackKind = typing.cast(PackKind, kind)
        result = project_supply_chain_panel(
            manifest={"pack": {"kind": kind}, "supply_chain": {}},
            record_kind=narrow_kind,
            submit_created_at=None,
        )
        assert result.pack_kind == kind

    def test_retention_uses_seven_year_floor_constant(self) -> None:
        """The retention computation MUST match the existing
        production constant at ``protocol/supply_chain.py:99``
        (``7 * 365 * 24 * 3600`` seconds). Drift would let the bundle
        retention escape the ADR-016 §70-72 regulator-floor window."""
        from cognic_agentos.protocol.supply_chain import (
            SIGSTORE_BUNDLE_RETENTION_SECONDS,
        )

        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": ["attestations/bundle.sigstore"],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.sigstore_bundle_retention_expires_at is not None
        delta = result.sigstore_bundle_retention_expires_at - self._SUBMIT_TIME
        assert delta.total_seconds() == SIGSTORE_BUNDLE_RETENTION_SECONDS

    # -- R1 P2 #1: signer-shaped manifest regression --------------------

    def test_signer_shaped_manifest_derives_every_path_from_attestation_paths(
        self,
    ) -> None:
        """R1 P2 #1 regression — the live ``agentos sign --bundle``
        contract declares EVERY attestation file through
        ``[supply_chain].attestation_paths`` (per
        ``cli/verify.py:_REQUIRED_ATTESTATION_FILES`` + the manifest
        templates). The block does NOT carry granular
        ``sbom_path`` / ``sigstore_bundle_path`` / etc. keys. The
        projector MUST derive each named path field by matching an
        ``attestation_paths`` entry's POSIX basename against the
        canonical attestation filename — otherwise a real signed pack
        shows ``sigstore_bundle_path_declared=None`` + no retention.

        Canonical basenames (per ``cli/verify.py``):
        ``cosign.sig`` / ``bundle.sigstore`` / ``sbom.cdx.json`` /
        ``vuln-scan.json`` / ``license-audit.json`` /
        ``slsa-provenance.intoto.json`` / ``intoto-layout.json``."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": [
                    "attestations/cosign.sig",
                    "attestations/bundle.sigstore",
                    "attestations/sbom.cdx.json",
                    "attestations/vuln-scan.json",
                    "attestations/license-audit.json",
                    "attestations/slsa-provenance.intoto.json",
                    "attestations/intoto-layout.json",
                ],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        # Every named path field derived from the attestation_paths list.
        assert result.sbom_path_declared == "attestations/sbom.cdx.json"
        assert result.vuln_scan_path_declared == "attestations/vuln-scan.json"
        assert result.license_audit_path_declared == "attestations/license-audit.json"
        assert result.sigstore_bundle_path_declared == "attestations/bundle.sigstore"
        assert result.in_toto_layout_declared == "attestations/intoto-layout.json"
        # The bundle path WAS derived → retention computes.
        assert result.sigstore_bundle_retention_expires_at is not None
        # The raw list is still surfaced verbatim.
        assert result.declared_attestation_paths == (
            "attestations/cosign.sig",
            "attestations/bundle.sigstore",
            "attestations/sbom.cdx.json",
            "attestations/vuln-scan.json",
            "attestations/license-audit.json",
            "attestations/slsa-provenance.intoto.json",
            "attestations/intoto-layout.json",
        )

    def test_signer_shaped_bundle_only_manifest_computes_retention(self) -> None:
        """R1 P2 #1 — the minimal signer-shaped case: a pack whose
        ``attestation_paths`` carries the Sigstore bundle (canonical
        basename ``bundle.sigstore``) and nothing else MUST still
        derive ``sigstore_bundle_path_declared`` + compute the 7-year
        retention. This is the exact case the pre-fix projector got
        wrong (returned None because it looked for a non-existent
        ``sigstore_bundle_path`` key)."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": ["attestations/bundle.sigstore"],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.sigstore_bundle_path_declared == "attestations/bundle.sigstore"
        assert result.sigstore_bundle_retention_expires_at is not None

    def test_path_field_derivation_matches_on_basename_not_full_path(self) -> None:
        """The derivation matches on the POSIX BASENAME of each
        ``attestation_paths`` entry — an author who declares the
        canonical file under a non-default directory still has it
        recognised, and the FULL declared path (as the author wrote
        it) is surfaced, not a normalised one."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": ["custom/dir/bundle.sigstore"],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.sigstore_bundle_path_declared == "custom/dir/bundle.sigstore"

    def test_path_field_none_when_canonical_file_absent_from_list(self) -> None:
        """A named path field is None when no ``attestation_paths``
        entry matches its canonical basename — e.g. a pack that
        declares only ``cosign.sig`` has ``sbom_path_declared=None``."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {
                "attestation_paths": ["attestations/cosign.sig"],
            },
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=self._SUBMIT_TIME,
        )
        assert result.sbom_path_declared is None
        assert result.vuln_scan_path_declared is None
        assert result.license_audit_path_declared is None
        assert result.sigstore_bundle_path_declared is None
        assert result.in_toto_layout_declared is None
        # No bundle declared → no retention even with a submit timestamp.
        assert result.sigstore_bundle_retention_expires_at is None

    # -- R1 P2 #2: out-of-range SLSA level regression -------------------

    @pytest.mark.parametrize("out_of_range", [0, -1, -3, 5, 6, 99, 1000])
    def test_out_of_range_slsa_level_falls_back_to_none(self, out_of_range: int) -> None:
        """R1 P2 #2 regression — ADR-016 §24 + ``protocol/supply_chain.py``
        ``SLSAResult.level`` expect an int 1..4. An out-of-range
        ``slsa_level`` (0, negative, or 5+) is corruption — the
        projector MUST surface None rather than presenting an invalid
        SLSA level on the reviewer panel (this projector also feeds the
        T7 composer, so a bogus level would propagate into gate input).

        ``slsa_level`` itself is an OPTIONAL author-declared key — the
        canonical signer does not auto-populate it (the SLSA level
        lives inside the ``slsa-provenance.intoto.json`` predicate, not
        the manifest), but the validator tolerates the key so an
        author MAY declare it; the panel projects it AS DECLARED with
        the 1..4 validity gate."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {"slsa_level": out_of_range},
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.slsa_level_declared is None, f"failed for {out_of_range}"

    @pytest.mark.parametrize("in_range", [1, 2, 3, 4])
    def test_in_range_slsa_level_projects(self, in_range: int) -> None:
        """The four valid ADR-016 §24 SLSA build levels (1-4) project
        through unchanged — the range gate accepts the canonical
        values and rejects only out-of-range corruption."""
        manifest = {
            "pack": {"kind": "tool"},
            "supply_chain": {"slsa_level": in_range},
        }
        result = project_supply_chain_panel(
            manifest=manifest,
            record_kind="tool",
            submit_created_at=None,
        )
        assert result.slsa_level_declared == in_range

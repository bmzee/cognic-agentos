"""Sprint 7B.3 T5 — ADR-016 supply-chain evidence panel (CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§325-339 + ADR-016 §23-33 + §70-72, this module ships the reviewer-
facing supply-chain evidence panel:

- :data:`AttestationKind` — closed-enum 7-value Literal per ADR-016
  §23-33. Wire-protocol-public — used as the closed-set vocabulary
  reviewers see when auditing what the pack author declared at sign
  time AND as the keyset for the 5-gate composer's Gate 1 (signature)
  evidence lookup at T7.
- :class:`SupplyChainPanelData` — pure-functional projector output;
  frozen dataclass mirroring the wire-shape of the
  :class:`SupplyChainPanel` Pydantic DTO at ``portal/api/packs/dto.py``.
- :func:`project_supply_chain_panel` — pure projector. No I/O, no DB
  access, no global state. The route handler at
  :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
  persisted manifest via the T2 manifest-evidence-source seam + sources
  the submit-row ``created_at`` via the T5 storage seam (the projector
  receives both as kwargs).

**Plan §333 — projector projects declarations, NOT verification status**:
the panel surfaces ONLY what the author DECLARED in the manifest. The
actual signature-verification status surfaces via the composer's Gate
1 result on the approve endpoint (T7-T9), NOT on this panel. A
reviewer reads the panel to see WHAT the author declared; the
composer result to see WHETHER the declarations VERIFIED.

**Manifest contract (R1 P2 #1 — verified against the live signer)**:
the canonical ``[supply_chain]`` manifest block carries exactly two
author-authored keys per ``cli/validators/supply_chain.py``:

- ``attestation_paths: list[str]`` — REQUIRED. The list of attestation
  files the author declares. ``agentos sign --bundle`` writes the
  seven canonical attestation files (``cosign.sig`` / ``bundle.sigstore``
  / ``sbom.cdx.json`` / ``vuln-scan.json`` / ``license-audit.json`` /
  ``slsa-provenance.intoto.json`` / ``intoto-layout.json`` per
  ``cli/verify.py:_REQUIRED_ATTESTATION_FILES``) and the manifest
  templates seed ``attestation_paths`` with them under the
  ``attestations/`` directory.
- ``blob_path: str`` — OPTIONAL. The cosign signature blob path
  (validated by ``cli/validators/supply_chain.py`` but NOT projected
  by this panel — it is a verify-time concern, not a reviewer-evidence
  field).

The block does NOT carry granular per-kind keys (``sbom_path`` /
``sigstore_bundle_path`` / ``in_toto_layout`` / etc.). The projector
therefore **derives** each named path field by matching an
``attestation_paths`` entry's POSIX basename against the canonical
attestation filename (see :data:`_CANONICAL_ATTESTATION_BASENAMES`).
This is R1 P2 #1: the pre-fix projector read non-existent granular
keys and returned ``None`` for every real signed pack — including no
sigstore retention.

``slsa_level`` is the one exception: it is NOT a canonical signer-
emitted field (the SLSA build level lives inside the
``slsa-provenance.intoto.json`` predicate per
``protocol/supply_chain.py`` ``SLSAResult.level``, not the manifest
block) — but ``cli/validators/supply_chain.py`` tolerates unknown
keys, so an author MAY optionally declare ``[supply_chain].slsa_level``
to document their intended level. The panel projects it AS DECLARED
with the ADR-016 §24 1..4 validity gate (R1 P2 #2).

**Architectural-arrow invariant**: this module lives in
``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate composer
(T7) can read the same projector output without crossing layers. The
arrow runs ``portal → packs/evidence`` exclusively — projectors do NOT
import portal types.

**Defensive-shape doctrine (mirrors :func:`project_data_governance_panel`
and :func:`project_risk_tier_panel`)**: missing block, non-dict block,
non-list ``attestation_paths``, non-string entries inside it, non-int
or out-of-range ``slsa_level``, and absence of a canonical attestation
file ALL surface as the safe-default value (``None``, empty tuple, or
filtered list) rather than crashing the route or leaking a malformed
value onto the wire. The reviewer sees the gap on-panel; the composer
reads the same data WITHOUT having to defend against type drift a
second time.

**Retention computation (ADR-016 §70-72)**: when the derived
``sigstore_bundle_path_declared`` is non-None AND the route handler
sources a non-None ``submit_created_at``, the panel computes the
7-year retention floor via
``submit_created_at + timedelta(seconds=7 * 365 * 24 * 3600)`` —
exactly matching the production constant at
:data:`protocol.supply_chain.SIGSTORE_BUNDLE_RETENTION_SECONDS` (no
leap-year adjustment; this is the regulator-floor window, tenants can
extend but cannot shorten). When EITHER condition fails, retention is
None — the reviewer sees the gap and the bundle is treated as
unbounded retention for audit purposes.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any, Final, Literal

from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.protocol.supply_chain import SIGSTORE_BUNDLE_RETENTION_SECONDS

__all__ = [
    "AttestationKind",
    "SupplyChainPanelData",
    "project_supply_chain_panel",
]


AttestationKind = Literal[
    "cosign",
    "slsa",
    "sbom",
    "vuln_scan_baseline",
    "license_audit",
    "sigstore_bundle",
    "in_toto",
]
"""Closed-enum 7-value vocabulary for the seven attestation kinds per
ADR-016 §23-33.

Wire-protocol-public — also the keyset for the 5-gate composer's
Gate 1 (signature) evidence lookup at T7. Drift between this Literal
and ADR-016 §23-33 is wire-protocol regression — pinned by
``test_supply_chain_panel.py::TestSprint7B3T5SliceAAttestationKindVocab``.

Each value pairs with the canonical attestation FILE the live
``agentos sign --bundle`` writes (per
``cli/verify.py:_REQUIRED_ATTESTATION_FILES``):

- ``"cosign"``        — §23 cosign signature blob (``cosign.sig``).
- ``"slsa"``          — §24 SLSA provenance attestation
  (``slsa-provenance.intoto.json``).
- ``"sbom"``          — §25 CycloneDX SBOM (``sbom.cdx.json``).
- ``"vuln_scan_baseline"`` — §26 vuln-scan baseline (``vuln-scan.json``;
  grype JSON output).
- ``"license_audit"``  — §27 license audit (``license-audit.json``;
  pip-licenses JSON output).
- ``"sigstore_bundle"`` — §28 cosign ``--bundle`` Rekor-bound bundle
  (``bundle.sigstore``; offline-reverifiable for 7 years per §70-72).
- ``"in_toto"``        — §29 in-toto layout describing the build
  pipeline (``intoto-layout.json``).
"""


#: Maps each canonical attestation FILENAME (the POSIX basename of an
#: ``attestation_paths`` entry, per
#: ``cli/verify.py:_REQUIRED_ATTESTATION_FILES``) to the
#: :class:`SupplyChainPanelData` field that surfaces its declared
#: path. ``cosign.sig`` is NOT in this map — the cosign signature
#: blob is a verify-time concern surfaced via the composer's Gate 1
#: at T7, not a reviewer-evidence field on this panel.
#:
#: R1 P2 #1: the projector DERIVES each named path field by matching
#: an ``attestation_paths`` entry's basename against this table. The
#: canonical ``[supply_chain]`` manifest block does NOT carry granular
#: per-kind path keys — ``attestation_paths`` is the single declared
#: source.
_CANONICAL_ATTESTATION_BASENAMES: Final[dict[str, str]] = {
    "sbom.cdx.json": "sbom_path_declared",
    "vuln-scan.json": "vuln_scan_path_declared",
    "license-audit.json": "license_audit_path_declared",
    "bundle.sigstore": "sigstore_bundle_path_declared",
    "intoto-layout.json": "in_toto_layout_declared",
}

#: ADR-016 §24 — SLSA build levels are 1..4. ``protocol/supply_chain.py``
#: ``SLSAResult.level`` reads ``predicate.slsaLevel`` "expecting an int
#: 1..4". An out-of-range declared value is corruption — the projector
#: surfaces ``None`` rather than presenting an invalid level on the
#: reviewer panel (this projector also feeds the T7 composer, so a
#: bogus level would propagate into gate input).
_SLSA_LEVEL_MIN: Final[int] = 1
_SLSA_LEVEL_MAX: Final[int] = 4


@dataclasses.dataclass(frozen=True)
class SupplyChainPanelData:
    """Pure-functional projector output per plan §334.

    Mirrors the wire-shape of the :class:`SupplyChainPanel` Pydantic
    DTO at ``portal/api/packs/dto.py``; the DTO's ``from_attributes=True``
    config lets the route handler call
    ``SupplyChainPanel.model_validate(panel_data)`` directly without an
    intermediate ``dataclasses.asdict`` step.

    Architectural-arrow invariant: this dataclass lives in
    ``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate
    composer (T7) can read the same projector output without crossing
    layers. The arrow runs ``portal → packs/evidence`` exclusively.

    Fields (9 total, frozen, ordered per plan §334):

    - ``pack_kind``: authoritative :class:`PackRecord.kind` echoed
      verbatim by the projector; the route handler is the authority,
      not the manifest.
    - ``declared_attestation_paths``: tuple of paths the author
      declared in ``manifest.supply_chain.attestation_paths``, surfaced
      verbatim. Tuple (not list) so the projector output is immutable.
      Non-string entries silently filtered.
    - ``slsa_level_declared``: integer SLSA level (1-4) the author
      OPTIONALLY declared in ``manifest.supply_chain.slsa_level``.
      ``None`` when missing / non-int / out-of-range. (NOT a canonical
      signer-emitted field — see module docstring.)
    - ``sbom_path_declared``: SBOM file path, DERIVED from
      ``attestation_paths`` by canonical-basename match
      (``sbom.cdx.json``). ``None`` when no entry matches.
    - ``vuln_scan_path_declared``: vuln-scan output path, DERIVED
      (``vuln-scan.json``). ``None`` when no entry matches.
    - ``license_audit_path_declared``: license-audit output path,
      DERIVED (``license-audit.json``). ``None`` when no entry matches.
    - ``sigstore_bundle_path_declared``: Rekor-bound bundle path,
      DERIVED (``bundle.sigstore``). ``None`` when no entry matches.
    - ``in_toto_layout_declared``: in-toto layout path, DERIVED
      (``intoto-layout.json``). ``None`` when no entry matches.
    - ``sigstore_bundle_retention_expires_at``: ISO 8601 datetime
      computed from submit-row ``created_at`` + 7 years per ADR-016
      §70-72. ``None`` when EITHER the bundle path could not be derived
      OR the route handler could not source a ``submit_created_at``
      (e.g. pre-7B.3 chain row).
    """

    pack_kind: PackKind
    declared_attestation_paths: tuple[str, ...]
    slsa_level_declared: int | None
    sbom_path_declared: str | None
    vuln_scan_path_declared: str | None
    license_audit_path_declared: str | None
    sigstore_bundle_path_declared: str | None
    in_toto_layout_declared: str | None
    sigstore_bundle_retention_expires_at: datetime | None


def _project_attestation_paths(block: dict[str, Any]) -> tuple[str, ...]:
    """Defensive-shape helper: project the ``attestation_paths`` list
    to a tuple of strings. Non-list values and non-string entries are
    silently dropped — the field shape is ``tuple[str, ...]`` and the
    projector never leaks a non-string onto the wire."""
    raw = block.get("attestation_paths")
    if not isinstance(raw, list):
        return ()
    return tuple(entry for entry in raw if isinstance(entry, str))


def _derive_named_paths(
    declared_paths: tuple[str, ...],
) -> dict[str, str | None]:
    """R1 P2 #1: derive the five named path fields from the declared
    ``attestation_paths`` list by matching each entry's POSIX basename
    against :data:`_CANONICAL_ATTESTATION_BASENAMES`.

    Returns a dict keyed by :class:`SupplyChainPanelData` field name —
    every field in :data:`_CANONICAL_ATTESTATION_BASENAMES` is present
    in the result (value ``None`` when no entry matched). Matching uses
    :class:`pathlib.PurePosixPath` because manifest paths are POSIX-
    style regardless of the author's host OS; the FULL declared path
    (as the author wrote it) is surfaced, not a normalised one. On a
    duplicate basename the FIRST matching entry wins (deterministic
    iteration order over the author-declared list)."""
    derived: dict[str, str | None] = dict.fromkeys(_CANONICAL_ATTESTATION_BASENAMES.values(), None)
    for path in declared_paths:
        basename = PurePosixPath(path).name
        field_name = _CANONICAL_ATTESTATION_BASENAMES.get(basename)
        if field_name is not None and derived[field_name] is None:
            derived[field_name] = path
    return derived


def _project_slsa_level(block: dict[str, Any]) -> int | None:
    """Defensive-shape helper: project the optional author-declared
    ``slsa_level`` field.

    Refuses non-int values, ``bool`` (a subclass of ``int`` — ``True``
    would otherwise narrow to ``1``), AND out-of-range values per
    ADR-016 §24's 1..4 SLSA build-level range (R1 P2 #2). An out-of-
    range declared level is corruption — surfacing it would present an
    invalid level on the reviewer panel + propagate into the T7
    composer's gate input."""
    raw = block.get("slsa_level")
    # ``bool`` is a subclass of ``int`` per Python — exclude it
    # explicitly so a stray ``true`` from the manifest doesn't surface
    # as SLSA level 1.
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, int):
        return None
    # ADR-016 §24 — SLSA build levels are 1..4. Out-of-range = corruption.
    if not (_SLSA_LEVEL_MIN <= raw <= _SLSA_LEVEL_MAX):
        return None
    return raw


def project_supply_chain_panel(
    *,
    manifest: dict[str, Any],
    record_kind: PackKind,
    submit_created_at: datetime | None,
) -> SupplyChainPanelData:
    """Project a pack manifest's ``supply_chain`` block onto the
    reviewer-facing evidence panel per plan §333-336.

    Pure-functional: no I/O, no DB access, no global state. The route
    handler in :mod:`cognic_agentos.portal.api.packs.evidence_routes`
    fetches the persisted manifest via ``store.load_lifecycle_history``
    + :func:`find_latest_submit_row` + ``payload["manifest"]`` AND
    sources the submit row's ``created_at`` via the T5 storage seam
    :meth:`PackRecordStore.load_latest_submit_created_at`, then passes
    both to this projector.

    ``record_kind`` is the authoritative :attr:`PackRecord.kind` value
    — the handler cross-checks it against ``manifest["pack"]["kind"]``
    BEFORE invoking this projector (the cross-check is route-layer
    concern, not projector-layer).

    ``submit_created_at`` is the persisted timestamp of the chain row
    that recorded the most recent submit. Used to compute the 7-year
    sigstore-bundle retention per ADR-016 §70-72. ``None`` when the
    route handler could not source the timestamp — yields
    ``sigstore_bundle_retention_expires_at = None`` per the truth-
    table in the projector contract docs.

    R1 P2 #1 — the five named path fields are DERIVED from the
    ``attestation_paths`` list by canonical-basename match (the
    ``[supply_chain]`` block does NOT carry granular per-kind keys; see
    module docstring). ``slsa_level`` is the one optional author-
    declared key, projected AS DECLARED with the ADR-016 §24 1..4
    validity gate.

    Defensive shape handling: missing ``supply_chain`` block, non-dict
    block, non-list ``attestation_paths``, non-string entries, non-int
    or out-of-range ``slsa_level``, and absence of a canonical
    attestation file all surface as the safe default — see module
    docstring for the full truth table.

    Returns: :class:`SupplyChainPanelData` — a frozen dataclass that
    the DTO at ``portal/api/packs/dto.py`` consumes via
    ``from_attributes=True``.
    """
    raw_block = manifest.get("supply_chain")
    block: dict[str, Any] = raw_block if isinstance(raw_block, dict) else {}

    declared_paths = _project_attestation_paths(block)
    slsa_level = _project_slsa_level(block)

    # R1 P2 #1 — derive the five named path fields from the declared
    # attestation_paths list (NOT from non-existent granular keys).
    named = _derive_named_paths(declared_paths)
    sbom_path = named["sbom_path_declared"]
    vuln_scan_path = named["vuln_scan_path_declared"]
    license_audit_path = named["license_audit_path_declared"]
    sigstore_bundle_path = named["sigstore_bundle_path_declared"]
    in_toto_layout = named["in_toto_layout_declared"]

    # ADR-016 §70-72 retention: only computed when BOTH (a) the bundle
    # path was derived from attestation_paths and (b) the route handler
    # sourced a submit_created_at. The two conditions are AND-gated —
    # surfacing a retention without a declared bundle would mislead the
    # reviewer (there is nothing to retain); surfacing a retention
    # without a submit_created_at would be a synthetic timestamp
    # violation of the production-grade rule. Mirrors the production
    # constant at ``protocol/supply_chain.py:99`` (no leap-year
    # adjustment — the ADR-016 floor is in seconds, not calendar years).
    if sigstore_bundle_path is not None and submit_created_at is not None:
        retention_expires_at: datetime | None = submit_created_at + timedelta(
            seconds=SIGSTORE_BUNDLE_RETENTION_SECONDS
        )
    else:
        retention_expires_at = None

    return SupplyChainPanelData(
        pack_kind=record_kind,
        declared_attestation_paths=declared_paths,
        slsa_level_declared=slsa_level,
        sbom_path_declared=sbom_path,
        vuln_scan_path_declared=vuln_scan_path,
        license_audit_path_declared=license_audit_path,
        sigstore_bundle_path_declared=sigstore_bundle_path,
        in_toto_layout_declared=in_toto_layout,
        sigstore_bundle_retention_expires_at=retention_expires_at,
    )

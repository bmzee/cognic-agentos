"""Sprint 7B.3 T6 — ADR-002 + ADR-003 conformance-matrix evidence panel
(CRITICAL CONTROLS).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§341-356 + ``docs/MCP-CONFORMANCE.md`` + ``docs/A2A-CONFORMANCE.md``,
this module ships the reviewer-facing conformance-matrix evidence
panel — the fourth and final 7B.3 evidence panel:

- :data:`MatrixComparisonFlag` — closed-enum 6-value Literal per plan
  §352. Wire-protocol-public — the closed-set vocabulary reviewers see
  when auditing how a pack's declared MCP/A2A/OASF features compare to
  the AgentOS conformance posture.
- :class:`MatrixDeclaration` / :class:`MatrixComparison` /
  :class:`OwaspCheckResultData` / :class:`OwaspVerdictData` /
  :class:`ConformanceMatrixPanelData` — pure-functional projector
  output; frozen dataclasses mirroring the wire-shape of the
  :class:`ConformanceMatrixPanel` Pydantic DTO at
  ``portal/api/packs/dto.py``.
- :func:`project_conformance_matrix_panel` — pure projector. No I/O at
  call time (the static conformance matrix is loaded ONCE at module
  import — see below). The route handler at
  :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
  persisted manifest via the T2 manifest-evidence-source seam AND the
  submit-row ``payload["conformance"]`` (the OWASP verdict written by
  7B.2 T9) and passes both to this projector.

**Static-shipped conformance matrix (R10 LOCKED — Round Flag #8)**:
the AgentOS conformance posture lives in two prose-table Markdown docs
(``docs/MCP-CONFORMANCE.md`` "Capability conformance" table +
``docs/A2A-CONFORMANCE.md`` "Feature conformance matrix" table). The
runtime panel MUST NOT parse Markdown at request time; instead the
build-time generator ``tools/generate_conformance_matrix_json.py``
parses the two tables once → emits ``conformance_matrix.json`` shipped
alongside this module. :data:`_CONFORMANCE_MATRIX` is loaded ONCE at
module import. The committed JSON is pinned against the generator's
output by the build-time drift detector at
``tests/unit/tools/test_generate_conformance_matrix_json.py`` — a docs
edit that moves a Wave-1 posture without regenerating the JSON fails
that test.

**R9 kind-aware applicability (plan §351)**: not every protocol matrix
applies to every pack kind:

- ``mcp``  — applicable to ``tool`` / ``skill`` / ``agent`` packs.
- ``a2a``  — applicable to ``agent`` packs ONLY (inter-agent protocol).
- ``oasf`` — applicable to ``agent`` packs ONLY (AGNTCY/OASF identity).
- ``hook`` packs — NONE of the three apply (hooks have no protocol
  surface per ADR-004).

When a protocol is not applicable for the pack's kind, the panel marks
:attr:`MatrixDeclaration.applicable` ``False``, emits an empty
``declared_features`` tuple, and produces NO :class:`MatrixComparison`
entries for it — "mark not_applicable rather than failing absent
protocol blocks" per plan §351. A hook pack that (wrongly) carries an
``[mcp]`` block still produces zero MCP comparisons.

**Manifest-field → matrix-slug curation**: the conformance matrix is
keyed by *slugified capability names* from the Markdown tables (e.g.
``sampling`` / ``streaming_messages``); the pack manifest declares
*named boolean / list fields* in its ``[mcp]`` / ``[a2a]`` blocks (e.g.
``sampling_supported`` / ``streaming``). :data:`_MCP_FIELD_TO_SLUG` +
:data:`_A2A_FIELD_TO_SLUG` are the curated bridges. The
:data:`test_conformance_matrix_panel.py::
TestSprint7B3T6SliceHShippedMatrix` drift detectors pin every curated
slug against the shipped matrix so a JSON regenerate that drops a slug
fails loudly at test time.

**Two field families per MCP capability (R-reviewer P2 #1)**: per
``docs/PACK-MANIFEST-SPEC.md`` §4, the canonical ``agentos init-tool``
scaffold + the spec's "required" rows use the boolean ``[mcp]`` fields
``caching`` / ``elicitation_form``; the runtime/docs alternative shape
uses ``caching_strategy`` (string) / ``elicitation_modes`` (list).
:data:`_MCP_FIELD_TO_SLUG` carries BOTH families — each maps to the
same matrix slug, and :func:`_project_protocol` dedupes by slug so a
pack declaring both shapes of one capability still produces exactly
one :class:`MatrixComparison`. A panel that recognised only the
runtime/docs shape would show a real scaffolded pack as
``declared_features=()``.

**Dual-path block resolution (R-reviewer P2 #2)**: per
``docs/PACK-MANIFEST-SPEC.md`` lines 17-21 + the R23 dual-path
doctrine, every validator + the runtime reader resolve a manifest
block from BOTH the canonical top-level path (``[mcp]`` / ``[a2a]`` /
``[identity]``) AND the legacy nested path
(``[tool.cognic.<block>]``). :func:`_resolve_blocks` mirrors that —
a docs-shaped submitted manifest declaring ``[tool.cognic.mcp]`` would
otherwise project empty declarations + no flags. When a block is
declared at both paths the fields are unioned then deduped by slug.

**Architectural-arrow invariant**: this module lives in
``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate composer
(T7) can read the same projector output without crossing layers. The
arrow runs ``portal → packs/evidence`` exclusively — projectors do NOT
import portal types.

**Defensive-shape doctrine (mirrors the T3-T5 panels)**: missing
block, non-dict block, non-list ``oasf_capability_set``, non-string
entries inside it, a malformed ``conformance`` payload, and a curated
field whose slug is absent from the shipped matrix ALL surface as the
safe-default value (empty tuple, ``None`` verdict, or an explicit
``*_unknown`` flag) rather than crashing the route or leaking a
malformed value onto the wire.

**OWASP verdict projection (plan §353)**: the panel surfaces the T9
chain-row ``payload["conformance"]`` (OWASP suite verdict) inline so
the reviewer sees BOTH the feature-declaration matrices AND the OWASP
verdict in one panel. The verdict is projected into the panel-local
:class:`OwaspVerdictData` frozen dataclass — NOT the
:class:`~cognic_agentos.packs.conformance.checks.ConformanceReport`
dataclass directly. This is a deliberate divergence from plan §350's
illustrative ``ConformanceReport | None`` signature: each 7B.3
projector owns its own output dataclass (T3-T5 precedent), and
``ConformanceReport``'s field ORDER is itself wire-protocol-public per
ADR-006 — reusing it directly would couple the panel wire-shape to the
chain-payload wire-shape. The verdict CONTENT (overall status,
per-category status + findings, summary, errored categories) is
faithfully mirrored; reconstruction is defensive (a malformed payload
yields ``owasp_verdict=None``, never a crash).
"""

from __future__ import annotations

import dataclasses
import json
import typing
from pathlib import Path
from typing import Any, Final, Literal

from cognic_agentos.packs.conformance.checks import (
    ConformanceCheckStatus,
    ConformanceOverallStatus,
    OWASPCheckCategory,
)
from cognic_agentos.packs.lifecycle import PackKind

__all__ = [
    "ConformanceMatrixPanelData",
    "MatrixComparison",
    "MatrixComparisonFlag",
    "MatrixDeclaration",
    "OwaspCheckResultData",
    "OwaspVerdictData",
    "project_conformance_matrix_panel",
]


MatrixComparisonFlag = Literal[
    "mcp_capability_restricted",
    "mcp_capability_unknown",
    "a2a_feature_forbidden",
    "a2a_wave2_feature_declared",
    "a2a_feature_unknown",
    "oasf_capability_wave2_declared",
]
"""Closed-enum 6-value vocabulary for the conformance-matrix evidence-
panel ``flagged_mismatches`` tuple + per-:class:`MatrixComparison`
``flag`` field per plan §352.

Each value names a class of mismatch between a pack's manifest-declared
protocol features and the AgentOS conformance posture:

- ``"mcp_capability_restricted"`` — the manifest declares an MCP
  capability the conformance matrix marks NOT plainly supported in
  Wave 1 (``⚠️`` restricted — e.g. ``sampling`` / ``roots`` /
  ``elicitation``; or, defensively, a ``❌`` posture the MCP table
  does not structurally carry today but the projector still surfaces
  conservatively). The reviewer must verify the tenant Rego policy
  (ADR-015) + the pack manifest jointly permit the capability before
  approving.
- ``"mcp_capability_unknown"`` — the manifest declares an MCP
  capability whose curated slug is ABSENT from the shipped conformance
  matrix. This is a JSON-vs-field-map drift signal (the
  :data:`_MCP_FIELD_TO_SLUG` bridge points at a slug the matrix no
  longer carries) — pinned at test time by the shipped-matrix drift
  detectors, but the projector still surfaces it defensively rather
  than crashing.
- ``"a2a_feature_forbidden"`` — the manifest declares an A2A feature
  the conformance matrix marks ``❌`` forbidden in Wave 1 (e.g.
  ``multi_modal_payloads`` / ``federated_a2a`` / ``anonymous_a2a``).
  A pack declaring a forbidden feature cannot pass the Wave-1 trust
  gate; the reviewer rejects.
- ``"a2a_wave2_feature_declared"`` — the manifest declares an A2A
  feature the matrix marks ``⚠️`` restricted in Wave 1 (e.g.
  ``push_notification_config`` / ``long_running_task_resumption``).
  These features are optional in Wave 1 and promoted in Wave 2; a
  Wave-1 manifest declaring them is forward-declaring. The reviewer
  notes it but it does not block.
- ``"a2a_feature_unknown"`` — symmetric for A2A: the curated slug is
  absent from the shipped matrix.
- ``"oasf_capability_wave2_declared"`` — the manifest's
  ``[identity].oasf_capability_set`` is non-empty. AGNTCY/OASF
  capability sets are a Wave-2 identity feature per the ADR-002
  amendment; a Wave-1 agent pack declaring them is forward-declaring.

**No ``"none"`` sentinel** (deliberate divergence from the T3
:data:`~cognic_agentos.packs.evidence.data_governance.DataGovernanceDiffFlag`
vocabulary): the data-governance panel needs a ``"none"`` sentinel to
distinguish "no tenant policy wired" (empty tuple) from "policy wired,
no drift" (``("none",)``). The conformance matrix is ALWAYS shipped, so
there is no such ambiguity here — an empty ``flagged_mismatches`` tuple
unambiguously means "comparison ran, no mismatches found". Adding a
``"none"`` sentinel with no disambiguation purpose would be the kind of
speculative vocabulary the codebase's no-speculative-sentinel doctrine
forbids.

Wave-1 narrow: drift between this Literal and plan §352 is wire-
protocol-public regression — pinned by
``test_conformance_matrix_panel.py::
TestSprint7B3T6SliceAMatrixComparisonFlagVocab``.
"""


#: Static-shipped conformance matrix JSON path — sits alongside this
#: module; generated by ``tools/generate_conformance_matrix_json.py``.
_CONFORMANCE_MATRIX_PATH: Final[Path] = Path(__file__).with_name("conformance_matrix.json")


def _load_conformance_matrix(
    path: Path = _CONFORMANCE_MATRIX_PATH,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Load the static-shipped conformance matrix JSON at module import.

    R10 LOCKED — runtime NEVER parses the source Markdown; it reads the
    build-time-generated JSON projection. Fail-loud: a missing or
    malformed JSON file raises at import (a deployment-time error the
    operator must fix), NOT a silent empty-matrix fallback that would
    let every conformance comparison vacuously pass.

    ``path`` defaults to the shipped JSON sibling; it is parameterised
    only so the drift-detector test can point the loader at a
    deliberately-malformed fixture and assert the fail-loud guard fires
    (the module-import call site below always uses the default).
    """
    raw = path.read_text(encoding="utf-8")
    matrix: dict[str, dict[str, dict[str, Any]]] = json.loads(raw)
    if set(matrix.keys()) != {"mcp", "a2a"}:
        raise ValueError(
            f"conformance_matrix.json must carry exactly {{'mcp', 'a2a'}} top-level "
            f"keys, found {sorted(matrix.keys())} — regenerate via "
            "tools/generate_conformance_matrix_json.py"
        )
    return matrix


#: Module-import-time singleton — the conformance matrix every panel
#: projection reads. :func:`project_conformance_matrix_panel` accepts an
#: optional ``matrix`` kwarg defaulting to this so tests can inject a
#: synthetic matrix (e.g. to exercise the ``*_unknown`` drift paths)
#: without shipping a deliberately-broken JSON.
_CONFORMANCE_MATRIX: Final[dict[str, dict[str, dict[str, Any]]]] = _load_conformance_matrix()


#: Curated bridge: manifest ``[mcp]`` block field name → conformance-
#: matrix capability slug. A field is "declared" when its value is
#: truthy per :func:`_field_is_declared` (bool ``True`` / non-empty
#: list / non-empty non-``"none"`` string). Pinned against the shipped
#: matrix by ``TestSprint7B3T6SliceHShippedMatrix``.
#:
#: **Two field families per capability** (R-reviewer P2 #1, verified
#: against ``docs/PACK-MANIFEST-SPEC.md`` §4): the canonical scaffold
#: shape (``agentos init-tool`` + the spec's "required" rows) uses the
#: boolean fields ``caching`` / ``elicitation_form``; the runtime/docs
#: alternative shape uses ``caching_strategy`` (string) /
#: ``elicitation_modes`` (list). Both map to the SAME conformance-
#: matrix slug — :func:`_project_protocol` dedupes by slug so a pack
#: declaring both shapes of one capability still produces exactly one
#: :class:`MatrixComparison`. Mirrors the
#: ``cli/validators/mcp.py::_detect_caching_field`` /
#: ``_detect_form_elicitation_field`` dual-family doctrine (R26 P2 #1).
_MCP_FIELD_TO_SLUG: Final[dict[str, str]] = {
    "resources_supported": "resources",
    "prompts_supported": "prompts",
    "sampling_supported": "sampling",
    # elicitation — canonical scaffold bool first, runtime/docs list second.
    "elicitation_form": "elicitation",
    "elicitation_modes": "elicitation",
    # caching — canonical scaffold bool first, runtime/docs string second.
    "caching": "caching",
    "caching_strategy": "caching",
}

#: Curated bridge: manifest ``[a2a]`` block field name → conformance-
#: matrix feature slug. ``capabilities_supported`` is intentionally
#: ABSENT — its entries are pack-specific skill capability names (e.g.
#: ``regulatory_qa``), NOT A2A protocol features, so they do not
#: compare against the feature matrix. Unlike ``[mcp]``, the
#: ``docs/PACK-MANIFEST-SPEC.md`` §3 ``[a2a]`` fields have a SINGLE
#: canonical shape (all booleans) — no two-family bridge needed here.
_A2A_FIELD_TO_SLUG: Final[dict[str, str]] = {
    "streaming": "streaming_messages",
    "push_notification_config": "push_notification_config",
    "artifacts_supported": "artifacts",
}

#: Dual-path block locations (R-reviewer P2 #2, verified against
#: ``docs/PACK-MANIFEST-SPEC.md`` lines 17-21 + the R23 dual-path
#: doctrine): every validator + the runtime reader resolve a manifest
#: block from BOTH the canonical top-level path AND the legacy
#: ``[tool.cognic.<block>]`` nested path. The conformance panel mirrors
#: that — a docs-shaped submitted manifest declaring ``[tool.cognic.mcp]``
#: would otherwise project empty declarations + no flags. Each tuple is
#: ``(label, accessor-path)``; :func:`_resolve_blocks` walks every
#: accessor and returns the UNION of present block dicts (canonical
#: first), so a pack declaring a block at both paths has its fields
#: unioned then deduped-by-slug.
_MCP_BLOCK_LOCATIONS: Final[tuple[tuple[str, ...], ...]] = (("mcp",), ("tool", "cognic", "mcp"))
_A2A_BLOCK_LOCATIONS: Final[tuple[tuple[str, ...], ...]] = (("a2a",), ("tool", "cognic", "a2a"))
_IDENTITY_BLOCK_LOCATIONS: Final[tuple[tuple[str, ...], ...]] = (
    ("identity",),
    ("tool", "cognic", "identity"),
)

#: R9 kind-applicability sets — which pack kinds each protocol matrix
#: applies to per plan §351.
_MCP_APPLICABLE_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent"})
_A2A_APPLICABLE_KINDS: Final[frozenset[str]] = frozenset({"agent"})
_OASF_APPLICABLE_KINDS: Final[frozenset[str]] = frozenset({"agent"})

#: Known OWASP categories — used to filter a (potentially untrusted)
#: persisted ``payload["conformance"]`` payload during defensive
#: verdict reconstruction.
_KNOWN_OWASP_CATEGORIES: Final[frozenset[str]] = frozenset(typing.get_args(OWASPCheckCategory))
_KNOWN_OWASP_STATUSES: Final[frozenset[str]] = frozenset(typing.get_args(ConformanceCheckStatus))
_KNOWN_OWASP_OVERALL: Final[frozenset[str]] = frozenset(typing.get_args(ConformanceOverallStatus))


@dataclasses.dataclass(frozen=True)
class MatrixDeclaration:
    """Per-protocol summary of what the manifest declared + whether the
    protocol matrix applies to this pack kind (R9).

    Fields:

    - ``applicable``: ``True`` when the protocol matrix applies to the
      pack's kind per the R9 applicability rule (plan §351). When
      ``False`` the panel produces no :class:`MatrixComparison` entries
      for this protocol.
    - ``applicability_reason``: human-readable reason for the
      ``applicable`` value (``"applicable"`` on the green path; an
      explanatory string when not applicable).
    - ``declared_features``: tuple of conformance-matrix slugs (MCP /
      A2A) or capability strings (OASF) the manifest declared for this
      protocol. Empty tuple when the protocol is not applicable OR the
      manifest declared nothing.
    """

    applicable: bool
    applicability_reason: str
    declared_features: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class MatrixComparison:
    """One declared-feature → conformance-matrix comparison row.

    Fields:

    - ``protocol``: ``"mcp"`` / ``"a2a"`` / ``"oasf"``.
    - ``feature``: the conformance-matrix slug (MCP / A2A) or the OASF
      capability string the manifest declared.
    - ``matrix_wave_1``: the matrix's Wave-1 posture for ``feature``
      (``"supported"`` / ``"restricted"`` / ``"forbidden"``); ``None``
      when the slug is absent from the matrix (``*_unknown`` flag) or
      the protocol is OASF (no matrix — OASF capabilities are compared
      against the Wave-1/Wave-2 identity-feature posture, not a table).
    - ``matrix_wave_2_promoted``: ``True`` when the matrix commits to
      promoting the feature in Wave 2. ``False`` for unknown slugs +
      OASF.
    - ``flag``: the :data:`MatrixComparisonFlag` mismatch for this row,
      or ``None`` when the declaration is clean (Wave-1 ``supported``).
    """

    protocol: str
    feature: str
    matrix_wave_1: str | None
    matrix_wave_2_promoted: bool
    flag: MatrixComparisonFlag | None


@dataclasses.dataclass(frozen=True)
class OwaspCheckResultData:
    """Panel-local mirror of one OWASP per-category check result.

    Mirrors :class:`~cognic_agentos.packs.conformance.checks.ConformanceCheckResult`
    with ``str``-typed defensive fields — the persisted
    ``payload["conformance"]`` is reconstructed defensively (an unknown
    category / status is filtered out, never surfaced).
    """

    category: str
    status: str
    findings: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class OwaspVerdictData:
    """Panel-local projection of the T9 chain-row ``payload["conformance"]``
    OWASP suite verdict per plan §353.

    Deliberately NOT the
    :class:`~cognic_agentos.packs.conformance.checks.ConformanceReport`
    dataclass — see the module docstring's "OWASP verdict projection"
    note. ``results`` is a TUPLE (each entry carries its own
    ``category``) rather than a dict so the dataclass is hashable +
    frozen-friendly + deterministically ordered.

    Fields:

    - ``overall_status``: ``"green"`` / ``"red"`` / ``"yellow"`` —
      the composite verdict (yellow = incomplete suite, per 7B.2 T8).
    - ``results``: per-category :class:`OwaspCheckResultData` tuple,
      preserving the persisted payload's iteration order.
    - ``summary``: the runner's human-readable count phrase.
    - ``errored_categories``: categories whose checker raised during
      the suite run (drives the ``yellow`` overall status).
    """

    overall_status: str
    results: tuple[OwaspCheckResultData, ...]
    summary: str
    errored_categories: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ConformanceMatrixPanelData:
    """Pure-functional projector output per plan §350.

    Mirrors the wire-shape of the :class:`ConformanceMatrixPanel`
    Pydantic DTO at ``portal/api/packs/dto.py``; the DTO's
    ``from_attributes=True`` config lets the route handler call
    ``ConformanceMatrixPanel.model_validate(panel_data)`` directly.

    Architectural-arrow invariant: this dataclass lives in
    ``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate
    composer (T7) can read the same projector output without crossing
    layers.

    Fields:

    - ``pack_kind``: authoritative :class:`PackRecord.kind` echoed
      verbatim by the projector; the route handler is the authority,
      not the manifest.
    - ``declarations``: dict keyed ``"mcp"`` / ``"a2a"`` / ``"oasf"``
      → :class:`MatrixDeclaration`. ALL THREE keys are always present
      (R9 applicability is carried IN the value, not by key absence).
    - ``comparisons``: tuple of :class:`MatrixComparison` rows — one
      per declared feature across all APPLICABLE protocols. Ordered
      MCP → A2A → OASF, each protocol's features in manifest-
      declaration order.
    - ``flagged_mismatches``: deduplicated, alphabetically-sorted tuple
      of distinct non-``None`` :data:`MatrixComparisonFlag` values
      drawn from ``comparisons`` — the reviewer's at-a-glance scan
      list. Empty tuple = comparison ran, no mismatches.
    - ``owasp_verdict``: the projected T9 OWASP suite verdict, or
      ``None`` when the submit row carried no ``payload["conformance"]``
      (pre-7B.2-T9 chain rows) or the payload was malformed.
    """

    pack_kind: PackKind
    declarations: dict[str, MatrixDeclaration]
    comparisons: tuple[MatrixComparison, ...]
    flagged_mismatches: tuple[MatrixComparisonFlag, ...]
    owasp_verdict: OwaspVerdictData | None


def _resolve_path(manifest: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``manifest``; return the leaf dict or
    ``None`` on any absent / non-dict intermediate.

    Mirrors ``cli/validators/mcp.py::_resolve_path`` — the dual-path
    block resolver every validator + the runtime reader use (R23
    doctrine).
    """
    cursor: Any = manifest
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _resolve_blocks(
    manifest: dict[str, Any], locations: tuple[tuple[str, ...], ...]
) -> list[dict[str, Any]]:
    """Resolve a manifest block across its dual-path locations
    (canonical top-level + legacy ``[tool.cognic.<block>]``) per
    R-reviewer P2 #2 + the R23 dual-path doctrine.

    Returns every PRESENT dict block in location order (canonical
    first); absent / non-dict paths are skipped. Empty list when the
    block is declared nowhere. A pack that declares the block at BOTH
    paths has both dicts returned — the projector then unions their
    declared fields and dedupes by slug.
    """
    return [block for path in locations if (block := _resolve_path(manifest, path)) is not None]


def _field_is_declared(value: Any) -> bool:
    """A manifest protocol-block field counts as "declared" when:

    - it is the bool ``True`` (``False`` / non-bool falsy → not declared);
    - it is a non-empty list;
    - it is a non-empty string that is not the literal ``"none"``
      (covers ``caching_strategy = "none"`` — an explicit opt-out).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, str):
        return value != "" and value != "none"
    return False


def _compare_mcp_feature(
    slug: str, matrix: dict[str, dict[str, Any]]
) -> tuple[str | None, bool, MatrixComparisonFlag | None]:
    """Compare one declared MCP capability slug against the matrix.

    Returns ``(matrix_wave_1, matrix_wave_2_promoted, flag)``.
    """
    entry = matrix.get(slug)
    if entry is None:
        return None, False, "mcp_capability_unknown"
    wave_1 = entry["wave_1"]
    promoted = bool(entry["wave_2_promoted"])
    # The MCP "Capability conformance" table only ever marks Wave-1
    # cells ✅ (supported) or ⚠️ (restricted) — there is no structural
    # ❌ MCP capability today. The branch below still handles a
    # forbidden posture conservatively (collapses into the "restricted"
    # flag — "the matrix does not plainly support this; reviewer must
    # scrutinise") rather than reserving a speculative
    # mcp_capability_forbidden enum value with no fire-path.
    if wave_1 != "supported":
        return wave_1, promoted, "mcp_capability_restricted"
    return wave_1, promoted, None


def _compare_a2a_feature(
    slug: str, matrix: dict[str, dict[str, Any]]
) -> tuple[str | None, bool, MatrixComparisonFlag | None]:
    """Compare one declared A2A feature slug against the matrix.

    Returns ``(matrix_wave_1, matrix_wave_2_promoted, flag)``.
    """
    entry = matrix.get(slug)
    if entry is None:
        return None, False, "a2a_feature_unknown"
    wave_1 = entry["wave_1"]
    promoted = bool(entry["wave_2_promoted"])
    if wave_1 == "forbidden":
        return wave_1, promoted, "a2a_feature_forbidden"
    if wave_1 == "restricted":
        return wave_1, promoted, "a2a_wave2_feature_declared"
    return wave_1, promoted, None


def _project_protocol(
    *,
    protocol: str,
    blocks: list[dict[str, Any]],
    field_map: dict[str, str],
    applicable: bool,
    applicability_reason: str,
    matrix: dict[str, dict[str, Any]],
    comparator: typing.Callable[
        [str, dict[str, dict[str, Any]]],
        tuple[str | None, bool, MatrixComparisonFlag | None],
    ],
) -> tuple[MatrixDeclaration, list[MatrixComparison]]:
    """Project one MCP/A2A protocol block into its declaration + the
    comparison rows for every declared feature.

    ``blocks`` is the dual-path-resolved list of present block dicts
    (canonical ``[mcp]`` / ``[a2a]`` first, legacy
    ``[tool.cognic.<block>]`` second) per :func:`_resolve_blocks`. The
    projection unions across every block x the curated ``field_map``
    and **dedupes by conformance-matrix slug** — a capability declared
    via more than one field family (e.g. both ``caching`` and
    ``caching_strategy``; R-reviewer P2 #1) OR at more than one block
    path (e.g. both ``[mcp]`` and ``[tool.cognic.mcp]``; R-reviewer
    P2 #2) yields exactly ONE :class:`MatrixComparison`. First
    occurrence in ``blocks``-order x ``field_map``-order wins;
    iteration order is fully deterministic.

    Returns an empty declared-features tuple + no comparisons when
    ``applicable`` is ``False`` OR ``blocks`` is empty — the
    defensive-shape doctrine.
    """
    if not applicable:
        return (
            MatrixDeclaration(
                applicable=False,
                applicability_reason=applicability_reason,
                declared_features=(),
            ),
            [],
        )
    declared_slugs: list[str] = []
    seen_slugs: set[str] = set()
    comparisons: list[MatrixComparison] = []
    # blocks-order (canonical first) x curated-field-map-order — both
    # deterministic; only curated protocol features compare; dedup by
    # slug folds the two field families + the two block paths together.
    for block in blocks:
        for field_name, slug in field_map.items():
            if slug in seen_slugs:
                continue
            if not _field_is_declared(block.get(field_name)):
                continue
            seen_slugs.add(slug)
            declared_slugs.append(slug)
            wave_1, promoted, flag = comparator(slug, matrix)
            comparisons.append(
                MatrixComparison(
                    protocol=protocol,
                    feature=slug,
                    matrix_wave_1=wave_1,
                    matrix_wave_2_promoted=promoted,
                    flag=flag,
                )
            )
    return (
        MatrixDeclaration(
            applicable=True,
            applicability_reason="applicable",
            declared_features=tuple(declared_slugs),
        ),
        comparisons,
    )


def _project_oasf(
    *, identity_blocks: list[dict[str, Any]], applicable: bool, applicability_reason: str
) -> tuple[MatrixDeclaration, list[MatrixComparison]]:
    """Project the ``[identity].oasf_capability_set`` declaration.

    OASF capabilities have no conformance TABLE — every declared
    capability is a Wave-2 identity feature per the ADR-002 amendment,
    so each surfaces as an ``oasf_capability_wave2_declared`` flag.

    ``identity_blocks`` is the dual-path-resolved list (canonical
    ``[identity]`` first, legacy ``[tool.cognic.identity]`` second) per
    R-reviewer P2 #2. The ``oasf_capability_set`` lists are UNIONED
    across both blocks with non-string entries filtered + duplicate
    capability strings deduped (first occurrence wins; order
    preserved).
    """
    if not applicable:
        return (
            MatrixDeclaration(
                applicable=False,
                applicability_reason=applicability_reason,
                declared_features=(),
            ),
            [],
        )
    capabilities: list[str] = []
    seen: set[str] = set()
    for block in identity_blocks:
        raw = block.get("oasf_capability_set")
        if not isinstance(raw, list):
            continue
        for entry in raw:
            if isinstance(entry, str) and entry not in seen:
                seen.add(entry)
                capabilities.append(entry)
    comparisons = [
        MatrixComparison(
            protocol="oasf",
            feature=capability,
            matrix_wave_1=None,
            matrix_wave_2_promoted=False,
            flag="oasf_capability_wave2_declared",
        )
        for capability in capabilities
    ]
    return (
        MatrixDeclaration(
            applicable=True,
            applicability_reason="applicable",
            declared_features=tuple(capabilities),
        ),
        comparisons,
    )


def _project_owasp_verdict(conformance_payload: Any) -> OwaspVerdictData | None:
    """Defensively reconstruct the OWASP suite verdict from the
    persisted ``payload["conformance"]`` dict per plan §353.

    Returns ``None`` for a missing / non-dict / malformed payload — the
    panel surfaces "no verdict attached" rather than crashing or
    leaking a half-formed value. An unknown category or status inside
    ``results`` is filtered out (not surfaced).
    """
    if not isinstance(conformance_payload, dict):
        return None
    overall = conformance_payload.get("overall_status")
    if overall not in _KNOWN_OWASP_OVERALL:
        return None

    raw_results = conformance_payload.get("results")
    results: list[OwaspCheckResultData] = []
    if isinstance(raw_results, dict):
        for category, raw in raw_results.items():
            if category not in _KNOWN_OWASP_CATEGORIES or not isinstance(raw, dict):
                continue
            status = raw.get("status")
            if status not in _KNOWN_OWASP_STATUSES:
                continue
            raw_findings = raw.get("findings")
            findings = (
                tuple(f for f in raw_findings if isinstance(f, str))
                if isinstance(raw_findings, list)
                else ()
            )
            results.append(
                OwaspCheckResultData(category=category, status=status, findings=findings)
            )

    raw_summary = conformance_payload.get("summary")
    summary = raw_summary if isinstance(raw_summary, str) else ""

    raw_errored = conformance_payload.get("errored_categories")
    errored = (
        tuple(c for c in raw_errored if isinstance(c, str) and c in _KNOWN_OWASP_CATEGORIES)
        if isinstance(raw_errored, list)
        else ()
    )

    return OwaspVerdictData(
        overall_status=overall,
        results=tuple(results),
        summary=summary,
        errored_categories=errored,
    )


def project_conformance_matrix_panel(
    *,
    manifest: dict[str, Any],
    record_kind: PackKind,
    conformance_payload: dict[str, Any] | None,
    matrix: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> ConformanceMatrixPanelData:
    """Project a pack manifest's protocol declarations + the persisted
    OWASP verdict onto the reviewer-facing conformance-matrix evidence
    panel per plan §349-353.

    Pure-functional: no I/O at call time (the static conformance matrix
    is loaded ONCE at module import into :data:`_CONFORMANCE_MATRIX`).
    The route handler in
    :mod:`cognic_agentos.portal.api.packs.evidence_routes` fetches the
    persisted manifest via ``store.load_lifecycle_history`` +
    :func:`find_latest_submit_row` + ``payload["manifest"]`` AND the
    submit row's ``payload["conformance"]`` (the OWASP verdict written
    by 7B.2 T9), then passes both to this projector.

    ``record_kind`` is the authoritative :attr:`PackRecord.kind` value
    — the handler cross-checks it against ``manifest["pack"]["kind"]``
    BEFORE invoking this projector (the cross-check is route-layer
    concern, not projector-layer). The projector ALSO derives R9
    matrix applicability from ``record_kind``, NOT the manifest's kind.

    ``conformance_payload`` is the persisted ``payload["conformance"]``
    dict (or ``None`` for pre-7B.2-T9 chain rows). Reconstructed
    defensively into :class:`OwaspVerdictData` — a malformed payload
    yields ``owasp_verdict=None``.

    ``matrix`` is an optional injection point defaulting to the module-
    loaded :data:`_CONFORMANCE_MATRIX`. Production callers (the route
    handler) omit it; tests inject a synthetic matrix to exercise the
    ``*_unknown`` drift paths without shipping a deliberately-broken
    JSON.

    Returns: :class:`ConformanceMatrixPanelData` — a frozen dataclass
    that the DTO at ``portal/api/packs/dto.py`` consumes via
    ``from_attributes=True``.
    """
    active_matrix = matrix if matrix is not None else _CONFORMANCE_MATRIX

    mcp_applicable = record_kind in _MCP_APPLICABLE_KINDS
    a2a_applicable = record_kind in _A2A_APPLICABLE_KINDS
    oasf_applicable = record_kind in _OASF_APPLICABLE_KINDS

    mcp_declaration, mcp_comparisons = _project_protocol(
        protocol="mcp",
        blocks=_resolve_blocks(manifest, _MCP_BLOCK_LOCATIONS),
        field_map=_MCP_FIELD_TO_SLUG,
        applicable=mcp_applicable,
        applicability_reason=(
            "applicable" if mcp_applicable else f"MCP matrix does not apply to {record_kind} packs"
        ),
        matrix=active_matrix["mcp"],
        comparator=_compare_mcp_feature,
    )
    a2a_declaration, a2a_comparisons = _project_protocol(
        protocol="a2a",
        blocks=_resolve_blocks(manifest, _A2A_BLOCK_LOCATIONS),
        field_map=_A2A_FIELD_TO_SLUG,
        applicable=a2a_applicable,
        applicability_reason=(
            "applicable"
            if a2a_applicable
            else f"A2A matrix applies to agent packs only, not {record_kind} packs"
        ),
        matrix=active_matrix["a2a"],
        comparator=_compare_a2a_feature,
    )
    oasf_declaration, oasf_comparisons = _project_oasf(
        identity_blocks=_resolve_blocks(manifest, _IDENTITY_BLOCK_LOCATIONS),
        applicable=oasf_applicable,
        applicability_reason=(
            "applicable"
            if oasf_applicable
            else f"AGNTCY/OASF identity applies to agent packs only, not {record_kind} packs"
        ),
    )

    comparisons = tuple(mcp_comparisons + a2a_comparisons + oasf_comparisons)
    flagged = tuple(
        sorted({comparison.flag for comparison in comparisons if comparison.flag is not None})
    )

    return ConformanceMatrixPanelData(
        pack_kind=record_kind,
        declarations={
            "mcp": mcp_declaration,
            "a2a": a2a_declaration,
            "oasf": oasf_declaration,
        },
        comparisons=comparisons,
        flagged_mismatches=flagged,
        owasp_verdict=_project_owasp_verdict(conformance_payload),
    )

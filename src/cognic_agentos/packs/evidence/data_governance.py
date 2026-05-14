"""Sprint 7B.3 T3 — ADR-017 data-governance evidence panel (CRITICAL CONTROLS).

Per AGENTS.md stop-rule L54 + L156, this module is on the durable
critical-controls coverage gate (95% line / 90% branch floor). The
panel projects a pack's persisted manifest into the reviewer-facing
data-governance evidence surface AND optionally flags drift between
the pack's declared contract and the tenant policy.

Slice A scope (T3 — this commit):

- :data:`DataGovernanceDiffFlag` closed-enum Literal (7 values per
  plan §303). Wire-protocol-public on the panel response
  ``tenant_policy_diff`` field; drift between this Literal and the
  :class:`DataGovernancePanel` DTO at ``portal/api/packs/dto.py`` is
  pinned by ``tests/unit/packs/evidence/test_data_governance_panel.py``.

Slice B (later commit in this same T3 task) lands the pure-functional
:func:`project_data_governance_panel` projector. Slices C-F land the
DTO + route + integration.

Architectural-arrow invariant: this module lives in ``packs/`` (not
``portal/``) so the 5-gate composer (T7) can consume the same
projector without crossing layers. The dto + route consume the
vocabulary from here (one source of truth).

Tenant-policy-diff doctrine (per plan §304): when the tenant-policy
store is not yet wired (production-grade scaffold — the
``TenantDataGovernancePolicy`` substrate ships in a follow-up sprint),
the projector returns an empty diff tuple. The empty-tuple-on-no-policy
contract is wire-protocol-public so a reviewer reading the panel
cannot mistake "no policy configured" for "no violations found";
deployments that don't have a tenant policy substrate yet see a panel
with manifest fields populated + ``tenant_policy_diff = ()``.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Final, Literal, TypedDict

from cognic_agentos.packs.lifecycle import PackKind

__all__ = [
    "DataGovernanceDiffFlag",
    "DataGovernancePanelData",
    "TenantDataGovernancePolicy",
    "project_data_governance_panel",
]


#: Vocab-consolidation marker per the guard test at
#: ``tests/unit/cli/validators/test_data_governance_vocab_consolidation.py::
#: test_runtime_dlp_module_not_yet_present``.
#:
#: This module is the Wave-1 **panel projector** at the same path AGENTS.md
#: L54 reserves for "Pack data-governance contracts + runtime DLP
#: enforcement". The projector surfaces ADR-017 data-governance fields as
#: raw strings — it does NOT enforce DLP at runtime (the runtime DLP
#: enforcement substrate ships in a follow-up sprint). Because the
#: projector consumes ``data_classes`` / ``purpose`` / ``retention_policy``
#: as strings (no Literal typing required at the projection layer), there
#: is no live vocabulary import yet.
#:
#: When the runtime DLP enforcement substrate lands at this path (or as a
#: sibling module under ``packs/evidence/``), the developer landing it
#: MUST either:
#:
#: 1. Import vocabulary FROM :mod:`cognic_agentos.cli._governance_vocab`
#:    directly, OR
#: 2. Migrate both consumers (cli validators + runtime enforcer) to a
#:    shared module IN THE SAME COMMIT that lights up runtime DLP.
#:
#: This marker documents that the consolidation question is explicitly
#: deferred to that future commit; the panel projector at this path does
#: NOT introduce parallel vocabulary that would diverge from the
#: build-time validators at
#: :mod:`cognic_agentos.cli.validators.data_governance`.
_GOVERNANCE_VOCAB_SOURCE: Final[str] = "cognic_agentos.cli._governance_vocab"


DataGovernanceDiffFlag = Literal[
    "data_class_not_in_tenant_allowlist",
    "purpose_not_declared",
    "retention_exceeds_tenant_max",
    "egress_endpoint_not_in_tenant_allowlist",
    "dlp_pre_hook_missing",
    "dlp_post_hook_missing",
    "none",
]
"""Closed-enum 7-value vocabulary for the data-governance evidence-panel
``tenant_policy_diff`` tuple per plan §303.

Each value names a specific class of drift between a pack's manifest
:class:`data_governance` block (per ADR-017) and the deploying
tenant's policy:

- ``"data_class_not_in_tenant_allowlist"`` — pack declares a
  :class:`~cognic_agentos.cli._governance_vocab.DataClass` not in the
  tenant's allow-listed set (e.g. pack declares ``customer_pii`` but
  the tenant only permits ``public`` + ``internal``).
- ``"purpose_not_declared"`` — pack's ``purpose`` value is not in the
  tenant's allow-listed purposes for the declared data classes.
- ``"retention_exceeds_tenant_max"`` — pack's ``retention_max_window``
  exceeds the tenant's regulator-floor maximum for the declared data
  classes.
- ``"egress_endpoint_not_in_tenant_allowlist"`` — pack's
  ``egress_allow_list`` includes an endpoint outside the tenant's
  policy.
- ``"dlp_pre_hook_missing"`` — pack declares a ``dlp_pre_hooks`` entry
  that does not resolve to an installed hook pack at scan time (the
  panel surface flags it; the runtime DLP gate refuses at invocation
  time).
- ``"dlp_post_hook_missing"`` — same as above for ``dlp_post_hooks``.
- ``"none"`` — sentinel for "no drift detected"; emitted ONLY when
  the projector ran against a tenant policy AND found no violations.
  Distinguished from the empty-tuple-on-no-policy contract per plan
  §304: ``()`` means "no tenant policy wired", ``("none",)`` means
  "policy wired + no drift".

Wave-1 narrow: drift between this Literal and ADR-017 + plan §303 is
wire-protocol-public regression — pinned by
``test_data_governance_panel.py::
TestSprint7B3T3SliceADataGovernanceDiffFlagVocab``.
"""


class TenantDataGovernancePolicy(TypedDict, total=False):
    """Wave-1 in-memory tenant data-governance policy shape per ADR-017.

    The persistence substrate ships in a follow-up sprint (per plan
    §304). Wave-1: routes pass ``tenant_policy=None`` and the projector
    returns an empty diff tuple; 7B.3 unit tests construct synthetic
    dicts to exercise each diff flag value.

    All fields are optional — a partial policy is valid; the projector
    only computes diff flags for fields the caller supplied. Adding new
    policy fields in a follow-up sprint is an additive backward-compat
    extension.

    Fields:

    - ``allowed_data_classes``: pack's :attr:`data_classes` must be a
      subset of this set; any extra trips
      ``data_class_not_in_tenant_allowlist``.
    - ``allowed_purposes``: pack's :attr:`purpose` must be a member;
      otherwise trips ``purpose_not_declared``.
    - ``max_retention_window``: positive number; pack's
      :attr:`retention_max_window` must be ``<=`` this value; otherwise
      trips ``retention_exceeds_tenant_max``.
    - ``allowed_egress_endpoints``: pack's :attr:`egress_allow_list`
      must be a subset; any extra trips
      ``egress_endpoint_not_in_tenant_allowlist``.
    - ``required_dlp_pre_hooks``: every hook ID in this set MUST be
      present in pack's :attr:`dlp_pre_hooks`; any missing trips
      ``dlp_pre_hook_missing``.
    - ``required_dlp_post_hooks``: symmetric for the post-phase.
    """

    allowed_data_classes: frozenset[str]
    allowed_purposes: frozenset[str]
    max_retention_window: float
    allowed_egress_endpoints: frozenset[str]
    required_dlp_pre_hooks: frozenset[str]
    required_dlp_post_hooks: frozenset[str]


@dataclasses.dataclass(frozen=True)
class DataGovernancePanelData:
    """Pure-functional projector output per plan §302.

    Mirrors the wire-shape of the :class:`DataGovernancePanel` Pydantic
    DTO at ``portal/api/packs/dto.py``; the DTO's ``from_attributes=True``
    config lets the route handler call
    ``DataGovernancePanel.model_validate(panel_data)`` directly without
    an intermediate ``dataclasses.asdict`` step.

    Architectural-arrow invariant: this dataclass lives in
    ``packs/evidence/`` (NOT ``portal/api/packs/``) so the 5-gate
    composer (T7) can read the same projector output without crossing
    layers. The arrow runs ``portal → packs/evidence`` exclusively.

    Field types mirror the DTO (modulo ``frozen=True`` semantics).
    Tuple types are used for the multi-valued fields so the dataclass
    is hashable + immutable; lists in the manifest are coerced at
    projector time.
    """

    pack_kind: PackKind
    data_classes: tuple[str, ...]
    purpose: str
    purpose_description: str
    retention_policy: str
    retention_max_window: str
    egress_allow_list: tuple[str, ...]
    dlp_pre_hooks: tuple[str, ...]
    dlp_post_hooks: tuple[str, ...]
    tenant_policy_diff: tuple[DataGovernanceDiffFlag, ...]


def _coerce_str_tuple(value: Any) -> tuple[str, ...]:
    """Coerce a manifest list-of-string field to a tuple of strings.

    Defensive: a corrupted persisted manifest with a non-list value
    (or a list containing non-string entries) surfaces as an empty
    tuple rather than crashing the route handler. Pinned by the
    ``test_malformed_data_governance_block_defaults_empty`` regression.
    """
    if not isinstance(value, list):
        return ()
    return tuple(entry for entry in value if isinstance(entry, str))


def _is_positive_number(value: Any) -> bool:
    """Mirror of :func:`cli.validators.data_governance._is_positive_number`.

    Bool is rejected (Python's ``bool`` is an ``int`` subclass; without
    this guard ``True`` would pass as 1.0). Used by the diff helper to
    decide whether the manifest's ``retention_max_window`` is comparable
    against the tenant policy's :attr:`max_retention_window`.
    """
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return value > 0


def _compute_tenant_policy_diff(
    *,
    data_classes: tuple[str, ...],
    purpose: str,
    retention_max_window_raw: Any,
    egress_allow_list: tuple[str, ...],
    dlp_pre_hooks: tuple[str, ...],
    dlp_post_hooks: tuple[str, ...],
    tenant_policy: TenantDataGovernancePolicy | None,
) -> tuple[DataGovernanceDiffFlag, ...]:
    """Compute the tenant-policy diff tuple per plan §303 + §304.

    Returns ``()`` (empty tuple) when ``tenant_policy is None`` per
    plan §304's empty-tuple-on-no-policy contract. Returns
    ``("none",)`` when policy is wired AND no violations are detected
    (the "policy wired + clean" sentinel). Otherwise returns a tuple of
    one or more :data:`DataGovernanceDiffFlag` violations (the
    ``"none"`` sentinel is NEVER mixed with violation flags).
    """
    if tenant_policy is None:
        return ()

    flags: list[DataGovernanceDiffFlag] = []

    allowed_dcs = tenant_policy.get("allowed_data_classes")
    if allowed_dcs is not None and any(dc not in allowed_dcs for dc in data_classes):
        flags.append("data_class_not_in_tenant_allowlist")

    allowed_purposes = tenant_policy.get("allowed_purposes")
    if allowed_purposes is not None and purpose != "" and purpose not in allowed_purposes:
        flags.append("purpose_not_declared")

    max_retention = tenant_policy.get("max_retention_window")
    if (
        max_retention is not None
        and _is_positive_number(retention_max_window_raw)
        and float(retention_max_window_raw) > max_retention
    ):
        flags.append("retention_exceeds_tenant_max")

    allowed_egress = tenant_policy.get("allowed_egress_endpoints")
    if allowed_egress is not None and any(
        endpoint not in allowed_egress for endpoint in egress_allow_list
    ):
        flags.append("egress_endpoint_not_in_tenant_allowlist")

    required_pre = tenant_policy.get("required_dlp_pre_hooks")
    if required_pre is not None and any(required not in dlp_pre_hooks for required in required_pre):
        flags.append("dlp_pre_hook_missing")

    required_post = tenant_policy.get("required_dlp_post_hooks")
    if required_post is not None and any(
        required not in dlp_post_hooks for required in required_post
    ):
        flags.append("dlp_post_hook_missing")

    return tuple(flags) if flags else ("none",)


def project_data_governance_panel(
    *,
    manifest: dict[str, Any],
    record_kind: PackKind,
    tenant_policy: TenantDataGovernancePolicy | None = None,
) -> DataGovernancePanelData:
    """Project a pack manifest's ``data_governance`` block onto the
    reviewer-facing evidence panel per plan §302.

    Pure-functional: no I/O, no DB access, no global state. The route
    handler in :mod:`cognic_agentos.portal.api.packs.evidence_routes`
    fetches the persisted manifest via ``store.load_lifecycle_history``
    + :func:`find_latest_submit_row` + ``payload["manifest"]`` and
    passes the dict in. ``record_kind`` is the authoritative
    :attr:`PackRecord.kind` value — the handler cross-checks it against
    ``manifest["pack"]["kind"]`` BEFORE invoking this projector (the
    cross-check is route-layer concern, not projector-layer).

    Defensive shape handling: missing ``data_governance`` block,
    non-dict block, and missing optional fields all surface as empty
    values rather than raising. This isolates the panel from
    partially-corrupted persisted manifests + lets the reviewer see
    whatever the persisted state contains (the corruption itself is a
    separate observability concern surfaced by the storage / chain
    integrity gates).

    ``tenant_policy=None`` (the Wave-1 caller path) → empty diff tuple
    per plan §304. When the tenant-policy persistence substrate ships
    in a follow-up sprint, callers populate the parameter from the
    bank-overlay's tenant policy adapter; this signature is forward-
    compatible without a wire-protocol break.

    Returns: :class:`DataGovernancePanelData` — a frozen dataclass that
    the DTO at ``portal/api/packs/dto.py`` consumes via
    ``from_attributes=True``.
    """
    raw_block = manifest.get("data_governance")
    block: dict[str, Any] = raw_block if isinstance(raw_block, dict) else {}

    data_classes = _coerce_str_tuple(block.get("data_classes", []))
    purpose_raw = block.get("purpose", "")
    purpose = purpose_raw if isinstance(purpose_raw, str) else ""
    purpose_description_raw = block.get("purpose_description", "")
    purpose_description = (
        purpose_description_raw if isinstance(purpose_description_raw, str) else ""
    )
    retention_policy_raw = block.get("retention_policy", "")
    retention_policy = retention_policy_raw if isinstance(retention_policy_raw, str) else ""
    retention_max_window_raw = block.get("retention_max_window")
    retention_max_window = "" if retention_max_window_raw is None else str(retention_max_window_raw)
    egress_allow_list = _coerce_str_tuple(block.get("egress_allow_list", []))
    dlp_pre_hooks = _coerce_str_tuple(block.get("dlp_pre_hooks", []))
    dlp_post_hooks = _coerce_str_tuple(block.get("dlp_post_hooks", []))

    tenant_policy_diff = _compute_tenant_policy_diff(
        data_classes=data_classes,
        purpose=purpose,
        retention_max_window_raw=retention_max_window_raw,
        egress_allow_list=egress_allow_list,
        dlp_pre_hooks=dlp_pre_hooks,
        dlp_post_hooks=dlp_post_hooks,
        tenant_policy=tenant_policy,
    )

    return DataGovernancePanelData(
        pack_kind=record_kind,
        data_classes=data_classes,
        purpose=purpose,
        purpose_description=purpose_description,
        retention_policy=retention_policy,
        retention_max_window=retention_max_window,
        egress_allow_list=egress_allow_list,
        dlp_pre_hooks=dlp_pre_hooks,
        dlp_post_hooks=dlp_post_hooks,
        tenant_policy_diff=tenant_policy_diff,
    )

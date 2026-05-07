"""Sprint-7A R1 P2 #4 — build-time data-governance vocabulary.

Closed-enum literals for the three ADR-017 fields that the
data-governance validator (T10) cross-checks against pack manifests:

  - ``DataClass`` — the catalogue of data classes packs may handle
    (public, customer_pii, payment_data, etc.).
  - ``Purpose`` — the catalogue of business purposes for which a pack
    may process data (transaction_processing, regulatory_reporting,
    etc.).
  - ``RetentionPolicy`` — the catalogue of retention policies a pack
    may declare (none, session_only, regulator_floor, etc.).

This module is the **build-time owner** of the data-governance
vocabulary. The runtime DLP enforcement substrate per ADR-017 lands in
a future sprint; when it ships, the runtime module MUST consolidate
against this same source-of-truth (either by importing directly OR by
migrating both consumers to a shared module in the same commit). DO
NOT duplicate — divergence between build-time and runtime on what
counts as "customer_pii" produces pack-author confusion + audit gaps.

The migration guard test in
``tests/unit/cli/validators/test_data_governance_vocab_consolidation.py``
(landed in T10) pins this contract.

Sprint-7A T1 per R1 P2 #4 reviewer correction (the original draft
referenced a non-existent ``core/dataclasses.py`` module — that name
also collided with the stdlib ``dataclasses``; this module owns the
build-time vocab cleanly under the CLI namespace).
"""

from __future__ import annotations

from typing import Literal

#: Catalogue of data classes Wave-1 packs may declare in
#: ``[tool.cognic.data_governance].data_classes``. New classes land in
#: their owning sprint per ADR-017; T10 validator refuses any class
#: not in this set.
DataClass = Literal[
    "public",
    "internal",
    "customer_pii",
    "payment_data",
    "credentials",
    "regulator_communication",
    "audit_trail",
    "model_inputs",
    "model_outputs",
]


#: Catalogue of business purposes for pack processing.
Purpose = Literal[
    "transaction_processing",
    "regulatory_reporting",
    "fraud_detection",
    "customer_support",
    "audit_evidence",
    "operational_telemetry",
]


#: Catalogue of retention policies a pack may declare in
#: ``[tool.cognic.data_governance].retention_policy``. The
#: ``regulator_floor`` policy is special-cased by the data-governance
#: validator (T10): if a pack also declares
#: ``regulator_retention_required = true``, the validator cross-checks
#: ``retention_max_window`` against the per-tenant regulator floor.
RetentionPolicy = Literal[
    "none",
    "session_only",
    "task_only",
    "purpose_window",
    "regulator_floor",
    "indefinite_with_legal_basis",
]


#: Restricted-tier ``DataClass`` values. T10 (data-governance) and T9
#: (MCP) cross-check pack manifests against this set: caching restricted
#: data + form-elicitation against restricted data + low-risk-tier with
#: restricted data are all refused. T10 owns the set; T9 imports from
#: here so the build-time validators agree on which classes are
#: restricted.
#:
#: Every member MUST also appear in the :data:`DataClass` literal — the
#: vocab-consolidation guard test pins this invariant.
#:
#: The runtime layer's analogous set lives at
#: ``protocol.mcp_capabilities._RESTRICTED_DATA_CLASSES`` and uses
#: domain-specific identifiers (``customer_pii`` /
#: ``payment_action`` / ``regulator_communication``). Naming overlap
#: is partial: build-time uses ``payment_data`` while the runtime uses
#: ``payment_action``. A future doctrine commit should reconcile
#: these — the migration-guard test in
#: ``tests/unit/cli/validators/test_data_governance_vocab_consolidation.py``
#: pins the contract.
RESTRICTED_DATA_CLASSES: frozenset[str] = frozenset(
    {
        "customer_pii",
        "payment_data",
        "credentials",
        "regulator_communication",
    }
)


#: Catalogue of risk tiers per ADR-014. The runtime tool-approval
#: gate keys per-call workflows off these values; the build-time T11
#: validator refuses any tier outside this set + cross-checks that
#: the declared tier is high enough for the declared data classes.
#:
#: Order of declaration here is the canonical "authority" ordering
#: (lowest-authority first). The ``RISK_TIER_ORDER`` tuple below
#: pins this for "at-least" comparisons.
RiskTier = Literal[
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
]


#: Canonical authority ordering of :data:`RiskTier` values, lowest-
#: authority first. T11 uses index lookups against this tuple to
#: implement the "at-least" cross-check (declared tier index >=
#: required tier index for each data class). The vocab-consolidation
#: guard test pins ``set(RISK_TIER_ORDER) == set(get_args(RiskTier))``.
RISK_TIER_ORDER: tuple[str, ...] = (
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
)


#: Per-data-class minimum-tier mapping for the T11 cross-check. A
#: pack declaring a class in this map MUST also declare a tier at
#: or above the mapped minimum; otherwise T11 fires
#: ``risk_tier_inconsistent_with_data_classes`` with payload
#: ``failure_mode="tier_below_minimum_for_data_class"``.
#:
#: Classes NOT in this map (``public``, ``internal``, ``audit_trail``,
#: ``model_inputs``, ``model_outputs``) carry no minimum-tier
#: requirement at Wave-1 — the runtime DLP gate handles per-record
#: filtering for those.
DATA_CLASS_TO_MIN_RISK_TIER: dict[str, str] = {
    "customer_pii": "customer_data_read",
    "payment_data": "payment_action",
    "credentials": "customer_data_write",
    "regulator_communication": "regulator_communication",
}


#: T10 cross-check uses this set: tiers that DO NOT permit handling
#: any restricted-tier data class. A manifest declaring a tier in
#: this set + restricted ``data_classes`` trips the T10 refusal
#: ``data_governance_contract_inconsistent_with_risk_tier`` (T11
#: also fires its own per-class refusals; T10's framing is
#: data-governance-side perspective on the same violation).
LOW_AUTHORITY_TIERS: frozenset[str] = frozenset({"read_only", "internal_write"})


__all__ = [
    "DATA_CLASS_TO_MIN_RISK_TIER",
    "LOW_AUTHORITY_TIERS",
    "RESTRICTED_DATA_CLASSES",
    "RISK_TIER_ORDER",
    "DataClass",
    "Purpose",
    "RetentionPolicy",
    "RiskTier",
]

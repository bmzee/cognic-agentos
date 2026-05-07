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


__all__ = [
    "DataClass",
    "Purpose",
    "RetentionPolicy",
]

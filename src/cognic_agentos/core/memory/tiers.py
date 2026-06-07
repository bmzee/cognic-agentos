"""Sprint 11.5a — memory tiers, block kinds, subject vocabulary, refusal taxonomy.

core/ stop-rule per AGENTS.md (Memory governance enforcement, ADR-019).
The DataClass / Purpose / RESTRICTED_DATA_CLASSES copies below are a
DELIBERATE inline mirror of cli/_governance_vocab — core/ MUST NOT import
cli/* at runtime (architectural arrow runs cli -> core). Lockstep is pinned
test-only by tests/unit/core/memory/test_vocab_drift.py.
"""

from __future__ import annotations

import dataclasses
from typing import Literal

MemoryTier = Literal["scratch", "task", "long_term"]
BlockKind = Literal["persona", "user_profile", "agent_notes"]

# --- Local copy of cli/_governance_vocab (drift-pinned test-only) ---
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
Purpose = Literal[
    "transaction_processing",
    "regulatory_reporting",
    "fraud_detection",
    "customer_support",
    "audit_evidence",
    "operational_telemetry",
]
RESTRICTED_DATA_CLASSES: frozenset[str] = frozenset(
    {"customer_pii", "payment_data", "credentials", "regulator_communication"}
)

MemoryRefusalReason = Literal[
    "memory_write_frozen",
    "memory_subagent_durable_access_refused",
    "memory_long_term_write_denied",
    "memory_dlp_undeclared_restricted_class",
    "memory_restricted_class_write_denied",
    "memory_purpose_not_declared",
    "memory_consent_required",
    "memory_consent_invalid",
    "memory_approval_engine_not_available",
    "memory_recall_capability_missing",
    "memory_cross_subject_access_refused",
    "memory_purpose_mismatch",
    # Sprint 11.5b T1 — lifecycle refusal reasons (erasure/forget/redact ops)
    "memory_record_not_found",
    "memory_record_already_tombstoned",
    "memory_redaction_path_invalid",
    "memory_regulator_erasure_metadata_required",
    # Sprint 11.5c T1 — vector-ranked recall requested but unavailable
    # (no query supplied OR no MemoryVectorIndex wired). Wire-public.
    "memory_vector_recall_unavailable",
    # ADR-023 (Wave-2) — export-retention config-overlay resolution failure.
    # Raised by MemoryAPI.export() when a wired TenantConfigResolver surfaces a
    # corrupt / floor-violating stored overlay (TenantConfigOverlayInvalid)
    # while resolving memory_export_retention_seconds; fail-closed. When no
    # resolver is wired (the default until the Task-10 composition root), export
    # uses settings.memory_export_retention_seconds and this value never fires.
    "memory_export_tenant_config_overlay_invalid",
]

#: Reasons a forget() call may be initiated — carried on the memory.forget chain event.
#: Wire-protocol-public per ADR-019 §"Forget + redact".
ForgetReason = Literal["user_request", "retention_expired", "regulator_erasure", "correction"]

#: Reasons a redact() call may be initiated — carried on the memory.redact chain event.
#: Wire-protocol-public per ADR-019 §"Forget + redact".
RedactionReason = Literal["pii_minimization", "regulator_order", "correction"]


@dataclasses.dataclass(frozen=True, slots=True)
class SubjectRef:
    kind: Literal["human", "agent"]
    id: str

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("SubjectRef.id must be non-empty (no tenant-wide/unscoped memory)")

    @property
    def canonical(self) -> str:
        return f"{self.kind}:{self.id}"


class MemoryOperationRefused(Exception):
    """Typed refusal carrying ONLY the wire-public closed-enum reason."""

    def __init__(self, reason: MemoryRefusalReason) -> None:
        super().__init__(reason)
        self.reason: MemoryRefusalReason = reason

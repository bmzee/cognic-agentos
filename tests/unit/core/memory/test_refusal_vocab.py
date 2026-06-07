"""Sprint 11.5a + 11.5b T1 + 11.5c T1 — MemoryRefusalReason count-pin.

11.5a shipped 12 values. Sprint 11.5b T1 extended to 16 (+4 lifecycle
erasure/forget/redact reasons). Sprint 11.5c T1 extended to 17 (+1
vector-recall reason). ADR-023 (Wave-2) extends to 18 (+1 export-retention
config-overlay reason). ANY addition, rename, or removal is a
wire-protocol break visible in this test's diff.
"""

import typing

from cognic_agentos.core.memory.tiers import MemoryRefusalReason

_EXPECTED = {
    # 11.5a original 12
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
    # 11.5b T1 additions (+4 lifecycle reasons)
    "memory_record_not_found",
    "memory_record_already_tombstoned",
    "memory_redaction_path_invalid",
    "memory_regulator_erasure_metadata_required",
    # 11.5c T1 additions (+1 vector-recall reason)
    "memory_vector_recall_unavailable",
    # ADR-023 (Wave-2) additions (+1 export-retention config-overlay reason)
    "memory_export_tenant_config_overlay_invalid",
}


def test_refusal_vocab_is_exactly_the_18_wire_public_reasons():
    assert set(typing.get_args(MemoryRefusalReason)) == _EXPECTED


def test_refusal_vocab_count_pinned():
    assert len(typing.get_args(MemoryRefusalReason)) == 18


def test_refusal_taxonomy_has_eighteen_values_after_adr023() -> None:
    assert len(typing.get_args(MemoryRefusalReason)) == 18


def test_vector_recall_unavailable_is_a_memory_refusal_reason() -> None:
    assert "memory_vector_recall_unavailable" in typing.get_args(MemoryRefusalReason)

"""Sprint 11.5a + 11.5b T1 — MemoryRefusalReason count-pin.

11.5a shipped 12 values. Sprint 11.5b T1 extended to 16 (+4 lifecycle
erasure/forget/redact reasons). ANY addition, rename, or removal is a
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
}


def test_refusal_vocab_is_exactly_the_16_wire_public_reasons():
    assert set(typing.get_args(MemoryRefusalReason)) == _EXPECTED


def test_refusal_vocab_count_pinned():
    assert len(typing.get_args(MemoryRefusalReason)) == 16

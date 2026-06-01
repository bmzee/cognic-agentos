import typing

from cognic_agentos.core.memory.tiers import MemoryRefusalReason

_EXPECTED = {
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
}


def test_refusal_vocab_is_exactly_the_12_wire_public_reasons():
    assert set(typing.get_args(MemoryRefusalReason)) == _EXPECTED


def test_refusal_vocab_count_pinned():
    assert len(typing.get_args(MemoryRefusalReason)) == 12

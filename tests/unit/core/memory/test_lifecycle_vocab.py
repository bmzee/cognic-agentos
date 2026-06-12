"""Sprint 11.5b T1 — lifecycle refusal vocabulary count-pin + ForgetReason / RedactionReason.

Originally pinned the 12 → 16 extension of MemoryRefusalReason; the count
pin below has since moved with the vocabulary (16 → 17 at Sprint 11.5c,
→ 18 at ADR-023, → 23 at Sprint 13.5c3's +5 approval-seam reasons per
ADR-014). Also pins the two lifecycle vocab Literals. ANY drift here is a
wire-protocol break.
"""

import typing

from cognic_agentos.core.memory.tiers import ForgetReason, MemoryRefusalReason, RedactionReason

_NEW_LIFECYCLE_REASONS = {
    "memory_record_not_found",
    "memory_record_already_tombstoned",
    "memory_redaction_path_invalid",
    "memory_regulator_erasure_metadata_required",
}


def test_memory_refusal_reason_is_23_values_closed_enum():
    vals = set(typing.get_args(MemoryRefusalReason))
    # 17 at Sprint-11.5c; 18 at ADR-023; 23 at Sprint-13.5c3 (+5 approval-seam).
    assert len(vals) == 23
    assert vals >= _NEW_LIFECYCLE_REASONS
    assert "memory_write_frozen" in vals and "memory_purpose_mismatch" in vals


def test_forget_reason_closed_enum():
    assert set(typing.get_args(ForgetReason)) == {
        "user_request",
        "retention_expired",
        "regulator_erasure",
        "correction",
    }


def test_redaction_reason_closed_enum():
    assert set(typing.get_args(RedactionReason)) == {
        "pii_minimization",
        "regulator_order",
        "correction",
    }

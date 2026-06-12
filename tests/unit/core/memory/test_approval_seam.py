"""Sprint 13.5c3 (ADR-014 + ADR-019) — memory approval seam cutover tests."""

from __future__ import annotations

import dataclasses
import typing


def test_refusal_vocabulary_carries_five_approval_values() -> None:
    # Wire-protocol-public (spec §4); the engine-absent fallback value is KEPT.
    from cognic_agentos.core.memory.tiers import MemoryRefusalReason

    values = set(typing.get_args(MemoryRefusalReason))
    assert {
        "memory_approval_pending",
        "memory_approval_denied",
        "memory_approval_expired",
        "memory_approval_binding_mismatch",
        "memory_approval_request_not_found",
    } <= values
    assert "memory_approval_engine_not_available" in values  # fallback kept
    assert len(values) == 23  # 18 at 11.5/ADR-023; 23 at 13.5c3 (ADR-014)


def test_refused_carries_optional_approval_request_id() -> None:
    from cognic_agentos.core.memory.tiers import MemoryOperationRefused

    bare = MemoryOperationRefused("memory_approval_pending")
    assert bare.approval_request_id is None  # additive — old raise sites unchanged
    rich = MemoryOperationRefused("memory_approval_pending", approval_request_id="abc")
    assert rich.approval_request_id == "abc"


def test_memory_write_record_carries_three_defaulted_evidence_fields() -> None:
    # Spec §6: gate-built record; callers never construct it (no forgery surface).
    from cognic_agentos.core.memory._context import MemoryWriteRecord
    from cognic_agentos.core.memory.tiers import SubjectRef

    rec = MemoryWriteRecord(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        subject=SubjectRef(kind="human", id="cust-7"),
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        value={"x": 1},
        request_id="memory-write-abc",
    )
    assert rec.approval_verified is False
    assert rec.approval_request_id is None
    assert rec.approval_audit_record_ref is None
    rich = dataclasses.replace(
        rec, approval_verified=True, approval_request_id="rid", approval_audit_record_ref="ref"
    )
    assert rich.approval_verified is True

"""Sprint 13.5c3 (ADR-014 + ADR-019) — memory approval seam cutover tests."""

from __future__ import annotations

import dataclasses
import typing

import pytest


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


# ---------------------------------------------------------------------------
# T3 — binding-digest helpers (spec §3.3, F4: value digest, never raw value)
# ---------------------------------------------------------------------------


def _digest_kwargs(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "tier": "long_term",
        "purpose": "customer_support",
        "data_classes": ("internal", "public"),
        "key": "k1",
        "block_kind": None,
        "subject_canonical": "human:cust-7",
        "actor_id": "svc",
        "risk_tier": "payment_action",
        "value": {"x": 1},
    }
    base.update(over)
    return base


def test_memory_tool_identity_shape_and_collision_proofing() -> None:
    from cognic_agentos.core.memory.gate import _memory_tool_identity

    ident = _memory_tool_identity(agent_id="kyc")
    assert ident.startswith("memory:")
    assert len(ident) == 7 + 64  # fits String(256)
    assert ident == _memory_tool_identity(agent_id="kyc")
    assert _memory_tool_identity(agent_id="a:b") != _memory_tool_identity(agent_id="a")


def test_args_digest_binds_shape_content_and_actor() -> None:
    # Spec §3.3 (F4): tier/purpose/data_classes/key|block/subject/actor_id/
    # risk_tier/VALUE-digest are bound; a change in ANY must change the digest.
    from cognic_agentos.core.memory.gate import _memory_args_digest

    base = _memory_args_digest(**_digest_kwargs())  # type: ignore[arg-type]
    assert base == _memory_args_digest(**_digest_kwargs())  # type: ignore[arg-type]
    for change in (
        {"value": {"x": 2}},  # CONTENT binding (F4)
        {"actor_id": "svc-2"},  # actor binding (c2 refinement)
        {"tier": "task"},
        {"purpose": "fraud_detection"},
        {"data_classes": ("internal",)},
        {"key": "other-key"},
        {"block_kind": "user_profile"},  # block-shape binding (pure-function pin)
        {"risk_tier": "cross_tenant"},
        {"subject_canonical": "human:cust-999"},
    ):
        assert _memory_args_digest(**{**_digest_kwargs(), **change}) != base  # type: ignore[arg-type]
    # data_classes order-insensitive (sorted in the digest):
    one = _memory_args_digest(**{**_digest_kwargs(), "data_classes": ("public", "internal")})  # type: ignore[arg-type]
    two = _memory_args_digest(**{**_digest_kwargs(), "data_classes": ("internal", "public")})  # type: ignore[arg-type]
    assert one == two


def test_value_digest_single_source(monkeypatch: pytest.MonkeyPatch) -> None:
    # The binding reuses _digest._value_digest — the SAME definition behind
    # the memory.write row's redacted_value_digest (storage re-exports it;
    # canonical home is core/memory/_digest.py per the Layer-C architecture
    # fence). PROOF by monkeypatch: patching the gate-module binding changes
    # the args digest, and under a constant patched helper two DIFFERENT
    # values digest equal (the value reaches the binding ONLY through it).
    from cognic_agentos.core.memory import gate as gate_module

    base = gate_module._memory_args_digest(**_digest_kwargs())  # type: ignore[arg-type]
    monkeypatch.setattr(gate_module, "_value_digest", lambda value: "SENTINEL")
    patched_one = gate_module._memory_args_digest(**_digest_kwargs())  # type: ignore[arg-type]
    other_value_kwargs = {**_digest_kwargs(), "value": {"x": 2}}
    patched_two = gate_module._memory_args_digest(**other_value_kwargs)  # type: ignore[arg-type]
    assert patched_one != base  # the helper IS in the digest path
    assert patched_one == patched_two  # value flows ONLY through the helper

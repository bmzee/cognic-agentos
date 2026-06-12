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


# ---------------------------------------------------------------------------
# T4+ wired-gate fixtures (copies: test_write_gate.py fakes + the c-series
# approval-engine fixtures; alembic-migrated DB)
# ---------------------------------------------------------------------------


class _Frozen:
    def __init__(self, frozen: bool) -> None:
        self._frozen = frozen

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        return self._frozen


class _FakeDLP:
    def __init__(self, detected: frozenset[str] = frozenset()) -> None:
        self._detected = detected

    def scan(self, value: object) -> object:
        from cognic_agentos.core.dlp.scanner import DLPVerdict, RedactionSpan

        spans = tuple(RedactionSpan(c, 0, 1) for c in sorted(self._detected))
        return DLPVerdict(
            detected_classes=self._detected,
            redaction_spans=spans,
            confidence=1.0 if self._detected else 0.0,
        )


class _FakeConsent:
    def __init__(self, raises: Exception | None = None) -> None:
        self._raises = raises

    async def validate(self, token: object, **kwargs: object) -> None:
        if self._raises is not None:
            raise self._raises


class _FakeOPA:
    def __init__(self, allow: bool = True) -> None:
        self._allow = allow

    async def evaluate(self, *, decision_point: str, input: dict[str, object]) -> object:
        from cognic_agentos.core.policy.engine import Decision

        return Decision(
            allow=self._allow, rule_matched=decision_point, reasoning="fake", decision_data=None
        )


def _ctx(**over: object) -> object:
    from cognic_agentos.core.memory._context import MemoryCallerContext
    from cognic_agentos.core.memory.tiers import SubjectRef

    base: dict[str, object] = dict(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=SubjectRef(kind="human", id="cust-7"),
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(),
        declared_purposes=frozenset({"customer_support", "fraud_detection"}),
        declared_data_classes=frozenset({"public", "internal", "customer_pii"}),
        risk_tier="payment_action",
    )
    base.update(over)
    return MemoryCallerContext(**base)  # type: ignore[arg-type]


class _StubApprovalPolicy:
    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


class _MutableClock:
    def __init__(self) -> None:
        from datetime import UTC, datetime

        self.now = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)

    def __call__(self) -> object:
        return self.now


async def _mk_migrated_db(tmp_path: object) -> object:
    import asyncio as _asyncio

    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path}/memory-seam.db"
    cfg = make_alembic_config(url)
    await _asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _mk_approval_engine(db: object, *, flow: str, clock: object = None) -> object:
    from datetime import UTC, datetime

    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.core.decision_history import DecisionHistoryStore

    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=ApprovalRequestStore(DecisionHistoryStore(db)),  # type: ignore[arg-type]
        settings=build_settings_without_env_file(),
        clock=clock or (lambda: datetime(2026, 6, 12, 12, 0, tzinfo=UTC)),  # type: ignore[arg-type]
    )


def _mk_gate(
    *,
    context: object | None = None,
    approval_engine: object = None,
    dlp: object | None = None,
    consent: object | None = None,
    kill_switch: object | None = None,
) -> object:
    from cognic_agentos.core.memory.gate import MemoryGate

    return MemoryGate(
        context=context or _ctx(),  # type: ignore[arg-type]
        dlp=dlp or _FakeDLP(),  # type: ignore[arg-type]
        consent=consent or _FakeConsent(),  # type: ignore[arg-type]
        policy=_FakeOPA(),  # type: ignore[arg-type]
        kill_switch=kill_switch or _Frozen(False),  # type: ignore[arg-type]
        approval_engine=approval_engine,  # type: ignore[arg-type]
    )


async def _pending(db: object) -> list[object]:
    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore

    return list(await ApprovalRequestStore(DecisionHistoryStore(db)).list_pending("t1"))  # type: ignore[arg-type]


_WRITE_KWARGS: dict[str, object] = dict(
    value={"x": 1},
    tier="long_term",
    purpose="customer_support",
    data_classes=("internal",),
    key="k1",
)


# ---------------------------------------------------------------------------
# T4 — wired first-write path (spec §3.1/§3.2/§3.4/§3.5)
# ---------------------------------------------------------------------------


class TestWiredFirstWrite:
    async def test_long_term_high_tier_refuses_pending_with_correlator(
        self, tmp_path: object
    ) -> None:
        import uuid as _uuid

        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.core.memory.tiers import MemoryOperationRefused

        db = await _mk_migrated_db(tmp_path)
        gate = _mk_gate(approval_engine=_mk_approval_engine(db, flow="require_single_approval"))
        with pytest.raises(MemoryOperationRefused) as exc:
            await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
        assert exc.value.reason == "memory_approval_pending"
        rid = _uuid.UUID(exc.value.approval_request_id)
        detail = await ApprovalRequestStore(DecisionHistoryStore(db)).load_detail(  # type: ignore[arg-type]
            request_id=rid, tenant_id="t1"
        )
        assert detail is not None and detail.state == "pending"
        assert detail.tool_identity.startswith("memory:")
        assert detail.redacted_context.startswith("memory_write agent_id=kyc tier=long_term")
        assert detail.data_classes == ("internal",)

    async def test_auto_flow_proceeds_unverified(self, tmp_path: object) -> None:
        db = await _mk_migrated_db(tmp_path)
        gate = _mk_gate(approval_engine=_mk_approval_engine(db, flow="auto_run"))
        record = await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
        assert record.approval_verified is False
        assert await _pending(db) == []

    async def test_regulator_tier_required_refs_carry_hoisted_request_id(
        self, tmp_path: object
    ) -> None:
        import uuid as _uuid

        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.core.memory.tiers import MemoryOperationRefused

        db = await _mk_migrated_db(tmp_path)
        gate = _mk_gate(
            context=_ctx(risk_tier="regulator_communication"),
            approval_engine=_mk_approval_engine(db, flow="require_single_approval"),
        )
        with pytest.raises(MemoryOperationRefused) as exc:
            await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
        detail = await ApprovalRequestStore(DecisionHistoryStore(db)).load_detail(  # type: ignore[arg-type]
            request_id=_uuid.UUID(exc.value.approval_request_id), tenant_id="t1"
        )
        assert detail is not None
        ref = detail.required_refs["audit_record_ref"]
        assert ref.startswith("memory-write-")  # F3: the hoisted id, nothing minted

    async def test_customer_data_read_long_term_is_unconsulted(self, tmp_path: object) -> None:
        # ASYMMETRY LOCK (F2): the 5-set excludes customer_data_read.
        db = await _mk_migrated_db(tmp_path)
        gate = _mk_gate(
            context=_ctx(risk_tier="customer_data_read"),
            approval_engine=_mk_approval_engine(db, flow="require_single_approval"),
        )
        record = await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
        assert record.approval_verified is False
        assert await _pending(db) == []

    async def test_scratch_and_task_high_tier_unconsulted(self, tmp_path: object) -> None:
        db = await _mk_migrated_db(tmp_path)
        gate = _mk_gate(approval_engine=_mk_approval_engine(db, flow="require_single_approval"))
        for tier in ("scratch", "task"):
            record = await gate.check_write(**{**_WRITE_KWARGS, "tier": tier})  # type: ignore[attr-defined]
            assert record.approval_verified is False
        assert await _pending(db) == []

    async def test_dlp_consent_and_kill_switch_beat_approval(self, tmp_path: object) -> None:
        # ORDERING LOCK: Steps 0-6 refusals fire with ZERO approval rows.
        from cognic_agentos.core.memory.tiers import MemoryOperationRefused

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_approval_engine(db, flow="require_single_approval")
        cases = (
            (
                _mk_gate(approval_engine=engine, dlp=_FakeDLP(frozenset({"customer_pii"}))),
                "memory_dlp_undeclared_restricted_class",
            ),
            (
                _mk_gate(
                    approval_engine=engine,
                    consent=_FakeConsent(MemoryOperationRefused("memory_consent_required")),
                ),
                "memory_consent_required",
            ),
            (_mk_gate(approval_engine=engine, kill_switch=_Frozen(True)), "memory_write_frozen"),
        )
        for gate, expected in cases:
            with pytest.raises(MemoryOperationRefused) as exc:
                await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
            assert exc.value.reason == expected
        assert await _pending(db) == []

    async def test_engine_absent_byte_compat_and_inert_id(self, tmp_path: object) -> None:
        from cognic_agentos.core.memory.tiers import MemoryOperationRefused

        gate = _mk_gate(approval_engine=None)
        with pytest.raises(MemoryOperationRefused) as exc:
            await gate.check_write(**_WRITE_KWARGS)  # type: ignore[attr-defined]
        assert exc.value.reason == "memory_approval_engine_not_available"
        # Inert VALID dangling id on a safe-tier write (unwired):
        safe = _mk_gate(context=_ctx(risk_tier="internal_write"), approval_engine=None)
        record = await safe.check_write(  # type: ignore[attr-defined]
            **_WRITE_KWARGS, approval_request_id="11111111-1111-1111-1111-111111111111"
        )
        assert record.approval_verified is False

    async def test_malformed_approval_request_id_raises_value_error(self, tmp_path: object) -> None:
        # Spec §3.6 LOCK: caller-contract bug class, NOT a refusal reason.
        gate = _mk_gate(approval_engine=None)
        with pytest.raises(ValueError):
            await gate.check_write(**_WRITE_KWARGS, approval_request_id="not-a-uuid")  # type: ignore[attr-defined]

from __future__ import annotations

import asyncio
import typing
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.approval._types import (
    ApprovalEnvelope,
    ApprovalEnvelopeInvalid,
    ApprovalRequestNotFound,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.engine import _DATA_CLASSES, ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore


class _StubPolicy:
    def __init__(self, flow: str) -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


class _Clock:
    def __init__(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t


async def _engine(
    tmp_path: Any, *, flow: str, clock: _Clock, settings: Any = None
) -> ApprovalEngine:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'eng.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    store = ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))
    return ApprovalEngine(
        policy=_StubPolicy(flow),
        store=store,
        settings=settings or build_settings_without_env_file(),
        clock=clock,
    )


def _env(tier: str, *, refs: dict[str, str] | None = None, ctx: str = "ctx") -> ApprovalEnvelope:
    return ApprovalEnvelope(
        risk_tier=tier,
        tool_identity="cognic-tool-x",
        originator_subject="agent-1",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context=ctx,
        required_refs=refs or {},
    )


def test_data_class_mirror_matches_canonical() -> None:
    # Test-only drift detector (no runtime cli import): the engine's inline
    # data-class vocab mirror is lockstep with the canonical DataClass enum.
    from cognic_agentos.cli._governance_vocab import DataClass

    assert frozenset(typing.get_args(DataClass)) == _DATA_CLASSES


@pytest.mark.asyncio
async def test_create_request_persists_pending(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    req = await eng.create_request(envelope=_env("customer_data_read"))
    res = await eng.check(request_id=req.request_id, tenant_id="t1")
    assert res.state == "pending"
    assert res.args_digest == b"\x02" * 32 and res.tool_identity == "cognic-tool-x"
    assert res.flow == "require_single_approval" and res.risk_tier == "customer_data_read"


@pytest.mark.asyncio
async def test_create_request_auto_tier_refused(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="auto_run", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    with pytest.raises(ApprovalTransitionRefused) as ei:
        await eng.create_request(envelope=_env("read_only"))
    assert ei.value.reason == "auto_tier_no_approval_required"


@pytest.mark.asyncio
async def test_envelope_unknown_tier_rejected_before_persist(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="require_4_eyes", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=_env("totally_unknown"))
    assert ei.value.reason == "risk_tier_unknown"


@pytest.mark.asyncio
async def test_envelope_unknown_data_class_rejected(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    bad = ApprovalEnvelope(
        risk_tier="customer_data_read",
        tool_identity="t",
        originator_subject="a",
        tenant_id="t1",
        data_classes=("not_a_class",),
        args_digest=b"\x02" * 32,
        redacted_context="x",
        required_refs={},
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=bad)
    assert ei.value.reason == "data_class_unknown"


@pytest.mark.asyncio
async def test_envelope_bad_digest_len_rejected(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    bad = ApprovalEnvelope(
        risk_tier="customer_data_read",
        tool_identity="t",
        originator_subject="a",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 8,
        redacted_context="x",
        required_refs={},
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=bad)
    assert ei.value.reason == "args_digest_malformed"


@pytest.mark.asyncio
async def test_envelope_oversize_context_rejected(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=_env("customer_data_read", ctx="x" * 5000))
    assert ei.value.reason == "redacted_context_too_large"


@pytest.mark.asyncio
async def test_envelope_missing_tool_identity_rejected(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    bad = ApprovalEnvelope(
        risk_tier="customer_data_read",
        tool_identity="",
        originator_subject="a",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context="x",
        required_refs={},
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=bad)
    assert ei.value.reason == "tool_identity_missing"


@pytest.mark.asyncio
async def test_envelope_missing_tenant_rejected(tmp_path: Any) -> None:
    # P1: an empty tenant_id must refuse BEFORE persist — otherwise an approval
    # row + chain evidence with tenant_id="" would break the tenant-scoped safety
    # model.
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    bad = ApprovalEnvelope(
        risk_tier="customer_data_read",
        tool_identity="t",
        originator_subject="a",
        tenant_id="",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context="x",
        required_refs={},
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=bad)
    assert ei.value.reason == "tenant_id_missing"


@pytest.mark.asyncio
async def test_envelope_missing_originator_rejected(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="require_4_eyes", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    bad = ApprovalEnvelope(
        risk_tier="payment_action",
        tool_identity="t",
        originator_subject="",
        tenant_id="t1",
        data_classes=("customer_pii",),
        args_digest=b"\x02" * 32,
        redacted_context="x",
        required_refs={},
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=bad)
    assert ei.value.reason == "originator_subject_missing"


@pytest.mark.asyncio
async def test_regulator_requires_audit_ref(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="require_4_eyes", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    with pytest.raises(ApprovalEnvelopeInvalid) as ei:
        await eng.create_request(envelope=_env("regulator_communication"))  # no audit_record_ref
    assert ei.value.reason == "regulator_audit_ref_missing"


@pytest.mark.asyncio
async def test_regulator_with_audit_ref_ok(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="require_4_eyes", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    req = await eng.create_request(
        envelope=_env("regulator_communication", refs={"audit_record_ref": "dh-123"})
    )
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "pending"


@pytest.mark.asyncio
async def test_lazy_expiry_on_check(tmp_path: Any) -> None:
    clock = _Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    eng = await _engine(tmp_path, flow="require_single_approval", clock=clock)
    req = await eng.create_request(envelope=_env("customer_data_read"))
    clock.t = datetime(2026, 6, 10, 12, 10, tzinfo=UTC)  # 600s > 300s default TTL
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "expired"


@pytest.mark.asyncio
async def test_ttl_is_settings_driven(tmp_path: Any) -> None:
    settings = build_settings_without_env_file().model_copy(update={"approval_single_ttl_s": 10})
    clock = _Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    eng = await _engine(tmp_path, flow="require_single_approval", clock=clock, settings=settings)
    req = await eng.create_request(envelope=_env("customer_data_read"))
    clock.t = datetime(2026, 6, 10, 12, 0, 15, tzinfo=UTC)  # 15s > 10s configured TTL
    assert (await eng.check(request_id=req.request_id, tenant_id="t1")).state == "expired"


@pytest.mark.asyncio
async def test_check_cross_tenant_not_found(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path, flow="require_4_eyes", clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC))
    )
    req = await eng.create_request(envelope=_env("payment_action"))
    with pytest.raises(ApprovalRequestNotFound):
        await eng.check(request_id=req.request_id, tenant_id="t2")


@pytest.mark.asyncio
async def test_verify_grant_for_action_not_granted_returns_state(tmp_path: Any) -> None:
    # Not granted yet -> binding NOT enforced; the seam refuses on state, not here.
    eng = await _engine(
        tmp_path,
        flow="require_single_approval",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    req = await eng.create_request(envelope=_env("customer_data_read"))
    res = await eng.verify_grant_for_action(
        request_id=req.request_id,
        tenant_id="t1",
        expected_args_digest=b"\x09" * 32,
        expected_tool_identity="other",
    )
    assert res.state == "pending"


@pytest.mark.asyncio
async def test_engine_classify_delegates_to_policy(tmp_path: Any) -> None:
    eng = await _engine(
        tmp_path,
        flow="require_4_eyes",
        clock=_Clock(datetime(2026, 6, 10, 12, 0, tzinfo=UTC)),
    )
    assert await eng.classify(risk_tier="payment_action") == "require_4_eyes"

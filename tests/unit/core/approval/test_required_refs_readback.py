"""Sprint 13.5c3 — ApprovalCheckResult.required_refs read-back (spec §3.2).

The verify-time evidence echo: seams persist forward edges (e.g. memory's
``approval_audit_record_ref``) from the engine's OWN persisted row — never
from caller input (forgeable evidence rejected at spec review).
"""

from __future__ import annotations

import uuid


class _StubApprovalPolicy:
    """Fixed-flow classifier (OPA-free; the c-series seam stub)."""

    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


async def _mk_migrated_db(tmp_path: object) -> object:
    import asyncio as _asyncio

    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path}/approval-refs.db"
    cfg = make_alembic_config(url)
    await _asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _mk_approval_engine(db: object, *, flow: str) -> object:
    from datetime import UTC, datetime

    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.core.decision_history import DecisionHistoryStore

    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=ApprovalRequestStore(DecisionHistoryStore(db)),  # type: ignore[arg-type]
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 6, 12, 12, 0, tzinfo=UTC),
    )


def test_check_result_required_refs_defaults_empty() -> None:
    # Additive — every existing 13.5a/b/c construction site stays green.
    from cognic_agentos.core.approval._types import ApprovalCheckResult

    res = ApprovalCheckResult(
        state="pending",
        request_id=uuid.uuid4(),
        flow="require_single_approval",
        risk_tier="payment_action",
        tool_identity="mcp:" + "a" * 64,
        args_digest=b"d",
        envelope_digest=b"e",
        originator_subject="agent-1",
    )
    assert res.required_refs == {}


async def test_verify_echoes_persisted_refs(tmp_path: object) -> None:
    # create with {"audit_record_ref": ...} -> check() echoes it from the
    # persisted row.
    from cognic_agentos.core.approval._types import ApprovalEnvelope

    db = await _mk_migrated_db(tmp_path)
    engine = _mk_approval_engine(db, flow="require_single_approval")
    request = await engine.create_request(  # type: ignore[attr-defined]
        envelope=ApprovalEnvelope(
            risk_tier="regulator_communication",
            tool_identity="memory:" + "a" * 64,
            originator_subject="svc",
            tenant_id="t1",
            data_classes=("regulator_communication",),
            args_digest=b"d" * 32,
            redacted_context="memory_write agent_id=kyc",
            required_refs={"audit_record_ref": "memory-write-ref-1"},
        )
    )
    res = await engine.check(request_id=request.request_id, tenant_id="t1")  # type: ignore[attr-defined]
    assert res.required_refs == {"audit_record_ref": "memory-write-ref-1"}


async def test_empty_refs_row_echoes_empty_dict(tmp_path: object) -> None:
    from cognic_agentos.core.approval._types import ApprovalEnvelope

    db = await _mk_migrated_db(tmp_path)
    engine = _mk_approval_engine(db, flow="require_single_approval")
    request = await engine.create_request(  # type: ignore[attr-defined]
        envelope=ApprovalEnvelope(
            risk_tier="payment_action",
            tool_identity="memory:" + "b" * 64,
            originator_subject="svc",
            tenant_id="t1",
            data_classes=("internal",),
            args_digest=b"d" * 32,
            redacted_context="memory_write agent_id=kyc",
            required_refs={},
        )
    )
    res = await engine.check(request_id=request.request_id, tenant_id="t1")  # type: ignore[attr-defined]
    assert res.required_refs == {}

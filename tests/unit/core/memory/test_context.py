import dataclasses
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.memory._context import (
    BlockRef,
    Episode,
    MemoryCallerContext,
    MemoryHit,
    MemoryWriteRecord,
)
from cognic_agentos.core.memory.tiers import SubjectRef


def _make_ctx() -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc-1",
        served_subject=SubjectRef(kind="human", id="cust-7"),
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset({"long_term"}),
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"customer_pii"}),
        risk_tier="customer_data_read",
    )


def test_caller_context_carries_served_subject():
    assert _make_ctx().served_subject.canonical == "human:cust-7"


def test_caller_context_is_frozen():
    ctx = _make_ctx()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.tenant_id = "t2"  # type: ignore[misc]


def test_dtos_construct():
    rid = uuid.uuid4()
    now = datetime.now(UTC)
    subj = SubjectRef(kind="agent", id="a")
    hit = MemoryHit(
        record_id=rid,
        value="v",
        tier="task",
        data_classes=("public",),
        purpose="customer_support",
        created_at=now,
    )
    assert hit.block_kind is None
    assert BlockRef(record_id=rid, kind="persona", subject=subj, version=1).version == 1
    assert (
        Episode(record_id=rid, summary="s", decision_trace_id=None, created_at=now).summary == "s"
    )
    rec = MemoryWriteRecord(
        tenant_id="t1",
        agent_id="a",
        actor_id="svc",
        subject=subj,
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        value="v",
        request_id="r",
        block_kind="persona",
    )
    assert rec.tier == "long_term"
    assert rec.key is None

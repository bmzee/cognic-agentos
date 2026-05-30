import uuid

import pytest

from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.subagent.audit import SubAgentAuditEmitter
from cognic_agentos.subagent.audit_verifier import verify_subagent_linkage


@pytest.mark.asyncio
async def test_clean_parent_child_chain_verifies(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_trace_id="pt",
        child_request={},
        policy_snapshot={},
    )
    await emitter.emit_child_genesis(
        actor_id="w",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=spawn_id,
        child_trace_id="ct",
    )
    await emitter.emit_return(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=spawn_id,
        result_summary="ok",
        outcome="completed",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is True
    assert report.records_checked == 2  # start + return carry parent_record_id


@pytest.mark.asyncio
async def test_foreign_row_with_parent_record_id_key_is_ignored(engine, decision_store):
    await decision_store.append(
        DecisionRecord(
            decision_type="escalation.opened",
            request_id="r",
            tenant_id="bank-a",
            payload={"parent_record_id": "not-a-real-uuid", "level": "x"},
        )
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is True
    assert report.records_checked == 0  # the non-subagent row was skipped


@pytest.mark.asyncio
async def test_child_pointing_at_non_spawn_row_breaks(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_trace_id="pt",
        child_request={},
        policy_snapshot={},
    )
    ret_id = await emitter.emit_return(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=spawn_id,
        result_summary="ok",
        outcome="completed",
    )
    await emitter.emit_child_genesis(
        actor_id="w",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=ret_id,
        child_trace_id="ct",  # WRONG: points at a return row
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_record_id_wrong_decision_type"


@pytest.mark.asyncio
async def test_parent_row_not_found(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    await emitter.emit_child_genesis(
        actor_id="w",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=uuid.uuid4(),
        child_trace_id="ct",  # no spawn row exists
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_row_not_found"


@pytest.mark.asyncio
async def test_tenant_id_mismatch(engine, decision_store):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_trace_id="pt",
        child_request={},
        policy_snapshot={},
    )
    await emitter.emit_child_genesis(
        actor_id="w",
        tenant_id="bank-b",
        request_id="r",  # cross-tenant child
        parent_record_id=spawn_id,
        child_trace_id="ct",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "tenant_id_mismatch"


@pytest.mark.asyncio
async def test_child_missing_parent_record_id(engine, insert_raw_decision_row):
    await insert_raw_decision_row(
        record_id=uuid.uuid4(),
        sequence=1,
        event_type="subagent.start",
        payload={"child_trace_id": "ct"},
        tenant_id="bank-a",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "child_missing_parent_record_id"


@pytest.mark.asyncio
async def test_parent_row_not_before_child_row(engine, insert_raw_decision_row):
    parent_id = uuid.uuid4()
    await insert_raw_decision_row(
        record_id=uuid.uuid4(),
        sequence=1,
        event_type="subagent.start",
        payload={"parent_record_id": str(parent_id), "child_trace_id": "ct"},
        tenant_id="bank-a",
    )
    await insert_raw_decision_row(
        record_id=parent_id,
        sequence=2,
        event_type="subagent.spawn",
        payload={"parent_trace_id": "pt"},
        tenant_id="bank-a",
    )
    report = await verify_subagent_linkage(engine)
    assert report.is_clean is False
    assert report.break_kind == "parent_row_not_before_child_row"

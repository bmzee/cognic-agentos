import uuid

import pytest

from cognic_agentos.subagent.audit import SubAgentAuditEmitter


@pytest.mark.asyncio
async def test_spawn_then_child_genesis_links_by_parent_record_id(
    decision_store, decision_store_rows
):
    emitter = SubAgentAuditEmitter(decision_store)
    spawn_id = await emitter.emit_spawn(
        actor_id="orchestrator",
        tenant_id="bank-a",
        request_id="req-1",
        parent_trace_id="ptrace",
        child_request={"prompt": "verify AML"},
        policy_snapshot={"tools": ["aml_check"]},
    )
    child_id = await emitter.emit_child_genesis(
        actor_id="worker",
        tenant_id="bank-a",
        request_id="req-1",
        parent_record_id=spawn_id,
        child_trace_id="ctrace",
    )
    assert isinstance(spawn_id, uuid.UUID)
    assert isinstance(child_id, uuid.UUID)
    rows = await decision_store_rows()
    child = next(r for r in rows if r.record_id == child_id)
    assert child.event_type == "subagent.start"
    assert child.payload["parent_record_id"] == str(spawn_id)
    assert list(child.iso_controls) == ["A.6.2.5"]
    spawn = next(r for r in rows if r.record_id == spawn_id)
    assert spawn.event_type == "subagent.spawn"
    assert "parent_record_id" not in spawn.payload
    assert list(spawn.iso_controls) == ["A.6.2.5"]


@pytest.mark.asyncio
async def test_return_and_budget_carry_parent_link(decision_store, decision_store_rows):
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
    bud_id = await emitter.emit_budget(
        actor_id="o",
        tenant_id="bank-a",
        request_id="r",
        parent_record_id=spawn_id,
        tokens_used=120,
        wall_time_used_s=0.4,
    )
    rows = await decision_store_rows()
    ret = next(r for r in rows if r.record_id == ret_id)
    bud = next(r for r in rows if r.record_id == bud_id)
    assert ret.event_type == "subagent.return"
    assert ret.payload["parent_record_id"] == str(spawn_id)
    assert ret.payload["outcome"] == "completed"
    assert list(ret.iso_controls) == ["A.6.2.5"]
    assert bud.event_type == "subagent.budget"
    assert bud.payload["tokens_used"] == 120
    assert list(bud.iso_controls) == ["A.6.2.5"]

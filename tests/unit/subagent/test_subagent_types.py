import uuid

from cognic_agentos.subagent._types import (
    ChildRunContext,
    ManagedRunChildSpec,
    SubAgentBudgetExhausted,
    SubAgentChildQuotaZero,
)


def test_managed_run_child_spec_shape() -> None:
    spec = ManagedRunChildSpec(pack_id="cognic-tool-x", pack_version="1.0.0", argv=("--run",))
    assert (spec.pack_id, spec.pack_version, spec.argv) == ("cognic-tool-x", "1.0.0", ("--run",))


def test_child_run_context_new_optional_fields_default_to_none() -> None:
    # Build WITHOUT actor/parent_task_id/managed_run — all are additive optionals.
    ctx = ChildRunContext(
        prompt="p",
        granted_tools=frozenset(),
        requested_estimated_tokens=10,
        tenant_id="t",
        current_depth=1,
        child_trace_id="c",
        request_id="r",
        parent_record_id=uuid.uuid4(),
    )
    assert ctx.actor is None  # optional/additive — the managed-run runner fail-closes on None
    assert ctx.parent_task_id is None
    assert ctx.managed_run is None
    assert ctx.requested_estimated_tokens == 10  # renamed from `budget`


def test_subagent_budget_exhausted_carries_wire_reason() -> None:
    # Kept for wire-public compat (spec §6 LOCKED) though the live path no longer
    # raises it (compute_spawn_budget retired at T4); construction covers the
    # __init__ vocabulary binding (the CC-floor regression from the deleted helper test).
    exc = SubAgentBudgetExhausted(parent_remaining_budget=0)
    assert exc.reason == "subagent_parent_budget_exhausted"
    assert exc.parent_remaining_budget == 0


def test_subagent_child_quota_zero_carries_wire_reason() -> None:
    exc = SubAgentChildQuotaZero(child_pack_quota=0)
    assert exc.reason == "subagent_child_quota_zero"
    assert exc.child_pack_quota == 0

"""Sprint 11b T9 — wire the subagent UI emit hooks (ADR-020, A-projector).

Maps subagent.* + depth-cap escalation decision rows onto the EXISTING
subagent UI models (never renamed):
  - subagent.spawn               -> subagent.spawned
  - subagent.return (ok)         -> subagent.completed
  - subagent.return (not-ok)     -> subagent.failed
  - escalation.opened, scoped to level="depth_exceeded" AND a
    "subagent-spawn-*" request_id (the T6 depth-refusal path) -> subagent.recursion_capped

A-projector (decision memo D1): the projector mapping is wired + DI-proven.
The PRODUCTION emission of recursion_capped additionally requires escalation
rows to reach the UIEventEmitter — but EscalationStore writes via its OWN
DecisionHistoryStore instance (escalation.py:465) which the emitter does not
hook, so that routing is app-wiring deferred like the rest of the subagent
production path. core/escalation.py is NOT touched here. The depth-cap
emission tests below therefore append a representative escalation.opened row
through the hooked store (DI-proven, not production-live), while the
shape/evidence test proves the REAL depth path writes exactly that row shape.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import (
    AppendedDecisionSnapshot,
    DecisionHistoryStore,
    DecisionRecord,
    _decision_history,
)
from cognic_agentos.core.escalation import EscalationStore
from cognic_agentos.core.scheduler._types import TaskActor
from cognic_agentos.protocol.ui_events import (
    SubagentCompleted,
    SubagentFailed,
    SubagentRecursionCapped,
    SubagentSpawned,
    UIEventEmitter,
    _project_typed_decision_history,
)
from cognic_agentos.subagent._types import SubAgentDepthExceeded, SubAgentSpawnRequest
from cognic_agentos.subagent.spawn import SubAgentSpawner


# ---------------------------------------------------------------------------
# fixtures (file-local; mirrors tests/unit/subagent/conftest.py + the broker
# test's engine fixture — there is no protocol-dir conftest)
# ---------------------------------------------------------------------------
@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'subagent_ui.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def decision_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


async def _all_rows(engine: AsyncEngine) -> list[Any]:
    async with engine.begin() as conn:
        result = await conn.execute(
            select(_decision_history).order_by(_decision_history.c.sequence)
        )
        return list(result.all())


def _snap(
    *,
    decision_type: str,
    payload: dict[str, Any] | None = None,
    request_id: str = "subagent-spawn-abc123",
    sequence: int = 7,
    tenant_id: str = "bank-a",
) -> AppendedDecisionSnapshot:
    """Pure projector-input snapshot (no DB I/O)."""
    return AppendedDecisionSnapshot(
        record_id=uuid.UUID(int=0),
        chain_id="decision_history",
        sequence=sequence,
        new_hash=b"\xaa" * 32,
        created_at=datetime.now(UTC),
        decision_type=decision_type,
        request_id=request_id,
        payload=payload if payload is not None else {},
        tenant_id=tenant_id,
        trace_id="trace-x",
    )


async def _emitter_with_collector(
    engine: AsyncEngine, decision_store: DecisionHistoryStore
) -> list[Any]:
    """Wire a UIEventEmitter on `decision_store` + return a list that captures
    every emitted event. The emitter stays alive via the store's hook list."""
    collected: list[Any] = []

    async def _collector(evt: Any) -> None:
        collected.append(evt)

    emitter = UIEventEmitter(audit_store=AuditStore(engine), decision_history_store=decision_store)
    emitter.register_hook(_collector)
    return collected


def _subagent_events(collected: list[Any]) -> list[Any]:
    return [e for e in collected if getattr(e, "family", None) == "subagent"]


# ---------------------------------------------------------------------------
# projector unit tests (pure)
# ---------------------------------------------------------------------------
def test_subagent_spawn_projects_spawned() -> None:
    evt = _project_typed_decision_history(_snap(decision_type="subagent.spawn"))
    assert isinstance(evt, SubagentSpawned)
    assert evt.family == "subagent"
    assert evt.type == "spawned"


def test_subagent_return_completed_projects_completed() -> None:
    evt = _project_typed_decision_history(
        _snap(decision_type="subagent.return", payload={"outcome": "completed"})
    )
    assert isinstance(evt, SubagentCompleted)
    assert evt.type == "completed"


def test_subagent_return_failed_projects_failed() -> None:
    evt = _project_typed_decision_history(
        _snap(decision_type="subagent.return", payload={"outcome": "failed"})
    )
    assert isinstance(evt, SubagentFailed)
    assert evt.type == "failed"


def test_subagent_return_without_outcome_defaults_failed() -> None:
    """The replay-snapshot drift test drives subagent.return with a minimal
    payload (no outcome); the projector MUST still return a typed event (never
    None) — default to failed (the conservative UI signal)."""
    evt = _project_typed_decision_history(_snap(decision_type="subagent.return", payload={}))
    assert isinstance(evt, SubagentFailed)


def test_escalation_depth_cap_projects_recursion_capped() -> None:
    evt = _project_typed_decision_history(
        _snap(
            decision_type="escalation.opened",
            payload={"level": "depth_exceeded"},
            request_id="subagent-spawn-deadbeef",
        )
    )
    assert isinstance(evt, SubagentRecursionCapped)
    assert evt.family == "subagent"
    assert evt.type == "recursion_capped"


def test_generic_escalation_wrong_level_returns_none() -> None:
    """A non-depth-cap escalation (different level) MUST NOT project
    recursion_capped — it falls through to the mirror-only path."""
    evt = _project_typed_decision_history(
        _snap(
            decision_type="escalation.opened",
            payload={"level": "sla_breach"},
            request_id="subagent-spawn-deadbeef",
        )
    )
    assert evt is None


def test_depth_level_but_non_subagent_request_returns_none() -> None:
    """level=depth_exceeded but a non-subagent request_id (e.g. a future
    depth-cap from another subsystem) MUST NOT project recursion_capped."""
    evt = _project_typed_decision_history(
        _snap(
            decision_type="escalation.opened",
            payload={"level": "depth_exceeded"},
            request_id="portal-req-xyz",
        )
    )
    assert evt is None


def test_escalation_missing_level_returns_none() -> None:
    """A malformed escalation row with no level at all MUST NOT project
    (defensive — payload.get returns None, not 'depth_exceeded')."""
    evt = _project_typed_decision_history(
        _snap(
            decision_type="escalation.opened",
            payload={},
            request_id="subagent-spawn-deadbeef",
        )
    )
    assert evt is None


# ---------------------------------------------------------------------------
# emission tests (DI, via a hooked DecisionHistoryStore)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_emitter_emits_subagent_spawned_on_append(
    engine: AsyncEngine, decision_store: DecisionHistoryStore
) -> None:
    """Wiring proof: appending a subagent.spawn row to the hooked store fires
    _on_decision_append -> projects SubagentSpawned -> collector."""
    collected = await _emitter_with_collector(engine, decision_store)
    await decision_store.append(
        DecisionRecord(
            decision_type="subagent.spawn",
            request_id="subagent-spawn-abc",
            tenant_id="bank-a",
            payload={"child_request": {"prompt": "x"}},
        )
    )
    evts = _subagent_events(collected)
    assert len(evts) == 1
    assert isinstance(evts[0], SubagentSpawned)


@pytest.mark.asyncio
async def test_emitter_emits_subagent_completed_on_append(
    engine: AsyncEngine, decision_store: DecisionHistoryStore
) -> None:
    """subagent.return ok -> SubagentCompleted through the hooked store."""
    collected = await _emitter_with_collector(engine, decision_store)
    await decision_store.append(
        DecisionRecord(
            decision_type="subagent.return",
            request_id="subagent-spawn-abc",
            tenant_id="bank-a",
            payload={"outcome": "completed", "result_summary": "ok"},
        )
    )
    evts = _subagent_events(collected)
    assert len(evts) == 1
    assert isinstance(evts[0], SubagentCompleted)


@pytest.mark.asyncio
async def test_depth_cap_escalation_emits_recursion_capped_on_append(
    engine: AsyncEngine, decision_store: DecisionHistoryStore
) -> None:
    """DI emission proof for recursion_capped: an escalation.opened row shaped
    EXACTLY like the real depth-refusal path (level=depth_exceeded + a
    subagent-spawn-* request_id), appended through the hooked store, emits
    SubagentRecursionCapped. DI-proven; production routing of escalation rows
    to the emitter is deferred per memo D1 (see module docstring)."""
    collected = await _emitter_with_collector(engine, decision_store)
    await decision_store.append(
        DecisionRecord(
            decision_type="escalation.opened",
            request_id="subagent-spawn-abc",
            tenant_id="bank-a",
            payload={"level": "depth_exceeded", "reason": "depth 4 exceeds max 3"},
        )
    )
    evts = _subagent_events(collected)
    assert len(evts) == 1
    assert isinstance(evts[0], SubagentRecursionCapped)


@pytest.mark.asyncio
async def test_generic_escalation_emits_no_subagent_event_on_append(
    engine: AsyncEngine, decision_store: DecisionHistoryStore
) -> None:
    """Negative emission: a generic escalation.opened (non-depth level) appended
    through the hooked store emits NO subagent event (only the decision_audit
    mirror)."""
    collected = await _emitter_with_collector(engine, decision_store)
    await decision_store.append(
        DecisionRecord(
            decision_type="escalation.opened",
            request_id="portal-esc-1",
            tenant_id="bank-a",
            payload={"level": "sla_breach"},
        )
    )
    assert _subagent_events(collected) == []


# ---------------------------------------------------------------------------
# shape/evidence from the REAL T6 depth-refusal path
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_real_depth_refusal_writes_recursion_capped_keying_row(
    engine: AsyncEngine,
) -> None:
    """The real T6 depth path writes the escalation.opened row the projector
    keys on: level=depth_exceeded + request_id startswith subagent-spawn-.
    The unused deps (scheduler/audit/runner/parent_budget) are dummies — the
    depth check raises before any of them is touched; only EscalationStore is
    real. Closes the chain: real-path row shape -> projector -> recursion_capped."""
    spawner = SubAgentSpawner(
        scheduler=cast(Any, object()),
        audit=cast(Any, object()),
        child_runner=cast(Any, object()),
        escalation=EscalationStore(engine),
        parent_budget=cast(Any, object()),
        max_recursion_depth=3,
    )
    with pytest.raises(SubAgentDepthExceeded):
        await spawner.spawn(
            request=SubAgentSpawnRequest(
                prompt="verify",
                parent_tool_allow_list=frozenset({"aml_check"}),
                requested_tool_allow_list=frozenset({"aml_check"}),
                current_depth=3,  # child would be depth 4 > max 3
                requested_estimated_tokens=100,
                tenant_id="bank-a",
                parent_task_id=None,
            ),
            pack_id="cognic-tool-aml",
            actor=TaskActor(subject="orch", tenant_id="bank-a", actor_type="service"),
            class_="interactive",
            pack_kind="tool",
            pack_risk_tier="internal_write",
            parent_trace_id="ptrace",
        )

    rows = await _all_rows(engine)
    esc = [r for r in rows if r.event_type == "escalation.opened"]
    assert len(esc) == 1
    # the exact fields the projector consumes:
    assert esc[0].payload["level"] == "depth_exceeded"
    assert esc[0].request_id.startswith("subagent-spawn-")
    # and THAT row's snapshot projects to recursion_capped:
    evt = _project_typed_decision_history(
        _snap(
            decision_type="escalation.opened",
            payload=esc[0].payload,
            request_id=esc[0].request_id,
        )
    )
    assert isinstance(evt, SubagentRecursionCapped)

"""Sprint 11 — sub-agent audit emitter per ADR-005 §Audit. Emits the four
parent-chain events + the child genesis record, linked to the parent spawn
row by payload['parent_record_id']. Consumes DecisionHistoryStore.append;
does NOT edit core/decision_history.py or core/canonical.py. Critical-
controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.subagent._types import SUBAGENT_ISO_CONTROLS

ReturnOutcome = Literal["completed", "failed", "pending_approval"]


class SubAgentAuditEmitter:
    """Thin emitter over the decision-history chain. One instance per request
    flow; each method appends exactly one chain row and returns its record_id."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history

    async def emit_spawn(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_trace_id: str,
        child_request: dict[str, Any],
        policy_snapshot: dict[str, Any],
    ) -> uuid.UUID:
        """Emit subagent.spawn on the parent chain. Returns the spawn row's
        record_id — the value every child row carries as parent_record_id."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.spawn",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_trace_id": parent_trace_id,
                    "child_request": child_request,
                    "policy": policy_snapshot,
                },
            )
        )
        return record_id

    async def emit_child_genesis(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        child_trace_id: str,
    ) -> uuid.UUID:
        """Emit subagent.start — the child's own genesis record, linked to the
        parent spawn row by payload['parent_record_id']."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.start",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_record_id": str(parent_record_id),
                    "child_trace_id": child_trace_id,
                },
            )
        )
        return record_id

    async def emit_return(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        result_summary: str,
        outcome: ReturnOutcome,
        approval_request_id: str | None = None,
        run_id: str | None = None,
    ) -> uuid.UUID:
        """Emit subagent.return on the parent chain. The approval/run ids are
        added to the payload ONLY when non-None (the pending-approval path), so
        every existing non-pending return row stays byte-identical."""
        payload: dict[str, Any] = {
            "parent_record_id": str(parent_record_id),
            "result_summary": result_summary,
            "outcome": outcome,
        }
        if approval_request_id is not None:
            payload["approval_request_id"] = approval_request_id
        if run_id is not None:
            payload["run_id"] = run_id
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.return",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload=payload,
            )
        )
        return record_id

    async def emit_budget(
        self,
        *,
        actor_id: str,
        tenant_id: str,
        request_id: str,
        parent_record_id: uuid.UUID,
        tokens_used: int,
        wall_time_used_s: float,
    ) -> uuid.UUID:
        """Emit subagent.budget on the parent chain."""
        record_id, _ = await self._history.append(
            DecisionRecord(
                decision_type="subagent.budget",
                request_id=request_id,
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=SUBAGENT_ISO_CONTROLS,
                payload={
                    "parent_record_id": str(parent_record_id),
                    "tokens_used": tokens_used,
                    "wall_time_used_s": wall_time_used_s,
                },
            )
        )
        return record_id

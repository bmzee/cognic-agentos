"""Sprint 11 — cross-agent sub-agent linkage verifier per ADR-005 §Audit.
Mirrors core/chain_verifier.verify_suspend_wake_linkage: per-row payload
linkage (lookup-by-record_id + decision_type assert + tenant-column parity
+ causal sequence ordering), independent of the hash-walk (hash integrity is
the separate, existing guarantee). NOT a literal Merkle tree. New module — no
edit to core/chain_verifier.py. Critical-controls (subagent/ stop-rule)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.decision_history import _decision_history

# Only the child-linked sub-agent rows carry payload['parent_record_id'].
# Filtering on event_type (NOT payload-key presence) mirrors
# verify_suspend_wake_linkage and ignores foreign rows that reuse the key.
_LINKED_EVENT_TYPES = frozenset({"subagent.start", "subagent.return", "subagent.budget"})

SubAgentLinkageBreakKind = Literal[
    "child_missing_parent_record_id",
    "parent_row_not_found",
    "parent_record_id_wrong_decision_type",
    "tenant_id_mismatch",
    "parent_row_not_before_child_row",
]


@dataclass(frozen=True)
class SubAgentLinkageReport:
    is_clean: bool
    records_checked: int
    first_break_record_id: uuid.UUID | None = None
    break_kind: SubAgentLinkageBreakKind | None = None
    detail: str | None = None


def _coerce_record_id(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


async def verify_subagent_linkage(engine: AsyncEngine) -> SubAgentLinkageReport:
    """Verify parent-child sub-agent linkage over the decision_history chain.
    For every subagent.start/return/budget row, assert: (1) the parent row
    exists, (2) it is a subagent.spawn row, (3) tenant_id parity (ROW column),
    (4) parent.sequence < child.sequence. First-break semantics."""
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                select(_decision_history).order_by(_decision_history.c.sequence.asc())
            )
        ).all()

    rows_by_record_id: dict[uuid.UUID, Any] = {_coerce_record_id(r.record_id): r for r in rows}
    checked = 0
    for row in rows:
        if row.event_type not in _LINKED_EVENT_TYPES:
            continue  # foreign rows (incl. the spawn root) carry no parent link
        checked += 1
        child_id = _coerce_record_id(row.record_id)
        payload: dict[str, Any] = row.payload or {}
        raw_parent = payload.get("parent_record_id")
        if not isinstance(raw_parent, str) or raw_parent == "":
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="child_missing_parent_record_id",
                detail=f"row {child_id} has non-string payload['parent_record_id']={raw_parent!r}",
            )
        try:
            parent_id = uuid.UUID(raw_parent)
        except ValueError:
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="child_missing_parent_record_id",
                detail=f"row {child_id} has non-UUID parent_record_id={raw_parent!r}",
            )

        parent_row = rows_by_record_id.get(parent_id)
        if parent_row is None:
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="parent_row_not_found",
                detail=(
                    f"row {child_id} points at parent_record_id={parent_id} with no matching row"
                ),
            )
        if parent_row.event_type != "subagent.spawn":
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="parent_record_id_wrong_decision_type",
                detail=f"parent row {parent_id} is {parent_row.event_type!r}, not 'subagent.spawn'",
            )
        if row.tenant_id != parent_row.tenant_id:
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="tenant_id_mismatch",
                detail=(
                    f"child tenant_id={row.tenant_id!r} != "
                    f"parent tenant_id={parent_row.tenant_id!r}"
                ),
            )
        if int(parent_row.sequence) >= int(row.sequence):
            return SubAgentLinkageReport(
                is_clean=False,
                records_checked=checked,
                first_break_record_id=child_id,
                break_kind="parent_row_not_before_child_row",
                detail=f"parent seq {parent_row.sequence} not before child seq {row.sequence}",
            )

    return SubAgentLinkageReport(is_clean=True, records_checked=checked)

"""Bank-owned approval assignments (M8.5-D D2 phase A).

An assignment is current operational state keyed by ``(tenant_id,
tool_identity)``. Every mutation is atomic with an append-only
``approval.assignment_changed`` decision-history row. An absent assignment
means the existing tier policy governs; an empty assignment is deliberately
unrepresentable so assignment data can tighten but never loosen that policy.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Final, Literal

import sqlalchemy as sa
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.approval._types import ApprovalActor
from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.types import GovernanceJSON

ApprovalAssignmentInvalidReason = Literal[
    "assignment_empty",
    "assignment_subject_duplicate",
    "assignment_actor_not_human",
]

_ASSIGNMENT_ISO_CONTROLS: Final[tuple[str, ...]] = (
    "ISO42001.A.6.2.5",
    "ISO42001.A.9.2",
)

_approval_assignments = sa.Table(
    "approval_assignments",
    _metadata,
    sa.Column("tenant_id", sa.String(128), primary_key=True),
    sa.Column("tool_identity", sa.String(256), primary_key=True),
    sa.Column("approver_subjects", GovernanceJSON(), nullable=False),
    sa.Column("updated_by", sa.String(256), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalEligibility:
    eligible_approvers: frozenset[str]
    required_count: int


class ApprovalAssignmentInvalid(Exception):
    def __init__(self, reason: ApprovalAssignmentInvalidReason) -> None:
        super().__init__(reason)
        self.reason: ApprovalAssignmentInvalidReason = reason


class _AssignmentAbsent(Exception):
    """Internal rollback signal for an idempotent absent unassignment."""


def _normalise_subjects(approver_subjects: tuple[str, ...]) -> tuple[str, ...]:
    if not approver_subjects:
        raise ApprovalAssignmentInvalid("assignment_empty")
    if len(set(approver_subjects)) != len(approver_subjects):
        raise ApprovalAssignmentInvalid("assignment_subject_duplicate")
    return tuple(sorted(approver_subjects))


def _require_human(actor: ApprovalActor) -> None:
    if actor.actor_type != "human":
        raise ApprovalAssignmentInvalid("assignment_actor_not_human")


class ApprovalAssignmentStore:
    """Tenant-scoped assignment state plus chain-atomic mutation evidence."""

    def __init__(self, history: DecisionHistoryStore) -> None:
        self._history = history
        self._engine: AsyncEngine = history._engine

    async def resolve(self, *, tenant_id: str, tool_identity: str) -> ApprovalEligibility | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_approval_assignments.c.approver_subjects).where(
                        _approval_assignments.c.tenant_id == tenant_id,
                        _approval_assignments.c.tool_identity == tool_identity,
                    )
                )
            ).first()
        if row is None:
            return None
        subjects = frozenset(str(subject) for subject in row.approver_subjects)
        return ApprovalEligibility(
            eligible_approvers=subjects,
            required_count=len(subjects),
        )

    async def assign(
        self,
        *,
        tenant_id: str,
        tool_identity: str,
        approver_subjects: tuple[str, ...],
        actor: ApprovalActor,
        request_request_id: str,
    ) -> ApprovalEligibility:
        _require_human(actor)
        subjects = _normalise_subjects(approver_subjects)
        now = datetime.now(UTC)

        async def _precondition(
            conn: AsyncConnection, _sequence: int, _hash: bytes
        ) -> tuple[str, ...]:
            row = (
                await conn.execute(
                    select(_approval_assignments.c.approver_subjects)
                    .where(
                        _approval_assignments.c.tenant_id == tenant_id,
                        _approval_assignments.c.tool_identity == tool_identity,
                    )
                    .with_for_update()
                )
            ).first()
            previous = (
                tuple(sorted(str(subject) for subject in row.approver_subjects))
                if row is not None
                else ()
            )
            if row is None:
                await conn.execute(
                    insert(_approval_assignments).values(
                        tenant_id=tenant_id,
                        tool_identity=tool_identity,
                        approver_subjects=list(subjects),
                        updated_by=actor.subject,
                        updated_at=now,
                    )
                )
            else:
                await conn.execute(
                    update(_approval_assignments)
                    .where(
                        _approval_assignments.c.tenant_id == tenant_id,
                        _approval_assignments.c.tool_identity == tool_identity,
                    )
                    .values(
                        approver_subjects=list(subjects),
                        updated_by=actor.subject,
                        updated_at=now,
                    )
                )
            return previous

        def _build(previous: tuple[str, ...]) -> DecisionRecord:
            return self._record(
                tenant_id=tenant_id,
                tool_identity=tool_identity,
                previous=previous,
                current=subjects,
                actor=actor,
                request_request_id=request_request_id,
            )

        await self._history.append_with_precondition(
            record_builder=_build,
            precondition=_precondition,
        )
        return ApprovalEligibility(
            eligible_approvers=frozenset(subjects),
            required_count=len(subjects),
        )

    async def unassign(
        self,
        *,
        tenant_id: str,
        tool_identity: str,
        actor: ApprovalActor,
        request_request_id: str,
    ) -> bool:
        _require_human(actor)

        async def _precondition(
            conn: AsyncConnection, _sequence: int, _hash: bytes
        ) -> tuple[str, ...]:
            row = (
                await conn.execute(
                    select(_approval_assignments.c.approver_subjects)
                    .where(
                        _approval_assignments.c.tenant_id == tenant_id,
                        _approval_assignments.c.tool_identity == tool_identity,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise _AssignmentAbsent
            previous = tuple(sorted(str(subject) for subject in row.approver_subjects))
            await conn.execute(
                delete(_approval_assignments).where(
                    _approval_assignments.c.tenant_id == tenant_id,
                    _approval_assignments.c.tool_identity == tool_identity,
                )
            )
            return previous

        def _build(previous: tuple[str, ...]) -> DecisionRecord:
            return self._record(
                tenant_id=tenant_id,
                tool_identity=tool_identity,
                previous=previous,
                current=(),
                actor=actor,
                request_request_id=request_request_id,
            )

        try:
            await self._history.append_with_precondition(
                record_builder=_build,
                precondition=_precondition,
            )
        except _AssignmentAbsent:
            return False
        return True

    @staticmethod
    def _record(
        *,
        tenant_id: str,
        tool_identity: str,
        previous: tuple[str, ...],
        current: tuple[str, ...],
        actor: ApprovalActor,
        request_request_id: str,
    ) -> DecisionRecord:
        return DecisionRecord(
            decision_type="approval.assignment_changed",
            request_id=request_request_id,
            tenant_id=tenant_id,
            actor_id=actor.subject,
            iso_controls=_ASSIGNMENT_ISO_CONTROLS,
            payload={
                "tenant_id": tenant_id,
                "tool_identity": tool_identity,
                "previous_subjects": list(previous),
                "new_subjects": list(current),
                "actor_subject": actor.subject,
            },
        )


__all__ = (
    "ApprovalAssignmentInvalid",
    "ApprovalAssignmentInvalidReason",
    "ApprovalAssignmentStore",
    "ApprovalEligibility",
)

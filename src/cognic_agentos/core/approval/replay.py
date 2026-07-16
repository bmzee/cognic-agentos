"""Erasable custody for the exact bytes approved for replay (D2 phase B).

The approval envelope and decision-history rows remain value-free. This
separate table is the only durable copy of canonical arguments and terminal
results. Both write and read paths recompute their SHA-256 digests, while
erasure removes values but retains the row and digests as evidence.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Literal

import sqlalchemy as sa
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import _metadata

ApprovalReplayUnavailableReason = Literal[
    "replay_not_persisted",
    "replay_erased",
    "replay_digest_mismatch",
]

_TS = sa.TIMESTAMP(timezone=True)

_approval_replay_payloads = sa.Table(
    "approval_replay_payloads",
    _metadata,
    sa.Column(
        "request_id",
        sa.Uuid(),
        sa.ForeignKey(
            "approval_requests.request_id",
            name="fk_approval_replay_payloads_request",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    sa.Column("tenant_id", sa.String(128), nullable=False),
    sa.Column("canonical_args", sa.LargeBinary(), nullable=True),
    sa.Column("args_digest", sa.LargeBinary(), nullable=False),
    sa.Column("result_canonical", sa.LargeBinary(), nullable=True),
    sa.Column("result_digest", sa.LargeBinary(), nullable=True),
    sa.Column("created_at", _TS, nullable=False),
    sa.Column("executed_at", _TS, nullable=True),
    sa.Column("erased_at", _TS, nullable=True),
)


class ApprovalReplayUnavailable(Exception):
    """Replay material is absent, erased, or fails digest verification."""

    def __init__(self, reason: ApprovalReplayUnavailableReason) -> None:
        super().__init__(reason)
        self.reason: ApprovalReplayUnavailableReason = reason


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _build_persist_statement(
    *,
    request_id: uuid.UUID,
    tenant_id: str,
    canonical_args: bytes,
    args_digest: bytes,
    created_at: datetime,
) -> sa.Insert:
    """Validate the derived digest and build the one replay-row insert.

    ``ApprovalRequestStore.create_request_row`` consumes this helper inside
    its chain-atomic precondition so a replay-write failure cannot leave a
    visible pending request. The public :meth:`persist` method uses the same
    builder, keeping both write paths on one digest gate.
    """
    if _digest(canonical_args) != args_digest:
        raise ApprovalReplayUnavailable("replay_digest_mismatch")
    return insert(_approval_replay_payloads).values(
        request_id=request_id,
        tenant_id=tenant_id,
        canonical_args=canonical_args,
        args_digest=args_digest,
        result_canonical=None,
        result_digest=None,
        created_at=created_at,
        executed_at=None,
        erased_at=None,
    )


class ApprovalReplayStore:
    """Tenant-scoped value store with verification at every custody edge."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def persist(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        canonical_args: bytes,
        args_digest: bytes,
    ) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                _build_persist_statement(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    canonical_args=canonical_args,
                    args_digest=args_digest,
                    created_at=datetime.now(UTC),
                )
            )

    async def load(self, *, request_id: uuid.UUID, tenant_id: str) -> bytes:
        row = await self._load_row(request_id=request_id, tenant_id=tenant_id)
        if row is None:
            raise ApprovalReplayUnavailable("replay_not_persisted")
        if row.erased_at is not None:
            raise ApprovalReplayUnavailable("replay_erased")
        if row.canonical_args is None:
            raise ApprovalReplayUnavailable("replay_digest_mismatch")
        canonical_args = bytes(row.canonical_args)
        if _digest(canonical_args) != bytes(row.args_digest):
            raise ApprovalReplayUnavailable("replay_digest_mismatch")
        return canonical_args

    async def record_result(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        result_canonical: bytes,
        executed_at: datetime,
    ) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(_approval_replay_payloads)
                .where(
                    _approval_replay_payloads.c.request_id == request_id,
                    _approval_replay_payloads.c.tenant_id == tenant_id,
                    _approval_replay_payloads.c.erased_at.is_(None),
                )
                .values(
                    result_canonical=result_canonical,
                    result_digest=_digest(result_canonical),
                    executed_at=executed_at,
                )
            )
            if result.rowcount == 1:
                return
            row = (
                await conn.execute(
                    select(_approval_replay_payloads.c.erased_at).where(
                        _approval_replay_payloads.c.request_id == request_id,
                        _approval_replay_payloads.c.tenant_id == tenant_id,
                    )
                )
            ).first()
        if row is None:
            raise ApprovalReplayUnavailable("replay_not_persisted")
        raise ApprovalReplayUnavailable("replay_erased")

    async def load_result(self, *, request_id: uuid.UUID, tenant_id: str) -> bytes | None:
        row = await self._load_row(request_id=request_id, tenant_id=tenant_id)
        if row is None:
            raise ApprovalReplayUnavailable("replay_not_persisted")
        if row.erased_at is not None:
            raise ApprovalReplayUnavailable("replay_erased")
        if row.result_canonical is None and row.result_digest is None:
            return None
        if row.result_canonical is None or row.result_digest is None:
            raise ApprovalReplayUnavailable("replay_digest_mismatch")
        result = bytes(row.result_canonical)
        if _digest(result) != bytes(row.result_digest):
            raise ApprovalReplayUnavailable("replay_digest_mismatch")
        return result

    async def erase(self, *, request_id: uuid.UUID, tenant_id: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(_approval_replay_payloads)
                .where(
                    _approval_replay_payloads.c.request_id == request_id,
                    _approval_replay_payloads.c.tenant_id == tenant_id,
                    _approval_replay_payloads.c.erased_at.is_(None),
                )
                .values(
                    canonical_args=None,
                    result_canonical=None,
                    erased_at=datetime.now(UTC),
                )
            )
        return result.rowcount == 1

    async def _load_row(
        self, *, request_id: uuid.UUID, tenant_id: str
    ) -> sa.Row[tuple[object, ...]] | None:
        async with self._engine.connect() as conn:
            return (
                await conn.execute(
                    select(_approval_replay_payloads).where(
                        _approval_replay_payloads.c.request_id == request_id,
                        _approval_replay_payloads.c.tenant_id == tenant_id,
                    )
                )
            ).first()


__all__ = (
    "ApprovalReplayStore",
    "ApprovalReplayUnavailable",
    "ApprovalReplayUnavailableReason",
)

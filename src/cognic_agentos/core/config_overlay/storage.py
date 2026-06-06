"""ADR-023 storage — current state in a table, immutable history in the chain.

Mutation uses the in-closure ``append_with_precondition`` pattern (mirrors
``packs/storage.py``): the upsert/delete runs INSIDE the precondition closure so
the overlay row + chain row + chain head commit in one transaction
(``DecisionHistoryStore.append_with_precondition`` owns the single
``engine.begin()`` envelope; any raise rolls back all three). The chain
``record_id`` is minted AFTER the closure, so the row back-links by
``last_request_id`` (== ``DecisionRecord.request_id``), not by ``record_id``.

Writing the (NON-chain) ``tenant_config_overlay`` table from inside the
precondition is the documented pattern — the precondition contract only forbids
mutating *chain* tables (``packs/storage.py`` likewise UPDATEs its ``packs``
state-cache row in-closure).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.config_overlay.registry import (
    overridable_field,
    validate_tighten_only,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.types import GovernanceJSON

_ISO_A_6_2_5 = "ISO42001.A.6.2.5"

# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
# Mirrors the 0007 migration's column type exactly.
_tenant_config_overlay = sa.Table(
    "tenant_config_overlay",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(length=128), nullable=False),
    sa.Column("field_key", sa.String(length=128), nullable=False),
    sa.Column("value", GovernanceJSON(), nullable=False),
    sa.Column("set_by_actor", sa.String(length=256), nullable=False),
    sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_request_id", sa.String(length=64), nullable=False),
    sa.UniqueConstraint("tenant_id", "field_key", name="uq_tenant_config_overlay_tenant_field"),
    sa.Index("ix_tenant_config_overlay_tenant_id", "tenant_id"),
)


@dataclass(frozen=True, slots=True)
class TenantConfigOverlayRow:
    tenant_id: str
    field_key: str
    value: int | float
    set_by_actor: str
    set_at: datetime
    last_request_id: str


class TenantConfigOverlayStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._dh = DecisionHistoryStore(engine)

    async def get_many(self, tenant_id: str, field_keys: tuple[str, ...]) -> dict[str, int | float]:
        if not field_keys:
            return {}
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _tenant_config_overlay.c.field_key,
                        _tenant_config_overlay.c.value,
                    )
                    .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                    .where(_tenant_config_overlay.c.field_key.in_(field_keys))
                )
            ).fetchall()
        return {r.field_key: r.value for r in rows}

    async def list_for_tenant(self, tenant_id: str) -> list[TenantConfigOverlayRow]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_tenant_config_overlay).where(
                        _tenant_config_overlay.c.tenant_id == tenant_id
                    )
                )
            ).fetchall()
        return [
            TenantConfigOverlayRow(
                tenant_id=r.tenant_id,
                field_key=r.field_key,
                value=r.value,
                set_by_actor=r.set_by_actor,
                set_at=r.set_at,
                last_request_id=r.last_request_id,
            )
            for r in rows
        ]

    async def set_overlay(
        self,
        *,
        tenant_id: str,
        field_key: str,
        base_value: int | float,
        proposed: object,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        field = overridable_field(field_key)  # preflight default-deny
        accepted = validate_tighten_only(  # cheap pre-check (refuse before the lock)
            field, base_value=base_value, proposed=proposed
        )

        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(_tenant_config_overlay.c.value)
                    .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                    .where(_tenant_config_overlay.c.field_key == field_key)
                    .with_for_update()
                )
            ).first()
            previous = row.value if row is not None else None
            # Authoritative re-check under the lock (deterministic; defence-in-depth,
            # mirrors packs/storage validating inside the precondition closure).
            validate_tighten_only(field, base_value=base_value, proposed=proposed)
            now = datetime.now(UTC)
            if row is None:
                await conn.execute(
                    insert(_tenant_config_overlay).values(
                        id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        field_key=field_key,
                        value=accepted,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            else:
                await conn.execute(
                    update(_tenant_config_overlay)
                    .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                    .where(_tenant_config_overlay.c.field_key == field_key)
                    .values(
                        value=accepted,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="config.tenant_overlay.set",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=(_ISO_A_6_2_5,),
                payload={
                    "tenant_id": tenant_id,
                    "field_key": field_key,
                    "direction": field.direction,
                    "base_value": base_value,
                    "overlay_value": accepted,
                    "previous_overlay_value": captured["previous"],
                    "actor_subject": actor_subject,
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

    async def clear_overlay(
        self,
        *,
        tenant_id: str,
        field_key: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        field = overridable_field(field_key)

        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(_tenant_config_overlay.c.value)
                    .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                    .where(_tenant_config_overlay.c.field_key == field_key)
                    .with_for_update()
                )
            ).first()
            previous = row.value if row is not None else None
            await conn.execute(
                delete(_tenant_config_overlay)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                .where(_tenant_config_overlay.c.field_key == field_key)
            )
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="config.tenant_overlay.cleared",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=(_ISO_A_6_2_5,),
                payload={
                    "tenant_id": tenant_id,
                    "field_key": field_key,
                    "direction": field.direction,
                    "previous_overlay_value": captured["previous"],
                    "actor_subject": actor_subject,
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

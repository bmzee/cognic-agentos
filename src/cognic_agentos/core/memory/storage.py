"""Governed-memory storage Protocol + relational Table — Sprint 11.5a per ADR-019.

CRITICAL CONTROL (core/ stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). This module owns the persistence CONTRACT for the
memory substrate:

  * ``MemoryAdapter`` — the structural Protocol every concrete backend
    (PostgresMemoryAdapter / RedisMemoryAdapter) MUST satisfy. Those
    concrete adapters are Task 6 and are NOT in this module — T5 ships
    the contract only.
  * ``_memory_records`` — the in-process SQLAlchemy Table mirroring the
    ``memory_records`` table created by the ``0006`` migration. The Table
    here MUST agree column-for-column (type, length, nullability) with
    ``db/migrations/versions/20260531_0006_memory.py``; drift is pinned
    by ``tests/unit/db/test_migration_20260531_0006.py`` which reflects
    the migrated DB and compiles both for the SQLite dialect.
  * ``MemoryBackendUnavailable`` — an INFRA exception. It is deliberately
    NOT a ``MemoryOperationRefused`` subclass: a backend-down condition is
    not a governance refusal and must not be confused with the wire-public
    closed-enum ``MemoryRefusalReason`` taxonomy.

**Driver-import discipline (kernel-clean invariant).** The two concrete
adapters below take their backend handle by INJECTION — a SQLAlchemy
``AsyncEngine`` (Postgres; SQLAlchemy resolves the ``asyncpg`` driver
from the URL) or a duck-typed redis client (has async ``set``). Neither
``asyncpg`` nor ``redis`` is imported at module level: ``redis`` lives in
the ``[adapters]`` extra (NOT base deps), so ``import
cognic_agentos.core.memory.storage`` MUST succeed without the adapters
extra installed. ``RedisMemoryAdapter`` resolves redis exception types
LAZILY inside the write path so construction never needs the package.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.memory._context import (
    BlockRef,
    MemoryHit,
    MemoryRecordId,
    MemoryWriteRecord,
    RedactionReceipt,
    RedactionSpan,
    RegulatorErasureCommand,
)
from cognic_agentos.core.memory.tiers import (
    BlockKind,
    ForgetReason,
    MemoryOperationRefused,
    MemoryTier,
    RedactionReason,
    SubjectRef,
)
from cognic_agentos.db.types import GovernanceJSON

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

#: ISO 42001 control tuple stamped on every ``memory.write`` chain row.
#: A.7.4 (impact assessment) / A.8.2 (data quality) / A.8.5 (data
#: provenance) / A.10.2 (recorded information) per ADR-019 + ADR-006.
#: Tuple at the boundary; ``DecisionHistoryStore`` converts to a list
#: before ``canonical_bytes`` (which rejects tuples).
_MEMORY_WRITE_ISO_CONTROLS: tuple[str, ...] = ("A.7.4", "A.8.2", "A.8.5", "A.10.2")

#: Pin: ``sa.TIMESTAMP(timezone=True)`` — NOT ``sa.DateTime(timezone=True)``.
#: ``sa.DateTime`` compiles to ``DATE`` on Oracle, silently dropping the
#: offset. Mirrors ``SCHEDULER_TS_TYPE`` in the 0005 migration.
MEMORY_TS_TYPE = sa.TIMESTAMP(timezone=True)


@runtime_checkable
class MemoryAdapter(Protocol):
    """Structural contract for governed-memory persistence backends.

    Concrete adapters (Postgres / Redis) land in Task 6 and structurally
    conform to this Protocol — they are NOT defined in this module."""

    async def put(self, record: MemoryWriteRecord) -> MemoryRecordId: ...

    async def get(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        subject: SubjectRef,
        tier: MemoryTier,
        key: str | None = None,
        block_kind: BlockKind | None = None,
    ) -> MemoryHit | None: ...

    async def list_for_subject(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[MemoryHit]: ...

    async def list_blocks(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[BlockRef]: ...

    async def upsert_block(self, record: MemoryWriteRecord) -> MemoryRecordId: ...

    async def tombstone_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        reason: ForgetReason,
        actor_id: str,
    ) -> None: ...

    async def purge_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        erasure_command: RegulatorErasureCommand,
        actor_id: str,
    ) -> None: ...

    async def purge_expired(self, *, tombstone_window_s: int) -> int: ...

    async def redact_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        span: RedactionSpan,
        reason: RedactionReason,
        actor_id: str,
    ) -> RedactionReceipt: ...


class MemoryBackendUnavailable(Exception):
    """Infra failure (backend unreachable / driver error).

    Deliberately a plain ``Exception`` — NOT a ``MemoryOperationRefused``
    subclass. An unreachable backend is not a governance refusal and must
    not be mistaken for the wire-public ``MemoryRefusalReason`` taxonomy."""


_metadata = sa.MetaData()

#: In-process Table mirroring the ``memory_records`` table from the 0006
#: migration. Column type / length / nullability MUST be byte-identical to
#: the migration — pinned by ``test_migration_20260531_0006`` which compiles
#: both for the SQLite dialect and asserts equality.
_memory_records = sa.Table(
    "memory_records",
    _metadata,
    sa.Column("record_id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(128), nullable=False),
    sa.Column("subject_ref", sa.String(256), nullable=False),
    sa.Column("agent_id", sa.String(128), nullable=False),
    sa.Column("tier", sa.String(16), nullable=False),
    sa.Column("block_kind", sa.String(32), nullable=True),
    sa.Column("key", sa.String(256), nullable=True),
    sa.Column("value", GovernanceJSON(), nullable=False),
    sa.Column("data_classes", GovernanceJSON(), nullable=False),
    sa.Column("purpose", sa.String(64), nullable=False),
    sa.Column("retention_until", MEMORY_TS_TYPE, nullable=True),
    sa.Column("tombstone", MEMORY_TS_TYPE, nullable=True),
    sa.Column("redaction_version", sa.Integer(), nullable=False),
    sa.Column("sealed_prior_version_ref", sa.Uuid(), nullable=True),
    sa.Column("vector_ref", sa.String(256), nullable=True),
    sa.Column("created_at", MEMORY_TS_TYPE, nullable=False),
    sa.CheckConstraint(
        "(key IS NOT NULL AND block_kind IS NULL) OR (key IS NULL AND block_kind IS NOT NULL)",
        name="ck_memory_records_key_xor_block_kind",
    ),
)


def _value_digest(value: object) -> str:
    """SHA-256 of the canonical JSON bytes of ``value``.

    This is the ONLY representation of a memory value that may enter the
    hash chain — the raw value lives solely in the ``memory_records.value``
    column (default-deny long-term, regulator-erasure pathway per ADR-019).
    Uses ``core/canonical.canonical_bytes`` so the digest is stable across
    Python versions + platforms."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _apply_redaction(value: object, path: tuple[str, ...], replacement: object) -> object:
    """Deep-copy ``value`` and replace the leaf at ``path`` with ``replacement``.

    Raises ``ValueError`` on an empty path, a missing key, or a non-mapping
    midpoint — the caller maps the error to ``memory_redaction_path_invalid``
    (locked: field-path only, NOT byte-span or regex).

    The original ``value`` is NEVER mutated (deep copy is the contract)."""

    if not path:
        raise ValueError("redaction path must be non-empty")
    out = copy.deepcopy(value)
    cursor = out
    for seg in path[:-1]:
        if not isinstance(cursor, dict) or seg not in cursor:
            raise ValueError(f"redaction path segment {seg!r} not a mapping key")
        cursor = cursor[seg]
    leaf = path[-1]
    if not isinstance(cursor, dict) or leaf not in cursor:
        raise ValueError(f"redaction leaf {leaf!r} absent")
    cursor[leaf] = replacement
    return out


class PostgresMemoryAdapter:
    """Relational governed-memory backend for the ``task`` + ``long_term``
    tiers (and the long_term singleton blocks).

    A ``DecisionHistoryStore.append_with_precondition`` consumer: every
    ``put`` / ``upsert_block`` inserts the ``memory_records`` row INSIDE the
    chain-head ``FOR UPDATE`` locked transaction (the precondition), then
    appends one ``memory.write`` chain row carrying the value DIGEST (never
    the raw value) atomically with the row. Mirrors the
    ``core/scheduler/storage.py`` precondition shape exactly.

    Structurally conforms to :class:`MemoryAdapter`. Public methods are
    async + raise on every failure path (production-grade rule). The recall
    surfaces (:meth:`get` / :meth:`list_for_subject` / :meth:`list_blocks`)
    are implemented (Sprint 11.5a T10) and **agent-scoped** — each takes a
    required ``agent_id`` and filters on it, since a record belongs to the
    agent that wrote it (the block singleton identity is
    ``(tenant, subject, agent, kind)``)."""

    def __init__(self, *, engine: AsyncEngine, dh_store: DecisionHistoryStore) -> None:
        self._engine = engine
        self._dh = dh_store

    def _build_write_record(self, record: MemoryWriteRecord, rid: uuid.UUID) -> DecisionRecord:
        """Build the ``memory.write`` ``DecisionRecord``. The payload carries
        ``redacted_value_digest`` — NEVER the raw ``record.value``. The
        per-write GATE audit (consent / DLP / purpose) lands in later tasks;
        T6 emits only the storage-level ``memory.write`` event."""

        return DecisionRecord(
            decision_type="memory.write",
            request_id=record.request_id,
            payload={
                "tier": record.tier,
                "data_classes": list(record.data_classes),
                "purpose": record.purpose,
                "retention_until": (
                    record.retention_until.isoformat() if record.retention_until else None
                ),
                "record_id": str(rid),
                "subject_ref": record.subject.canonical,
                "block_kind": record.block_kind,
                "redacted_value_digest": _value_digest(record.value),
            },
            actor_id=record.actor_id,
            tenant_id=record.tenant_id,
            iso_controls=_MEMORY_WRITE_ISO_CONTROLS,
        )

    async def put(self, record: MemoryWriteRecord) -> MemoryRecordId:
        """Insert a keyed ``memory_records`` row + append one ``memory.write``
        chain row atomically. Returns the generated record id.

        ``append_with_precondition`` returns ``(event_id, new_hash)`` — NOT
        the record id — so the id is generated up front + captured by the
        closures."""

        if record.tier not in ("task", "long_term"):
            raise ValueError(
                "PostgresMemoryAdapter persists task/long_term only; got "
                f"tier={record.tier!r} — scratch must route to RedisMemoryAdapter"
            )

        rid = uuid.uuid4()
        now = datetime.now(UTC)

        async def _precondition(
            conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes
        ) -> uuid.UUID:
            # INSERT under the chain-head FOR UPDATE lock. If the INSERT
            # raises, the outer engine.begin() rolls back — no chain row.
            await conn.execute(
                _memory_records.insert().values(
                    record_id=rid,
                    tenant_id=record.tenant_id,
                    subject_ref=record.subject.canonical,
                    agent_id=record.agent_id,
                    tier=record.tier,
                    block_kind=None,
                    key=record.key,
                    value=record.value,
                    data_classes=list(record.data_classes),
                    purpose=record.purpose,
                    retention_until=record.retention_until,
                    tombstone=None,
                    redaction_version=0,
                    sealed_prior_version_ref=None,
                    vector_ref=None,
                    created_at=now,
                )
            )
            return rid

        def _build_record(captured_rid: uuid.UUID) -> DecisionRecord:
            return self._build_write_record(record, captured_rid)

        await self._dh.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )
        return rid

    async def upsert_block(self, record: MemoryWriteRecord) -> MemoryRecordId:
        """Singleton block upsert: tombstone the prior active block for the
        ``(tenant, subject, agent, block_kind)`` quad, then insert the new
        version — both INSIDE the precondition so they commit atomically with
        the ``memory.write`` chain row. Returns the new version's record id.

        Blocks are keyless (``key=None``, ``block_kind`` set) per the
        ``ck_memory_records_key_xor_block_kind`` XOR constraint."""

        if record.tier != "long_term":
            raise ValueError(f"blocks are long_term-only; got tier={record.tier!r}")

        rid = uuid.uuid4()
        now = datetime.now(UTC)

        async def _precondition(
            conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes
        ) -> uuid.UUID:
            # Tombstone the prior active block (idempotent if none active),
            # then insert the new version. Both run under the chain-head
            # FOR UPDATE lock so the singleton invariant + the chain row
            # commit atomically.
            await conn.execute(
                sa.update(_memory_records)
                .where(
                    _memory_records.c.tenant_id == record.tenant_id,
                    _memory_records.c.subject_ref == record.subject.canonical,
                    _memory_records.c.agent_id == record.agent_id,
                    _memory_records.c.block_kind == record.block_kind,
                    _memory_records.c.tombstone.is_(None),
                )
                .values(tombstone=sa.func.now())
            )
            await conn.execute(
                _memory_records.insert().values(
                    record_id=rid,
                    tenant_id=record.tenant_id,
                    subject_ref=record.subject.canonical,
                    agent_id=record.agent_id,
                    tier=record.tier,
                    block_kind=record.block_kind,
                    key=None,
                    value=record.value,
                    data_classes=list(record.data_classes),
                    purpose=record.purpose,
                    retention_until=record.retention_until,
                    tombstone=None,
                    redaction_version=0,
                    sealed_prior_version_ref=None,
                    vector_ref=None,
                    created_at=now,
                )
            )
            return rid

        def _build_record(captured_rid: uuid.UUID) -> DecisionRecord:
            return self._build_write_record(record, captured_rid)

        await self._dh.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )
        return rid

    async def tombstone_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        reason: ForgetReason,
        actor_id: str,
    ) -> None:
        """Soft-delete a memory record by setting its tombstone timestamp.

        Runs inside a ``append_with_precondition`` transaction so the
        ``memory.forget`` chain row is emitted atomically with the tombstone
        UPDATE — or rolled back entirely if the precondition raises.

        Raises :class:`~cognic_agentos.core.memory.tiers.MemoryOperationRefused`
        with ``memory_record_not_found`` if no active (non-tombstoned) row
        exists, or ``memory_record_already_tombstoned`` if the row has already
        been tombstoned. The refusal is raised INSIDE the precondition so no
        chain row is written on the refused path."""

        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes) -> None:
            row = (
                await conn.execute(
                    sa.select(_memory_records)
                    .where(
                        _memory_records.c.record_id == record_id,
                        _memory_records.c.tenant_id == tenant_id,
                        _memory_records.c.agent_id == agent_id,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise MemoryOperationRefused("memory_record_not_found")
            if row.tombstone is not None:
                raise MemoryOperationRefused("memory_record_already_tombstoned")
            await conn.execute(
                sa.update(_memory_records)
                .where(
                    _memory_records.c.record_id == record_id,
                    _memory_records.c.tenant_id == tenant_id,
                    _memory_records.c.agent_id == agent_id,
                )
                .values(tombstone=now)
            )

        def _build_record(_captured: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="memory.forget",
                request_id=f"memory-forget-{record_id}",
                payload={
                    "record_id": str(record_id),
                    "reason": reason,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_MEMORY_WRITE_ISO_CONTROLS,
            )

        await self._dh.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def purge_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        erasure_command: RegulatorErasureCommand,
        actor_id: str,
    ) -> None:
        """Physically DELETE a memory record and emit a ``memory.regulator_erasure``
        chain row with chain-of-custody metadata (NO value, NO digest).

        The precondition verifies that the row's ``subject_ref`` matches
        ``human:{erasure_command.subject_id}``. A mismatch raises
        ``memory_regulator_erasure_metadata_required`` inside the precondition so
        the engine rolls back — nothing is deleted and no chain row is written.

        Value-never-in-chain invariant: the ``memory.regulator_erasure`` payload
        carries ONLY custody metadata (``regulator_order_id``, ``requester_scope``,
        ``subject_id``, ``record_id``, ``actor_id``). No ``value`` or
        ``redacted_value_digest``."""

        expected_subject_ref = f"human:{erasure_command.subject_id}"

        async def _precondition(conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes) -> None:
            row = (
                await conn.execute(
                    sa.select(_memory_records)
                    .where(
                        _memory_records.c.record_id == record_id,
                        _memory_records.c.tenant_id == tenant_id,
                        _memory_records.c.agent_id == agent_id,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise MemoryOperationRefused("memory_record_not_found")
            # Subject-mismatch guard: the purge command's subject_id must match
            # the stored subject_ref. Refuses inside the precondition so nothing
            # is deleted and no chain row is written.
            if row.subject_ref != expected_subject_ref:
                raise MemoryOperationRefused("memory_regulator_erasure_metadata_required")
            await conn.execute(
                sa.delete(_memory_records).where(
                    _memory_records.c.record_id == record_id,
                    _memory_records.c.tenant_id == tenant_id,
                    _memory_records.c.agent_id == agent_id,
                )
            )

        def _build_record(_captured: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="memory.regulator_erasure",
                request_id=f"memory-regulator-erasure-{record_id}",
                payload={
                    "record_id": str(record_id),
                    "regulator_order_id": erasure_command.regulator_order_id,
                    "requester_scope": erasure_command.requester_scope,
                    "subject_id": erasure_command.subject_id,
                    "actor_id": actor_id,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    # NOTE: NO "value" or "redacted_value_digest" — value-never-in-chain
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_MEMORY_WRITE_ISO_CONTROLS,
            )

        await self._dh.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )

    async def purge_expired(self, *, tombstone_window_s: int) -> int:
        """Physically DELETE rows that are past their retention or tombstone window.

        Deletes rows where:

        - ``tombstone IS NOT NULL AND tombstone < now - tombstone_window_s``
          (soft-deleted and aged out of the grace window)
        - ``retention_until IS NOT NULL AND retention_until < now``
          (retention-expired)

        Returns the number of rows deleted. Emits NO chain row — the
        ``memory.forget`` row written at tombstone time is the audit; physical
        purge is housekeeping (Doctrine F: off-gate ``MemoryTombstoneReaper``
        drives this method on a schedule)."""

        now = datetime.now(UTC)
        cut = now.replace(tzinfo=UTC) if now.tzinfo is None else now
        from datetime import timedelta

        tombstone_cut = cut - timedelta(seconds=tombstone_window_s)

        async with self._engine.begin() as conn:
            result = await conn.execute(
                sa.delete(_memory_records).where(
                    sa.or_(
                        sa.and_(
                            _memory_records.c.tombstone.isnot(None),
                            _memory_records.c.tombstone < tombstone_cut,
                        ),
                        sa.and_(
                            _memory_records.c.retention_until.isnot(None),
                            _memory_records.c.retention_until < sa.func.now(),
                        ),
                    )
                )
            )
        return result.rowcount

    async def redact_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        span: RedactionSpan,
        reason: RedactionReason,
        actor_id: str,
    ) -> RedactionReceipt:
        """Create a new sealed version of a memory record with the redacted value.

        Steps (all inside ``append_with_precondition``):
        1. SELECT ... FOR UPDATE the active row.
        2. Apply ``_apply_redaction(old.value, span.path, span.replacement)`` —
           ``ValueError`` maps to ``memory_redaction_path_invalid``.
        3. SEAL the old row FIRST: ``SET tombstone = now``. For a BLOCK this frees
           the ``uq_memory_block_singleton`` slot BEFORE the new active version is
           inserted (the partial unique index rejects two active blocks for one
           identity). Same transaction — an insert failure rolls back, leaving the
           old row active.
        4. INSERT the new active row carrying the redacted value,
           ``redaction_version = old + 1`` and ``sealed_prior_version_ref = old.record_id``.
        5. Emit a ``memory.redact`` chain row with ``redacted_value_digest`` of the
           NEW value (NOT the old value), the new version id, and the reason.
           No raw value in the chain."""

        new_rid = uuid.uuid4()
        now = datetime.now(UTC)
        # Capture for _build_record closure
        _captured_info: dict[str, object] = {}

        async def _precondition(conn: AsyncConnection, _prev_seq: int, _prev_hash: bytes) -> None:
            row = (
                await conn.execute(
                    sa.select(_memory_records)
                    .where(
                        _memory_records.c.record_id == record_id,
                        _memory_records.c.tenant_id == tenant_id,
                        _memory_records.c.agent_id == agent_id,
                        _memory_records.c.tombstone.is_(None),
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise MemoryOperationRefused("memory_record_not_found")
            # Apply the redaction — ValueError maps to memory_redaction_path_invalid.
            try:
                new_value = _apply_redaction(row.value, span.path, span.replacement)
            except ValueError as exc:
                raise MemoryOperationRefused("memory_redaction_path_invalid") from exc

            new_redaction_version = row.redaction_version + 1
            _captured_info["new_value"] = new_value
            _captured_info["new_redaction_version"] = new_redaction_version
            _captured_info["old_data_classes"] = list(row.data_classes)
            _captured_info["old_purpose"] = row.purpose
            _captured_info["old_tier"] = row.tier
            _captured_info["old_retention_until"] = row.retention_until

            # Seal (tombstone) the OLD row FIRST, then insert the new version.
            # For a BLOCK this frees the uq_memory_block_singleton slot before the
            # new ACTIVE version is inserted — the migration's partial unique index
            # rejects two active blocks for one (tenant, subject, agent, block_kind)
            # identity. Matches upsert_block's tombstone-then-insert order. Same
            # transaction: an insert failure rolls back, leaving the old row active.
            await conn.execute(
                sa.update(_memory_records)
                .where(
                    _memory_records.c.record_id == record_id,
                    _memory_records.c.tenant_id == tenant_id,
                    _memory_records.c.agent_id == agent_id,
                )
                .values(tombstone=now)
            )
            await conn.execute(
                _memory_records.insert().values(
                    record_id=new_rid,
                    tenant_id=tenant_id,
                    subject_ref=row.subject_ref,
                    agent_id=agent_id,
                    tier=row.tier,
                    block_kind=row.block_kind,
                    key=row.key,
                    value=new_value,
                    data_classes=list(row.data_classes),
                    purpose=row.purpose,
                    retention_until=row.retention_until,
                    tombstone=None,
                    redaction_version=new_redaction_version,
                    sealed_prior_version_ref=record_id,
                    vector_ref=None,
                    created_at=now,
                )
            )

        def _build_record(_captured: None) -> DecisionRecord:
            new_value = _captured_info["new_value"]
            new_redaction_version = _captured_info["new_redaction_version"]
            return DecisionRecord(
                decision_type="memory.redact",
                request_id=f"memory-redact-{record_id}",
                payload={
                    "record_id": str(record_id),
                    "new_version_id": str(new_rid),
                    "redaction_version": new_redaction_version,
                    "reason": reason,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    # redacted_value_digest of the NEW value — NEVER the old value
                    "redacted_value_digest": _value_digest(new_value),
                    # NOTE: NO raw value in chain
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_MEMORY_WRITE_ISO_CONTROLS,
            )

        await self._dh.append_with_precondition(
            record_builder=_build_record,
            precondition=_precondition,
        )
        return RedactionReceipt(
            record_id=record_id,
            new_version_id=new_rid,
            redaction_version=int(_captured_info["new_redaction_version"]),  # type: ignore[call-overload]
        )

    async def get(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        subject: SubjectRef,
        tier: MemoryTier,
        key: str | None = None,
        block_kind: BlockKind | None = None,
    ) -> MemoryHit | None:
        """Read the single active (non-tombstoned) record matching
        ``(tenant_id, agent_id, subject, tier)`` + the optional ``key`` /
        ``block_kind`` narrowers. ``tenant_id`` AND ``agent_id`` are BOTH
        REQUIRED isolation boundaries — a record belongs to the agent that wrote
        it (the block singleton identity is ``(tenant, subject, agent, kind)``),
        so two agents in one tenant can each hold an active block for the same
        ``subject`` + ``block_kind``; a query without the ``agent_id`` filter
        would return another agent's row arbitrarily. Returns ``None`` when no
        active row matches."""

        stmt = sa.select(_memory_records).where(
            _memory_records.c.tenant_id == tenant_id,
            _memory_records.c.agent_id == agent_id,
            _memory_records.c.subject_ref == subject.canonical,
            _memory_records.c.tier == tier,
            _memory_records.c.tombstone.is_(None),
            sa.or_(
                _memory_records.c.retention_until.is_(None),
                _memory_records.c.retention_until > sa.func.now(),
            ),
        )
        if block_kind is not None:
            stmt = stmt.where(_memory_records.c.block_kind == block_kind)
        if key is not None:
            stmt = stmt.where(_memory_records.c.key == key)

        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).first()
        if row is None:
            return None
        return MemoryHit(
            record_id=row.record_id,
            value=row.value,
            tier=row.tier,
            data_classes=tuple(row.data_classes),
            purpose=row.purpose,
            created_at=row.created_at,
            block_kind=row.block_kind,
        )

    async def list_for_subject(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[MemoryHit]:
        """Return every active (non-tombstoned) record the CALLING agent wrote
        for ``(tenant_id, subject)`` ordered by ``created_at``. ``tenant_id`` AND
        ``agent_id`` are both isolation boundaries (same WHERE shape as
        :meth:`get`); rows of other tenants / agents / subjects and tombstoned
        rows are excluded. Maps each row to a :class:`MemoryHit` exactly as
        :meth:`get` does."""

        stmt = (
            sa.select(_memory_records)
            .where(
                _memory_records.c.tenant_id == tenant_id,
                _memory_records.c.agent_id == agent_id,
                _memory_records.c.subject_ref == subject.canonical,
                _memory_records.c.tombstone.is_(None),
                sa.or_(
                    _memory_records.c.retention_until.is_(None),
                    _memory_records.c.retention_until > sa.func.now(),
                ),
            )
            .order_by(_memory_records.c.created_at)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [
            MemoryHit(
                record_id=row.record_id,
                value=row.value,
                tier=row.tier,
                data_classes=tuple(row.data_classes),
                purpose=row.purpose,
                created_at=row.created_at,
                block_kind=row.block_kind,
            )
            for row in rows
        ]

    async def list_blocks(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[BlockRef]:
        """Return one :class:`BlockRef` per ACTIVE block the CALLING agent owns
        for ``(tenant_id, subject)``. ``version`` is the supersede generation —
        the count of rows (active + tombstoned) sharing the active row's
        ``(tenant_id, subject_ref, agent_id, block_kind)`` quad — so a block
        upserted N times reports ``version == N``. Keyed (non-block) rows,
        tombstoned blocks, and OTHER agents' blocks are excluded; ``tenant_id``
        AND ``agent_id`` are both isolation boundaries (the block singleton
        identity is ``(tenant, subject, agent, kind)``)."""

        active_stmt = sa.select(_memory_records).where(
            _memory_records.c.tenant_id == tenant_id,
            _memory_records.c.agent_id == agent_id,
            _memory_records.c.subject_ref == subject.canonical,
            _memory_records.c.block_kind.isnot(None),
            _memory_records.c.tombstone.is_(None),
            sa.or_(
                _memory_records.c.retention_until.is_(None),
                _memory_records.c.retention_until > sa.func.now(),
            ),
        )
        # Supersede-generation counts keyed by (agent_id, block_kind): every row
        # (active + tombstoned) for this (tenant, agent, subject) block. One
        # grouped query → no per-row N+1.
        gen_stmt = (
            sa.select(
                _memory_records.c.agent_id,
                _memory_records.c.block_kind,
                sa.func.count().label("gen"),
            )
            .where(
                _memory_records.c.tenant_id == tenant_id,
                _memory_records.c.agent_id == agent_id,
                _memory_records.c.subject_ref == subject.canonical,
                _memory_records.c.block_kind.isnot(None),
            )
            .group_by(_memory_records.c.agent_id, _memory_records.c.block_kind)
        )
        async with self._engine.connect() as conn:
            active_rows = (await conn.execute(active_stmt)).all()
            gen_rows = (await conn.execute(gen_stmt)).all()
        generations: dict[tuple[str, str], int] = {
            (g.agent_id, g.block_kind): int(g.gen) for g in gen_rows
        }
        return [
            BlockRef(
                record_id=row.record_id,
                kind=row.block_kind,
                subject=subject,
                version=generations[(row.agent_id, row.block_kind)],
            )
            for row in active_rows
        ]


def _is_redis_unavailable(exc: BaseException) -> bool:
    """True when ``exc`` signals an unreachable redis backend.

    Catches the builtin connection-error family always, plus — resolved
    LAZILY so the module imports without the ``[adapters]`` extra — any
    ``redis.exceptions.RedisError``. A missing ``redis`` package simply
    means the redis branch is skipped (the builtin branch still applies)."""

    if isinstance(exc, ConnectionError | OSError | TimeoutError):
        return True
    try:
        from redis.exceptions import RedisError
    except ImportError:
        return False
    return isinstance(exc, RedisError)


@runtime_checkable
class _AsyncRedisLike(Protocol):
    """Minimal duck-typed contract for the injected redis client — only the
    async ``set`` used by the scratch write path. Keeps ``RedisMemoryAdapter``
    constructible without importing ``redis`` at module level."""

    async def set(self, *args: Any, **kwargs: Any) -> Any: ...


class RedisMemoryAdapter:
    """Ephemeral governed-memory backend for the ``scratch`` tier ONLY.

    **Fail-closed (Cut-A rule).** :meth:`put` raises
    :class:`MemoryBackendUnavailable` on ANY redis backend error — there is
    NO fallback to Postgres and NO silent success. Persisting scratch
    un-erasably (e.g. into the relational store) in 11.5a would violate the
    Cut-A rule: ``forget`` / the reaper land in 11.5b, so a scratch write
    that cannot reach its TTL'd redis home MUST be refused rather than
    quietly durably persisted.

    Structurally conforms to :class:`MemoryAdapter`. ``upsert_block`` /
    ``list_blocks`` are never valid for scratch (blocks are long_term →
    :class:`PostgresMemoryAdapter`); ``get`` / ``list_for_subject`` are
    scratch-recall surfaces deferred BEYOND T10 — the Redis-backed scratch read
    path is wired with the harness/app routing in 11.5b. All four raise
    ``NotImplementedError`` (honest deferral, NOT silent no-op)."""

    def __init__(self, *, redis_client: _AsyncRedisLike, scratch_ttl_s: int) -> None:
        self._redis = redis_client
        self._scratch_ttl_s = scratch_ttl_s

    async def put(self, record: MemoryWriteRecord) -> MemoryRecordId:
        """Write the scratch value to redis under a TTL'd key. Fail-closed:
        any backend error raises :class:`MemoryBackendUnavailable` — no
        Postgres fallback, no silent allow.

        The value never enters the hash chain here (scratch writes are not
        chain-linked); the raw value is stored only transiently in redis."""

        rid = uuid.uuid4()
        key = f"memory:scratch:{record.tenant_id}:{record.subject.canonical}:{record.key}:{rid}"
        payload = canonical_bytes(record.value)
        try:
            await self._redis.set(key, payload, ex=self._scratch_ttl_s)
        except Exception as exc:
            # Blind catch is INTENTIONAL (fail-closed governance default):
            # ANY backend error on a scratch WRITE => the write did not land
            # => refuse. Silently allowing (or durably persisting) would
            # violate the Cut-A rule. We do not re-raise other exception
            # classes as themselves because a caller that sees anything other
            # than MemoryBackendUnavailable might assume the write succeeded.
            # No blind-except suppression directive is needed: flake8-blind-
            # except (BLE) is not enabled in this repo's ruff config, so a
            # suppression directive here would be flagged RUF100-unused.
            detail = (
                "scratch backend (redis) unreachable"
                if _is_redis_unavailable(exc)
                else f"scratch backend (redis) write failed: {type(exc).__name__}"
            )
            raise MemoryBackendUnavailable(detail) from exc
        return rid

    async def get(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        subject: SubjectRef,
        tier: MemoryTier,
        key: str | None = None,
        block_kind: BlockKind | None = None,
    ) -> MemoryHit | None:
        raise NotImplementedError(
            "RedisMemoryAdapter scratch recall is deferred beyond T10 — the "
            "Redis-backed scratch read path is wired with the harness/app routing "
            "in 11.5b (the T10 MemoryAPI is DI-tested against the Postgres adapter "
            "for task/long_term)."
        )

    async def list_for_subject(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[MemoryHit]:
        raise NotImplementedError(
            "RedisMemoryAdapter scratch recall is deferred beyond T10 — see "
            "RedisMemoryAdapter.get (Redis-backed scratch reads land in 11.5b)."
        )

    async def upsert_block(self, record: MemoryWriteRecord) -> MemoryRecordId:
        raise NotImplementedError("blocks are long_term-only; use PostgresMemoryAdapter")

    async def list_blocks(
        self, *, tenant_id: str, agent_id: str, subject: SubjectRef
    ) -> list[BlockRef]:
        raise NotImplementedError("blocks are long_term-only; use PostgresMemoryAdapter")

    async def tombstone_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        reason: ForgetReason,
        actor_id: str,
    ) -> None:
        raise NotImplementedError(
            "RedisMemoryAdapter does not support tombstone_record — scratch records "
            "self-expire via Redis TTL. Use PostgresMemoryAdapter for durable erasure."
        )

    async def purge_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        erasure_command: RegulatorErasureCommand,
        actor_id: str,
    ) -> None:
        raise NotImplementedError(
            "RedisMemoryAdapter does not support purge_record — scratch records "
            "self-expire via Redis TTL. Use PostgresMemoryAdapter for durable erasure."
        )

    async def purge_expired(self, *, tombstone_window_s: int) -> int:
        raise NotImplementedError(
            "RedisMemoryAdapter does not support purge_expired — scratch records "
            "self-expire via Redis TTL. Use PostgresMemoryAdapter for durable erasure."
        )

    async def redact_record(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        record_id: MemoryRecordId,
        span: RedactionSpan,
        reason: RedactionReason,
        actor_id: str,
    ) -> RedactionReceipt:
        raise NotImplementedError(
            "RedisMemoryAdapter does not support redact_record — scratch records "
            "self-expire via Redis TTL. Use PostgresMemoryAdapter for durable redaction."
        )


__all__: tuple[str, ...] = (
    "MemoryAdapter",
    "MemoryBackendUnavailable",
    "PostgresMemoryAdapter",
    "RedisMemoryAdapter",
    "_apply_redaction",
)

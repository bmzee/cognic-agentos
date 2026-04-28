"""DecisionHistoryStore — append-only hash-chained decision-history table.

**Critical-controls module.** Per AGENTS.md amendment in PR #5: every
edit gets per-task halt-before-commit review. ``core/decision_history``
records governance-relevant decisions (per ADR-006 §"Initial control
coverage" — decision_history.append with optional ``impact: high``
satisfies ISO 42001 control A.7.4 "AI system impact assessment").

**Implementation note (Sprint 2 Task 7, Option 2):** this module is a
parallel implementation of ``core/audit`` against the
``decision_history`` chain. Both stores walk the same flow: SELECT FOR
UPDATE the chain-head row, build the canonical envelope including the
full record-identity fields, INSERT the evidence row, compare-and-set
the chain head — atomically. A future refactor may factor out a
private ``_HashChainedAppendStore`` base class shared between
AuditStore and DecisionHistoryStore. Tests on both modules pin the
guarantees so the refactor has a regression baseline.

Schema-side coupling: the ``decision_history`` Table registers against
the SAME ``_metadata`` as ``audit_event`` (imported from
``core.audit``). This way a single ``_metadata.create_all()`` (in
tests) or ``alembic upgrade head`` (in deployments) creates both
tables in one migration.

**Naming:** ``DecisionRecord`` rather than ``DecisionEvent`` so the
type matches the BUILD_PLAN deliverable shape
``DecisionHistoryStore.append(record)``. The ``decision_type`` field
maps to the migration's ``event_type`` column (column shape stays
parallel with ``audit_event`` for chain-verifier reuse).
"""

from __future__ import annotations

import dataclasses
import json as _json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    SmallInteger,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import canonical_bytes, hash_record
from cognic_agentos.db.types import GovernanceJSON, chain_hash_column_type

#: Locked at 1 for Sprint 2; bump requires AGENTS.md per-edit review of
#: ``core/canonical`` + a migration that sets the new default.
_SCHEMA_VERSION: int = 1

#: Sentinel for actor_id collision detection. Distinguishes "key
#: missing from payload" from "key present with value None" — the
#: ``dict.get(..., None)`` shorthand collapses both, which would let
#: ``DecisionRecord(actor_id='x', payload={'actor_id': None})``
#: silently overwrite the caller's explicit ``None`` instead of
#: raising on the inconsistency.
_MISSING: object = object()


# Module-level Table — registered in the SHARED _metadata imported from
# core.audit. Identical column shape to _audit_event so the chain
# verifier (Task 8) can walk both with the same code path.
_decision_history = Table(
    "decision_history",
    _metadata,
    Column("record_id", Uuid(), primary_key=True),
    Column("sequence", BigInteger, nullable=False, unique=True),
    Column("schema_version", SmallInteger, nullable=False),
    Column("tenant_id", String(64), nullable=True),
    Column("prev_hash", chain_hash_column_type(), nullable=False),
    Column("hash", chain_hash_column_type(), nullable=False, unique=True),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("request_id", String(64), nullable=False),
    Column("trace_id", String(32), nullable=True),
    Column("span_id", String(16), nullable=True),
    Column("langfuse_trace_id", String(64), nullable=True),
    Column("provider_label", String(32), nullable=True),
    Column("iso_controls", GovernanceJSON(), nullable=True),
    Column("payload", GovernanceJSON(), nullable=False),
)


@dataclasses.dataclass(frozen=True, slots=True)
class DecisionRecord:
    """Caller-side representation of a governance-tracked decision.

    The dataclass itself is frozen + slotted: field bindings cannot be
    reassigned after the record is handed to ``DecisionHistoryStore.append``.
    However, ``payload`` is a mutable dict and the caller still holds
    its reference. Payload immutability against caller-side mutation is
    enforced by the **store**, which normalises the payload through the
    canonical serializer at method boundary (JSON round-trip via
    ``canonical_bytes`` → ``json.loads``).

    Field shape parallels ``AuditEvent`` so the chain-verifier code
    path is shared. The semantic distinctions are:
      - ``decision_type`` (e.g. ``"approved"``, ``"escalated"``,
        ``"denied"``) — corresponds to the migration's ``event_type``
        column.
      - ``actor_id`` — the agent / role that made the decision.
        ``DecisionHistoryStore.append`` merges this into the
        normalised ``payload`` under the key ``"actor_id"`` before
        hashing + insertion, so the actor provenance lives in the
        chain (and the persisted ``payload`` JSON column). If the
        caller's ``payload`` already carries an ``actor_id`` key,
        equality with the dataclass field is required — mismatches
        raise ``ValueError`` rather than silently overwriting one
        value with the other. Sprint 4 RBAC may promote ``actor_id``
        to a top-level evidence column once tenant-context wiring
        lands.

    ``iso_controls`` is a tuple at the boundary; the store converts to
    list before passing into ``canonical_bytes`` (which rejects tuples
    per Round-3 amendment of the Sprint-2 plan).
    """

    decision_type: str
    request_id: str
    payload: dict[str, Any]
    actor_id: str | None = None
    tenant_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    langfuse_trace_id: str | None = None
    provider_label: str | None = None
    iso_controls: tuple[str, ...] = ()


class DecisionHistoryStore:
    """Append-only hash-chained decision-history store.

    Mirrors AuditStore.append for the parallel chain. Same atomic
    transaction shape: SELECT FOR UPDATE → INSERT → compare-and-set
    UPDATE. Concurrent appenders block on the chain-head row lock
    (proven on Postgres + Oracle in Task 12; SQLite cannot prove
    locking but the SQL shape is exercised here).
    """

    _CHAIN_ID = "decision_history"

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def append(self, record: DecisionRecord) -> tuple[uuid.UUID, bytes]:
        # Validate the dataclass actor_id type at runtime. The
        # annotation says ``str | None`` but Python doesn't enforce.
        # Rejecting non-str-non-None values here keeps actor provenance
        # type-uniform across the chain and the persisted column.
        if record.actor_id is not None and not isinstance(record.actor_id, str):
            raise TypeError(
                f"DecisionRecord.actor_id must be str | None, got "
                f"{type(record.actor_id).__name__}={record.actor_id!r}"
            )

        # Validate the RAW payload['actor_id'] BEFORE canonical
        # normalisation. canonical_bytes auto-promotes types it knows
        # how to stringify (UUID → hex string, Decimal → str, bytes →
        # base64, regular Enum → .value). A check that ran post-
        # normalisation would see those values as already-strings and
        # silently pass — contradicting the str|None contract for
        # actor provenance. Use the same _MISSING sentinel as the
        # collision-detection lookup so absent-vs-explicit-None
        # behaviour is consistent on this branch too.
        #
        # Note: ``StrEnum`` members ARE ``str`` subclasses at the
        # type level (`isinstance(StrEnum.X, str)` is True), so they
        # pass — equivalent to passing the .value directly.
        raw_payload_actor = record.payload.get("actor_id", _MISSING)
        if (
            raw_payload_actor is not _MISSING
            and raw_payload_actor is not None
            and not isinstance(raw_payload_actor, str)
        ):
            raise TypeError(
                f"payload['actor_id'] must be str (or absent / None), got "
                f"{type(raw_payload_actor).__name__}={raw_payload_actor!r}"
            )

        # Snapshot + canonicalise the payload BEFORE any await. Same
        # rationale as AuditStore.append (Round-3 amendment): deep
        # snapshot independent of caller mutation, canonical-form
        # validation at method boundary, projection to JSON-native
        # types so the persisted column matches the canonical bytes
        # hashed pre-insert across every dialect.
        payload_snapshot: dict[str, Any] = _json.loads(canonical_bytes(record.payload))
        iso_controls_list: list[str] = list(record.iso_controls)

        # Re-lookup the (now-normalised) payload actor_id for
        # collision detection against the dataclass field. The raw
        # check above already proved it's str-or-None; canonical
        # normalisation preserves str values verbatim, so the
        # post-normalisation value is the same string the caller
        # provided.
        existing_actor = payload_snapshot.get("actor_id", _MISSING)

        # Merge actor_id into the normalised payload. Sprint-2 contract:
        # the DecisionRecord.actor_id dataclass field is the source of
        # truth for actor provenance; the payload column is the
        # persistence target until Sprint 4 RBAC promotes actor_id to
        # a top-level evidence column. Without this merge, a caller
        # passing actor_id='agent-x' would lose the actor provenance
        # entirely — a serious evidence gap for a governance chain.
        #
        # Collision policy: if the caller's payload already carries an
        # actor_id key (including an explicit None), equality with
        # the dataclass field is required. Silent overwrite would let
        # typo or ambiguous caller-side construction land inconsistent
        # actor provenance into the chain. The _MISSING sentinel
        # distinguishes "key absent" from "key present with value None"
        # — both should not be treated as the same case, since the
        # caller might be explicitly asserting "no actor" via None.
        # Caller-side discipline: pass actor_id via the dataclass
        # field, OR via payload, OR both consistently — never
        # inconsistently.
        if record.actor_id is not None:
            if existing_actor is _MISSING:
                payload_snapshot["actor_id"] = record.actor_id
            elif existing_actor != record.actor_id:
                raise ValueError(
                    f"DecisionRecord.actor_id={record.actor_id!r} conflicts "
                    f"with payload['actor_id']={existing_actor!r}; the two "
                    f"must agree or the dataclass field must be left as None"
                )
            # else: existing_actor == record.actor_id; nothing to do.

        async with self._engine.begin() as conn:
            head_stmt = (
                select(_chain_heads.c.latest_sequence, _chain_heads.c.latest_hash)
                .where(_chain_heads.c.chain_id == self._CHAIN_ID)
                .with_for_update()
            )
            head = (await conn.execute(head_stmt)).one()
            prev_sequence = int(head.latest_sequence)
            prev_hash = bytes(head.latest_hash)
            new_sequence = prev_sequence + 1

            now = datetime.now(UTC)
            record_id = uuid.uuid4()

            envelope: dict[str, Any] = {
                "schema_version": _SCHEMA_VERSION,
                "chain_id": self._CHAIN_ID,
                "record_id": str(record_id),
                "sequence": new_sequence,
                "tenant_id": record.tenant_id,
                "created_at": now,
                # decision_type maps to the column 'event_type' for
                # shape parity with audit_event; the canonical envelope
                # field name follows the column.
                "event_type": record.decision_type,
                "request_id": record.request_id,
                "trace_id": record.trace_id,
                "span_id": record.span_id,
                "langfuse_trace_id": record.langfuse_trace_id,
                "provider_label": record.provider_label,
                "iso_controls": iso_controls_list,
                "payload": payload_snapshot,
            }
            new_hash = hash_record(canonical_bytes(envelope), prev_hash)

            await conn.execute(
                insert(_decision_history).values(
                    record_id=record_id,
                    sequence=new_sequence,
                    schema_version=_SCHEMA_VERSION,
                    tenant_id=record.tenant_id,
                    prev_hash=prev_hash,
                    hash=new_hash,
                    created_at=now,
                    event_type=record.decision_type,
                    request_id=record.request_id,
                    trace_id=record.trace_id,
                    span_id=record.span_id,
                    langfuse_trace_id=record.langfuse_trace_id,
                    provider_label=record.provider_label,
                    iso_controls=iso_controls_list,
                    payload=payload_snapshot,
                )
            )

            # Compare-and-set defence (Round-2 amendment): pins the
            # previously-read latest_sequence + latest_hash; rowcount
            # != 1 raises rather than silently committing an evidence
            # row with a desynced chain head.
            update_result = await conn.execute(
                update(_chain_heads)
                .where(_chain_heads.c.chain_id == self._CHAIN_ID)
                .where(_chain_heads.c.latest_sequence == prev_sequence)
                .where(_chain_heads.c.latest_hash == prev_hash)
                .values(
                    latest_sequence=new_sequence,
                    latest_hash=new_hash,
                    updated_at=now,
                )
            )
            if update_result.rowcount != 1:
                raise RuntimeError(
                    f"chain head compare-and-set failed for chain_id="
                    f"{self._CHAIN_ID!r}: expected sequence={prev_sequence}, "
                    f"hash={prev_hash.hex()}; UPDATE affected "
                    f"{update_result.rowcount} rows. The chain head drifted "
                    f"between the SELECT FOR UPDATE and the UPDATE — "
                    f"either a dialect did not honour the lock, an "
                    f"out-of-band write mutated the row, or the migration "
                    f"shape diverged from db/types."
                )

            return record_id, new_hash


__all__: tuple[str, ...] = (
    "DecisionHistoryStore",
    "DecisionRecord",
    "_decision_history",
)

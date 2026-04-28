"""AuditStore — append-only audit table with hash-chain integrity.

**Critical-controls module.** Per AGENTS.md amendment in PR #5: every
edit gets per-task halt-before-commit review. ``core/audit`` is the
runtime surface that emits evidence rows the chain verifier later
walks; mistakes here corrupt the chain silently.

Concurrency model (Round-2 amendment of the Sprint-2 plan):

  - Append serialises through ``governance_chain_heads`` via
    ``SELECT ... FOR UPDATE`` on the chain-head row. The first
    appender's transaction holds the lock; concurrent appenders
    block until commit + see the new head.
  - SQLAlchemy Core constructs are dialect-portable across
    Postgres + Oracle (no ``LIMIT``, no DESC scan).
  - SQLite does NOT honour ``FOR UPDATE`` (no row-level locking) so
    concurrency correctness is proven against real Postgres + Oracle
    in Task 12; the SQLite unit suite exercises the SQL shape +
    envelope wiring + chain-head update.

Hash material (Round-2 amendment #3 — full record-identity envelope):

  envelope = {
      "schema_version": _SCHEMA_VERSION,
      "chain_id": "audit_event",
      "record_id": str(uuid4),
      "sequence": new_sequence,
      "tenant_id": event.tenant_id,
      "created_at": now,
      "event_type": ...,
      "request_id": ...,
      "trace_id": ...,
      "span_id": ...,
      "langfuse_trace_id": ...,
      "provider_label": ...,
      "iso_controls": list(event.iso_controls),
      "payload": event.payload,
  }
  new_hash = hash_record(canonical_bytes(envelope), prev_hash)

Mutating any of those fields after the row is written breaks the
chain — the verifier (Task 8) recomputes from the same envelope.

Failure model: fail-loud on DB outage. ``append`` raises whatever
SQLAlchemy / DBAPI raised; the caller decides whether the request
path can survive without an audit emission. No silent buffering, no
in-process queue. Audit failure during a request handler should
either retry the audit (operator-driven) or surface as a 5xx — never
a successful 2xx with the audit silently dropped.

The module-level ``_metadata`` + ``_chain_heads`` + ``_audit_event``
Table objects are exported as a private surface for ``core/
decision_history`` (Task 7) and ``core/chain_verifier`` (Task 8) to
import. They mirror migration 0001's shape via the dialect-portable
column types in ``db/types``.
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
    MetaData,
    SmallInteger,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.types import TIMESTAMP, Uuid

from cognic_agentos.core.canonical import canonical_bytes, hash_record
from cognic_agentos.db.types import GovernanceJSON, chain_hash_column_type

#: schema_version locked at 1 for Sprint 2. A bump requires (a) an
#: AGENTS.md per-edit review of ``core/canonical``, (b) a migration
#: that sets a new default + back-fills existing rows, and (c) updated
#: golden hashes in ``tests/unit/core/test_canonical.py``.
_SCHEMA_VERSION: int = 1


# Module-level Table objects — shared with core/decision_history
# (Task 7) and core/chain_verifier (Task 8). Mirrors migration 0001
# via the dialect-portable types in ``db/types``.
_metadata = MetaData()

_chain_heads = Table(
    "governance_chain_heads",
    _metadata,
    Column("chain_id", String(32), primary_key=True),
    Column("latest_sequence", BigInteger, nullable=False),
    Column("latest_hash", chain_hash_column_type(), nullable=False),
    Column("updated_at", TIMESTAMP(timezone=True), nullable=False),
)

_audit_event = Table(
    "audit_event",
    _metadata,
    Column("record_id", Uuid(), primary_key=True),
    # No Identity() — sequence is application-assigned under the
    # chain-heads FOR UPDATE lock. Identity() would double-source the
    # value (DB auto-increment vs application-assigned), silently
    # desynchronising from chain_heads.latest_sequence after the
    # first concurrency hiccup.
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
class AuditEvent:
    """Caller-side representation of an audit emission.

    The dataclass itself is frozen + slotted: field bindings cannot be
    reassigned after the event is handed to ``AuditStore.append``.
    However, ``payload`` is a mutable dict and the caller still holds
    its reference. Payload immutability against caller-side mutation is
    enforced by the **store**, not the event: ``AuditStore.append``
    normalises the payload through the canonical serializer at method
    boundary (JSON round-trip via ``canonical_bytes`` →
    ``json.loads``), which both deep-snapshots the dict and projects it
    onto JSON-native types so the persisted column matches the hashed
    canonical bytes across every dialect.

    ``iso_controls`` is a tuple at the caller boundary (immutable,
    hashable); the store converts it to a list before passing into
    ``canonical_bytes`` (which rejects tuples per Round-3 amendment of
    the Sprint-2 plan).
    """

    event_type: str
    request_id: str
    payload: dict[str, Any]
    tenant_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    langfuse_trace_id: str | None = None
    provider_label: str | None = None
    iso_controls: tuple[str, ...] = ()


class AuditStore:
    """Append-only hash-chained audit-event store.

    Single transaction per append. Reads + locks the chain-head row,
    computes the new hash, INSERTs the evidence row, UPDATEs the
    chain head — atomically. Concurrent appenders block on the
    chain-head row lock and serialise; SQLite cannot prove this
    locally (no row-level locking) but Postgres + Oracle do.
    """

    _CHAIN_ID = "audit_event"

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]:
        # Snapshot + normalise the caller-mutable payload BEFORE any
        # await. The canonical-serializer round-trip
        # (``canonical_bytes`` → ``json.loads``) does four things in one
        # step:
        #
        #   1. Deep snapshot — the resulting dict is fresh, independent
        #      of the caller's mutable reference. A concurrent task
        #      mutating ``event.payload`` after this point can't affect
        #      the persisted/hashed evidence.
        #   2. Canonical-form validation at method boundary — the
        #      payload is checked for tuples / NaN / Infinity / naive
        #      datetimes / non-string-valued enums / non-string dict
        #      keys here, instead of failing later inside envelope
        #      construction. Failures surface at the API surface,
        #      where they belong.
        #   3. Projection onto JSON-native types — Python-rich values
        #      that ``canonical_bytes`` knows how to serialize
        #      (datetime → ISO 8601, UUID → hex, Decimal → str, bytes
        #      → base64, Enum → .value) are projected to strings so
        #      the JSON column binding is identical across PG / Oracle
        #      / SQLite. Without this, the canonical bytes hashed pre-
        #      insert would not match the canonical bytes the chain
        #      verifier reads back from the row, because the dialect-
        #      specific JSON binding might coerce a datetime to a
        #      string with a different precision (or fail outright on
        #      Oracle's CLOB path).
        #   4. Avoids invoking caller-defined ``__deepcopy__`` on
        #      arbitrary objects — only canonical-supported types
        #      survive the round-trip.
        #
        # ``iso_controls`` is a tuple at the boundary (immutable); the
        # tuple-to-list conversion is its own snapshot.
        payload_snapshot: dict[str, Any] = _json.loads(canonical_bytes(event.payload))
        iso_controls_list: list[str] = list(event.iso_controls)

        async with self._engine.begin() as conn:
            # Round-2 #1: SELECT ... FOR UPDATE on the chain-head row.
            # SQLAlchemy's with_for_update() compiles to dialect-correct
            # locking SQL on both PG (FOR UPDATE) and Oracle (FOR UPDATE).
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
                "tenant_id": event.tenant_id,
                "created_at": now,
                "event_type": event.event_type,
                "request_id": event.request_id,
                "trace_id": event.trace_id,
                "span_id": event.span_id,
                "langfuse_trace_id": event.langfuse_trace_id,
                "provider_label": event.provider_label,
                "iso_controls": iso_controls_list,
                "payload": payload_snapshot,
            }
            new_hash = hash_record(canonical_bytes(envelope), prev_hash)

            # INSERT the evidence row.
            await conn.execute(
                insert(_audit_event).values(
                    record_id=record_id,
                    sequence=new_sequence,
                    schema_version=_SCHEMA_VERSION,
                    tenant_id=event.tenant_id,
                    prev_hash=prev_hash,
                    hash=new_hash,
                    created_at=now,
                    event_type=event.event_type,
                    request_id=event.request_id,
                    trace_id=event.trace_id,
                    span_id=event.span_id,
                    langfuse_trace_id=event.langfuse_trace_id,
                    provider_label=event.provider_label,
                    # Always store the list (possibly empty) so the
                    # chain verifier doesn't have to handle NULL→[]
                    # conversion.
                    iso_controls=iso_controls_list,
                    payload=payload_snapshot,
                )
            )

            # Atomically advance the chain head. Compare-and-set on
            # latest_sequence + latest_hash: under correct FOR UPDATE
            # locking the chain head cannot drift between the SELECT
            # and this UPDATE, but defence-in-depth catches dialect
            # surprises (e.g. if a future SQLAlchemy version stops
            # honouring ``with_for_update`` on a particular dialect),
            # SQLite-style "advisory only" locks, and out-of-band
            # tampering. rowcount != 1 means the head drifted; raise
            # rather than committing an evidence row with a desynced
            # chain head (which would make the chain verifier flag
            # the row as tampered on the next walk).
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
    "AuditEvent",
    "AuditStore",
    "_audit_event",
    "_chain_heads",
    "_metadata",
)

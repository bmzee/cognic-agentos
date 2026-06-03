"""Sprint 11.5c — memory export op (retention-disciplined archive). core/ stop-rule.

CRITICAL CONTROL (ADR-019 export + ADR-016 retention discipline). Serializes a
caller-authorized (agent, subject) record set to canonical bytes (values
INCLUDED — caller holds memory.export.read), persists via the ObjectStoreAdapter
to a caller-supplied bucket with a caller-supplied retention window, and emits a
metadata-only memory.export chain row. The bucket + retention are injected by
MemoryAPI.export from validated Settings (``memory_export_bucket`` /
``memory_export_retention_seconds``) so a deployment configures them without a
code change; the 7-year ADR-016 floor is enforced at Settings construction (this
module is a pure serialize+persist primitive and does NOT own retention policy —
keeping it free of any core->protocol import). Persist runs BEFORE the chain emit
and fails closed (MemoryExportPersistenceFailed) so a failed persist leaves NO
chain row. Value-never-in-chain: the chain row carries only archive sha256 +
object key + record count + retention seconds. Cosign-signing the archive is
DEFERRED (the D3 valve candidate).
"""

from __future__ import annotations

import hashlib
import uuid
from typing import TYPE_CHECKING

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.core.memory._context import ExportReceipt

if TYPE_CHECKING:
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.memory._context import MemoryCallerContext, MemoryHit
    from cognic_agentos.core.memory.tiers import SubjectRef
    from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter

#: ISO 42001 controls for export: A.7.4 (impact assessment) / A.8.5 (secure
#: authentication / access) / A.10.2 (data retention).
_MEMORY_EXPORT_ISO_CONTROLS: tuple[str, ...] = ("A.7.4", "A.8.5", "A.10.2")


class MemoryExportPersistenceFailed(Exception):
    """Fail-closed wrapper for an object-store persistence failure. NO raw archive
    bytes in the message — only sha256 + length + key + exc class."""


def _export_object_key(
    *, tenant_id: str, agent_id: str, subject: SubjectRef, export_id: str
) -> str:
    """Derive a safe object-store key for the export archive.

    Hashes (tenant_id, agent_id, subject.canonical) to a single lowercase-hex
    segment so that raw identity material (which may contain ':', '/', uppercase,
    '@') never appears in the key and the key always satisfies
    LocalObjectStoreAdapter._KEY_RE = ^[a-z0-9][a-z0-9._/-]{0,255}$.
    """
    identity = hashlib.sha256(canonical_bytes([tenant_id, agent_id, subject.canonical])).hexdigest()
    return f"memory-exports/{identity}/{export_id}.json"


def _serialize(hits: list[MemoryHit]) -> bytes:
    """Serialize the hit list to canonical bytes (values INCLUDED).

    Uses canonical_bytes (NOT json.dumps) for deterministic, sort-key-normalised
    output that the archive sha256 commitment covers.  Stored values are
    JSONB-origin (dict/list/str/num/bool/None) so canonical_bytes handles them.
    datetime.created_at is serialised as an ISO 8601 string so canonical_bytes
    does not encounter a raw datetime object.
    """
    body = [
        {
            "record_id": str(h.record_id),
            "tier": h.tier,
            "purpose": h.purpose,
            "data_classes": list(h.data_classes),
            "block_kind": h.block_kind,
            "created_at": h.created_at.isoformat(),
            "value": h.value,
        }
        for h in hits
    ]
    return canonical_bytes(body)


async def export_memory(
    *,
    hits: list[MemoryHit],
    subject: SubjectRef,
    context: MemoryCallerContext,
    object_store: ObjectStoreAdapter,
    audit: DecisionHistoryStore,
    bucket: str,
    retention_seconds: int,
) -> ExportReceipt:
    """Serialize, persist (fail-closed), and emit a metadata-only chain row.

    ``bucket`` and ``retention_seconds`` are injected by the caller
    (``MemoryAPI.export`` reads them from validated Settings); this primitive
    does not own retention policy and never floors them — the 7-year ADR-016
    floor is enforced at ``Settings`` construction.

    Contract:
    1. Build archive bytes via _serialize (values included).
    2. Derive sha256 commitment over those bytes.
    3. PUT to object_store FIRST — if it raises, wrap in
       MemoryExportPersistenceFailed (no raw bytes; sha256 + len + key + exc class
       only) and propagate WITHOUT emitting any chain row.
    4. Only on successful PUT: append the metadata-only ``memory.export`` chain
       row.  The chain row carries sha256, key, record_count, retention_seconds —
       NEVER the archive bytes or any record value.
    5. Return ExportReceipt(object_key, archive_sha256, record_count).

    Distributed-atomicity boundary (deliberate design decision, not a TODO).
    The object-store PUT and the chain append are two systems with no shared
    transaction. The ordering is PUT-then-append so the only reachable
    inconsistency is an archive that exists under retention with no chain row
    (if ``audit.append`` raises after a successful PUT). That is the CONSERVATIVE
    failure for bank evidence: data is over-retained rather than a chain row
    referencing a non-existent artifact. No compensating delete is attempted —
    the archive is written under a retention window (WORM/immutable in
    production object stores) and a best-effort delete could itself fail or be
    refused, so swallowing it would be dishonest. An append failure therefore
    propagates to the caller. Pinned by
    ``test_export.py::test_append_failure_propagates_archive_orphaned``.
    """
    archive_bytes = _serialize(hits)
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    export_id = uuid.uuid4().hex
    key = _export_object_key(
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        subject=subject,
        export_id=export_id,
    )
    try:
        await object_store.put(
            bucket,
            key,
            archive_bytes,
            retention_seconds=retention_seconds,
        )
    except Exception as exc:
        raise MemoryExportPersistenceFailed(
            f"memory export persistence failed for subject={subject.canonical!r} "
            f"agent_id={context.agent_id!r} key={key!r}: class={type(exc).__name__} "
            f"archive_sha256={archive_sha256} archive_len={len(archive_bytes)}"
        ) from None
    await audit.append(
        DecisionRecord(
            decision_type="memory.export",
            request_id=f"memory-export-{export_id}",
            payload={
                "op": "export",
                "subject_ref": subject.canonical,
                "agent_id": context.agent_id,
                "object_key": key,
                "archive_sha256": archive_sha256,
                "record_count": len(hits),
                "retention_seconds": retention_seconds,
            },
            actor_id=context.actor_id,
            tenant_id=context.tenant_id,
            iso_controls=_MEMORY_EXPORT_ISO_CONTROLS,
        )
    )
    return ExportReceipt(object_key=key, archive_sha256=archive_sha256, record_count=len(hits))


__all__ = ("MemoryExportPersistenceFailed", "export_memory")

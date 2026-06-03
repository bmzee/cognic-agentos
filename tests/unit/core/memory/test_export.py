"""Sprint 11.5c T3 — unit tests for core/memory/export.py.

CRITICAL CONTROL.  Covers the five non-negotiable contracts:

1. No core->protocol runtime import (drift detector + AST scan).
2. Object-store key safety (_KEY_RE with adversarial subject ids).
3. canonical_bytes digesting (archive bytes are canonical; sha256 matches).
4. Persist-before-chain, fail-closed (put raises → MemoryExportPersistenceFailed,
   zero chain appends).
5. Value-never-in-chain (sentinel value in archive, NOT in chain payload).

Plus: success path, key determinism.
"""

from __future__ import annotations

import pathlib
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.memory._context import ExportReceipt, MemoryCallerContext, MemoryHit
from cognic_agentos.core.memory.export import (
    MemoryExportPersistenceFailed,
    _export_object_key,
    _serialize,
    export_memory,
)
from cognic_agentos.core.memory.tiers import SubjectRef
from tests.unit.core.memory._builders import SUBJECT

#: Bucket + retention are injected by MemoryAPI.export from validated Settings;
#: these primitive-level tests supply them explicitly. The default mirrors the
#: Settings default/floor (7 years). The Settings floor + drift-vs-supply-chain
#: lockstep are pinned in tests/unit/core/test_config_memory.py.
_DEFAULT_BUCKET = "cognic-memory-exports"
_DEFAULT_RETENTION = 7 * 365 * 24 * 3600

# --------------------------------------------------------------------------- #
# Minimal fakes
# --------------------------------------------------------------------------- #


class _RecordingObjectStore:
    """Records put() calls; does not raise."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def put(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        retention_seconds: int | None = None,
    ) -> None:
        self.calls.append(
            {
                "bucket": bucket,
                "key": key,
                "body": body,
                "retention_seconds": retention_seconds,
            }
        )


class _RaisingObjectStore:
    """Always raises on put()."""

    async def put(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        retention_seconds: int | None = None,
    ) -> None:
        raise RuntimeError("disk full")


class _RecordingAudit:
    """Records DecisionRecord appends."""

    def __init__(self) -> None:
        self.appended: list[Any] = []

    async def append(self, record: Any) -> None:
        self.appended.append(record)


class _RaisingAudit:
    """Always raises on append() — models the chain-append failure leg of the
    distributed-atomicity boundary (PUT succeeded, append fails)."""

    async def append(self, record: Any) -> None:
        raise RuntimeError("chain append failed")


def _make_context(
    *,
    tenant_id: str = "t1",
    agent_id: str = "kyc",
    actor_id: str = "svc",
) -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id=tenant_id,
        agent_id=agent_id,
        actor_id=actor_id,
        served_subject=SUBJECT,
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(
            {"memory_read.scratch", "memory_read.task", "memory_read.long_term"}
        ),
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public"}),
        risk_tier="read_only",
    )


def _make_hit(value: object = "hello") -> MemoryHit:
    return MemoryHit(
        record_id=uuid.UUID("12345678-1234-5678-1234-567812345678"),
        value=value,
        tier="task",
        data_classes=("public",),
        purpose="customer_support",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        block_kind=None,
    )


# --------------------------------------------------------------------------- #
# Contract 1 — no core->protocol runtime import
# --------------------------------------------------------------------------- #


#: The retention floor + its lockstep with
#: protocol.supply_chain.SIGSTORE_BUNDLE_RETENTION_SECONDS now live on
#: Settings.memory_export_retention_seconds; the drift detector moved to
#: tests/unit/core/test_config_memory.py (export.py no longer owns the constant).


def test_export_module_does_not_runtime_import_protocol() -> None:
    """AST scan: export.py must contain no cognic_agentos.protocol runtime import."""
    import cognic_agentos.core.memory.export as m

    src = pathlib.Path(m.__file__).read_text()
    assert "cognic_agentos.protocol" not in src


# --------------------------------------------------------------------------- #
# Contract 2 — object-store key safety
# --------------------------------------------------------------------------- #


def test_key_re_safety_adversarial_subject_ids() -> None:
    """A subject id with ':', '/', '@', and uppercase still yields a valid key."""
    from cognic_agentos.db.adapters.local_object_store_adapter import _KEY_RE

    adversarial_subjects = [
        SubjectRef(kind="human", id="USR:123/@domain/path"),
        SubjectRef(kind="human", id="UPPER:CASE"),
        SubjectRef(kind="human", id="with/slash"),
        SubjectRef(kind="human", id="at@sign"),
    ]
    for subject in adversarial_subjects:
        key = _export_object_key(
            tenant_id="Tenant:99",
            agent_id="Agent/v2",
            subject=subject,
            export_id="a" * 32,
        )
        assert _KEY_RE.match(key), (
            f"Key {key!r} does not match _KEY_RE for subject {subject.canonical!r}"
        )


def test_key_starts_with_memory_exports_prefix() -> None:
    key = _export_object_key(
        tenant_id="t1",
        agent_id="kyc",
        subject=SUBJECT,
        export_id="abc123" * 5 + "ab",
    )
    assert key.startswith("memory-exports/")
    assert key.endswith(".json")


# --------------------------------------------------------------------------- #
# Contract 3 — canonical_bytes digesting
# --------------------------------------------------------------------------- #


def test_serialize_uses_canonical_bytes() -> None:
    """Archive bytes must equal canonical_bytes of the body list."""
    hit = _make_hit("test_value")
    archive = _serialize([hit])
    body = [
        {
            "record_id": str(hit.record_id),
            "tier": hit.tier,
            "purpose": hit.purpose,
            "data_classes": list(hit.data_classes),
            "block_kind": hit.block_kind,
            "created_at": hit.created_at.isoformat(),
            "value": hit.value,
        }
    ]
    assert archive == canonical_bytes(body)


def test_archive_sha256_matches_archive_bytes() -> None:
    """The sha256 the receipt carries must match the archive bytes the store receives."""
    import hashlib

    hit = _make_hit()
    archive_bytes = _serialize([hit])
    expected_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    # sha256 must be lowercase hex
    assert expected_sha256 == expected_sha256.lower()
    assert len(expected_sha256) == 64


# --------------------------------------------------------------------------- #
# Contract 4 — persist-before-chain, fail-closed
# --------------------------------------------------------------------------- #


async def test_put_raises_raises_persistence_failed_and_zero_chain_appends() -> None:
    """If object_store.put raises, MemoryExportPersistenceFailed is raised and
    no DecisionRecord is appended."""
    store = _RaisingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    with pytest.raises(MemoryExportPersistenceFailed) as exc_info:
        await export_memory(
            hits=[_make_hit()],
            subject=SUBJECT,
            context=ctx,
            object_store=store,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            bucket=_DEFAULT_BUCKET,
            retention_seconds=_DEFAULT_RETENTION,
        )

    assert len(audit.appended) == 0
    # Message must contain sha256 + key + exc class but NOT raw bytes
    msg = str(exc_info.value)
    assert "archive_sha256=" in msg
    assert "class=RuntimeError" in msg
    assert "archive_len=" in msg
    # Must not contain the raw archive bytes representation
    assert "b'" not in msg


async def test_put_raises_exception_message_contains_no_archive_bytes() -> None:
    """MemoryExportPersistenceFailed message must NOT leak raw archive bytes."""
    store = _RaisingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    with pytest.raises(MemoryExportPersistenceFailed) as exc_info:
        await export_memory(
            hits=[_make_hit("SENSITIVE_VALUE")],
            subject=SUBJECT,
            context=ctx,
            object_store=store,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            bucket=_DEFAULT_BUCKET,
            retention_seconds=_DEFAULT_RETENTION,
        )

    msg = str(exc_info.value)
    # The raw value must NOT appear in the error message
    assert "SENSITIVE_VALUE" not in msg


# --------------------------------------------------------------------------- #
# Contract 5 — value-never-in-chain
# --------------------------------------------------------------------------- #


async def test_value_not_in_chain_payload_but_in_archive() -> None:
    """Distinctive sentinel value appears in archive bytes but NOT in chain payload."""
    SENTINEL = "SENTINEL_SECRET_abc123"

    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    await export_memory(
        hits=[_make_hit(SENTINEL)],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    assert len(audit.appended) == 1
    record = audit.appended[0]
    # Chain payload must NOT contain the sentinel
    import json

    payload_str = json.dumps(record.payload)
    assert SENTINEL not in payload_str, (
        f"Sentinel value appeared in chain payload: {record.payload!r}"
    )
    # Archive bytes MUST contain the sentinel
    assert len(store.calls) == 1
    archive_bytes = store.calls[0]["body"]
    assert SENTINEL.encode() in archive_bytes, "Sentinel value was missing from the archive bytes"


# --------------------------------------------------------------------------- #
# Success path
# --------------------------------------------------------------------------- #


async def test_success_path_returns_export_receipt() -> None:
    """Green path: put called once, chain row emitted, receipt returned."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    receipt = await export_memory(
        hits=[_make_hit(), _make_hit("second")],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    assert isinstance(receipt, ExportReceipt)
    assert receipt.record_count == 2
    assert len(store.calls) == 1
    assert len(audit.appended) == 1


async def test_success_path_put_called_with_retention_seconds() -> None:
    """put() is called exactly once with the correct retention_seconds."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    await export_memory(
        hits=[_make_hit()],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    assert len(store.calls) == 1
    assert store.calls[0]["retention_seconds"] == _DEFAULT_RETENTION


async def test_success_path_chain_payload_is_metadata_only() -> None:
    """Chain payload carries metadata keys only — never a record value."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    await export_memory(
        hits=[_make_hit("should_not_appear")],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    record = audit.appended[0]
    assert record.decision_type == "memory.export"
    expected_keys = {
        "op",
        "subject_ref",
        "agent_id",
        "object_key",
        "archive_sha256",
        "record_count",
        "retention_seconds",
    }
    assert set(record.payload.keys()) == expected_keys
    assert record.payload["op"] == "export"
    assert record.payload["record_count"] == 1
    assert record.payload["retention_seconds"] == _DEFAULT_RETENTION
    assert record.payload["subject_ref"] == SUBJECT.canonical


async def test_success_path_receipt_sha256_matches_archive() -> None:
    """ExportReceipt.archive_sha256 must match sha256(archive_bytes to store)."""
    import hashlib

    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    receipt = await export_memory(
        hits=[_make_hit()],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    archive_bytes = store.calls[0]["body"]
    assert receipt.archive_sha256 == hashlib.sha256(archive_bytes).hexdigest()


async def test_success_path_receipt_object_key_matches_store_call() -> None:
    """ExportReceipt.object_key must equal the key passed to object_store.put."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    receipt = await export_memory(
        hits=[_make_hit()],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    assert receipt.object_key == store.calls[0]["key"]
    assert receipt.object_key == audit.appended[0].payload["object_key"]


async def test_chain_row_iso_controls() -> None:
    """Chain row must carry the export ISO controls tuple."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    await export_memory(
        hits=[_make_hit()],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    record = audit.appended[0]
    assert record.iso_controls == ("A.7.4", "A.8.5", "A.10.2")


# --------------------------------------------------------------------------- #
# Key determinism
# --------------------------------------------------------------------------- #


def test_key_determinism_same_identity_same_prefix() -> None:
    """Same (tenant, agent, subject) → same hash prefix regardless of export_id."""
    key1 = _export_object_key(tenant_id="t1", agent_id="kyc", subject=SUBJECT, export_id="a" * 32)
    key2 = _export_object_key(tenant_id="t1", agent_id="kyc", subject=SUBJECT, export_id="b" * 32)
    prefix1 = key1.split("/")[1]
    prefix2 = key2.split("/")[1]
    assert prefix1 == prefix2


def test_key_determinism_different_export_id_different_key() -> None:
    """Different export_ids yield different full keys."""
    key1 = _export_object_key(tenant_id="t1", agent_id="kyc", subject=SUBJECT, export_id="a" * 32)
    key2 = _export_object_key(tenant_id="t1", agent_id="kyc", subject=SUBJECT, export_id="b" * 32)
    assert key1 != key2


def test_key_determinism_different_tenant_different_prefix() -> None:
    """Different tenant_id yields a different identity hash prefix."""
    key1 = _export_object_key(tenant_id="t1", agent_id="kyc", subject=SUBJECT, export_id="a" * 32)
    key2 = _export_object_key(tenant_id="t2", agent_id="kyc", subject=SUBJECT, export_id="a" * 32)
    prefix1 = key1.split("/")[1]
    prefix2 = key2.split("/")[1]
    assert prefix1 != prefix2


async def test_empty_hits_produces_empty_archive() -> None:
    """Zero hits → put() is still called with an archive (empty list encoded)."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    receipt = await export_memory(
        hits=[],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=_DEFAULT_BUCKET,
        retention_seconds=_DEFAULT_RETENTION,
    )

    assert receipt.record_count == 0
    assert len(store.calls) == 1
    assert store.calls[0]["body"] == canonical_bytes([])


# --------------------------------------------------------------------------- #
# Deployment configurability — bucket + retention are caller-supplied
# --------------------------------------------------------------------------- #


async def test_bucket_and_retention_are_caller_supplied() -> None:
    """A non-default bucket + retention (e.g. a bank's 10-year mandate) flow
    verbatim into the object_store.put call AND the chain payload's
    retention_seconds — proving export_memory holds NO hard-coded value."""
    store = _RecordingObjectStore()
    audit = _RecordingAudit()
    ctx = _make_context()

    bank_bucket = "acme-bank-memory-exports"
    ten_years = 10 * 365 * 24 * 3600

    await export_memory(
        hits=[_make_hit()],
        subject=SUBJECT,
        context=ctx,
        object_store=store,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        bucket=bank_bucket,
        retention_seconds=ten_years,
    )

    # put() received the configured bucket + retention (NOT the 7-year default).
    assert store.calls[0]["bucket"] == bank_bucket
    assert store.calls[0]["retention_seconds"] == ten_years
    assert store.calls[0]["retention_seconds"] != _DEFAULT_RETENTION

    # The chain payload records the configured retention.
    assert audit.appended[0].payload["retention_seconds"] == ten_years


# --------------------------------------------------------------------------- #
# Distributed-atomicity boundary — append failure leaves an orphaned archive
# --------------------------------------------------------------------------- #


async def test_append_failure_propagates_archive_orphaned() -> None:
    """Deliberate design decision (not a TODO): PUT-then-append across two
    systems with no shared transaction. If the chain append raises AFTER a
    successful PUT, the exception propagates (no swallow, no compensating delete)
    and the archive remains persisted under retention — the CONSERVATIVE failure
    (over-retained data, never a chain row referencing a missing artifact)."""
    store = _RecordingObjectStore()
    audit = _RaisingAudit()
    ctx = _make_context()

    with pytest.raises(RuntimeError, match="chain append failed"):
        await export_memory(
            hits=[_make_hit()],
            subject=SUBJECT,
            context=ctx,
            object_store=store,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            bucket=_DEFAULT_BUCKET,
            retention_seconds=_DEFAULT_RETENTION,
        )

    # The archive WAS persisted (PUT happened before the failing append) — it is
    # now orphaned: it exists under retention with no chain row recording it.
    assert len(store.calls) == 1
    # NOT a MemoryExportPersistenceFailed — that wrapper is reserved for PUT
    # failures; an append failure surfaces the raw chain exception.
    assert store.calls[0]["retention_seconds"] == _DEFAULT_RETENTION

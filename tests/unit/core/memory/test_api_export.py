"""Sprint 11.5c T3 — MemoryAPI.export (10th op) tests.

CRITICAL CONTROL. Pins three contracts:
  (a) sub-agent context → MemoryOperationRefused("memory_subagent_durable_access_refused")
      via check_lifecycle (ordered gate precedence; enumerate gate never reached).
  (b) Green path reads via adapter.list_for_subject and returns an ExportReceipt
      with the correct record_count.
  (c) object_store=None at construction → NotImplementedError (fail-loud sentinel,
      NOT a governance refusal).

Uses a lightweight LocalObjectStoreAdapter (real driver) to avoid mocking the
object-store entirely — the real driver validates the bucket + key via _BUCKET_RE
and _KEY_RE, which gives us a side-channel correctness check for Contract 2 of
export.py on the API path as well.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
from cognic_agentos.core.memory._context import ExportReceipt, MemoryCallerContext
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.consent import ConsentValidator
from cognic_agentos.core.memory.tiers import MemoryOperationRefused
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter

from ._builders import SUBJECT, _long_term_record, _scratch_record, _task_record
from .conftest import _READ_CAPS, _AllowAllPolicy, _build_api, _ctx, _InactiveKillSwitch

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _subagent_ctx() -> MemoryCallerContext:
    return MemoryCallerContext(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=SUBJECT,
        is_subagent=True,  # <-- key difference
        long_term_writes_allowed=False,
        cross_subject_recall=False,
        memory_read_capabilities=_READ_CAPS,
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public"}),
        risk_tier="read_only",
    )


def _build_api_with_store(
    ctx: MemoryCallerContext,
    memory_adapter: Any,
    dh_store: Any,
    object_store: Any = None,
    settings: Settings | None = None,
) -> MemoryAPI:
    return MemoryAPI(
        context=ctx,
        adapter=memory_adapter,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        policy=_AllowAllPolicy(),  # type: ignore[arg-type]
        kill_switch=_InactiveKillSwitch(),
        audit=dh_store,
        settings=settings or Settings(),
        object_store=object_store,
    )


# --------------------------------------------------------------------------- #
# (a) sub-agent context → MemoryOperationRefused
# --------------------------------------------------------------------------- #


async def test_export_refuses_subagent(memory_adapter, dh_store, tmp_path):
    """A sub-agent calling export() is refused via check_lifecycle() — the
    enumerate gate never runs (ordered gate precedence)."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    api = _build_api_with_store(_subagent_ctx(), memory_adapter, dh_store, object_store)

    with pytest.raises(MemoryOperationRefused) as exc_info:
        await api.export(SUBJECT)

    assert exc_info.value.reason == "memory_subagent_durable_access_refused"


# --------------------------------------------------------------------------- #
# (b) Green path — reads via adapter, returns correct ExportReceipt
# --------------------------------------------------------------------------- #


async def test_export_returns_receipt_with_correct_record_count(memory_adapter, dh_store, tmp_path):
    """Green path: adapter.list_for_subject is called and the receipt carries
    the number of records returned by the adapter."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api_with_store(ctx, memory_adapter, dh_store, object_store)

    # Seed two records through the real adapter so they exist in the store.
    await memory_adapter.put(_task_record(value="v1", key="k1"))
    await memory_adapter.put(_long_term_record(value="v2"))

    receipt = await api.export(SUBJECT)

    assert isinstance(receipt, ExportReceipt)
    assert receipt.record_count == 2


async def test_export_excludes_scratch_fallback_rows(memory_adapter, dh_store, tmp_path):
    """Regression (P1): a scratch fallback row inserted by put_scratch_fallback
    (the Redis-outage durability path, 11.5b T8) sits in Postgres and IS returned
    by list_for_subject while within its TTL window — but export() authorizes only
    the durable enumerate tiers (task/long_term). The ephemeral scratch value MUST
    NOT enter the 7-year retention archive. Pin record_count == 1 (durable only)
    AND that the scratch sentinel is absent from the archive bytes while the
    durable value is present.

    TM-revert verified load-bearing: removing the `_ENUMERATE_TIERS` filter in
    MemoryAPI.export makes record_count == 2 and surfaces SCRATCH_SENTINEL in the
    archive — this test then FAILS."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api_with_store(ctx, memory_adapter, dh_store, object_store)

    # One durable record (exportable) ...
    await memory_adapter.put(_long_term_record(value="DURABLE_VALUE"))
    # ... and one scratch fallback row still within its TTL window (would be
    # returned by list_for_subject absent the tier filter — same (tenant, agent,
    # subject) as the export call).
    await memory_adapter.put_scratch_fallback(
        _scratch_record(value="SCRATCH_SENTINEL", agent_id="kyc"),
        retention_until=datetime.now(UTC) + timedelta(hours=1),
    )

    receipt = await api.export(SUBJECT)

    # Only the durable record is exported.
    assert receipt.record_count == 1

    # The archive bytes exclude the scratch sentinel and include the durable value.
    bucket_dir = tmp_path / "cognic-memory-exports"
    archive_files = list(bucket_dir.rglob("*.json"))
    assert len(archive_files) == 1
    archive_bytes = archive_files[0].read_bytes()
    assert b"SCRATCH_SENTINEL" not in archive_bytes
    assert b"DURABLE_VALUE" in archive_bytes


async def test_export_empty_subject_returns_zero_count(memory_adapter, dh_store, tmp_path):
    """No records for subject → receipt.record_count == 0."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api_with_store(ctx, memory_adapter, dh_store, object_store)

    receipt = await api.export(SUBJECT)

    assert isinstance(receipt, ExportReceipt)
    assert receipt.record_count == 0


async def test_export_persists_archive_and_emits_chain_row(
    memory_adapter, dh_store, tmp_path, decision_history_rows
):
    """Green path: archive is persisted (LocalObjectStoreAdapter creates a file)
    AND exactly one memory.export chain row is emitted."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _build_api_with_store(ctx, memory_adapter, dh_store, object_store)

    await memory_adapter.put(_task_record(value="payload"))

    receipt = await api.export(SUBJECT)

    # The object-store file must exist at the derived path.
    bucket_dir = tmp_path / "cognic-memory-exports"
    assert bucket_dir.exists()
    # Verify by listing all files under the bucket.
    all_files = list(bucket_dir.rglob("*.json"))
    assert len(all_files) >= 1

    # Chain row: exactly one memory.export event.
    rows = await decision_history_rows()
    export_rows = [r for r in rows if r.event_type == "memory.export"]
    assert len(export_rows) == 1
    row = export_rows[0]
    assert row.payload["op"] == "export"
    assert row.payload["record_count"] == 1
    assert row.payload["archive_sha256"] == receipt.archive_sha256
    assert row.payload["object_key"] == receipt.object_key
    assert tuple(row.iso_controls) == ("A.7.4", "A.8.5", "A.10.2")


# --------------------------------------------------------------------------- #
# Deployment configurability — Settings bucket + retention thread through
# --------------------------------------------------------------------------- #


async def test_export_threads_configured_bucket_and_retention(
    memory_adapter, dh_store, tmp_path, decision_history_rows
):
    """MemoryAPI.export threads Settings.memory_export_bucket +
    memory_export_retention_seconds through to the archive location AND the
    memory.export chain payload — no hard-coded value on the API path. A bank
    configuring a 10-year mandate + a deployment-specific bucket gets both
    without a code change."""
    object_store = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    ten_years = 10 * 365 * 24 * 3600
    settings = Settings(
        memory_export_bucket="acme-bank-memory-exports",
        memory_export_retention_seconds=ten_years,
    )
    api = _build_api_with_store(ctx, memory_adapter, dh_store, object_store, settings=settings)

    await memory_adapter.put(_task_record(value="payload"))
    await api.export(SUBJECT)

    # Archive landed under the configured bucket directory (not the default).
    assert (tmp_path / "acme-bank-memory-exports").exists()
    assert not (tmp_path / "cognic-memory-exports").exists()

    # The chain payload records the configured retention.
    rows = await decision_history_rows()
    export_rows = [r for r in rows if r.event_type == "memory.export"]
    assert len(export_rows) == 1
    assert export_rows[0].payload["retention_seconds"] == ten_years


# --------------------------------------------------------------------------- #
# (c) object_store=None → NotImplementedError
# --------------------------------------------------------------------------- #


async def test_export_raises_not_implemented_when_object_store_is_none(memory_adapter, dh_store):
    """MemoryAPI.export raises NotImplementedError (not MemoryOperationRefused)
    when no object_store was wired at construction AND the caller clears the gate
    (non-sub-agent, enumerate-allowed) — the wiring check is reached only after
    the gate passes."""
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    # _build_api (from conftest) does NOT pass object_store — defaults to None.
    api = _build_api(ctx, memory_adapter, dh_store)

    with pytest.raises(NotImplementedError, match="object_store"):
        await api.export(SUBJECT)


async def test_export_subagent_refused_even_without_object_store(memory_adapter, dh_store):
    """Governance precedence (P2): a sub-agent is refused via check_lifecycle()
    BEFORE the object_store wiring check. A deployment without an object_store
    must NOT mask memory_subagent_durable_access_refused with a NotImplementedError
    — the gate runs first.

    TM-revert verified load-bearing: with the wiring check ordered before the
    gate, this raises NotImplementedError instead and the test FAILS."""
    # object_store defaults to None (unwired) AND the context is a sub-agent.
    api = _build_api_with_store(_subagent_ctx(), memory_adapter, dh_store, object_store=None)

    with pytest.raises(MemoryOperationRefused) as exc_info:
        await api.export(SUBJECT)

    assert exc_info.value.reason == "memory_subagent_durable_access_refused"

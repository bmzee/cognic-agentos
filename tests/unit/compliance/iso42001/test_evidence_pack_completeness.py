"""Sprint 9 T4 — evidence-pack window completeness."""

from __future__ import annotations

import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.signing import CosignArtifacts, SigningIdentity
from cognic_agentos.core.audit import (
    AuditEvent,
    AuditStore,
    _audit_event,
    _chain_heads,
    _metadata,
)
from cognic_agentos.core.canonical import ZERO_HASH


async def _fake_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    return CosignArtifacts(signature=b"s", bundle=b"b")


def _pem(tmp_path: Path) -> str:
    key = tmp_path / "k.pem"
    key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n")
    return str(key)


async def test_pack_contains_exactly_the_in_window_rows(tmp_path: Path) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'c.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    audit = AuditStore(engine)
    # Seed 3 t-1 audit rows; created_at is server-set on append, so UPDATE
    # each to a controlled timestamp keyed by its (unique) request_id.
    for rid in ("in-a", "in-b", "out"):
        await audit.append(AuditEvent(event_type="a", request_id=rid, payload={}, tenant_id="t-1"))
    base = datetime(2026, 6, 1, tzinfo=UTC)
    stamps = {
        "in-a": base,
        "in-b": base + timedelta(hours=1),
        "out": base + timedelta(days=30),
    }
    async with engine.begin() as conn:
        for rid, ts in stamps.items():
            await conn.execute(
                update(_audit_event).where(_audit_event.c.request_id == rid).values(created_at=ts)
            )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=base,
        period_end=base + timedelta(days=1),
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        f = tar.extractfile("audit_event.jsonl")
        assert f is not None
        audit_jsonl = f.read()
    request_ids = {json.loads(line)["request_id"] for line in audit_jsonl.splitlines()}
    assert request_ids == {"in-a", "in-b"}  # the out-of-window row is excluded

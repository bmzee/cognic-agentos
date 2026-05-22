"""Sprint 9 T4 — evidence-pack exporter: wire shape, Merkle, tenant isolation."""

from __future__ import annotations

import io
import json
import tarfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS
from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.merkle import merkle_root
from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    EvidencePackSigningError,
    SigningIdentity,
)
from cognic_agentos.core.audit import AuditEvent, AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

_WIDE = (datetime(2000, 1, 1, tzinfo=UTC), datetime(2100, 1, 1, tzinfo=UTC))

#: The 12 wire-public manifest.json keys (stop-rule contract).
_MANIFEST_KEYS = {
    "schema_version",
    "agentos_version",
    "tenant_id",
    "period_start",
    "period_end",
    "generated_at",
    "merkle_algorithm",
    "merkle_root",
    "audit_event_row_count",
    "decision_history_row_count",
    "signing_identity",
    "per_control_coverage",
}

#: The DB-column key set of one serialised chain row (audit_event and
#: decision_history carry the identical 15 column names).
_ROW_COLUMNS = {
    "record_id",
    "sequence",
    "schema_version",
    "tenant_id",
    "prev_hash",
    "hash",
    "created_at",
    "event_type",
    "request_id",
    "trace_id",
    "span_id",
    "langfuse_trace_id",
    "provider_label",
    "iso_controls",
    "payload",
}


async def _fake_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
    return CosignArtifacts(signature=b"fake-sig", bundle=b"fake-bundle")


async def _seeded_engine(
    tmp_path: Path,
) -> tuple[AsyncEngine, AuditStore, DecisionHistoryStore]:
    """File-backed sqlite engine with the governance schema + chain heads,
    plus AuditStore / DecisionHistoryStore for seeding."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ev.db'}")
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
    return engine, AuditStore(engine), DecisionHistoryStore(engine)


def _pem(tmp_path: Path) -> str:
    key = tmp_path / "evidence-key.pem"
    key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    return str(key)


def _members(tar_bytes: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        out: dict[str, bytes] = {}
        for m in tar.getmembers():
            f = tar.extractfile(m)
            assert f is not None
            out[m.name] = f.read()
        return out


def _assert_row_encoding(row: dict[str, object]) -> None:
    """Pin the wire encoding of one serialised chain row (stop-rule)."""
    assert set(row) == _ROW_COLUMNS
    for col in ("prev_hash", "hash"):
        value = row[col]
        assert isinstance(value, str)
        assert len(value) == 64
        assert value == value.lower()
        bytes.fromhex(value)  # raises if not lowercase hex
    created_at = row["created_at"]
    assert isinstance(created_at, str)
    datetime.fromisoformat(created_at)  # raises if not ISO-8601
    record_id = row["record_id"]
    assert isinstance(record_id, str)
    uuid.UUID(record_id)  # raises if not a UUID string
    assert isinstance(row["payload"], dict)
    assert isinstance(row["iso_controls"], list)


async def test_export_produces_signed_tarball_with_pinned_members(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="audit.test",
            request_id="r1",
            payload={},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d.test",
            request_id="r2",
            payload={"k": "v"},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.7.4",),
        )
    )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    assert set(members) == {
        "manifest.json",
        "manifest.json.sig",
        "manifest.json.bundle.sigstore",
        "audit_event.jsonl",
        "decision_history.jsonl",
    }
    # The cosign artifact members are the signer's outputs verbatim.
    assert members["manifest.json.sig"] == b"fake-sig"
    assert members["manifest.json.bundle.sigstore"] == b"fake-bundle"

    manifest = json.loads(members["manifest.json"])
    # manifest.json IS the canonical compact form (sorted keys, tight separators).
    assert members["manifest.json"] == json.dumps(
        manifest, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    # Exactly the 12 wire-public manifest keys — no more, no fewer.
    assert set(manifest) == _MANIFEST_KEYS
    assert manifest["schema_version"] == 1
    assert manifest["tenant_id"] == "t-1"
    assert manifest["merkle_algorithm"] == "iso42001-evidence-merkle-v1"
    assert manifest["signing_identity"] == _pem(tmp_path)
    assert manifest["audit_event_row_count"] == 1
    assert manifest["decision_history_row_count"] == 1

    # per_control_coverage carries all 8 registry controls verbatim, with
    # display + title from the registry and the seeded controls counted.
    coverage = manifest["per_control_coverage"]
    assert set(coverage) == {entry.control_id for entry in ISO42001_CONTROLS}
    for entry in ISO42001_CONTROLS:
        cell = coverage[entry.control_id]
        assert cell["display"] == entry.display
        assert cell["title"] == entry.title
    seeded = {"ISO42001.A.9.2", "ISO42001.A.7.4"}
    for cid, cell in coverage.items():
        assert cell["tagged_row_count"] == (1 if cid in seeded else 0)


async def test_jsonl_row_encoding_is_pinned(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(
        AuditEvent(
            event_type="a",
            request_id="r1",
            payload={"x": 1},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await audit.append(
        AuditEvent(
            event_type="a",
            request_id="r2",
            payload={"x": 2},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.9.2",),
        )
    )
    await dh.append(
        DecisionRecord(
            decision_type="d",
            request_id="r3",
            payload={"y": 3},
            tenant_id="t-1",
            iso_controls=("ISO42001.A.7.4",),
        )
    )
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    audit_jsonl = members["audit_event.jsonl"]
    dh_jsonl = members["decision_history.jsonl"]
    # Non-empty JSONL is newline-terminated.
    assert audit_jsonl.endswith(b"\n")
    assert dh_jsonl.endswith(b"\n")
    audit_rows = [json.loads(line) for line in audit_jsonl.splitlines()]
    dh_rows = [json.loads(line) for line in dh_jsonl.splitlines()]
    for row in (*audit_rows, *dh_rows):
        _assert_row_encoding(row)
    # The audit chain exports sequence-ascending (deterministic Merkle order).
    sequences = [row["sequence"] for row in audit_rows]
    assert len(sequences) == 2
    assert sequences == sorted(sequences)


async def test_export_merkle_root_recomputes_from_bundled_rows(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(AuditEvent(event_type="a", request_id="r1", payload={}, tenant_id="t-1"))
    await dh.append(DecisionRecord(decision_type="d", request_id="r2", payload={}, tenant_id="t-1"))
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    manifest = json.loads(members["manifest.json"])
    audit_hashes = [
        bytes.fromhex(json.loads(line)["hash"])
        for line in members["audit_event.jsonl"].splitlines()
    ]
    dh_hashes = [
        bytes.fromhex(json.loads(line)["hash"])
        for line in members["decision_history.jsonl"].splitlines()
    ]
    # audit_event chain then decision_history chain, each sequence-ordered.
    assert merkle_root(audit_hashes + dh_hashes).hex() == manifest["merkle_root"]


async def test_export_excludes_other_tenant_rows(tmp_path: Path) -> None:
    engine, audit, dh = await _seeded_engine(tmp_path)
    await audit.append(AuditEvent(event_type="a", request_id="r1", payload={}, tenant_id="t-1"))
    await audit.append(AuditEvent(event_type="a", request_id="r2", payload={}, tenant_id="t-2"))
    await dh.append(DecisionRecord(decision_type="d", request_id="r3", payload={}, tenant_id="t-2"))
    tar_bytes = await export_evidence_pack(
        engine=engine,
        tenant_id="t-1",
        period_start=_WIDE[0],
        period_end=_WIDE[1],
        signing_key_path=_pem(tmp_path),
        secret_adapter=None,
        signer=_fake_signer,
    )
    members = _members(tar_bytes)
    audit_lines = members["audit_event.jsonl"].splitlines()
    assert len(audit_lines) == 1
    assert json.loads(audit_lines[0])["tenant_id"] == "t-1"
    assert members["decision_history.jsonl"] == b""  # no t-1 decision rows


async def test_export_rejects_signer_returning_empty_signature(tmp_path: Path) -> None:
    engine, *_ = await _seeded_engine(tmp_path)

    async def _empty_sig_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
        return CosignArtifacts(signature=b"", bundle=b"bundle")

    with pytest.raises(EvidencePackSigningError, match="empty signature"):
        await export_evidence_pack(
            engine=engine,
            tenant_id="t-1",
            period_start=_WIDE[0],
            period_end=_WIDE[1],
            signing_key_path=_pem(tmp_path),
            secret_adapter=None,
            signer=_empty_sig_signer,
        )


async def test_export_rejects_signer_returning_empty_bundle(tmp_path: Path) -> None:
    engine, *_ = await _seeded_engine(tmp_path)

    async def _empty_bundle_signer(manifest: bytes, identity: SigningIdentity) -> CosignArtifacts:
        return CosignArtifacts(signature=b"sig", bundle=b"")

    with pytest.raises(EvidencePackSigningError, match="empty Sigstore bundle"):
        await export_evidence_pack(
            engine=engine,
            tenant_id="t-1",
            period_start=_WIDE[0],
            period_end=_WIDE[1],
            signing_key_path=_pem(tmp_path),
            secret_adapter=None,
            signer=_empty_bundle_signer,
        )

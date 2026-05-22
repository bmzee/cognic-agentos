"""ISO 42001 evidence-pack exporter — Sprint 9 (ADR-006).

WIRE-PUBLIC / STOP-RULE — examiners consume the tarball, manifest, and
JSONL shapes produced here. Reads the exported `_audit_event` /
`_decision_history` Table objects through an injected AsyncEngine; never
imports or mutates `core/audit.py` / `core/decision_history.py` source.

On the critical-controls coverage gate (T10).
"""

from __future__ import annotations

import io
import json
import tarfile
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Table, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos import __version__
from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS
from cognic_agentos.compliance.iso42001.merkle import merkle_root
from cognic_agentos.compliance.iso42001.signing import (
    CosignArtifacts,
    SigningIdentity,
    cosign_sign_blob,
    resolve_signing_identity,
    validate_cosign_artifacts,
)
from cognic_agentos.core.audit import _audit_event
from cognic_agentos.core.decision_history import _decision_history

#: Manifest schema version + the Merkle scheme identifier (wire-public).
_SCHEMA_VERSION = 1
_MERKLE_ALGORITHM = "iso42001-evidence-merkle-v1"

#: Signer seam — production default is real cosign; tests inject a stub.
Signer = Callable[[bytes, SigningIdentity], Awaitable[CosignArtifacts]]


def _row_to_json(row: Any) -> dict[str, Any]:
    """Serialise one chain row to the spec §6.2.1 wire shape — bytes
    columns (`prev_hash`, `hash`) as lowercase hex, datetimes ISO-8601,
    UUIDs as strings; field names match the DB columns exactly."""
    out: dict[str, Any] = {}
    for key, value in row._mapping.items():
        if isinstance(value, bytes):
            out[key] = value.hex()
        elif isinstance(value, datetime):
            out[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            out[key] = str(value)
        else:
            out[key] = value
    return out


async def _query_chain(
    conn: AsyncConnection,
    table: Table,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
) -> list[Any]:
    """In-scope rows for one chain — tenant-filtered, half-open window
    [start, end), sequence-ordered (the deterministic Merkle order)."""
    stmt = (
        select(table)
        .where(table.c.tenant_id == tenant_id)
        .where(table.c.created_at >= period_start)
        .where(table.c.created_at < period_end)
        .order_by(table.c.sequence)
    )
    result = await conn.execute(stmt)
    return list(result.fetchall())


def _jsonl(rows: list[Any]) -> bytes:
    """One row per line, deterministic key order."""
    return b"".join(
        (json.dumps(_row_to_json(r), separators=(",", ":"), sort_keys=True) + "\n").encode()
        for r in rows
    )


def _per_control_coverage(rows: list[Any]) -> dict[str, dict[str, Any]]:
    """Registry-driven coverage section — every ADR-006 control plus the
    count of in-scope rows tagged with it."""
    observed: dict[str, int] = {}
    for row in rows:
        for cid in row._mapping["iso_controls"] or ():
            observed[cid] = observed.get(cid, 0) + 1
    return {
        entry.control_id: {
            "display": entry.display,
            "title": entry.title,
            "tagged_row_count": observed.get(entry.control_id, 0),
        }
        for entry in ISO42001_CONTROLS
    }


def _build_tarball(
    *,
    manifest: bytes,
    signature: bytes,
    bundle: bytes,
    audit_jsonl: bytes,
    decision_history_jsonl: bytes,
) -> bytes:
    """The five-member `.tar.gz` (member names are wire-public)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (
            ("manifest.json", manifest),
            ("manifest.json.sig", signature),
            ("manifest.json.bundle.sigstore", bundle),
            ("audit_event.jsonl", audit_jsonl),
            ("decision_history.jsonl", decision_history_jsonl),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def export_evidence_pack(
    *,
    engine: AsyncEngine,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    signing_key_path: str | None,
    secret_adapter: Any = None,
    signer: Signer = cosign_sign_blob,
) -> bytes:
    """Produce a signed ISO 42001 evidence-pack `.tar.gz` for one tenant
    over [period_start, period_end). Fail-loud on any signing failure —
    an unsigned examiner artifact is never returned."""
    identity = await resolve_signing_identity(
        key_path=signing_key_path, secret_adapter=secret_adapter
    )
    async with engine.connect() as conn:
        audit_rows = await _query_chain(conn, _audit_event, tenant_id, period_start, period_end)
        dh_rows = await _query_chain(conn, _decision_history, tenant_id, period_start, period_end)

    # Merkle leaves: audit_event chain THEN decision_history chain, each
    # already sequence-ordered; leaf input = the row's raw `hash` bytes.
    leaves = [r._mapping["hash"] for r in audit_rows] + [r._mapping["hash"] for r in dh_rows]
    root = merkle_root(leaves)

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "agentos_version": __version__,
        "tenant_id": tenant_id,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "merkle_algorithm": _MERKLE_ALGORITHM,
        "merkle_root": root.hex(),
        "audit_event_row_count": len(audit_rows),
        "decision_history_row_count": len(dh_rows),
        "signing_identity": identity.identity,
        "per_control_coverage": _per_control_coverage([*audit_rows, *dh_rows]),
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")

    artifacts = await signer(manifest_bytes, identity)
    # The `signer` seam accepts test / custom signers, not only the
    # default cosign_sign_blob — re-validate the output here so no signer
    # path can produce a structurally-complete but unverifiable pack.
    validate_cosign_artifacts(artifacts)

    return _build_tarball(
        manifest=manifest_bytes,
        signature=artifacts.signature,
        bundle=artifacts.bundle,
        audit_jsonl=_jsonl(audit_rows),
        decision_history_jsonl=_jsonl(dh_rows),
    )

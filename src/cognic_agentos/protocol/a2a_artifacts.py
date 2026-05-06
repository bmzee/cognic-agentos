"""protocol/a2a_artifacts.py — A2A artifact reference generator.

Per A2A-CONFORMANCE.md §"Artifacts" + ADR-003: large outputs (PDFs,
evidence packs, JSON > threshold) are stored via Sprint-4's
``ObjectStoreAdapter`` and returned as :class:`ArtifactRef`
references; smaller payloads ride inline in the Task envelope.
Per-tenant retention is configured via
``Settings.a2a_artifact_retention_seconds``; the inline-vs-store
threshold via ``Settings.a2a_artifact_inline_threshold_bytes``.

T11 R0 doctrines (locked with implementation engineer):

  - **Audit chain-linkage on BOTH inline + object-store paths** —
    every :meth:`A2AArtifactStore.store_or_inline` call emits
    ``a2a.artifact_prepared`` with ``storage_mode`` discriminator
    so examiners see the storage DECISION, not just the stored
    blob. Bucket / key / retention metadata appear only on the
    object-store path.
  - **Inline threshold via Settings**, never a module-level
    constant. ``Settings.a2a_artifact_inline_threshold_bytes``
    (default 64 KiB, ``>0`` validator) drives the inline-vs-store
    decision. Banks with stricter inline-payload caps override
    downward via the standard env-var mechanism.
  - **Audit-pipeline failures safe-swallow** per the Sprint-5
    ``_emit_call_evidence`` discipline (mirrors T9
    ``_emit_a2a_evidence`` + T10 ``_emit_streaming_evidence``).
    The artifact emission still returns bytes / ref to the caller
    so the upstream task can complete.

Boundary semantics (regression-pinned in tests):

    len(bytes) <= threshold  →  inline (return bytes verbatim)
    len(bytes) >  threshold  →  object_store (return ArtifactRef)

NOT critical-controls per AGENTS.md (the storage decision rides
audit, not the wire-protocol contract — wire bytes are caller-owned).
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from typing import Any

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter

_LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Reference to an artifact stored via
    :class:`ObjectStoreAdapter`. The ``uri`` is an
    ``objstore://<bucket>/<key>`` URL the consumer dereferences via
    ``ObjectStoreAdapter.get(bucket, key)``; ``sha256`` lets the
    consumer verify content integrity end-to-end without trusting
    the indirection layer.
    """

    uri: str
    sha256: str
    size_bytes: int
    mime_type: str


class A2AArtifactStore:
    """Inline-or-store artifact emitter.

    Construction injects ``Settings`` (for threshold + retention),
    ``ObjectStoreAdapter`` (Sprint-4 protocol), and ``AuditStore``
    (chain-linkage). The handler emits ``a2a.artifact_prepared`` on
    every call regardless of which path was taken so the audit
    chain captures the storage decision.

    Single concurrent caller per instance; stateless across calls
    (the ObjectStoreAdapter handles its own concurrency).
    """

    def __init__(
        self,
        *,
        settings: Settings,
        object_store: ObjectStoreAdapter,
        audit_store: AuditStore,
    ) -> None:
        self._settings = settings
        self._object_store = object_store
        self._audit = audit_store

    async def store_or_inline(
        self,
        *,
        bytes_: bytes,
        mime_type: str,
        tenant_id: str,
        request_id: str = "system",
    ) -> ArtifactRef | bytes:
        """Store the bytes via :class:`ObjectStoreAdapter` if larger
        than the configured threshold, else return them inline.

        Either path emits ``a2a.artifact_prepared`` to the audit
        chain. Audit failures safe-swallow; the primary return
        value (bytes or :class:`ArtifactRef`) propagates to the
        caller regardless.
        """
        threshold = self._settings.a2a_artifact_inline_threshold_bytes
        size = len(bytes_)
        digest = hashlib.sha256(bytes_).hexdigest()

        if size <= threshold:
            await self._emit_artifact_evidence(
                storage_mode="inline",
                sha256=digest,
                size_bytes=size,
                mime_type=mime_type,
                tenant_id=tenant_id,
                request_id=request_id,
                bucket=None,
                key=None,
            )
            return bytes_

        # Object-store path. Bucket scoped per tenant; key includes
        # a 2-char prefix for filesystem-friendly fan-out, mirroring
        # standard content-addressed-storage layouts.
        bucket = f"a2a-artifacts-{tenant_id}"
        key = f"{digest[:2]}/{digest}"
        retention = self._settings.a2a_artifact_retention_seconds
        await self._object_store.put(
            bucket=bucket,
            key=key,
            body=bytes_,
            retention_seconds=retention,
        )
        await self._emit_artifact_evidence(
            storage_mode="object_store",
            sha256=digest,
            size_bytes=size,
            mime_type=mime_type,
            tenant_id=tenant_id,
            request_id=request_id,
            bucket=bucket,
            key=key,
        )
        return ArtifactRef(
            uri=f"objstore://{bucket}/{key}",
            sha256=digest,
            size_bytes=size,
            mime_type=mime_type,
        )

    async def _emit_artifact_evidence(
        self,
        *,
        storage_mode: str,
        sha256: str,
        size_bytes: int,
        mime_type: str,
        tenant_id: str,
        request_id: str,
        bucket: str | None,
        key: str | None,
    ) -> None:
        """Emit ``a2a.artifact_prepared`` audit row. Bucket / key /
        retention only present on the object-store path; inline
        path emits the storage decision + content-addressed
        identity (sha256 + size) only.

        Audit-pipeline failures safe-swallow — the artifact
        emission's primary return value still propagates to the
        caller.
        """
        payload: dict[str, Any] = {
            "storage_mode": storage_mode,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "mime_type": mime_type,
        }
        if bucket is not None:
            payload["bucket"] = bucket
        if key is not None:
            payload["key"] = key
        if storage_mode == "object_store":
            payload["retention_seconds"] = self._settings.a2a_artifact_retention_seconds

        try:
            await self._audit.append(
                AuditEvent(
                    event_type="a2a.artifact_prepared",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=payload,
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed for a2a.artifact_prepared "
                "(tenant_id=%s storage_mode=%s sha256_prefix=%s "
                "audit_error_type=%s); artifact emission still "
                "returns to the caller.",
                tenant_id,
                storage_mode,
                sha256[:8],
                type(audit_exc).__name__,
            )


__all__ = (
    "A2AArtifactStore",
    "ArtifactRef",
)

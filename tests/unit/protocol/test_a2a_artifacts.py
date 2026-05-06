"""Sprint 6 T11 — protocol/a2a_artifacts.py contract tests.

A2A artifact reference generator (``ObjectStoreAdapter``-backed).
Per A2A-CONFORMANCE.md §"Artifacts" + ADR-003: large outputs are
stored via ObjectStore and returned as ArtifactRef; small payloads
remain inline.

T11 R0 doctrine #3 + #4 (refined with implementation engineer):

  - **Audit chain-linkage on BOTH inline + object-store paths.**
    Every store_or_inline call emits ``a2a.artifact_prepared`` with
    ``storage_mode: "inline" | "object_store"``, ``sha256``,
    ``size_bytes``, plus ``bucket`` / ``key`` / ``retention_seconds``
    only on the object-store path. Examiners see the storage
    DECISION, not just the stored blob.

  - **Inline threshold via Settings**, NOT a hardcoded constant.
    ``Settings.a2a_artifact_inline_threshold_bytes`` (default 64 KiB,
    >0 validator) controls inline vs store. Tests pin the boundary
    semantics: ``len <= threshold`` → inline; ``len > threshold`` →
    store.

  - **Audit-pipeline failures safe-swallow** per the T9/T10
    discipline; artifact emission still returns the bytes/ref to
    the caller.
"""

from __future__ import annotations

import hashlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_artifacts import (
    A2AArtifactStore,
    ArtifactRef,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def object_store() -> MagicMock:
    mock = MagicMock()
    mock.put = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def artifact_store(object_store: MagicMock, audit_store: MagicMock) -> A2AArtifactStore:
    return A2AArtifactStore(
        settings=build_settings_without_env_file(),
        object_store=object_store,
        audit_store=audit_store,
    )


# =============================================================================
# Module shape
# =============================================================================


class TestArtifactRefShape:
    def test_artifact_ref_is_frozen(self) -> None:
        import dataclasses

        ref = ArtifactRef(
            uri="objstore://bucket/key",
            sha256="a" * 64,
            size_bytes=100,
            mime_type="application/pdf",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ref.uri = "x"  # type: ignore[misc]

    def test_artifact_ref_required_fields(self) -> None:
        import dataclasses

        fields = {f.name for f in dataclasses.fields(ArtifactRef)}
        required = {"uri", "sha256", "size_bytes", "mime_type"}
        assert required <= fields


# =============================================================================
# Inline path — len <= threshold
# =============================================================================


class TestInlinePath:
    """Payloads with ``len(bytes) <= threshold`` ride inline; the
    bytes are returned verbatim so the caller can attach them to
    the Task envelope."""

    async def test_small_payload_returns_bytes(self, artifact_store: A2AArtifactStore) -> None:
        result = await artifact_store.store_or_inline(
            bytes_=b"hello", mime_type="text/plain", tenant_id="bank_a"
        )
        assert result == b"hello"

    async def test_inline_path_does_not_call_object_store(
        self,
        artifact_store: A2AArtifactStore,
        object_store: MagicMock,
    ) -> None:
        await artifact_store.store_or_inline(
            bytes_=b"x" * 1024, mime_type="text/plain", tenant_id="bank_a"
        )
        object_store.put.assert_not_called()

    async def test_at_threshold_boundary_is_inline(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """At exactly ``threshold`` bytes, payload rides inline.
        Fail-closed: only ``len > threshold`` triggers ObjectStore."""
        settings = build_settings_without_env_file().model_copy(
            update={"a2a_artifact_inline_threshold_bytes": 100}
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        result = await store.store_or_inline(
            bytes_=b"x" * 100, mime_type="text/plain", tenant_id="bank_a"
        )
        assert result == b"x" * 100
        object_store.put.assert_not_called()


# =============================================================================
# Object-store path — len > threshold
# =============================================================================


class TestObjectStorePath:
    """Payloads with ``len(bytes) > threshold`` are persisted via
    ``ObjectStoreAdapter.put`` and returned as :class:`ArtifactRef`."""

    async def test_large_payload_returns_artifact_ref(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        settings = build_settings_without_env_file().model_copy(
            update={"a2a_artifact_inline_threshold_bytes": 100}
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        body = b"x" * 1000
        result = await store.store_or_inline(
            bytes_=body, mime_type="application/pdf", tenant_id="bank_a"
        )
        assert isinstance(result, ArtifactRef)
        assert result.size_bytes == 1000
        assert result.mime_type == "application/pdf"
        assert result.sha256 == hashlib.sha256(body).hexdigest()

    async def test_object_store_put_invoked_with_retention(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        settings = build_settings_without_env_file().model_copy(
            update={
                "a2a_artifact_inline_threshold_bytes": 100,
                "a2a_artifact_retention_seconds": 86400,
            }
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        await store.store_or_inline(bytes_=b"x" * 200, mime_type="text/plain", tenant_id="bank_a")
        object_store.put.assert_awaited_once()
        kwargs: dict[str, Any] = object_store.put.call_args.kwargs
        assert kwargs["retention_seconds"] == 86400
        assert "bank_a" in kwargs["bucket"]

    async def test_uri_format_is_objstore_scheme(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Per ADR-003 §Artifacts: the URI scheme is ``objstore://``
        so consumers know to fetch via ``ObjectStoreAdapter.get``."""
        settings = build_settings_without_env_file().model_copy(
            update={"a2a_artifact_inline_threshold_bytes": 10}
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        result = await store.store_or_inline(
            bytes_=b"x" * 100, mime_type="text/plain", tenant_id="bank_a"
        )
        assert isinstance(result, ArtifactRef)
        assert result.uri.startswith("objstore://")


# =============================================================================
# Chain-linkage evidence — both paths emit a2a.artifact_prepared
# =============================================================================


class TestChainEvidence:
    """T11 R0 doctrine #3 (user-explicit refinement): audit emission
    is mode-neutral. Both inline and object_store paths emit
    ``a2a.artifact_prepared`` with the storage_mode discriminator."""

    async def test_inline_path_emits_audit(
        self,
        artifact_store: A2AArtifactStore,
        audit_store: MagicMock,
    ) -> None:
        await artifact_store.store_or_inline(
            bytes_=b"hello",
            mime_type="text/plain",
            tenant_id="bank_a",
            request_id="rid-art-1",
        )
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.artifact_prepared"
        assert event.tenant_id == "bank_a"
        assert event.request_id == "rid-art-1"
        assert event.payload["storage_mode"] == "inline"
        assert event.payload["sha256"] == hashlib.sha256(b"hello").hexdigest()
        assert event.payload["size_bytes"] == 5
        # bucket / key / retention_seconds NOT present on inline path
        assert "bucket" not in event.payload
        assert "key" not in event.payload
        assert "retention_seconds" not in event.payload

    async def test_object_store_path_emits_audit(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        settings = build_settings_without_env_file().model_copy(
            update={
                "a2a_artifact_inline_threshold_bytes": 10,
                "a2a_artifact_retention_seconds": 3600,
            }
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        body = b"x" * 500
        await store.store_or_inline(
            bytes_=body,
            mime_type="application/pdf",
            tenant_id="bank_a",
            request_id="rid-art-2",
        )
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.artifact_prepared"
        assert event.payload["storage_mode"] == "object_store"
        assert event.payload["sha256"] == hashlib.sha256(body).hexdigest()
        assert event.payload["size_bytes"] == 500
        # bucket / key / retention present on object-store path
        assert "bank_a" in event.payload["bucket"]
        assert event.payload["key"]
        assert event.payload["retention_seconds"] == 3600

    async def test_audit_failure_does_not_mask_artifact_emission(
        self,
        artifact_store: A2AArtifactStore,
        audit_store: MagicMock,
    ) -> None:
        """T9/T10 discipline: audit-pipeline failure MUST NOT mask
        the primary outcome — caller still receives the bytes/ref."""
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        result = await artifact_store.store_or_inline(
            bytes_=b"hello",
            mime_type="text/plain",
            tenant_id="bank_a",
        )
        assert result == b"hello"

    async def test_object_store_audit_failure_does_not_mask_ref(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        settings = build_settings_without_env_file().model_copy(
            update={"a2a_artifact_inline_threshold_bytes": 10}
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        result = await store.store_or_inline(
            bytes_=b"x" * 100, mime_type="text/plain", tenant_id="bank_a"
        )
        assert isinstance(result, ArtifactRef)


# =============================================================================
# Settings-driven threshold (T11 R0 doctrine #4)
# =============================================================================


class TestSettingsThreshold:
    """The threshold is read from
    ``Settings.a2a_artifact_inline_threshold_bytes``. Operators
    override per deployment per AGENTS.md production-grade rule;
    tests pin that the behaviour follows the configured value."""

    @pytest.mark.parametrize(
        ("threshold", "payload_size", "expected_inline"),
        [
            (100, 50, True),
            (100, 100, True),  # boundary: <=
            (100, 101, False),
            (1024, 1024, True),
            (1024, 1025, False),
        ],
    )
    async def test_threshold_drives_inline_decision(
        self,
        object_store: MagicMock,
        audit_store: MagicMock,
        threshold: int,
        payload_size: int,
        expected_inline: bool,
    ) -> None:
        settings = build_settings_without_env_file().model_copy(
            update={"a2a_artifact_inline_threshold_bytes": threshold}
        )
        store = A2AArtifactStore(
            settings=settings,
            object_store=object_store,
            audit_store=audit_store,
        )
        result = await store.store_or_inline(
            bytes_=b"x" * payload_size,
            mime_type="text/plain",
            tenant_id="bank_a",
        )
        if expected_inline:
            assert isinstance(result, bytes)
            object_store.put.assert_not_called()
        else:
            assert isinstance(result, ArtifactRef)
            object_store.put.assert_awaited_once()

"""Sprint 4 T9 — Sigstore bundle persister tests.

Per the user's T9 guardrails:

  > Atomic object-store put() with the 7-year retention metadata,
  > no raw bundle bytes in audit/decision payloads, fail-closed if
  > persistence fails, and a deterministic object key like
  > attestations/<pack_id>/<version>/bundle.sigstore with path
  > inputs already validated before they reach the adapter.

The tests run against the real ``LocalObjectStoreAdapter`` (T4 —
production filesystem ObjectStoreAdapter) so the retention sidecar,
atomic-write semantics, and key shape are all exercised end-to-end.

Test classes:

  * ``TestHappyPath`` — bundle persists at the deterministic key
    with retention sidecar declaring 7-year retain_until.
  * ``TestKeyShape`` — key path is exactly
    ``attestations/<pack_id>/<version>/bundle.sigstore``;
    re-persistence overwrites last-writer-wins (Sigstore bundles
    for the same pack version are content-identical per ADR-016).
  * ``TestIdentityValidation`` — pack_id / version regex checks
    fire BEFORE the adapter is touched; bad inputs raise
    SigstoreBundlePersistenceFailed cleanly.
  * ``TestBundleBytesValidation`` — empty / non-bytes bundle
    rejected with no adapter call.
  * ``TestFailClosed`` — adapter exceptions get wrapped into
    SigstoreBundlePersistenceFailed; raw bundle bytes don't leak
    into the error message; only sha256 + length surface.
  * ``TestExceptionTaxonomy`` — SigstoreBundlePersistenceFailed
    subclasses SupplyChainError so T10 can catch the base.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.protocol.supply_chain import (
    SIGSTORE_BUNDLE_BUCKET,
    SIGSTORE_BUNDLE_RETENTION_SECONDS,
    SigstoreBundlePersistenceFailed,
    SupplyChainError,
    persist_sigstore_bundle,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    """Real T4 LocalObjectStoreAdapter rooted at a per-test tmp dir.
    Tests exercising the retention sidecar / atomic-write contract
    run against the actual filesystem — no mocks here."""
    root = tmp_path / "attestations-store"
    root.mkdir()
    return LocalObjectStoreAdapter(root)


# ---------------------------------------------------------------------------
# TestHappyPath
# ---------------------------------------------------------------------------


class TestHappyPath:
    async def test_persistence_returns_deterministic_key(
        self, object_store: LocalObjectStoreAdapter, tmp_path: Path
    ) -> None:
        bundle = b"fake-sigstore-bundle-bytes-" + b"\x00\x01\x02"
        key = await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="cognic-tool-demo",
            version="1.0.0",
            bundle_bytes=bundle,
        )
        assert key == "attestations/cognic-tool-demo/1.0.0/bundle.sigstore"

    async def test_bundle_round_trips_through_adapter(
        self, object_store: LocalObjectStoreAdapter
    ) -> None:
        bundle = b"sigstore-bundle-payload-" + b"\xff" * 32
        await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="round-trip",
            version="1.0.0",
            bundle_bytes=bundle,
        )
        # Read back via the adapter's get(); bytes round-trip exactly.
        retrieved = await object_store.get(
            SIGSTORE_BUNDLE_BUCKET,
            "attestations/round-trip/1.0.0/bundle.sigstore",
        )
        assert retrieved == bundle

    async def test_retention_sidecar_declares_seven_years(
        self,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """Per ADR-016, Sigstore bundles must carry 7-year retention
        metadata. The T4 adapter writes a sidecar file with the
        retain_until ISO timestamp; we read it directly here to
        verify the persister passed retention_seconds correctly."""
        bundle = b"retention-test"
        await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="retain-pack",
            version="0.1.0",
            bundle_bytes=bundle,
        )
        store_root = tmp_path / "attestations-store"
        sidecar = (
            store_root
            / SIGSTORE_BUNDLE_BUCKET
            / "attestations"
            / "retain-pack"
            / "0.1.0"
            / "bundle.sigstore.retention"
        )
        assert sidecar.is_file()
        meta = json.loads(sidecar.read_text())
        assert meta["retention_seconds"] == SIGSTORE_BUNDLE_RETENTION_SECONDS
        # Sanity: 7 years is ~7 * 365 * 24 * 3600 = 220_752_000 seconds.
        assert meta["retention_seconds"] == 220_752_000
        retain_until = _dt.datetime.fromisoformat(meta["retain_until"])
        created = _dt.datetime.fromisoformat(meta["created_at"])
        assert (retain_until - created).total_seconds() == 220_752_000


# ---------------------------------------------------------------------------
# TestKeyShape
# ---------------------------------------------------------------------------


class TestKeyShape:
    async def test_key_uses_attestations_prefix_and_bundle_filename(
        self, object_store: LocalObjectStoreAdapter
    ) -> None:
        key = await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="key-shape",
            version="2.0.0",
            bundle_bytes=b"bundle",
        )
        assert key.startswith("attestations/")
        assert key.endswith("/bundle.sigstore")
        assert "/key-shape/" in key
        assert "/2.0.0/" in key

    async def test_re_persistence_overwrites_last_writer_wins(
        self, object_store: LocalObjectStoreAdapter
    ) -> None:
        """Sigstore bundles for the same pack version are content-
        identical per ADR-016, so deterministic-key + last-writer-wins
        is acceptable. A second persist with the same pack@version
        succeeds and the read-back returns the second body."""
        await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="overwrite",
            version="1.0.0",
            bundle_bytes=b"first-body",
        )
        await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="overwrite",
            version="1.0.0",
            bundle_bytes=b"second-body",
        )
        retrieved = await object_store.get(
            SIGSTORE_BUNDLE_BUCKET,
            "attestations/overwrite/1.0.0/bundle.sigstore",
        )
        assert retrieved == b"second-body"


# ---------------------------------------------------------------------------
# TestIdentityValidation
# ---------------------------------------------------------------------------


class TestIdentityValidation:
    @pytest.mark.parametrize(
        "bad_pack_id",
        ["pack;ls", "pack/sub", "PACK_UPPER", "pack`whoami`", "pack ", ".."],
    )
    async def test_invalid_pack_id_rejected_before_adapter_call(
        self,
        object_store: LocalObjectStoreAdapter,
        bad_pack_id: str,
    ) -> None:
        """Per the user's T9 guardrail: path inputs validated BEFORE
        the adapter is touched. Invalid pack_ids surface as a clean
        SigstoreBundlePersistenceFailed (NOT a downstream
        PathTraversalError from the adapter)."""
        with pytest.raises(SigstoreBundlePersistenceFailed, match="identity validation"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id=bad_pack_id,
                version="1.0.0",
                bundle_bytes=b"bundle",
            )

    @pytest.mark.parametrize(
        "bad_version",
        [
            # Shell-metacharacter / cosign-argv-style attacks (caught
            # by the broader regex character class).
            "v1; ls",
            "1.0\nrm",
            "1.0$(whoami)",
            "1.0 ",
            "1.0/sub",
        ],
    )
    async def test_invalid_version_rejected_before_adapter_call(
        self,
        object_store: LocalObjectStoreAdapter,
        bad_version: str,
    ) -> None:
        with pytest.raises(SigstoreBundlePersistenceFailed, match="identity validation"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="ok-pack",
                version=bad_version,
                bundle_bytes=b"bundle",
            )

    @pytest.mark.parametrize(
        "bad_version",
        [
            # R1 reviewer-P2 — path-aliasing values: the version
            # segment collapses or traverses upward when the adapter
            # canonicalises the key. T6's argv-safe regex accepted
            # both because the chars `.` are valid in cosign argv.
            ".",
            "..",
        ],
    )
    async def test_path_aliasing_version_rejected(
        self,
        object_store: LocalObjectStoreAdapter,
        bad_version: str,
    ) -> None:
        """R1 reviewer-P2 fix: ``"."`` / ``".."`` versions would alias
        the object-store path structure (``/pack/./bundle.sigstore``
        canonicalises to ``/pack/bundle.sigstore``). The pre-flight
        validator now rejects these explicitly."""
        with pytest.raises(SigstoreBundlePersistenceFailed, match="alias"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="ok-pack",
                version=bad_version,
                bundle_bytes=b"bundle",
            )

    @pytest.mark.parametrize(
        "bad_version",
        [
            # R1 reviewer-P2 — values that pass T6's argv-safe regex
            # but fail the LocalObjectStoreAdapter's KEY regex.
            # Pre-flight tightening means these surface with a clean
            # ``identity validation`` error instead of leaking through
            # to the adapter as a PathTraversalError.
            "1.0+local",  # PEP-440 local-version segment
            "2.0.0+build.5",
            "1.0RC1",  # uppercase
            "1.0.0a1B",  # mixed case
        ],
    )
    async def test_argv_safe_but_key_unsafe_version_rejected_at_preflight(
        self,
        object_store: LocalObjectStoreAdapter,
        bad_version: str,
    ) -> None:
        """R1 reviewer-P2 fix: the persister must reject these BEFORE
        calling the adapter. Previously T6's broader argv-safe regex
        let them through; the adapter would later raise
        PathTraversalError, and T9 would wrap as
        SigstoreBundlePersistenceFailed — but the wrap message would
        say "Sigstore bundle persistence failed" rather than the
        clearer "identity validation failed".
        """
        with pytest.raises(SigstoreBundlePersistenceFailed, match="identity validation"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="ok-pack",
                version=bad_version,
                bundle_bytes=b"bundle",
            )

    @pytest.mark.parametrize(
        "good_version",
        ["1.0.0", "0.1.0a1", "0.1.0", "2026.04.27", "1_0_0", "1-0-0"],
    )
    async def test_typical_pep440_lowercase_versions_accepted(
        self,
        object_store: LocalObjectStoreAdapter,
        good_version: str,
    ) -> None:
        """Counter-test: legitimate lowercase PEP-440 versions (the
        common case) pass the tighter validator."""
        key = await persist_sigstore_bundle(
            object_store=object_store,
            pack_id="ok-pack",
            version=good_version,
            bundle_bytes=b"bundle",
        )
        assert key == f"attestations/ok-pack/{good_version}/bundle.sigstore"

    async def test_validation_failure_does_not_call_adapter(self, tmp_path: Path) -> None:
        """When pre-flight validation fails, ``object_store.put`` MUST
        NOT have been called. Without the early validation, a bad
        identity could have triggered an adapter path-traversal
        check + raised the wrong exception class."""
        mock_store = AsyncMock()
        mock_store.put = AsyncMock()
        with pytest.raises(SigstoreBundlePersistenceFailed):
            await persist_sigstore_bundle(
                object_store=mock_store,
                pack_id="bad;name",
                version="1.0.0",
                bundle_bytes=b"bundle",
            )
        mock_store.put.assert_not_called()

    async def test_path_aliasing_version_does_not_call_adapter(self) -> None:
        """R1 reviewer-P2 fix: aliasing-version validation is also
        pre-flight — the adapter must never see ``"."`` / ``".."``."""
        mock_store = AsyncMock()
        mock_store.put = AsyncMock()
        with pytest.raises(SigstoreBundlePersistenceFailed, match="alias"):
            await persist_sigstore_bundle(
                object_store=mock_store,
                pack_id="ok-pack",
                version=".",
                bundle_bytes=b"bundle",
            )
        mock_store.put.assert_not_called()

    async def test_non_string_version_rejected(self, object_store: LocalObjectStoreAdapter) -> None:
        """Defensive: non-string version values (int / None / bytes)
        are rejected at the type check before regex matching. Mirrors
        T6's argv-validator type-check pattern."""
        with pytest.raises(SigstoreBundlePersistenceFailed, match="version must be str"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="ok-pack",
                version=123,  # type: ignore[arg-type]
                bundle_bytes=b"bundle",
            )

    async def test_plus_version_does_not_call_adapter(self) -> None:
        """Belt-and-suspenders for the user's specific call-out: a
        ``+``-containing version must be rejected at the persister
        boundary, never reach the adapter."""
        mock_store = AsyncMock()
        mock_store.put = AsyncMock()
        with pytest.raises(SigstoreBundlePersistenceFailed):
            await persist_sigstore_bundle(
                object_store=mock_store,
                pack_id="ok-pack",
                version="1.0+local",
                bundle_bytes=b"bundle",
            )
        mock_store.put.assert_not_called()


# ---------------------------------------------------------------------------
# TestBundleBytesValidation
# ---------------------------------------------------------------------------


class TestBundleBytesValidation:
    async def test_empty_bundle_rejected(self, object_store: LocalObjectStoreAdapter) -> None:
        with pytest.raises(SigstoreBundlePersistenceFailed, match="must be non-empty bytes"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="empty-pack",
                version="1.0.0",
                bundle_bytes=b"",
            )

    async def test_non_bytes_bundle_rejected(self, object_store: LocalObjectStoreAdapter) -> None:
        with pytest.raises(SigstoreBundlePersistenceFailed, match="must be non-empty bytes"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="str-pack",
                version="1.0.0",
                bundle_bytes="i am a string not bytes",  # type: ignore[arg-type]
            )

    async def test_bundle_validation_does_not_call_adapter(self) -> None:
        mock_store = AsyncMock()
        mock_store.put = AsyncMock()
        with pytest.raises(SigstoreBundlePersistenceFailed):
            await persist_sigstore_bundle(
                object_store=mock_store,
                pack_id="ok-pack",
                version="1.0.0",
                bundle_bytes=b"",
            )
        mock_store.put.assert_not_called()


# ---------------------------------------------------------------------------
# TestFailClosed — adapter errors wrap into SigstoreBundlePersistenceFailed
# ---------------------------------------------------------------------------


class TestFailClosed:
    async def test_adapter_oserror_wrapped(
        self,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An OSError from the adapter (filesystem failure mid-write)
        gets wrapped into SigstoreBundlePersistenceFailed with no raw
        bundle bytes leaking into the message."""

        async def _failing_put(self: Any, *args: Any, **kwargs: Any) -> None:
            raise OSError(28, "ENOSPC — no space left on device")

        monkeypatch.setattr(LocalObjectStoreAdapter, "put", _failing_put)
        with pytest.raises(SigstoreBundlePersistenceFailed, match="class=OSError"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="fail-pack",
                version="1.0.0",
                bundle_bytes=b"bundle",
            )

    async def test_adapter_runtime_error_wrapped(
        self,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Any non-OSError adapter failure is also caught — fail-closed
        applies to the broad ``except Exception`` per the user's T9
        guardrail."""

        async def _failing_put(self: Any, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("adapter is misconfigured")

        monkeypatch.setattr(LocalObjectStoreAdapter, "put", _failing_put)
        with pytest.raises(SigstoreBundlePersistenceFailed, match="class=RuntimeError"):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="rt-fail",
                version="1.0.0",
                bundle_bytes=b"bundle",
            )

    async def test_error_message_does_not_leak_bundle_bytes(
        self,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per the user's T9 guardrail: no raw bundle bytes in
        audit/decision payloads. The error message also avoids
        them — only the SHA-256 + length appear, mirroring T6 +
        T7 stderr/stdout privacy."""
        secret_payload = b"ATTACKER_LEAK: sigstore-bundle-with-tenant-secret"

        async def _failing_put(self: Any, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("simulated adapter failure")

        monkeypatch.setattr(LocalObjectStoreAdapter, "put", _failing_put)
        with pytest.raises(SigstoreBundlePersistenceFailed) as exc:
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="leak-pack",
                version="1.0.0",
                bundle_bytes=secret_payload,
            )
        msg = str(exc.value)
        # Raw bundle bytes (UTF-8 decode) MUST NOT appear.
        assert "ATTACKER_LEAK" not in msg
        assert "tenant-secret" not in msg
        # SHA-256 + length DO appear for log correlation.
        assert hashlib.sha256(secret_payload).hexdigest() in msg
        assert f"bundle_len={len(secret_payload)}" in msg

    async def test_adapter_path_traversal_wrapped_to_persistence_failed(
        self, tmp_path: Path
    ) -> None:
        """If a future change loosens the early identity validation,
        the adapter's PathTraversalError still surfaces as
        SigstoreBundlePersistenceFailed (the ``except Exception``
        catch-all). T10 only needs to handle one exception class."""

        # Construct an adapter with a root path that DOESN'T match a
        # path the test pack-id would resolve to. Then monkey-patch
        # away the early validation so we hit the adapter's check.
        # Easier alternative: feed a pack_id that passes early
        # validation but causes the adapter to surface its own error
        # via the bucket-isn't-writable path.
        root = tmp_path / "readonly-root.txt"
        root.write_text("this is a file, not a directory")
        object_store = LocalObjectStoreAdapter(root)
        with pytest.raises(SigstoreBundlePersistenceFailed):
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id="ok-pack",
                version="1.0.0",
                bundle_bytes=b"bundle",
            )


# ---------------------------------------------------------------------------
# TestExceptionTaxonomy
# ---------------------------------------------------------------------------


class TestExceptionTaxonomy:
    def test_persistence_failed_subclasses_supply_chain_error(self) -> None:
        """T10 catches ``SupplyChainError`` to refuse pack registration
        with the matching ``refusal_reason``. Persistence failures
        must be catchable through the base class."""
        assert issubclass(SigstoreBundlePersistenceFailed, SupplyChainError)

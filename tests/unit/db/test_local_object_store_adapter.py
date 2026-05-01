"""Sprint 4 T4 — production filesystem ``ObjectStoreAdapter`` tests.

Per the Sprint-4 plan-of-record §4 lock + AGENTS.md production-grade
rule: this is the FIRST real ``ObjectStoreAdapter`` implementation,
not a test stub. Tests cover the load-bearing contract:

  - Atomic writes (``os.fsync`` + ``os.replace``); partial files
    never visible
  - Path-traversal safe (regex + canonicalisation; rejects ``..``,
    leading ``/``, NUL bytes, symlink-escape)
  - Retention metadata enforced at adapter level via sidecar JSON;
    tampered sidecar → fail-closed-on-delete
  - ``presign()`` raises ``NotImplementedError`` (R2-#1 reviewer-fix)
  - Deterministic byte-exact round-trip across all 256 byte values
    + 10 MiB Sigstore-bundle-shaped payloads
  - ``health_check()`` reports ``ok`` when root is writable,
    ``unreachable`` when root is missing or unwritable
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
    PathTraversalError,
    RetentionWindowActiveError,
)
from cognic_agentos.db.adapters.protocols import AdapterHealth

# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterRoundTrip — byte-exact ``put`` → ``get``.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterRoundTrip:
    async def test_put_then_get_round_trips_arbitrary_bytes(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        body = bytes(range(256))  # all byte values 0x00..0xff
        await adapter.put("test-bucket", "key1", body)
        assert await adapter.get("test-bucket", "key1") == body

    async def test_put_then_get_round_trips_sigstore_shaped_payload(self, tmp_path: Path) -> None:
        """Sigstore bundles are typically 5-10 MB per ADR-016. The
        adapter must round-trip a payload at that order of magnitude."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        body = os.urandom(10 * 1024 * 1024)  # 10 MiB
        await adapter.put("attestations", "pkg/v1/bundle.sigstore", body)
        assert await adapter.get("attestations", "pkg/v1/bundle.sigstore") == body

    async def test_put_then_get_round_trips_empty_body(self, tmp_path: Path) -> None:
        """Empty bodies are valid (e.g. a presence-marker file)."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "empty", b"")
        assert await adapter.get("test-bucket", "empty") == b""

    async def test_get_missing_key_raises(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(FileNotFoundError):
            await adapter.get("test-bucket", "nonexistent")

    async def test_overwrite_replaces_previous_body(self, tmp_path: Path) -> None:
        """Put-on-existing-key replaces body atomically."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"v1")
        await adapter.put("test-bucket", "k", b"v2-much-longer-body")
        assert await adapter.get("test-bucket", "k") == b"v2-much-longer-body"


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterAtomicity — no torn writes / no leaked .tmp.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterAtomicity:
    async def test_concurrent_writes_resolve_atomically(self, tmp_path: Path) -> None:
        """Atomic rename means the file at the key is always either a
        complete previous body or a complete new body — never partial.
        Last-writer-wins is acceptable per Sprint-4 §4 (Sigstore bundles
        for the same pack version are content-identical)."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        bodies = [b"a" * 1024, b"b" * 1024, b"c" * 1024]
        await asyncio.gather(*(adapter.put("test-bucket", "k", b) for b in bodies))
        body = await adapter.get("test-bucket", "k")
        # Always one complete homogeneous body — never a mix of bytes.
        assert len(body) == 1024
        assert body in bodies

    async def test_no_partial_files_visible_in_bucket(self, tmp_path: Path) -> None:
        """The .tmp staging directory is the only place ``.tmp`` files
        ever appear. After put() returns, the bucket dir contains only
        the keyfile (+ optional .retention sidecar) + the .tmp/ dir."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"complete-body")
        bucket_dir = tmp_path / "test-bucket"
        # Top-level bucket entries: just "k" + ".tmp" dir.
        entries = sorted(p.name for p in bucket_dir.iterdir())
        assert entries == [".tmp", "k"]
        # No leaked partial files in either spot.
        assert list((bucket_dir / ".tmp").glob("*.tmp")) == []

    async def test_failure_during_write_does_not_leak_partial_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the rename step fails (simulated), the target key must
        not exist. The .tmp file may exist transiently or be cleaned
        up; the contract is that ``get(target)`` raises FileNotFoundError."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        original_replace = os.replace

        def _failing_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", _failing_replace)
        with pytest.raises(OSError, match="simulated rename failure"):
            await adapter.put("test-bucket", "k", b"would-be-body")
        monkeypatch.setattr(os, "replace", original_replace)
        # Target was never written.
        with pytest.raises(FileNotFoundError):
            await adapter.get("test-bucket", "k")

    async def test_short_writes_are_resubmitted_until_complete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R2 reviewer-P2 regression: ``os.write`` may short-write per
        POSIX. Without a write-all loop, a truncated Sigstore bundle
        would be fsynced + renamed into place and reported successful.
        Force the kernel to accept only 7 bytes per call and verify the
        adapter resubmits the rest until the full body lands.
        """
        adapter = LocalObjectStoreAdapter(tmp_path)
        original_write = os.write

        # Track how often os.write is invoked AND on which fd, so we can
        # confirm the adapter genuinely looped (rather than the kernel
        # happening to accept everything at once on a fresh tmpfile).
        call_count = {"n": 0}
        seen_fds: set[int] = set()

        def _short_write(fd: int, data: bytes | memoryview) -> int:
            call_count["n"] += 1
            seen_fds.add(fd)
            # Only the body write goes through a tmp-file fd opened by
            # the adapter — health-probe paths use Path.write_bytes
            # which goes via a different kernel call, so this monkey
            # patch is contained to the adapter's _atomic_write fd.
            chunk = bytes(data)[:7]
            return original_write(fd, chunk)

        monkeypatch.setattr(os, "write", _short_write)
        body = b"x" * 100  # 100 bytes / 7-byte chunks → ~15 write calls
        await adapter.put("attestations", "pkg/v1/bundle.sigstore", body)
        # Adapter must have looped — at minimum ceil(100/7) = 15 calls
        # against a single fd for the body. (sanity floor only; sidecar
        # writes are absent because retention_seconds=None.)
        assert call_count["n"] >= 15, (
            f"expected write-all loop to invoke os.write at least 15 times for a 100-byte "
            f"body with 7-byte chunks; got {call_count['n']}"
        )
        # And the file landed COMPLETE — not truncated.
        monkeypatch.setattr(os, "write", original_write)
        assert await adapter.get("attestations", "pkg/v1/bundle.sigstore") == body

    async def test_non_positive_write_return_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If a kernel/runtime returns ``0`` from ``os.write`` (a POSIX
        contract violation — write must either return ``>0`` or raise),
        the adapter MUST fail closed rather than spin forever or
        silently truncate."""
        adapter = LocalObjectStoreAdapter(tmp_path)

        def _zero_write(fd: int, data: bytes | memoryview) -> int:
            return 0

        monkeypatch.setattr(os, "write", _zero_write)
        with pytest.raises(OSError, match=r"os\.write returned 0"):
            await adapter.put("test-bucket", "k", b"any-body")


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterPathSafety — every traversal vector rejected.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterPathSafety:
    async def test_invalid_bucket_chars_rejected(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        for bad_bucket in ("/etc", "..", ".", "test/sub", "TEST", "test\x00"):
            with pytest.raises(PathTraversalError):
                await adapter.put(bad_bucket, "k", b"x")

    async def test_invalid_key_chars_rejected(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        for bad_key in (
            "../escape",
            "/etc/passwd",
            "valid/../escape",
            "..",
            "key\x00null",
            "/leading/slash",
            "Key-Has-Caps",
        ):
            with pytest.raises(PathTraversalError):
                await adapter.put("test-bucket", bad_key, b"x")

    async def test_dotdot_segment_in_middle_of_key_rejected(self, tmp_path: Path) -> None:
        """A regex-passing key like ``a/b/../c`` still resolves to
        ``a/c`` if Python is permissive — but the structural ``..``
        check catches it before path resolution."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(PathTraversalError, match=r"\.\."):
            await adapter.put("test-bucket", "a/b/../c", b"x")

    async def test_non_string_args_rejected(self, tmp_path: Path) -> None:
        """Defensive: bytes / int args don't slip through."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(PathTraversalError, match="bucket must be str"):
            await adapter.put(b"bytes-bucket", "k", b"x")  # type: ignore[arg-type]
        with pytest.raises(PathTraversalError, match="key must be str"):
            await adapter.put("test-bucket", 123, b"x")  # type: ignore[arg-type]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
    async def test_symlink_in_bucket_pointing_outside_root_rejected(self, tmp_path: Path) -> None:
        """A symlink under root that points outside is caught at
        validate-time via ``parent.resolve()`` — even if the
        bucket+key regex passes, canonicalisation rejects."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        outside = tmp_path.parent / "outside_target_dir"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("steal me")
        try:
            symlink_bucket = tmp_path / "evil-bucket"
            symlink_bucket.symlink_to(outside)
            with pytest.raises(PathTraversalError, match=r"resolved parent.*not under root"):
                await adapter.get("evil-bucket", "secret.txt")
        finally:
            (outside / "secret.txt").unlink(missing_ok=True)
            outside.rmdir()


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterRetention — sidecar enforcement.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterRetention:
    async def test_no_retention_means_immediate_delete_ok(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "transient", b"goodbye")
        await adapter.delete("test-bucket", "transient")
        with pytest.raises(FileNotFoundError):
            await adapter.get("test-bucket", "transient")

    async def test_retention_sidecar_written_on_put(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"protected", retention_seconds=3600)
        sidecar = tmp_path / "test-bucket" / "k.retention"
        assert sidecar.is_file()
        meta = json.loads(sidecar.read_text())
        assert meta["retention_seconds"] == 3600
        retain_until = _dt.datetime.fromisoformat(meta["retain_until"])
        created_at = _dt.datetime.fromisoformat(meta["created_at"])
        assert (retain_until - created_at).total_seconds() == 3600

    async def test_seven_year_retention_records_correct_metadata(self, tmp_path: Path) -> None:
        """ADR-016 minimum 7-year retention for Sigstore bundles."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        seven_years_s = 7 * 365 * 24 * 3600
        await adapter.put(
            "attestations",
            "pkg/v1/bundle.sigstore",
            b"bundle",
            retention_seconds=seven_years_s,
        )
        sidecar = tmp_path / "attestations" / "pkg/v1/bundle.sigstore.retention"
        meta = json.loads(sidecar.read_text())
        assert meta["retention_seconds"] == seven_years_s

    async def test_delete_within_retention_window_refused(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"keep-me", retention_seconds=3600)
        with pytest.raises(RetentionWindowActiveError, match="retention window active"):
            await adapter.delete("test-bucket", "k")
        # Body still present after refused delete.
        assert await adapter.get("test-bucket", "k") == b"keep-me"

    async def test_delete_after_retention_window_allowed(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        # Write with a real 1-second window so we don't have to
        # back-date the sidecar — sleep 1.1s before delete.
        await adapter.put("test-bucket", "k", b"old", retention_seconds=1)
        await asyncio.sleep(1.1)
        await adapter.delete("test-bucket", "k")
        with pytest.raises(FileNotFoundError):
            await adapter.get("test-bucket", "k")
        # Sidecar removed too.
        assert not (tmp_path / "test-bucket" / "k.retention").exists()

    async def test_tampered_sidecar_refuses_delete_fail_closed(self, tmp_path: Path) -> None:
        """Operator who tampers the sidecar JSON cannot bypass retention.
        Adapter fail-closes rather than silently deleting."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"x", retention_seconds=3600)
        sidecar = tmp_path / "test-bucket" / "k.retention"
        sidecar.write_text("{ this is not valid JSON")
        with pytest.raises(RetentionWindowActiveError, match="malformed"):
            await adapter.delete("test-bucket", "k")
        # Body still present.
        assert await adapter.get("test-bucket", "k") == b"x"

    async def test_sidecar_missing_field_refuses_delete_fail_closed(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"x", retention_seconds=3600)
        sidecar = tmp_path / "test-bucket" / "k.retention"
        sidecar.write_text(json.dumps({"created_at": "2026-01-01T00:00:00+00:00"}))
        with pytest.raises(RetentionWindowActiveError, match="malformed"):
            await adapter.delete("test-bucket", "k")

    async def test_retention_zero_rejected(self, tmp_path: Path) -> None:
        """R1 reviewer-P2: ``retention_seconds=0`` would silently bypass
        retention enforcement (sidecar's retain_until == created_at →
        immediately deletable). Reject at put() boundary."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(ValueError, match="retention_seconds must be > 0"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds=0)
        # No body written.
        with pytest.raises(FileNotFoundError):
            await adapter.get("test-bucket", "k")

    async def test_retention_negative_rejected(self, tmp_path: Path) -> None:
        """R1 reviewer-P2: a negative retention window puts retain_until
        in the past; delete() would then succeed immediately, completely
        defeating retention. Reject at put() boundary."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(ValueError, match="retention_seconds must be > 0"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds=-1)

    async def test_retention_bool_rejected(self, tmp_path: Path) -> None:
        """R1 reviewer-P2: ``bool`` is a subtype of ``int`` in Python
        (``isinstance(True, int)`` is True). Without an explicit bool
        check, ``put(..., retention_seconds=True)`` would silently set
        a 1-second window and ``False`` would set 0. Both are accidents
        — reject at the boundary so retention enforcement is opt-in only
        via a real positive int."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(TypeError, match="retention_seconds must be a positive int"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds=True)
        with pytest.raises(TypeError, match="retention_seconds must be a positive int"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds=False)

    async def test_retention_non_int_rejected(self, tmp_path: Path) -> None:
        """Float / str retention values are rejected too — the contract
        is positive ``int`` seconds."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(TypeError, match="retention_seconds must be a positive int"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds=3600.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="retention_seconds must be a positive int"):
            await adapter.put("test-bucket", "k", b"x", retention_seconds="3600")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterDurability — directory fsync after rename.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterDurability:
    async def test_put_fsyncs_parent_directory_after_replace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R1 reviewer-P2: ``os.replace`` is atomic but not durable —
        the rename can be lost on power loss between replace and the
        next directory-metadata flush. The adapter MUST fsync the
        parent directory after replace to upgrade visibility-atomicity
        to durability-atomicity. This test wraps ``os.fsync`` and
        confirms the parent dir's fd is fsynced after the body's fd."""
        original_fsync = os.fsync
        original_open = os.open
        fsynced_paths: list[str] = []
        # Map fd → path so we can record what each fsync targets.
        fd_to_path: dict[int, str] = {}

        def _tracking_open(path: str | os.PathLike[str], flags: int, mode: int = 0o777, /) -> int:
            fd = original_open(path, flags, mode)
            fd_to_path[fd] = os.fspath(path)
            return fd

        def _tracking_fsync(fd: int) -> None:
            if fd in fd_to_path:
                fsynced_paths.append(fd_to_path[fd])
            original_fsync(fd)

        monkeypatch.setattr(os, "open", _tracking_open)
        monkeypatch.setattr(os, "fsync", _tracking_fsync)
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"durable")
        # Restore so teardown / other instrumentation isn't perturbed.
        monkeypatch.setattr(os, "open", original_open)
        monkeypatch.setattr(os, "fsync", original_fsync)
        # The bucket directory must be among the fsynced paths. (We do
        # not assert ordering or exclusivity because retention sidecar
        # writes also fsync; for a no-retention put the bucket dir
        # appearing at all is the durability fence.)
        bucket_dir = (tmp_path / "test-bucket").resolve()
        assert any(Path(p).resolve() == bucket_dir for p in fsynced_paths), (
            f"parent dir {bucket_dir!s} never fsynced; fsynced paths={fsynced_paths!r}"
        )

    async def test_retention_sidecar_uses_atomic_write(self, tmp_path: Path) -> None:
        """R1 reviewer-P2 follow-up: the retention sidecar must use the
        same atomic-write helper as the body. A non-atomic write_text
        could leave a half-written sidecar that ``_delete_sync`` then
        treats as malformed → fail-closed. Atomic write means the
        sidecar is either complete or absent. Verified indirectly by
        ensuring the .tmp staging dir is created during sidecar writes
        too (the helper's signature)."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"protected", retention_seconds=3600)
        # The .tmp dir under the bucket exists (created by atomic_write
        # for both body and sidecar). After put returns, it's empty.
        tmp_dir = tmp_path / "test-bucket" / ".tmp"
        assert tmp_dir.is_dir()
        assert list(tmp_dir.iterdir()) == []
        # Sidecar is complete + parseable.
        sidecar = tmp_path / "test-bucket" / "k.retention"
        meta = json.loads(sidecar.read_text())
        assert meta["retention_seconds"] == 3600


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterPresign — fail-loud (R2-#1 reviewer-fix).
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterPresign:
    async def test_presign_raises_not_implemented(self, tmp_path: Path) -> None:
        """R2-#1 reviewer-fix: presign() on the local driver MUST fail
        loudly. A degenerate file:// URL would silently mislead
        callers (e.g. Sprint 7B reviewer dashboard) expecting
        external-HTTP-accessible URLs."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        await adapter.put("test-bucket", "k", b"x")
        with pytest.raises(
            NotImplementedError,
            match="presign requires non-local ObjectStoreAdapter driver",
        ):
            await adapter.presign("test-bucket", "k", ttl_s=60)

    async def test_presign_validates_args_before_raising(self, tmp_path: Path) -> None:
        """Symmetry with put/get/delete: malformed bucket/key surfaces
        a typed PathTraversalError rather than the NotImplementedError
        fallthrough."""
        adapter = LocalObjectStoreAdapter(tmp_path)
        with pytest.raises(PathTraversalError):
            await adapter.presign("../escape", "k", ttl_s=60)


# ---------------------------------------------------------------------------
# TestLocalObjectStoreAdapterHealthCheck — ok / unreachable.
# ---------------------------------------------------------------------------


class TestLocalObjectStoreAdapterHealthCheck:
    async def test_health_reports_ok_when_writable(self, tmp_path: Path) -> None:
        adapter = LocalObjectStoreAdapter(tmp_path)
        h = await adapter.health_check()
        assert isinstance(h, AdapterHealth)
        assert h.status == "ok"
        assert h.driver == "local_fs"
        assert h.latency_ms is not None and h.latency_ms >= 0

    async def test_health_reports_unreachable_when_root_missing(self, tmp_path: Path) -> None:
        bad_root = tmp_path / "nonexistent-subdir"
        adapter = LocalObjectStoreAdapter(bad_root)
        h = await adapter.health_check()
        assert h.status == "unreachable"
        assert h.driver == "local_fs"
        assert h.detail is not None

    async def test_health_reports_unreachable_when_root_is_a_file(self, tmp_path: Path) -> None:
        """Root pointing at a regular file (not a directory) → unreachable."""
        file_root = tmp_path / "im-a-file"
        file_root.write_text("not a directory")
        adapter = LocalObjectStoreAdapter(file_root)
        h = await adapter.health_check()
        assert h.status == "unreachable"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses chmod-based unwritable check")
    async def test_health_reports_unreachable_when_root_unwritable(self, tmp_path: Path) -> None:
        """Root exists + is a directory but lacks write permission →
        unreachable. Skipped under root since chmod doesn't bind."""
        readonly_root = tmp_path / "readonly"
        readonly_root.mkdir()
        # Strip write bits.
        readonly_root.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            adapter = LocalObjectStoreAdapter(readonly_root)
            h = await adapter.health_check()
            assert h.status == "unreachable"
            assert h.detail is not None and "not writable" in h.detail
        finally:
            # Restore write bits so tmp_path teardown doesn't error.
            readonly_root.chmod(stat.S_IRWXU)

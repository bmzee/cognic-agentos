"""``LocalObjectStoreAdapter`` — production filesystem ``ObjectStoreAdapter``.

Layer: persistence adapter (per ADR-009). The FIRST real
``ObjectStoreAdapter`` implementation per AGENTS.md production-grade
rule + the Sprint-4 plan-of-record §4 lock. Filesystem-backed
deployments (single-host AgentOS, NFS / EFS / Azure Files / GlusterFS
/ on-prem mounts) run this driver in production indefinitely. Sprint
8 adds an S3 driver as an *alternative* `Settings.object_store_driver`
choice — both drivers conform to the same Protocol; deployments
select per-tenant.

Contract per Sprint-4 plan §4:

1. **Filesystem-backed.** Root path from ``Settings.local_object_store_root``.
   Bucket = single path segment under root; key may contain ``/``-separated
   sub-segments.

2. **Atomic writes via ``os.fsync`` + ``os.replace``.** ``put()`` writes
   to ``<root>/<bucket>/.tmp/<uuid4>.tmp``, fsyncs the file, then
   ``os.replace`` (POSIX atomic rename on the same filesystem) into
   the final ``<root>/<bucket>/<key>`` path. Crash-safe: a reader
   ``get()``-ing concurrently sees either the previous content or the
   complete new content; partial writes never leak. Concurrent writes
   to the same key resolve last-writer-wins atomically (Sigstore
   bundles for the same pack version are content-identical, so this
   is acceptable).

3. **Path-traversal safe.** Bucket and key arguments are regex-validated
   at the boundary; resolved target paths must canonicalise (via
   ``Path.resolve()``) under the configured root. Rejects ``..``
   segments, leading ``/``, NUL bytes, and symlinks pointing outside
   root.

4. **Retention metadata enforced at adapter level.** ``put(...,
   retention_seconds=N)`` writes a sidecar ``<key>.retention`` JSON
   file containing ``{created_at, retain_until, retention_seconds}``.
   ``delete()`` reads the sidecar and raises ``RetentionWindowActiveError``
   if the retention window has not elapsed. Tampered / unparseable
   sidecars are treated as fail-closed (refuse delete) — operators
   must repair the sidecar to recover.

5. **``presign(...)`` raises ``NotImplementedError``** (R2-#1 reviewer-
   fix in T2). The local driver does not synthesise a degenerate
   ``file://`` URL that would silently mislead callers expecting
   cross-host signed-URL semantics. Callers needing external URLs
   must select an S3-class driver.

6. **``get()`` returns opaque bytes.** No decompression, no
   content-type interpretation; payload round-trips byte-identically.

7. **``health_check()``** probes by writing + deleting a sentinel file
   under root. Reports ``unreachable`` when root is missing, not a
   directory, or not writable; ``ok`` otherwise with elapsed wall-time
   in ``latency_ms``.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path

from cognic_agentos.db.adapters.protocols import AdapterHealth

_LOG = logging.getLogger("cognic_agentos.db.adapters.local_object_store")

#: Bucket validation: single segment, lower-snake-case + a few safe
#: punctuation chars. NO ``/`` because bucket is one path segment under
#: root. Length capped at 128 chars for filesystem-portability.
_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

#: Key validation: may contain ``/`` between segments. Each segment
#: follows the same shape rules. Length capped at 256 chars.
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,255}$")

#: Sidecar suffix appended to the key path when retention metadata
#: is recorded. Stays alongside the file in the same directory so
#: list operations + cleanup discover it consistently.
_RETENTION_SIDECAR_SUFFIX = ".retention"

#: Staging-directory name. Atomic writes land here as
#: ``<bucket>/.tmp/<uuid4>.tmp`` before the rename. The ``.``-prefix
#: keeps the directory hidden from typical ``ls`` and excluded from
#: most "list this bucket" patterns.
_TMP_DIR_NAME = ".tmp"

#: Sentinel-probe filename for ``health_check``. The ``.`` prefix +
#: distinctive suffix means an operator inspecting the root sees
#: exactly what wrote it.
_HEALTH_PROBE_NAME = ".cognic_health_probe"


class PathTraversalError(ValueError):
    """Raised when a bucket or key argument fails the path-safety contract.

    Covers: regex-violating characters, NUL bytes, leading ``/``, ``..``
    segments, and resolved paths that canonicalise outside the configured
    root (e.g. through a symlink).
    """


class RetentionWindowActiveError(RuntimeError):
    """Raised on ``delete()`` when the retention sidecar's
    ``retain_until`` has not elapsed, OR when the sidecar is tampered /
    unparseable (fail-closed).
    """


class LocalObjectStoreAdapter:
    """Production filesystem ``ObjectStoreAdapter``.

    Constructor takes ``root: Path`` — typically
    ``Settings.local_object_store_root``. The root is resolved at
    construction (``Path.resolve()``) so every subsequent path-safety
    check compares against the canonical absolute form.

    The adapter is async-safe: every public method dispatches blocking
    filesystem work via ``asyncio.to_thread`` so a 10 MiB write doesn't
    pin the event loop.
    """

    driver: str = "local_fs"

    def __init__(self, root: Path) -> None:
        # Resolve the root once at construction; cache for path-safety
        # checks. Resolution does NOT require the path to exist (Python
        # 3.6+ behaviour) — that lets the adapter construct cleanly
        # before the directory has been created. Lazy mkdir at first
        # ``put()``; ``health_check()`` reports unreachable until then.
        self._root: Path = Path(root).resolve()

    # --- public API -------------------------------------------------------

    async def put(
        self,
        bucket: str,
        key: str,
        body: bytes,
        *,
        retention_seconds: int | None = None,
    ) -> None:
        """Persist ``body`` atomically at ``bucket/key``.

        See module docstring §2 for atomicity contract + §4 for retention.

        ``retention_seconds`` (when set) must be a positive ``int``.
        Booleans (which are ``int`` subtypes in Python) are explicitly
        rejected so a stray ``True``/``False`` cannot silently disable
        retention or set a 1-second window. Zero or negative values are
        also rejected — the only way to opt out of retention is
        ``retention_seconds=None``. R1 reviewer-P2: previous shape
        accepted bool / 0 / negative and silently bypassed retention.
        """
        if retention_seconds is not None:
            # Reject bool BEFORE the int check because ``bool`` is a
            # subtype of ``int`` in Python (``isinstance(True, int)`` is
            # True). Without this, ``put(..., retention_seconds=True)``
            # would silently treat True as a 1-second retention window.
            if isinstance(retention_seconds, bool) or not isinstance(retention_seconds, int):
                raise TypeError(
                    f"retention_seconds must be a positive int when set; "
                    f"got {type(retention_seconds).__name__}"
                )
            if retention_seconds <= 0:
                raise ValueError(
                    f"retention_seconds must be > 0 when set; got {retention_seconds}. "
                    f"Use retention_seconds=None to opt out of retention enforcement."
                )
        target = self._validate_and_resolve(bucket, key)
        await asyncio.to_thread(self._put_sync, target, body, retention_seconds)

    async def get(self, bucket: str, key: str) -> bytes:
        """Read the bytes at ``bucket/key``. Raises ``FileNotFoundError``
        if the key does not exist."""
        target = self._validate_and_resolve(bucket, key)
        return await asyncio.to_thread(self._get_sync, target)

    async def delete(self, bucket: str, key: str) -> None:
        """Remove ``bucket/key``. Raises ``RetentionWindowActiveError``
        when the retention sidecar's ``retain_until`` has not elapsed,
        OR when the sidecar is tampered / unparseable (fail-closed)."""
        target = self._validate_and_resolve(bucket, key)
        await asyncio.to_thread(self._delete_sync, target)

    async def presign(self, bucket: str, key: str, ttl_s: int) -> str:
        """Always raises ``NotImplementedError`` per R2-#1 reviewer-fix.

        The local driver does not synthesise a degenerate ``file://``
        URL that would silently mislead callers expecting cross-host
        signed-URL semantics. See module docstring §5 + Protocol
        docstring on ``ObjectStoreAdapter.presign`` for the rationale.
        """
        # Validate args for symmetry with put/get/delete — a malformed
        # bucket/key surfaces a typed PathTraversalError rather than the
        # NotImplementedError fallthrough. Keeps the error taxonomy
        # consistent across methods.
        self._validate_and_resolve(bucket, key)
        raise NotImplementedError(
            "presign requires non-local ObjectStoreAdapter driver — "
            "local_fs deployments do not support signed-URL semantics"
        )

    async def health_check(self) -> AdapterHealth:
        """Probe by writing + deleting a sentinel file under root.

        Reports ``unreachable`` when root is missing, not a directory,
        or not writable; ``ok`` otherwise with elapsed wall-time in
        ``latency_ms``.
        """
        return await asyncio.to_thread(self._health_check_sync)

    # --- private sync helpers (run inside asyncio.to_thread) --------------

    def _put_sync(self, target: Path, body: bytes, retention_seconds: int | None) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Atomic body write: tmp → fsync(fd) → rename → fsync(parent dir).
        # The trailing fsync of the parent directory is what makes the
        # rename itself crash-durable. Without it, a power loss between
        # ``os.replace`` and the next directory-metadata flush can leave
        # the rename "applied to the page cache" but absent from disk
        # on restart. R1 reviewer-P2: previous shape skipped this step.
        self._atomic_write(target, body)
        # Retention sidecar: written AFTER the body lands so a torn
        # sequence (sidecar without body) is impossible. A torn body-
        # without-sidecar IS possible on a crash here, but the operator
        # can replay the put() to repair the sidecar; the body itself
        # is durably persisted. The sidecar is itself written through
        # ``_atomic_write`` so a partially-written sidecar can never be
        # observed by ``_delete_sync``.
        if retention_seconds is not None:
            now = _dt.datetime.now(_dt.UTC)
            sidecar_payload = {
                "created_at": now.isoformat(),
                "retain_until": (now + _dt.timedelta(seconds=retention_seconds)).isoformat(),
                "retention_seconds": retention_seconds,
            }
            sidecar_path = target.with_name(target.name + _RETENTION_SIDECAR_SUFFIX)
            sidecar_bytes = json.dumps(sidecar_payload, separators=(",", ":")).encode("utf-8")
            self._atomic_write(sidecar_path, sidecar_bytes)

    def _atomic_write(self, target: Path, body: bytes) -> None:
        """Crash-durable write: tmp + fsync(fd) + rename + fsync(parent dir).

        On POSIX, ``os.replace`` is an atomic rename within the same
        filesystem (guaranteed because tmp lives under the bucket dir
        under root). Atomicity gives "all-or-nothing visibility"; the
        trailing parent-directory fsync upgrades that to "all-or-nothing
        durability across crash". Used for both the body and the
        retention sidecar so neither can be observed half-written.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_dir = target.parent / _TMP_DIR_NAME
        tmp_dir.mkdir(exist_ok=True)
        tmp_path = tmp_dir / f"{uuid.uuid4().hex}.tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                # ``os.write`` is permitted by POSIX to short-write —
                # it returns the number of bytes actually written and
                # the caller is responsible for resubmitting the rest.
                # Without this loop a truncated Sigstore bundle could
                # be fsynced + renamed into place and reported as a
                # successful atomic put. R2 reviewer-P2 fix.
                view = memoryview(body)
                total = len(view)
                offset = 0
                while offset < total:
                    written = os.write(fd, view[offset:])
                    if written <= 0:
                        # POSIX guarantees ``os.write`` either returns
                        # ``> 0`` or raises (``OSError``); a non-positive
                        # return is a kernel/runtime contract violation
                        # — fail closed rather than spin or silently
                        # truncate.
                        raise OSError(
                            f"os.write returned {written} for fd={fd} "
                            f"after {offset}/{total} bytes — refusing to "
                            f"finalise potentially truncated write"
                        )
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp_path, target)
        except Exception:
            # Cleanup on failure so we don't leak partial .tmp files.
            # Best-effort: original exception takes precedence over any
            # cleanup error.
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise
        # Crash-durability fence: fsync the parent directory so the
        # rename itself is on stable storage. Best-effort across
        # platforms: some filesystems (e.g. certain network mounts)
        # don't support O_DIRECTORY; ENOTSUP / EINVAL falls through
        # without raising because the visible-rename guarantee from
        # ``os.replace`` is independent of the durability fence.
        with contextlib.suppress(OSError):
            dir_fd = os.open(target.parent, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    def _get_sync(self, target: Path) -> bytes:
        # Re-resolve the target at read time so a symlink swapped in
        # between validate-time and read-time can't escape the root.
        resolved = target.resolve(strict=True)
        if not resolved.is_relative_to(self._root):
            raise PathTraversalError(
                f"resolved path {resolved!s} is not under root {self._root!s} "
                f"(possible symlink swap)"
            )
        return resolved.read_bytes()

    def _delete_sync(self, target: Path) -> None:
        sidecar_path = target.with_name(target.name + _RETENTION_SIDECAR_SUFFIX)
        if sidecar_path.exists():
            try:
                meta = json.loads(sidecar_path.read_text(encoding="utf-8"))
                retain_until_iso = meta["retain_until"]
                retain_until = _dt.datetime.fromisoformat(retain_until_iso)
            except (
                OSError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                # Fail-closed on malformed/tampered sidecar: refuse delete
                # rather than silently bypass retention. Operator must
                # repair the sidecar (or remove it deliberately).
                raise RetentionWindowActiveError(
                    f"retention sidecar at {sidecar_path!s} is malformed; "
                    f"cannot verify retention window — refusing delete"
                ) from exc
            now = _dt.datetime.now(_dt.UTC)
            if retain_until > now:
                raise RetentionWindowActiveError(
                    f"retention window active for {target!s}; "
                    f"retain_until={retain_until.isoformat()} > now={now.isoformat()}"
                )
            # Window expired — remove sidecar before file so a crash
            # mid-delete leaves the body without a sidecar (re-deletable)
            # rather than the inverse.
            sidecar_path.unlink(missing_ok=True)
        # Tolerate the file already being absent — ``delete`` is
        # idempotent for the body. (Retention enforcement above still
        # applies even if body is missing but sidecar is present.)
        with contextlib.suppress(FileNotFoundError):
            target.unlink()

    def _health_check_sync(self) -> AdapterHealth:
        start = time.monotonic()
        if not self._root.exists() or not self._root.is_dir():
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=(f"root path {self._root!s} does not exist or is not a directory"),
            )
        probe_path = self._root / _HEALTH_PROBE_NAME
        try:
            probe_path.write_bytes(b"")
            probe_path.unlink(missing_ok=True)
        except OSError as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=(
                    f"root path {self._root!s} is not writable: {exc.__class__.__name__}: {exc}"
                ),
            )
        latency_ms = (time.monotonic() - start) * 1000.0
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=round(latency_ms, 4),
        )

    # --- path safety ------------------------------------------------------

    def _validate_and_resolve(self, bucket: str, key: str) -> Path:
        """Validate ``bucket`` + ``key`` and return the safe target path.

        Validation order (fail-closed at the first violation):
          1. Both args must be ``str`` (defensive — Python type
             system doesn't catch ``bytes`` or unexpected shapes).
          2. NUL bytes in either argument are rejected outright.
          3. Bucket matches ``_BUCKET_RE`` (single path segment).
          4. Key matches ``_KEY_RE`` and contains no ``..`` segments
             and does not start with ``/``.
          5. Resolved target ``parent`` (the directory the file lives
             in) is under the configured root.
        """
        if not isinstance(bucket, str):
            raise PathTraversalError(f"bucket must be str; got {type(bucket).__name__}")
        if not isinstance(key, str):
            raise PathTraversalError(f"key must be str; got {type(key).__name__}")
        if "\x00" in bucket or "\x00" in key:
            raise PathTraversalError("NUL byte in bucket or key — path-traversal-bait rejected")
        if not _BUCKET_RE.match(bucket):
            raise PathTraversalError(f"invalid bucket {bucket!r}: must match {_BUCKET_RE.pattern}")
        if not _KEY_RE.match(key):
            raise PathTraversalError(f"invalid key {key!r}: must match {_KEY_RE.pattern}")
        # Defence-in-depth: even though the regex disallows leading
        # ``/`` and the bucket regex disallows ``/`` entirely, the
        # ``..`` segment rejection has to be checked structurally.
        if any(seg == ".." for seg in key.split("/")):
            raise PathTraversalError(f"invalid key {key!r}: contains '..' path-traversal segment")
        target = self._root / bucket / key
        # The parent dir may not exist yet (first put). Resolve as far
        # as we can without strict=True so put() works for fresh
        # buckets. The resolved parent must canonicalise under root —
        # this catches symlinks anywhere in the path that escape root.
        try:
            resolved_parent = target.parent.resolve()
        except OSError:
            # Filesystem error during resolution: fail closed.
            raise PathTraversalError(f"failed to resolve parent of {target!s}") from None
        if not resolved_parent.is_relative_to(self._root):
            raise PathTraversalError(
                f"resolved parent {resolved_parent!s} is not under root "
                f"{self._root!s} (symlink escape or path-traversal)"
            )
        return target


__all__ = (
    "LocalObjectStoreAdapter",
    "PathTraversalError",
    "RetentionWindowActiveError",
)


# Module-level registration so ``load_bundled_adapters()`` populates
# the ``("object_store", "local_fs")`` slot on import. Mirrors the
# pattern used by every Sprint-1C bundled adapter (postgres, qdrant,
# etc.). The kernel image's allowlist in ``__init__.py`` includes
# this module with no required optional deps — pure-stdlib + Path.
from cognic_agentos.db.adapters.registry import bundled_registry  # noqa: E402

bundled_registry.register("object_store", "local_fs", LocalObjectStoreAdapter)

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
from collections.abc import AsyncIterator, Iterator
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

    async def list_prefix(
        self,
        bucket: str,
        prefix: str,
    ) -> AsyncIterator[str]:
        """Lazily yield keys under ``bucket/prefix`` in deterministic
        depth-first sorted-per-directory order.

        **Order contract (NOT globally lexicographic).** The local_fs
        driver sorts entries within each directory and traverses
        depth-first; this differs from globally-lexicographic order
        (S3 ``ListObjectsV2``) for keys spanning directory boundaries.
        Concrete: keys ``a/z`` and ``a.txt`` yield ``["a/z", "a.txt"]``
        here (depth-first into ``a/`` before yielding the sibling file
        ``a.txt``) vs ``["a.txt", "a/z"]`` under S3 (``.`` 0x2E <
        ``/`` 0x2F). Globally-lex order is incompatible with the
        Protocol's lazy-iteration contract (would require buffering or
        merge-sort); per-driver determinism is the deliberate trade-off
        per ``ObjectStoreAdapter.list_prefix`` Protocol docstring.
        Callers needing a specific cross-driver order MUST re-sort.

        Sprint 8.5 T0.5 — async-generator implementing the
        ``ObjectStoreAdapter.list_prefix`` Protocol contract per spec §3.5.
        Required by ``CheckpointStore.load_latest()`` + ``purge_expired()``
        (per spec §4.1) for per-tenant prefix walks; tenant-isolation
        enforcement surface per spec §9 + P3.r6.

        Walks the prefix directory via ``os.scandir()`` recursively,
        sorting entries within each directory + descending depth-first.
        This yields **depth-first sorted-per-directory order** — NOT
        globally lexicographic across the full yield sequence (see the
        "Order contract" paragraph above + the
        ``test_depth_first_traversal_pinned_not_globally_lex``
        regression).

        Path-traversal defence (mirrors the existing ``_validate_and_resolve``
        doctrine at :389; ``_get_sync`` symlink-swap defence at :312-321):

        1. Bucket validated via the SAME ``_BUCKET_RE`` shape check used
           by put/get/delete (via the extracted ``_validate_bucket_or_raise``
           helper — NO regex duplication).
        2. Prefix rejected if it contains ``..`` segments, NUL bytes, or
           leading ``/`` (mirrors ``_KEY_RE`` + structural checks).
        3. Bucket root resolved; refused if not relative to ``self._root``
           (symlink escape at bucket level).
        4. Prefix join resolved; refused if not relative to the resolved
           bucket root (symlink escape at prefix level).
        5. **DUAL is_relative_to check at every recursion step** — every
           visited directory AND every yielded file is re-resolved + checked
           against BOTH ``self._root`` (catches root escape, P1.r10) AND
           the ``walk_root_bound`` (catches cross-prefix tenant isolation
           breach within the same root, P1.r11).
        """
        # Steps 1+2: validate bucket + prefix shape (NO regex duplication).
        self._validate_bucket_or_raise(bucket)
        self._validate_prefix_or_raise(prefix)

        # Step 3: bucket root resolved + root-safety check.
        bucket_root_target = self._root / bucket
        try:
            bucket_root_resolved = bucket_root_target.resolve()
        except (OSError, RuntimeError):
            # RuntimeError: Python 3.12 pathlib raises RuntimeError
            # ("Symlink loop from ...") for a symlink loop encountered
            # during resolve(); OSError covers other filesystem errors.
            # Both fail-closed to the PathTraversalError taxonomy so a
            # caller's `except PathTraversalError` catches a loop.
            raise PathTraversalError(
                f"failed to resolve bucket root {bucket_root_target!s} "
                f"(filesystem error or symlink loop detected)"
            ) from None
        if not bucket_root_resolved.is_relative_to(self._root):
            raise PathTraversalError(
                f"resolved bucket root {bucket_root_resolved!s} is not under "
                f"root {self._root!s} (symlink escape at bucket level)"
            )

        # Step 4: prefix join resolved + bucket-relativity check.
        prefix_target = bucket_root_resolved / prefix if prefix else bucket_root_resolved
        try:
            prefix_resolved = prefix_target.resolve()
        except (OSError, RuntimeError):
            # A resolution FAILURE here is a genuine error, not a benign
            # missing prefix: resolve(strict=False) does NOT raise for a
            # non-existent path (that case is handled by the
            # exists()/is_dir() guard below). The only inputs that reach
            # this except are a symlink loop (Python 3.12 pathlib raises
            # RuntimeError) or a filesystem error (OSError) — both
            # fail-closed to the PathTraversalError taxonomy.
            raise PathTraversalError(
                f"failed to resolve prefix {prefix_target!s} "
                f"(filesystem error or symlink loop detected)"
            ) from None
        if not prefix_resolved.is_relative_to(bucket_root_resolved):
            raise PathTraversalError(
                f"resolved prefix {prefix_resolved!s} is not under bucket root "
                f"{bucket_root_resolved!s} (symlink escape at prefix level)"
            )

        # If the prefix directory does not exist OR is not a directory,
        # yield nothing (normal empty-iterator behavior per Protocol §3.5).
        if not prefix_resolved.exists() or not prefix_resolved.is_dir():
            return

        # Step 5: lazy recursive walk with per-step DUAL is_relative_to check.
        for key in self._walk_keys_root_safe(
            prefix_resolved,
            bucket_root_resolved,
            walk_root_bound=prefix_resolved,
        ):
            yield key

    def _walk_keys_root_safe(
        self,
        prefix_root: Path,
        bucket_root: Path,
        *,
        walk_root_bound: Path,
    ) -> Iterator[str]:
        """Sync recursive walk helper — yields keys (relative to
        ``bucket_root``) for every file under ``prefix_root`` in
        depth-first sorted-per-directory order (NOT globally
        lexicographic; see ``list_prefix`` docstring's order contract).
        Sync because Path operations don't benefit from async; the
        outer async-generator yields control to the event loop per
        loop iteration.

        DUAL ROOT-SAFETY INVARIANT (P1.r10 + P1.r11 load-bearing — every
        visited directory AND every yielded file MUST canonicalise under
        BOTH ``self._root`` AND ``walk_root_bound``. The single
        ``is_relative_to(self._root)`` check is insufficient: a tenant-a
        symlink pointing at tenant-b within the SAME root would pass the
        root check + yield tenant-b keys under tenant-a's listing — that's
        a tenant-isolation breach per spec §9. The dual check catches the
        cross-prefix case because the tenant-b target is not relative to
        the tenant-a walk_root_bound.

        ``walk_root_bound`` is ``prefix_resolved`` from ``list_prefix``
        step 4 — the resolved prefix subtree the caller asked to enumerate.
        EVERY yielded key (and every dir descended into) MUST live within
        that subtree; a symlink whose resolved target escapes the subtree
        (even if it stays within ``self._root``) is a tenant-isolation
        breach and fails-closed with ``PathTraversalError``.
        """
        try:
            entries = sorted(os.scandir(prefix_root), key=lambda e: e.name)
        except (FileNotFoundError, NotADirectoryError):
            return

        for entry in entries:
            entry_path = Path(entry.path)
            try:
                entry_resolved = entry_path.resolve()
            except (OSError, RuntimeError):
                # Symlink loop (Python 3.12 pathlib raises RuntimeError)
                # OR permission denied (OSError); skip this entry
                # silently. This site DELIBERATELY does not raise: a
                # sweep over a multi-million-key tenant must not abort
                # on one bad/looping symlink — raising here would be a
                # DoS vector (a single planted loop symlink could kill
                # every list_prefix call). A merely-dangling symlink
                # (target gone) does NOT reach here — resolve(strict=
                # False) returns the path without raising for that.
                continue

            # Check 1: resolved target under self._root.
            if not entry_resolved.is_relative_to(self._root):
                raise PathTraversalError(
                    f"walk encountered entry {entry_path!s} that resolves to "
                    f"{entry_resolved!s} outside root {self._root!s} "
                    f"(symlink escape during list_prefix walk)"
                )

            # Check 2: resolved target under walk_root_bound (P1.r11
            # tenant-isolation pin — catches cross-prefix symlinks WITHIN
            # the same root).
            if not entry_resolved.is_relative_to(walk_root_bound):
                raise PathTraversalError(
                    f"walk encountered entry {entry_path!s} that resolves to "
                    f"{entry_resolved!s} outside walk_root_bound "
                    f"{walk_root_bound!s} (cross-prefix symlink — "
                    f"tenant-isolation breach)"
                )

            # Filter adapter-internal artefacts that are NOT user object
            # keys. The local driver writes 3 classes of bookkeeping
            # artefacts inside the bucket tree (see module docstring §2
            # + §4 + §7):
            #
            #   - ``.tmp/`` staging directory (atomic-write fan-in;
            #     in-flight ``put()`` calls land here under random uuid4
            #     names before ``os.replace`` to the final key). Lives
            #     ONLY at the bucket-root level: <root>/<bucket>/.tmp/.
            #   - ``<key>.retention`` sidecars (per-key retention metadata
            #     used by ``delete()`` to enforce the WORM window). Live
            #     NEXT TO the corresponding user file.
            #   - ``.cognic_health_probe`` (health_check sentinel at
            #     bucket root). Lives ONLY at bucket root.
            #
            # An S3 ``ListObjectsV2`` equivalent would never expose these
            # — they are local-driver-only. ``list_prefix`` yields ONLY
            # user-put keys per the Protocol contract. Filtering happens
            # AFTER the dual is_relative_to checks so a symlinked
            # internal-name still fails-loud rather than silently skip
            # past the security gate.
            #
            # PRECISION-TUNED per T0.5 reviewer round 2: ``_KEY_RE``
            # at :82 allows user keys like ``report.retention`` (legal
            # by shape) + ``tenant/.tmp/file`` (legal by shape) +
            # ``tenant/.cognic_health_probe`` (legal by shape). A naive
            # filter that skipped EVERY ``.retention``-suffixed file
            # and EVERY ``.tmp`` directory would silently hide legal
            # user keys — that would make the local driver diverge from
            # the ObjectStore contract (put accepts the key, get reads
            # it, but list hides it). The precise filter uses position
            # + content tests to discriminate real artefacts from user
            # keys.
            entry_name = entry.name
            is_at_bucket_root = entry_resolved.parent == bucket_root

            # .tmp/ — ONLY at bucket root. A user .tmp dir at deeper
            # path (e.g., ``tenant-a/.tmp/file``) is a legal user key
            # segment and MUST be descended/yielded.
            if entry.is_dir() and entry_name == _TMP_DIR_NAME and is_at_bucket_root:
                continue

            # .cognic_health_probe — ONLY at bucket root. A user file
            # with that name at deeper path is a legal user key.
            if entry.is_file() and entry_name == _HEALTH_PROBE_NAME and is_at_bucket_root:
                continue

            # <key>.retention sidecar — UNAMBIGUOUS post-T0.5 reservation
            # at the put() boundary. ``_validate_and_resolve`` refuses
            # any user key ending in ``.retention``, so any file with
            # that suffix in the bucket tree MUST be an adapter-internal
            # sidecar. Filter unconditionally; no partner-check or
            # content-parsing required (and no risk of parsing arbitrary
            # user payloads at list time).
            #
            # Pre-reservation, the filter tried partner + JSON-shape
            # discrimination — both checks had false-positive classes
            # the T0.5 reviewer round 3 surfaced (the namespace was
            # fundamentally ambiguous because put accepted both shapes).
            # Reservation closes the ambiguity at the source.
            if entry.is_file() and entry_name.endswith(_RETENTION_SIDECAR_SUFFIX):
                continue

            if entry.is_file():
                rel = entry_resolved.relative_to(bucket_root)
                yield str(rel).replace(os.sep, "/")
            elif entry.is_dir():
                # Descend with the SAME walk_root_bound — the bound NEVER
                # tightens or relaxes during recursion; it stays pinned to
                # the original prefix subtree the caller asked to enumerate.
                yield from self._walk_keys_root_safe(
                    entry_resolved,
                    bucket_root,
                    walk_root_bound=walk_root_bound,
                )

    def _validate_bucket_or_raise(self, bucket: str) -> None:
        """Extracted from ``_validate_and_resolve`` steps 1-3 — NO regex
        duplication; same ``_BUCKET_RE``; same NUL byte + type checks.
        Used by both ``_validate_and_resolve`` (existing path) and
        ``list_prefix`` (Sprint 8.5).
        """
        if not isinstance(bucket, str):
            raise PathTraversalError(f"bucket must be str; got {type(bucket).__name__}")
        if "\x00" in bucket:
            raise PathTraversalError("NUL byte in bucket — path-traversal-bait rejected")
        if not _BUCKET_RE.match(bucket):
            raise PathTraversalError(f"invalid bucket {bucket!r}: must match {_BUCKET_RE.pattern}")

    def _validate_prefix_or_raise(self, prefix: str) -> None:
        """Prefix-specific structural validator. Prefix has slightly
        different shape than key: may be empty (= whole bucket walk) OR
        end with ``/``; may contain ``/`` separators internally; but MUST
        NOT contain ``..`` segments, NUL bytes, or leading ``/`` (mirrors
        ``_KEY_RE`` semantics from the existing ``_validate_and_resolve``).

        Sprint 8.5 T0.5 round-4 fix: ALSO refuses prefixes whose first
        ``/``-separated segment targets a bucket-root-reserved namespace
        (``.tmp`` staging dir, ``.cognic_health_probe`` sentinel). Without
        this check, a caller could pass ``list_prefix(bucket, ".tmp/")``
        directly + the walker would start at the staging dir + yield its
        in-flight uuid4-named tmp files as if they were user keys. The
        bucket-root filter in ``_walk_keys_root_safe`` only catches
        ``.tmp`` when encountered as a CHILD during a parent-prefix walk
        — when ``.tmp`` is the prefix itself, the walker never sees it
        as a child to skip. Reject at the validator boundary so the
        walker never enters reserved namespaces regardless of how the
        caller addresses them.

        Deeper-path ``.tmp`` / ``.cognic_health_probe`` segments (e.g.,
        prefix ``tenant-a/.tmp/``) are LEGAL — those are user namespaces
        per ``_KEY_RE``; only the BUCKET-ROOT first segment is reserved.
        """
        if not isinstance(prefix, str):
            raise PathTraversalError(f"prefix must be str; got {type(prefix).__name__}")
        if "\x00" in prefix:
            raise PathTraversalError("NUL byte in prefix — path-traversal-bait rejected")
        if prefix.startswith("/"):
            raise PathTraversalError(f"invalid prefix {prefix!r}: must not start with '/'")
        if any(seg == ".." for seg in prefix.split("/")):
            raise PathTraversalError(
                f"invalid prefix {prefix!r}: contains '..' path-traversal segment"
            )
        # Bucket-root reserved-namespace refusal — first segment check.
        # Empty prefix ('' = whole bucket walk) is OK because no segment
        # is being addressed. A non-empty prefix whose first segment is
        # a reserved bucket-root artefact name MUST be refused; the
        # walker must never enter the staging dir or the health-probe
        # path regardless of how the prefix is shaped.
        if prefix:
            first_segment = prefix.split("/", 1)[0]
            if first_segment == _TMP_DIR_NAME:
                raise PathTraversalError(
                    f"invalid prefix {prefix!r}: bucket-root "
                    f"{_TMP_DIR_NAME!r} is the adapter staging namespace; "
                    f"contents are in-flight atomic writes, NOT user keys "
                    f"(Sprint 8.5 T0.5 round-4 reserved-namespace refusal)"
                )
            if first_segment == _HEALTH_PROBE_NAME:
                raise PathTraversalError(
                    f"invalid prefix {prefix!r}: bucket-root "
                    f"{_HEALTH_PROBE_NAME!r} is the adapter health-probe "
                    f"namespace, NOT a user key"
                )

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
        try:
            resolved = target.resolve(strict=True)
        except FileNotFoundError:
            # Genuine absent object — preserve get()'s documented
            # FileNotFoundError contract (NOT a path-traversal event).
            # Must be caught BEFORE the (OSError, RuntimeError) arm
            # because FileNotFoundError is an OSError subclass.
            raise
        except (OSError, RuntimeError):
            # Symlink loop (Python 3.12 pathlib raises RuntimeError, not
            # OSError) OR another filesystem error during resolution —
            # fail-closed to the PathTraversalError taxonomy, same as
            # the four list_prefix / _validate_and_resolve resolve-guards.
            raise PathTraversalError(
                f"failed to resolve {target!s} (filesystem error or symlink loop detected)"
            ) from None
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
          5. Key MUST NOT end with the reserved ``.retention`` suffix
             (Sprint 8.5 T0.5 — adapter-internal namespace; see
             ``_RETENTION_SIDECAR_SUFFIX``). Reserved at the put()
             boundary so list_prefix() can unambiguously filter
             sidecars without content inspection.
          6. Resolved target ``parent`` (the directory the file lives
             in) is under the configured root.
        """
        # Delegate bucket validation to the shared helper (Sprint 8.5 T0.5
        # — NO regex duplication; same _BUCKET_RE; same NUL byte + type
        # checks; also used by list_prefix).
        self._validate_bucket_or_raise(bucket)
        if not isinstance(key, str):
            raise PathTraversalError(f"key must be str; got {type(key).__name__}")
        if "\x00" in key:
            raise PathTraversalError("NUL byte in key — path-traversal-bait rejected")
        if not _KEY_RE.match(key):
            raise PathTraversalError(f"invalid key {key!r}: must match {_KEY_RE.pattern}")
        # Defence-in-depth: even though the regex disallows leading
        # ``/`` and the bucket regex disallows ``/`` entirely, the
        # ``..`` segment rejection has to be checked structurally.
        if any(seg == ".." for seg in key.split("/")):
            raise PathTraversalError(f"invalid key {key!r}: contains '..' path-traversal segment")
        # Sprint 8.5 T0.5 reservation: refuse keys ending in the
        # ``.retention`` sidecar suffix. Without reservation, list_prefix
        # cannot unambiguously discriminate adapter sidecars from user
        # objects that happen to end ``.retention`` (the namespace is
        # fundamentally ambiguous — content + partner-file checks both
        # have false-positive classes per the T0.5 reviewer round 3
        # finding). Reserving at the boundary makes the filter clean:
        # any ``.retention``-suffixed file in the bucket tree MUST be
        # an adapter-internal sidecar after this commit.
        if key.endswith(_RETENTION_SIDECAR_SUFFIX):
            raise PathTraversalError(
                f"invalid key {key!r}: keys ending in "
                f"{_RETENTION_SIDECAR_SUFFIX!r} are reserved for the "
                f"adapter's retention-sidecar namespace (Sprint 8.5 T0.5 "
                f"reservation; see _validate_and_resolve docstring step 5). "
                f"Use a different suffix for user objects."
            )
        target = self._root / bucket / key
        # The parent dir may not exist yet (first put). Resolve as far
        # as we can without strict=True so put() works for fresh
        # buckets. The resolved parent must canonicalise under root —
        # this catches symlinks anywhere in the path that escape root.
        try:
            resolved_parent = target.parent.resolve()
        except (OSError, RuntimeError):
            # Filesystem error (OSError) OR symlink loop (Python 3.12
            # pathlib raises RuntimeError) during resolution: fail
            # closed to the PathTraversalError taxonomy.
            raise PathTraversalError(
                f"failed to resolve parent of {target!s} "
                f"(filesystem error or symlink loop detected)"
            ) from None
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

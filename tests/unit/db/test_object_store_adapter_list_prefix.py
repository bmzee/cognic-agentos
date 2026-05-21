"""Sprint 8.5 T0.5 — ObjectStoreAdapter.list_prefix Protocol-conformance test.

Pins the async-generator shape (per spec §3.5 P2.r2) + lazy-iteration
contract + ordering semantics (per-directory sorted; depth-first across
directories — NOT globally lexicographic; see the
``test_depth_first_traversal_pinned_not_globally_lex`` regression)
+ missing-prefix + empty-string-prefix behavior + path-traversal defence
+ DUAL symlink-escape defence (P1.r10 + P1.r11) + reserved-namespace
prefix refusal (.tmp/ + .cognic_health_probe at bucket root) +
adapter-internal-artefact filtering (no .retention sidecars / .tmp/
staging / health probe leak as keys) on the Sprint-4 LocalObjectStoreAdapter.

Test taxonomy (21 total — round-4 adds 4 contract-gap regressions on
top of round-3's reservation fix):

- TestListPrefixProtocolShape: 2 Protocol-shape regressions (P2.r2 lock —
  plain ``def`` returning AsyncIterator[str], NOT ``async def``).
- TestLocalObjectStoreAdapterListPrefixBehavior: 16 runtime behavior
  regressions:
    1.  lazy iteration returns AsyncIterator directly
    2.  per-directory sorted ordering (single-dir scope)
    3.  depth-first traversal pinned NOT globally lex (multi-dir scope —
        round-4 contract narrowing)
    4.  missing prefix returns empty iterator
    5.  empty-string prefix walks whole bucket
    6.  full keys (not relative-to-prefix)
    7.  `..` path-traversal refused
    8.  cross-bucket isolation
    9.  skips adapter-internal artefacts (sidecars + .tmp/ + health
        probe; bucket-root-scoped filters during parent-prefix walk)
    10. put() refuses user keys ending in `.retention` (round-3
        reservation — closes namespace ambiguity at the source)
    11. reservation applies uniformly to get() and delete() too
        (defence-in-depth)
    12. list_prefix refuses direct `.tmp` / `.tmp/` / `.tmp/anything`
        bucket-root staging prefixes (round-4 — closes the direct-
        addressing escape past the during-walk filter)
    13. list_prefix refuses direct `.cognic_health_probe` prefix
        (round-4 — symmetric with .tmp/ refusal)
    14. deeper-path .tmp segment in prefix still yielded (round-4
        defence-in-depth — locks bucket-root-only scope of the new
        reservation)
    15. user key with .tmp segment at deeper path yielded
        (.tmp during-walk skip scoped to bucket root only)
    16. user key named .cognic_health_probe at deeper path yielded
        (health-probe during-walk skip scoped to bucket root only)
- TestListPrefixSymlinkEscapeDefence: 3 symlink-escape regressions
  (P1.r10 root-escape at prefix level + mid-walk; P1.r11 cross-prefix
  tenant isolation — the load-bearing tenant-isolation pin per spec §9).
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
    PathTraversalError,
)
from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter

# pytest-asyncio runs in auto mode (per pyproject.toml [tool.pytest.ini_options]);
# async tests are auto-marked. Sync Protocol-shape tests in
# TestListPrefixProtocolShape do not need (and would warn under) a
# module-level pytest.mark.asyncio.


class TestListPrefixProtocolShape:
    """Pin the async-generator wire-shape per spec §3.5 P2.r2."""

    def test_protocol_method_is_plain_def_not_async_def(self) -> None:
        """``def list_prefix(...) -> AsyncIterator[str]`` NOT ``async def``.

        The wrong shape would type as "coroutine returning AsyncIterator"
        and break the ``async for x in f()`` caller pattern. Per spec §3.5
        P2.r2 — pinned at Protocol declaration time.
        """
        method = ObjectStoreAdapter.list_prefix
        assert not inspect.iscoroutinefunction(method), (
            "ObjectStoreAdapter.list_prefix MUST be plain `def` returning "
            "AsyncIterator[str], NOT `async def`. Per spec §3.5 P2.r2."
        )

    def test_protocol_method_return_annotation_is_async_iterator(self) -> None:
        """Annotation MUST be AsyncIterator[str], not Coroutine."""
        ann = str(inspect.signature(ObjectStoreAdapter.list_prefix).return_annotation)
        assert "AsyncIterator" in ann, (
            f"list_prefix return annotation must contain AsyncIterator; got {ann!r}"
        )


class TestLocalObjectStoreAdapterListPrefixBehavior:
    """Pin the runtime contract on the Sprint-4 driver."""

    async def test_lazy_iteration_returns_async_iterator_directly(self, tmp_path: Path) -> None:
        """Async-generator returns AsyncIterator DIRECTLY without await.

        Caller pattern ``async for key in adapter.list_prefix(...)`` is
        the only supported one per spec §3.5. If the method were
        ``async def`` it would return a coroutine that callers had to
        ``await`` first — this regression catches that drift.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        for i in range(5):
            await adapter.put("bucket-a", f"prefix-x/key-{i}", b"data")

        it = adapter.list_prefix("bucket-a", "prefix-x/")
        assert hasattr(it, "__aiter__"), (
            "list_prefix() must return AsyncIterator directly, NOT a coroutine"
        )
        collected = [k async for k in it]
        assert len(collected) == 5

    async def test_per_directory_sorted_ordering(self, tmp_path: Path) -> None:
        """Entries WITHIN the same directory MUST be yielded in
        lexicographic order. Multi-directory scenarios use depth-first
        traversal which is NOT globally lexicographic — see
        ``test_depth_first_traversal_pinned_NOT_globally_lex`` below
        for the multi-dir contract.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        for i in [3, 1, 4, 1, 5, 9, 2, 6]:  # insert out of order; dupes are fine (overwrite)
            await adapter.put("bucket-b", f"prefix/key-{i:02d}", b"x")
        keys = [k async for k in adapter.list_prefix("bucket-b", "prefix/")]
        assert keys == sorted(keys), f"single-dir keys not sorted: {keys}"

    async def test_depth_first_traversal_pinned_not_globally_lex(self, tmp_path: Path) -> None:
        """The local_fs driver yields keys in depth-first sorted-per-
        directory order, which is NOT globally lexicographic for keys
        spanning directory boundaries (Sprint 8.5 T0.5 round-4 contract
        narrowing — see ``list_prefix`` docstring's "Order contract"
        section).

        Concrete pin: keys ``a/z`` and ``a.txt`` yield ``['a/z', 'a.txt']``
        under local_fs (depth-first into ``a/`` before yielding the
        sibling file ``a.txt``). Globally lexicographic order would be
        ``['a.txt', 'a/z']`` (``.`` 0x2E < ``/`` 0x2F). A future S3
        driver will yield the globally-lex order via ``ListObjectsV2``;
        the Protocol guarantees only per-driver determinism, NOT
        cross-driver order parity. Callers needing a specific order
        MUST re-sort.

        Locks the determinism so a refactor that accidentally produces
        a different deterministic order (e.g., breadth-first) fails
        loud. Locks the docs/impl agreement.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-order", "a/z", b"x")
        await adapter.put("bucket-order", "a.txt", b"y")
        keys = [k async for k in adapter.list_prefix("bucket-order", "")]
        # Depth-first sorted-per-directory: at bucket root, entries are
        # `a` (dir) and `a.txt` (file), sorted lexicographically: `a` < `a.txt`
        # (the dir entry comes first by os.scandir + sorted). Descend into
        # `a/` first, yield `a/z`, then come back up + yield `a.txt`.
        assert keys == ["a/z", "a.txt"], (
            f"depth-first order pin failed: got {keys}; "
            f"expected ['a/z', 'a.txt'] (Sprint 8.5 T0.5 round-4 contract)"
        )
        # Defence-in-depth: confirm this differs from globally-lex order
        # so a future regression that silently re-sorts to global lex
        # fails loud here (different invariants; different drivers).
        assert keys != sorted(keys), (
            f"keys unexpectedly globally-lex sorted: {keys}; "
            f"local_fs driver MUST yield depth-first NOT globally-lex"
        )

    async def test_missing_prefix_returns_empty_iterator(self, tmp_path: Path) -> None:
        """A non-empty prefix that points at a nonexistent directory
        yields a normal empty iterator (NOT an exception). Distinct
        from the empty-string prefix case (covered by
        test_empty_string_prefix_walks_whole_bucket below) — this one
        passes a real prefix string that just happens to match nothing.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        keys = [k async for k in adapter.list_prefix("bucket-empty", "no-prefix/")]
        assert keys == []

    async def test_empty_string_prefix_walks_whole_bucket(self, tmp_path: Path) -> None:
        """Empty prefix (prefix='') walks the whole bucket per spec §3.5
        ("may be empty (= whole bucket walk)"). Distinct from the
        missing-prefix case (test_missing_prefix_returns_empty_iterator
        above) — this one passes the explicit empty string + expects
        every user-put key to be yielded.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-e", "tenant-a/file1.txt", b"x")
        await adapter.put("bucket-e", "tenant-b/file2.txt", b"y")
        keys = [k async for k in adapter.list_prefix("bucket-e", "")]
        assert keys == ["tenant-a/file1.txt", "tenant-b/file2.txt"]

    async def test_yields_full_keys_not_relative(self, tmp_path: Path) -> None:
        """Yields full keys (e.g., 'tenant-a/session-1/file.json'),
        NOT relative-to-prefix ('session-1/file.json').
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-c", "tenant-a/session-1/file.json", b"x")
        keys = [k async for k in adapter.list_prefix("bucket-c", "tenant-a/")]
        assert keys == ["tenant-a/session-1/file.json"]

    async def test_path_traversal_in_prefix_refused(self, tmp_path: Path) -> None:
        """`..` in prefix MUST refuse via PathTraversalError per spec §3.5
        defence-in-depth (P1.r10 string-traversal class).
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        with pytest.raises(PathTraversalError):
            async for _ in adapter.list_prefix("bucket-d", "../etc/"):
                pass

    async def test_prefix_isolates_to_named_bucket(self, tmp_path: Path) -> None:
        """A prefix in bucket-a MUST NOT yield keys from bucket-b."""
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-a", "shared/key", b"a")
        await adapter.put("bucket-b", "shared/key", b"b")
        keys_a = [k async for k in adapter.list_prefix("bucket-a", "shared/")]
        keys_b = [k async for k in adapter.list_prefix("bucket-b", "shared/")]
        assert keys_a == ["shared/key"]
        assert keys_b == ["shared/key"]
        # No cross-contamination — each call returns ONLY its bucket's keys.

    async def test_skips_adapter_internal_artefacts(self, tmp_path: Path) -> None:
        """Adapter-internal artefacts (retention sidecars, ``.tmp/``
        staging dir, health-probe sentinel) MUST NOT appear in
        ``list_prefix`` yields. These are local-driver-only bookkeeping
        artefacts; an S3 ``ListObjectsV2`` equivalent would never expose
        them. Per the Protocol §3.5 contract: ``list_prefix`` yields
        ONLY user-put object keys that ``put()``/``get()``/``delete()``
        round-trip.

        Covers all 3 internal classes via a single walk:
          - ``<key>.retention`` sidecar (created automatically by
            ``put(..., retention_seconds=N)``).
          - ``.tmp/`` staging directory (in-flight atomic writes;
            simulated by mkdir + a stub tmp file).
          - ``.cognic_health_probe`` sentinel (created by
            ``health_check()``; defence-in-depth — also write a stray
            one to defend against a filesystem where the probe lingers).
        """
        # Import the bookkeeping constants from the production module so
        # this test stays drift-detector-style — if the suffix or name
        # changes upstream, the test breaks loudly here.
        from cognic_agentos.db.adapters.local_object_store_adapter import (
            _HEALTH_PROBE_NAME,
            _RETENTION_SIDECAR_SUFFIX,
            _TMP_DIR_NAME,
        )

        adapter = LocalObjectStoreAdapter(root=tmp_path)

        # User key + auto-generated retention sidecar (`.retention`).
        await adapter.put("bucket-x", "user-key.json", b"data", retention_seconds=3600)
        # Run health_check — creates + cleans the sentinel.
        await adapter.health_check()

        # Manually create the .tmp/ staging dir + a stub tmp file inside
        # (in real operation this happens transiently during put()).
        tmp_dir = tmp_path / "bucket-x" / _TMP_DIR_NAME
        tmp_dir.mkdir(parents=True, exist_ok=True)
        (tmp_dir / "in-flight-write.tmp").write_bytes(b"x")

        # Manually drop a stray health-probe-named file (defence-in-depth
        # against filesystems where health_check's sentinel lingers).
        (tmp_path / "bucket-x" / _HEALTH_PROBE_NAME).write_text("x")

        keys = [k async for k in adapter.list_prefix("bucket-x", "")]

        # ONLY the user key should appear; no internal artefacts.
        assert keys == ["user-key.json"], f"adapter-internal artefacts leaked as keys: {keys}"
        # Per-class defence-in-depth assertions for diagnostic clarity:
        assert not any(k.endswith(_RETENTION_SIDECAR_SUFFIX) for k in keys), (
            f"retention sidecars leaked: {keys}"
        )
        assert not any(_TMP_DIR_NAME in k.split("/") for k in keys), (
            f".tmp/ staging dir leaked: {keys}"
        )
        assert not any(k.endswith(_HEALTH_PROBE_NAME) for k in keys), f"health probe leaked: {keys}"

    async def test_put_refuses_user_key_ending_dot_retention(self, tmp_path: Path) -> None:
        """``put()`` MUST refuse user keys ending in ``.retention``
        (Sprint 8.5 T0.5 reservation per ``_validate_and_resolve`` step 5).

        Reservation at the put() boundary closes the namespace ambiguity
        the T0.5 reviewer round 3 surfaced — without it, list_prefix
        would have to discriminate adapter sidecars from user objects
        via content inspection, and a user could deliberately craft a
        ``.retention`` file matching the sidecar JSON shape to hide it.
        Reserving at the source means: any ``.retention``-suffixed file
        in the bucket tree is UNAMBIGUOUSLY adapter-internal.

        Refused via the existing ``PathTraversalError`` taxonomy with a
        clear "reserved for the adapter's retention-sidecar namespace"
        message; callers catching that exception class already handle
        key-rejection.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        with pytest.raises(PathTraversalError, match="retention-sidecar namespace"):
            await adapter.put("bucket-f", "report.retention", b"user-data")

    async def test_reservation_applies_uniformly_to_get_and_delete(self, tmp_path: Path) -> None:
        """The ``.retention`` reservation flows through
        ``_validate_and_resolve`` — get() and delete() refuse the same
        key shape via the same code path. Defence-in-depth: even if a
        ``.retention`` file somehow appeared in the bucket tree (manual
        filesystem write, future refactor bypassing put), the adapter's
        public API cannot be tricked into reading or deleting it as a
        user object.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        with pytest.raises(PathTraversalError, match="retention-sidecar namespace"):
            await adapter.get("bucket-g", "foo.retention")
        with pytest.raises(PathTraversalError, match="retention-sidecar namespace"):
            await adapter.delete("bucket-g", "foo.retention")

    async def test_list_prefix_refuses_direct_tmp_staging_prefix(self, tmp_path: Path) -> None:
        """``list_prefix(bucket, '.tmp/')`` MUST refuse — the staging
        dir is the adapter's in-flight atomic-write namespace, NOT a
        user-listable namespace (Sprint 8.5 T0.5 round-4 fix). Without
        this refusal the walker would start AT the staging dir and
        yield its uuid4-named in-flight tmp files as if they were user
        keys (the bucket-root filter in ``_walk_keys_root_safe`` only
        catches ``.tmp`` when it appears as a CHILD during a parent-
        prefix walk — when ``.tmp`` is the prefix itself, the walker
        never sees it as a child to skip).

        Also exercises the ``.tmp`` and ``.tmp/anything`` first-segment
        shapes — all 3 MUST refuse via the same code path.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        # Populate the staging dir to prove the refusal happens BEFORE
        # the walker would expose anything.
        staging = tmp_path / "bucket-staging" / ".tmp"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "in-flight-attacker.tmp").write_bytes(b"attacker")

        for shape in (".tmp", ".tmp/", ".tmp/anything"):
            with pytest.raises(PathTraversalError, match="staging namespace"):
                async for _ in adapter.list_prefix("bucket-staging", shape):
                    pass

    async def test_list_prefix_refuses_direct_health_probe_prefix(self, tmp_path: Path) -> None:
        """``list_prefix(bucket, '.cognic_health_probe')`` MUST refuse —
        symmetric with the ``.tmp/`` refusal for completeness. Even
        though the health probe is a file (not a directory) and would
        naturally yield empty via ``is_dir()`` check, refusing
        explicitly at the validator boundary keeps the rejection
        contract symmetric + future-proofs against refactors that
        change the on-disk shape of the probe.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        with pytest.raises(PathTraversalError, match="health-probe namespace"):
            async for _ in adapter.list_prefix("bucket-h", ".cognic_health_probe"):
                pass

    async def test_deeper_path_tmp_segment_in_prefix_still_yielded(self, tmp_path: Path) -> None:
        """Defence-in-depth pin for the round-4 reservation scope: a
        ``.tmp`` segment at DEEPER path (NOT bucket-root first segment)
        is a LEGAL user-namespace prefix and MUST be enumerable.
        Locks the bucket-root-only scope of the round-4 refusal —
        prevents future over-tightening that would refuse user prefixes
        like ``tenant-a/.tmp/``.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-deeper", "tenant-a/.tmp/legit.txt", b"x")
        keys = [k async for k in adapter.list_prefix("bucket-deeper", "tenant-a/.tmp/")]
        assert keys == ["tenant-a/.tmp/legit.txt"], (
            f"deeper-path .tmp prefix was incorrectly refused: {keys}"
        )

    async def test_user_key_with_tmp_segment_at_deeper_path_yielded(self, tmp_path: Path) -> None:
        """A user-put key with a ``.tmp`` path segment at depth > 1
        MUST appear in list_prefix yields. ``_KEY_RE`` allows
        ``tenant-a/.tmp/file`` (starts with ``[a-z0-9]``, all chars in
        the segment-allow set). The ``.tmp/`` skip MUST be scoped to
        bucket-root level only — at deeper paths a ``.tmp`` directory
        is a legal user key segment.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-h", "tenant-a/.tmp/file.json", b"user-data")
        keys = [k async for k in adapter.list_prefix("bucket-h", "")]
        assert keys == ["tenant-a/.tmp/file.json"], (
            f"user key with .tmp segment at deeper path was incorrectly filtered: {keys}"
        )

    async def test_user_key_named_cognic_health_probe_at_deeper_path_yielded(
        self, tmp_path: Path
    ) -> None:
        """A user-put key named ``.cognic_health_probe`` at depth > 1
        MUST appear in list_prefix yields. ``_KEY_RE`` allows
        ``tenant-a/.cognic_health_probe`` (starts with ``[a-z0-9]``;
        ``.``, ``_``, alphanumerics all in the segment-allow set).
        The health-probe skip MUST be scoped to bucket-root level
        only — at deeper paths a file with that name is a legal user
        key.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-i", "tenant-a/.cognic_health_probe", b"user-data")
        keys = [k async for k in adapter.list_prefix("bucket-i", "")]
        assert keys == ["tenant-a/.cognic_health_probe"], (
            f"user key named .cognic_health_probe at deeper path was incorrectly filtered: {keys}"
        )


class TestListPrefixSymlinkEscapeDefence:
    """P1.r10 + P1.r11 LOAD-BEARING — symlink-escape regressions.

    String `..` traversal (test_path_traversal_in_prefix_refused above)
    is the EASY case. The real attack class is symlink escape — an
    attacker creates a symlink within the bucket that resolves outside
    root (P1.r10) OR within the same root but outside the requested
    prefix subtree (P1.r11 — cross-prefix tenant isolation). Per spec
    §9 + P3.r6 doctrine: the local driver is the tenant-isolation
    enforcement surface for the runtime checkpoint path; a bug here
    bypasses CheckpointStore's per-tenant prefix invariant.
    """

    async def test_symlink_in_prefix_dir_escaping_root_refused(self, tmp_path: Path) -> None:
        """A symlink at <root>/<bucket>/<prefix> pointing outside root
        MUST raise PathTraversalError, NOT yield keys from the symlink's
        target directory (P1.r10 root-escape at prefix level).
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        bucket_dir = tmp_path / "bucket-a"
        bucket_dir.mkdir(parents=True)

        outside = tmp_path.parent / "escape-target"
        outside.mkdir(exist_ok=True)
        (outside / "secret.txt").write_text("attacker-data")

        (bucket_dir / "escape").symlink_to(outside, target_is_directory=True)

        with pytest.raises(PathTraversalError, match="symlink escape"):
            async for _ in adapter.list_prefix("bucket-a", "escape/"):
                pass

    async def test_symlink_inside_walk_escaping_root_refused(self, tmp_path: Path) -> None:
        """A symlink encountered MID-WALK (after descending into a valid
        prefix directory) pointing outside root MUST raise
        PathTraversalError per the _walk_keys_root_safe step-1 invariant
        (P1.r10 root-escape mid-walk).
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        bucket_dir = tmp_path / "bucket-b"
        prefix_dir = bucket_dir / "tenant-a"
        prefix_dir.mkdir(parents=True)
        await adapter.put("bucket-b", "tenant-a/legit.txt", b"x")

        outside = tmp_path.parent / "escape-mid-walk"
        outside.mkdir(exist_ok=True)
        (outside / "attacker.txt").write_text("y")

        (prefix_dir / "evil-link").symlink_to(outside, target_is_directory=True)

        with pytest.raises(PathTraversalError, match="symlink escape"):
            async for _ in adapter.list_prefix("bucket-b", "tenant-a/"):
                pass

    async def test_symlink_pointing_to_other_tenant_prefix_refused(self, tmp_path: Path) -> None:
        """P1.r11 LOAD-BEARING tenant-isolation pin: a symlink in tenant-a's
        prefix pointing at tenant-b's prefix (WITHIN the same root) MUST
        be refused, NOT yield tenant-b's keys as if they were tenant-a's.

        Pre-P1.r11 the single ``is_relative_to(self._root)`` check passed
        (both tenants under root) + the walker yielded tenant-b's
        secret.txt as if it were tenant-a's — that's a tenant-isolation
        breach per spec §9. The dual ``is_relative_to(walk_root_bound)``
        check (Check 2 in _walk_keys_root_safe) catches it because
        tenant-b is sibling to tenant-a, NOT under tenant-a's
        walk_root_bound subtree.

        TM-revert proof at T0.5 step 8(b): removing the second check
        from _walk_keys_root_safe fails this regression.
        """
        adapter = LocalObjectStoreAdapter(root=tmp_path)
        await adapter.put("bucket-c", "tenant-a/own.txt", b"x")
        await adapter.put("bucket-c", "tenant-b/secret.txt", b"y")

        bucket_dir = tmp_path / "bucket-c" / "tenant-a"
        target_dir = tmp_path / "bucket-c" / "tenant-b"
        (bucket_dir / "cross-tenant-link").symlink_to(target_dir, target_is_directory=True)

        keys: list[str] = []
        with pytest.raises(PathTraversalError, match="cross-prefix symlink"):
            async for k in adapter.list_prefix("bucket-c", "tenant-a/"):
                keys.append(k)
        # Defence-in-depth assertion: even if the raise pattern changes
        # in a future refactor, tenant-b keys MUST NEVER appear in
        # tenant-a's listing. This second assertion fails-loud if a
        # future change accidentally narrows the raise to a broader
        # exception type that lets keys through.
        assert not any("tenant-b" in k or "secret.txt" in k for k in keys), (
            f"tenant-isolation breach: cross-tenant symlink yielded keys "
            f"{[k for k in keys if 'tenant-b' in k or 'secret.txt' in k]}"
        )

"""Sprint 8.5 T12 — focused negative-path coverage for
``db/adapters/local_object_store_adapter.py``.

Same-commit coverage repair landed alongside the T12 critical-controls
gate promotion (71 → 73). The tightening-edit-B check
(`feedback_verify_promotion_meets_floor_at_promotion_time`) found the
driver at 92.58% line on fresh ``coverage.json`` — below the 95%
durable-gate floor. The driver is promoted because Sprint 8.5's
``list_prefix()`` extension makes it a runtime checkpoint
tenant-isolation enforcement surface (a ``..`` traversal OR a
cross-prefix symlink leak would bypass the per-tenant prefix
isolation); the promotion MUST NOT land without same-commit repair.

Every test pins a path-traversal / symlink-escape / race branch the
happy-path suite left uncovered — these ARE the tenant-isolation
enforcement the gate promotion exists to protect.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
    PathTraversalError,
)

pytestmark = pytest.mark.asyncio


def _adapter(tmp_path: Path) -> LocalObjectStoreAdapter:
    """Adapter rooted at an existing dir so symlink fixtures can be
    created under the resolved root."""
    root = tmp_path / "objects"
    root.mkdir(parents=True, exist_ok=True)
    return LocalObjectStoreAdapter(root=root)


async def _collect(adapter: LocalObjectStoreAdapter, bucket: str, prefix: str) -> list[str]:
    return [key async for key in adapter.list_prefix(bucket, prefix)]


# ---------------------------------------------------------------------------
# _validate_prefix_or_raise — malformed prefix raises.
# ---------------------------------------------------------------------------


class TestValidatePrefixNegativePaths:
    """``list_prefix`` rejects a malformed prefix BEFORE walking — a
    NUL byte / leading-slash / non-str prefix is path-traversal bait."""

    async def test_rejects_non_str_prefix(self, tmp_path: Path) -> None:
        adapter = _adapter(tmp_path)
        with pytest.raises(PathTraversalError, match="prefix must be str"):
            await _collect(adapter, "bkt", 1234)  # type: ignore[arg-type]

    async def test_rejects_nul_byte_in_prefix(self, tmp_path: Path) -> None:
        adapter = _adapter(tmp_path)
        with pytest.raises(PathTraversalError, match="NUL byte"):
            await _collect(adapter, "bkt", "pre\x00fix")

    async def test_rejects_absolute_prefix(self, tmp_path: Path) -> None:
        adapter = _adapter(tmp_path)
        with pytest.raises(PathTraversalError, match="must not start with"):
            await _collect(adapter, "bkt", "/etc/passwd")


# ---------------------------------------------------------------------------
# list_prefix — bucket-root + prefix resolution edge cases.
# ---------------------------------------------------------------------------


class TestListPrefixResolutionEdgeCases:
    """The dual root-safety resolution (bucket root + prefix subtree)
    fails-closed on a symlink loop and on a symlink that escapes the
    adapter root."""

    async def test_bucket_root_symlink_loop_fails_closed(self, tmp_path: Path) -> None:
        # A bucket dir that is a self-referential symlink — Path.resolve()
        # raises OSError (ELOOP); the adapter maps it to PathTraversalError.
        adapter = _adapter(tmp_path)
        loop = adapter._root / "loopbkt"
        os.symlink(loop, loop)
        with pytest.raises(PathTraversalError, match="failed to resolve bucket root"):
            await _collect(adapter, "loopbkt", "")

    async def test_bucket_root_symlink_escape_fails_closed(self, tmp_path: Path) -> None:
        # A bucket dir symlinked OUTSIDE the adapter root — resolves fine
        # but is not relative to root → tenant-isolation breach refused.
        adapter = _adapter(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        os.symlink(outside, adapter._root / "escbkt")
        with pytest.raises(PathTraversalError, match="symlink escape at bucket level"):
            await _collect(adapter, "escbkt", "")

    async def test_prefix_symlink_loop_fails_closed(self, tmp_path: Path) -> None:
        # A prefix subtree that is a symlink loop — resolution raises
        # RuntimeError on Python 3.12; list_prefix fails closed to the
        # PathTraversalError taxonomy. A genuinely non-existent prefix
        # is a DIFFERENT case (resolve() does not raise for it; the
        # exists()/is_dir() guard yields an empty iterator) — a loop is
        # a corrupt/hostile filesystem state and must surface loud.
        adapter = _adapter(tmp_path)
        bucket_dir = adapter._root / "bkt"
        bucket_dir.mkdir()
        loop = bucket_dir / "looppfx"
        os.symlink(loop, loop)
        with pytest.raises(PathTraversalError, match="failed to resolve prefix"):
            await _collect(adapter, "bkt", "looppfx")


# ---------------------------------------------------------------------------
# _walk_keys_root_safe — scandir race + broken-symlink skip.
# ---------------------------------------------------------------------------


class TestWalkKeysRootSafeEdgeCases:
    """The recursive walk survives a directory lost to a race + a
    broken/looping symlink entry — one bad object never aborts a sweep
    over a multi-million-key tenant."""

    async def test_walk_survives_scandir_race(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The prefix dir exists at the exists()/is_dir() guard but is
        # gone by the time os.scandir runs — the walk returns cleanly.
        adapter = _adapter(tmp_path)
        prefix_dir = adapter._root / "bkt" / "pfx"
        prefix_dir.mkdir(parents=True)

        def _raising_scandir(_path: Any) -> Any:
            raise FileNotFoundError("dir lost to race")

        monkeypatch.setattr(os, "scandir", _raising_scandir)
        assert await _collect(adapter, "bkt", "pfx") == []

    async def test_walk_skips_looping_symlink_entry(self, tmp_path: Path) -> None:
        # A symlink-loop entry inside the prefix — entry.resolve() raises
        # OSError; the walk skips it silently rather than aborting.
        adapter = _adapter(tmp_path)
        prefix_dir = adapter._root / "bkt" / "pfx"
        prefix_dir.mkdir(parents=True)
        # Two-symlink loop: a → b, b → a.
        os.symlink(prefix_dir / "b", prefix_dir / "a")
        os.symlink(prefix_dir / "a", prefix_dir / "b")
        # A real file alongside the loop still lists.
        (prefix_dir / "real.txt").write_bytes(b"ok")
        keys = await _collect(adapter, "bkt", "pfx")
        assert keys == ["pfx/real.txt"]


# ---------------------------------------------------------------------------
# get() + put() — symlink-escape at the file boundary.
# ---------------------------------------------------------------------------


class TestGetPutSymlinkEscape:
    """``get`` re-resolves the target at read time + ``put`` resolves
    the parent — both fail-closed when a symlink escapes the root."""

    async def test_get_refuses_symlink_escape(self, tmp_path: Path) -> None:
        # The key path is a symlink to a file OUTSIDE the adapter root.
        adapter = _adapter(tmp_path)
        bucket_dir = adapter._root / "bkt"
        bucket_dir.mkdir()
        outside_file = tmp_path / "outside.txt"
        outside_file.write_bytes(b"secret-from-another-root")
        os.symlink(outside_file, bucket_dir / "esckey")
        with pytest.raises(PathTraversalError, match="not under root"):
            await adapter.get("bkt", "esckey")

    async def test_put_refuses_symlink_loop_parent(self, tmp_path: Path) -> None:
        # The parent dir of the put target is a self-referential symlink
        # — parent resolution raises OSError; put fails-closed.
        adapter = _adapter(tmp_path)
        bucket_dir = adapter._root / "bkt"
        bucket_dir.mkdir()
        loop = bucket_dir / "loopdir"
        os.symlink(loop, loop)
        with pytest.raises(PathTraversalError, match="failed to resolve parent"):
            await adapter.put("bkt", "loopdir/file.txt", b"x", retention_seconds=None)


class TestGetSymlinkLoopFinalKey:
    """``get`` re-resolves the FINAL key path with ``resolve(strict=True)``
    — a symlink loop AT the key (not just the parent) must fail-closed to
    the ``PathTraversalError`` taxonomy, while a genuinely absent object
    still surfaces as ``FileNotFoundError`` per ``get``'s contract.

    The joint invariant is the point: Python 3.12 ``Path.resolve()``
    raises ``RuntimeError`` on a symlink loop and ``FileNotFoundError``
    on an absent path — both are routed deliberately and differently.
    """

    async def test_get_refuses_symlink_loop_final_key(self, tmp_path: Path) -> None:
        # The key itself is a self-referential symlink loop — resolve()
        # raises RuntimeError on Python 3.12; get() maps it to the
        # PathTraversalError closed taxonomy (NOT a raw RuntimeError).
        adapter = _adapter(tmp_path)
        bucket_dir = adapter._root / "bkt"
        bucket_dir.mkdir()
        loop = bucket_dir / "loopkey"
        os.symlink(loop, loop)
        with pytest.raises(PathTraversalError, match="symlink loop detected"):
            await adapter.get("bkt", "loopkey")

    async def test_get_preserves_filenotfound_for_absent_key(self, tmp_path: Path) -> None:
        # A genuinely absent object is NOT a path-traversal event — get()
        # MUST still raise FileNotFoundError per its documented contract.
        adapter = _adapter(tmp_path)
        (adapter._root / "bkt").mkdir()
        with pytest.raises(FileNotFoundError):
            await adapter.get("bkt", "no-such-key")

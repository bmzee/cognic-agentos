"""Sprint 8A T10a — sandbox_session @asynccontextmanager helper.

Per spec §288-334 — the helper composes backend.create() on entry +
session-cleanup on exit, routing through warm_pool.release_or_destroy
when use_warm_pool=True and a pool is wired, else session.destroy().

The 2 spec-locked pinning tests at §317-319:

* test_helper_releases_to_pool_when_pool_wired — warm-pool route
* test_helper_destroys_when_pool_not_wired — fallback route

The Round-2 P2 reviewer fix the spec cites: without the warm-pool
route, warm-pool members would be one-shot under the ergonomic API
because the context manager's __aexit__ would call
session.destroy() unconditionally, defeating the latency target.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    sandbox_session,
)

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
    warm_pool_key="python-interactive",
)

_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


def _make_session() -> MagicMock:
    s = MagicMock()
    s.session_id = "session-abc"
    s.policy = _POLICY
    s.tenant_id = "t-1"
    s.pack_context = _PACK_CTX
    s.warm_pool_hit = False
    s.destroy = AsyncMock()
    return s


def _make_backend(session: MagicMock) -> AsyncMock:
    backend = AsyncMock()
    backend.create.return_value = session
    return backend


class TestSandboxSessionHelperRouting:
    """Spec §317-319 — exit-routing pinning tests."""

    @pytest.mark.asyncio
    async def test_helper_releases_to_pool_when_pool_wired(self) -> None:
        """use_warm_pool=True + warm_pool wired → exit routes through
        warm_pool.release_or_destroy(session), NOT session.destroy().
        Without this, warm-pool members would be one-shot under the
        ergonomic API (Round-2 P2 reviewer fix per spec §309-311)."""
        session = _make_session()
        backend = _make_backend(session)
        warm_pool = AsyncMock()
        actor = MagicMock(subject="test-subject")

        async with sandbox_session(
            backend,
            _POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=True,
            warm_pool=warm_pool,
        ) as s:
            assert s is session

        warm_pool.release_or_destroy.assert_awaited_once_with(session)
        session.destroy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_helper_destroys_when_pool_not_wired(self) -> None:
        """use_warm_pool=True but warm_pool=None → exit calls
        session.destroy() (fallback route). Backends that don't have
        a pool wired must still tear down sessions cleanly."""
        session = _make_session()
        backend = _make_backend(session)
        actor = MagicMock(subject="test-subject")

        async with sandbox_session(
            backend,
            _POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=True,
            warm_pool=None,
        ):
            pass

        session.destroy.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_helper_destroys_when_use_warm_pool_false(self) -> None:
        """use_warm_pool=False → exit calls session.destroy() regardless
        of whether warm_pool is wired. Forces cold tear-down for
        admission-context paths that shouldn't return to the pool."""
        session = _make_session()
        backend = _make_backend(session)
        warm_pool = AsyncMock()
        actor = MagicMock(subject="test-subject")

        async with sandbox_session(
            backend,
            _POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
            warm_pool=warm_pool,
        ):
            pass

        session.destroy.assert_awaited_once()
        warm_pool.release_or_destroy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_helper_threads_kwargs_to_backend_create(self) -> None:
        """Sanity: every kwarg the helper accepts (actor, tenant_id,
        pack_context, use_warm_pool) is forwarded to backend.create
        verbatim. A drift here would break the admission contract."""
        session = _make_session()
        backend = _make_backend(session)
        actor = MagicMock(subject="test-subject")

        async with sandbox_session(
            backend,
            _POLICY,
            actor=actor,
            tenant_id="t-XYZ",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        ):
            pass

        backend.create.assert_awaited_once_with(
            _POLICY,
            actor=actor,
            tenant_id="t-XYZ",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )

    @pytest.mark.asyncio
    async def test_helper_cleanup_fires_on_inner_exception(self) -> None:
        """The exit-cleanup path (destroy or release_or_destroy) MUST
        fire even when the inner block raises — otherwise an exception
        inside the user's ``async with`` block leaks the session."""
        session = _make_session()
        backend = _make_backend(session)
        actor = MagicMock(subject="test-subject")

        with pytest.raises(RuntimeError, match="inner-block-error"):
            async with sandbox_session(
                backend,
                _POLICY,
                actor=actor,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            ):
                raise RuntimeError("inner-block-error")

        # Cleanup still fired despite the exception
        session.destroy.assert_awaited_once()

"""Sprint 8.5 T6 — session lifecycle after suspend() per spec §3.1.

Pins:

* ``session.exec()`` after ``session.suspend()`` raises (the session is
  no longer usable; caller MUST ``wake()`` to get a fresh session).
* ``session.checkpoint()`` after ``session.suspend()`` raises (same
  rule).
* The raise carries a wake-pointer message so the caller knows what
  to do next.

The session-lifetime invariant uses a plain ``RuntimeError`` (NOT a
``SandboxLifecycleRefused`` — the closed-enum vocabulary is for
admission + wake refusals, not for session-usage errors).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSession,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy


def _policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        egress_allow_list=("api.example.com",),
        vault_path=None,
    )


def _pack_ctx() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.t",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )


def _suspended_session() -> DockerSiblingSession:
    return DockerSiblingSession(
        session_id="suspended-sess",
        policy=_policy(),
        tenant_id="t-1",
        pack_context=_pack_ctx(),
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=MagicMock(),
        _internal_network_name="net",
        _sidecar_container_name="sidecar",
        _actor_subject="actor-1",
        _egress_network_name="egress",
        _suspended=True,
    )


class TestExecRefusesAfterSuspend:
    @pytest.mark.asyncio
    async def test_exec_on_suspended_session_raises(self) -> None:
        session = _suspended_session()
        with pytest.raises(RuntimeError) as exc:
            await session.exec(["echo", "hello"])
        # Message points at wake() so the caller knows the recovery path.
        assert "wake" in str(exc.value).lower()
        assert session.session_id in str(exc.value)


class TestCheckpointRefusesAfterSuspend:
    @pytest.mark.asyncio
    async def test_checkpoint_on_suspended_session_raises(self) -> None:
        """checkpoint() on a suspended session is ALSO invalid — the
        container is gone + the session is no longer usable per spec
        §3.1. The backend's _do_checkpoint guard fires."""
        session = _suspended_session()
        # Wire a backend mock with a checkpoint_store so the
        # NotImplementedError "wire CheckpointStore" path doesn't
        # intercept; the _suspended guard fires first.
        backend_mock = MagicMock()
        backend_mock._checkpoint_store = MagicMock()  # non-None
        session._backend = backend_mock

        # The session.checkpoint() delegates to backend._do_checkpoint;
        # we test by invoking the real _do_checkpoint via the actual
        # method on the bound backend. But since _backend is a Mock, we
        # need to call through the real DockerSiblingSandboxBackend
        # method instead. Simpler: test the exec guard (above) +
        # cover the checkpoint guard via the same logic at backend
        # level.
        # Use a real backend so _do_checkpoint actually runs.
        from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )

        rego = MagicMock()
        rego.evaluate = MagicMock()
        catalog = MagicMock()
        ckpt_store = MagicMock()
        real_backend = DockerSiblingSandboxBackend(
            docker_client=MagicMock(),
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
            warm_pool=None,
            checkpoint_store=ckpt_store,
        )
        session._backend = real_backend
        with pytest.raises(RuntimeError) as exc:
            await session.checkpoint("test-label")
        assert "wake" in str(exc.value).lower()


class TestDoubleSuspendRaises:
    @pytest.mark.asyncio
    async def test_suspending_twice_raises(self) -> None:
        """Per backend._do_suspend's idempotent guard — a second
        suspend() on the same session surfaces fail-loud so the
        caller learns about the usage bug."""
        from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )

        rego = MagicMock()
        rego.evaluate = MagicMock()
        catalog = MagicMock()
        ckpt_store = MagicMock()
        real_backend = DockerSiblingSandboxBackend(
            docker_client=MagicMock(),
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=MagicMock(),
            decision_history_store=MagicMock(),
            settings=MagicMock(),
            warm_pool=None,
            checkpoint_store=ckpt_store,
        )
        session = _suspended_session()
        session._backend = real_backend
        # Second suspend should raise.
        with pytest.raises(RuntimeError):
            await session.suspend()

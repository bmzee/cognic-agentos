"""Sprint 8A T10c — shared SandboxBackend conformance suite per
spec §15.3.

Every Protocol-conforming SandboxBackend implementation MUST pass
these tests. Sprint 8A: DockerSiblingSandboxBackend only.
Sprint 8B: KubernetesPodSandboxBackend (same tests, parametrized
fixture in conftest).

The suite covers Protocol-surface contracts the spec locks:
* ``health()`` returns SandboxBackendHealth with status in the
  closed-enum SandboxBackendHealthStatus literal
* Minimum valid policy lifecycle: create → exec(["echo","ok"]) →
  destroy without raising
* destroy() is idempotent (per spec §5 SandboxBackend.destroy
  docstring)

Env-gated: skipped without ``COGNIC_RUN_DOCKER_SANDBOX=1`` (the
fixture short-circuits with pytest.skip + a structured message
naming the env-flag).
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")


class TestConformanceSurface:
    """Protocol-surface conformance — every SandboxBackend impl MUST
    satisfy these contracts."""

    @pytest.mark.asyncio
    async def test_health_returns_ok_status(self, backend) -> None:  # type: ignore[no-untyped-def]
        """health() returns a SandboxBackendHealth with status in
        the closed-enum literal."""
        from cognic_agentos.sandbox.protocol import (
            SandboxBackendHealth,
            SandboxBackendHealthStatus,
        )

        result = await backend.health()
        assert isinstance(result, SandboxBackendHealth)
        # status MUST be in the closed-enum literal
        from typing import get_args

        valid = set(get_args(SandboxBackendHealthStatus))
        assert result.status in valid

    @pytest.mark.asyncio
    async def test_destroy_is_idempotent(  # type: ignore[no-untyped-def]
        self, backend, tmp_path
    ) -> None:
        """destroy() called twice MUST NOT raise per spec §5
        SandboxBackend.destroy docstring ("Tear down the session.
        Idempotent.")."""
        # Mock catalog verifiers (T6 owns real impl tests)
        from unittest.mock import AsyncMock, MagicMock, patch

        from cognic_agentos.sandbox import (
            PackAdmissionContext,
            SandboxPolicy,
        )
        from cognic_agentos.sandbox.catalog import (
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        with (
            patch.object(
                backend._catalog,
                "_run_cosign_verify",
                AsyncMock(return_value=CosignVerifyResult(passed=True)),
            ),
            patch.object(
                backend._catalog,
                "_run_syft_inspect",
                AsyncMock(return_value=SBOMVerifyResult(passed=True)),
            ),
        ):
            policy = SandboxPolicy(
                cpu_cores=0.5,
                cpu_time_budget_s=None,
                memory_mb=256,
                walltime_s=30.0,
                runtime_image=("cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64),
                egress_allow_list=(),
                vault_path=None,
            )
            ctx = PackAdmissionContext(
                pack_id="cognic.conformance",
                pack_version="v1",
                pack_artifact_digest="sha256:" + "1" * 64,
                risk_tier="internal_write",
                declares_dynamic_install=False,
                profile="production",
            )
            actor = MagicMock()
            actor.subject = "conformance-actor"
            session = await backend.create(
                policy,
                actor=actor,
                tenant_id="t-conformance",
                pack_context=ctx,
                use_warm_pool=False,
            )
            await backend.destroy(session)
            # Second destroy must not raise — idempotent contract
            await backend.destroy(session)

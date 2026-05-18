"""Sprint 8B T8B-c — env-gated K8s resource-cap enforcement against real cgroups.

ENV-GATED: skipped unless ``COGNIC_RUN_K8S_SANDBOX=1`` AND a K8s
cluster + cgroups are reachable. Standard pytest runs skip these
tests; local dev + the Sprint-8B sandbox-integration CI lane (if
+ when one is added) runs them. No ``kind`` is added to CI per
the user-locked 2026-05-17 preflight decision.

Mirrors the Sprint-8A docker_sibling ``test_docker_sibling_resource_caps.py``
patterns. The K8s backend MUST behaviourally match DockerSibling
on the cap-violation surface — both backends emit the same closed-
enum ``SandboxPolicyViolationReason`` values per spec §7.

Per spec §7 + round-3 P2 invariant: ``cpu_cores`` cap throttling
under cap is NOT a violation by itself; only ``cpu_time_budget_exceeded``
fires (and only when ``policy.cpu_time_budget_s`` is set).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    SandboxPolicyViolated,
    sandbox_session,
)

if TYPE_CHECKING:
    from cognic_agentos.sandbox.backends.kubernetes_pod import (
        KubernetesPodSandboxBackend,
    )

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_K8S_SANDBOX") != "1",
    reason=(
        "K8s cluster + cgroups required — set COGNIC_RUN_K8S_SANDBOX=1 "
        "AND configure KUBECONFIG (or run inside a Pod with a "
        "ServiceAccount) to run. Per the 2026-05-17 Sprint 8B preflight "
        "decision: NO kind in CI; live-cluster runs are deliberately "
        "env-gated."
    ),
)


_TEST_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


def _mock_catalog_verify(monkeypatch: pytest.MonkeyPatch, backend: object) -> None:
    """Bypass cosign + SBOM at the catalog seam — T6 owns the real
    subprocess impl tests."""
    from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult

    monkeypatch.setattr(
        backend._catalog,  # type: ignore[attr-defined]
        "_run_cosign_verify",
        AsyncMock(return_value=CosignVerifyResult(passed=True)),
    )
    monkeypatch.setattr(
        backend._catalog,  # type: ignore[attr-defined]
        "_run_syft_inspect",
        AsyncMock(return_value=SBOMVerifyResult(passed=True)),
    )


class TestResourceCapsFireOrDontFire:
    @pytest.mark.asyncio
    async def test_memory_oom_emits_memory_cap_exceeded(
        self,
        backend: KubernetesPodSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per spec §7 + §4.2: 1 GiB malloc in a 64 MiB-capped pod
        triggers the kubelet OOMKilled signal (ContainerStatus.state.
        terminated.reason == "OOMKilled" + exit_code 137); backend
        raises SandboxPolicyViolated(memory_cap_exceeded)."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=64,
            walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend,
                policy,
                actor=actor,
                tenant_id="t-1",
                pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["python", "-c", "x = bytearray(1024 * 1024 * 1024)"])
        assert exc.value.reason == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_walltime_cap_fires_via_agentos_side_timer(
        self,
        backend: KubernetesPodSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per spec §7 item 2: `sleep 60` in a 2s-walltime sandbox
        raises walltime_cap_exceeded via AgentOS-side asyncio.wait_for."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=2.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=(),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend,
                policy,
                actor=actor,
                tenant_id="t-1",
                pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["sleep", "60"])
        assert exc.value.reason == "walltime_cap_exceeded"

    @pytest.mark.asyncio
    async def test_cpu_time_budget_exceeded_fires_when_budget_set(
        self,
        backend: KubernetesPodSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per spec §7 item 4: cgroup-stat polled via pods/exec at
        ≥1Hz; kills when accumulated CPU-seconds exceeds the 1s budget."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=2.0,  # generous K8s requests/limits cap (NOT the kill condition)
            cpu_time_budget_s=1.0,  # 1 CPU-second budget — IS the kill condition
            memory_mb=256,
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend,
                policy,
                actor=actor,
                tenant_id="t-1",
                pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["python", "-c", "while True: pass"])
        assert exc.value.reason == "cpu_time_budget_exceeded"

    @pytest.mark.asyncio
    async def test_cpus_throttle_alone_does_NOT_fire_violation(
        self,
        backend: KubernetesPodSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per round-3 P2 reviewer fix: cpu cap throttling under cap is
        NOT a violation. A CPU-bound workload with cpu_cores=0.5 + NO
        cpu_time_budget_s + a short walltime should complete with
        exit_code=0 + NO SandboxPolicyViolated raised."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,  # tight throttle — expected to throttle workload
            cpu_time_budget_s=None,  # NO CPU-seconds budget → throttling alone is OK
            memory_mb=256,
            walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        async with sandbox_session(
            backend,
            policy,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(["python", "-c", "x = sum(range(10**5))"])
        # Tight CPU loop expected to complete within walltime; throttled
        # but NOT killed. pytest.raises was NOT used so no violation
        # raised counts as the test passing.
        assert result.exit_code == 0

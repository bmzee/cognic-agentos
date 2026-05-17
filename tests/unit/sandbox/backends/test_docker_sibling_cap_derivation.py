"""Sprint 8A T10b — cgroup-cap derivation pure-helper unit tests.

NON-env-gated. Pins the pure-functional helpers that translate
``SandboxPolicy`` resource-cap fields into the Docker HostConfig
key/value pairs (Memory / MemorySwap / CpuQuota / CpuPeriod) +
verifies the cap fields land on the assembled container config.

Per spec §7 lines 513-524:

| Cap              | Docker flag                                     |
|------------------|-------------------------------------------------|
| CPU              | --cpus=0.5  → CpuQuota / CpuPeriod combo        |
| Memory           | --memory=512m + --memory-swap=512m              |

``--cpus=N`` translates to ``CpuQuota=N * CpuPeriod`` with a default
``CpuPeriod=100000`` microseconds. Setting ``MemorySwap=Memory``
disables swap inside the container — without this, a workload past
the Memory cap pages to swap instead of triggering the OOM-kill
path that fires ``memory_cap_exceeded`` per spec §4.2.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    _build_sandbox_container_config,
    _derive_cpu_quota_period,
    _derive_memory_caps_bytes,
)

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


# ---------------------------------------------------------------------------
# _derive_cpu_quota_period — CpuQuota/CpuPeriod math
# ---------------------------------------------------------------------------


class TestDeriveCpuQuotaPeriod:
    """Per spec §7 line 517 — Docker --cpus=0.5 is equivalent to
    CpuQuota=50000 + CpuPeriod=100000 (50ms quota per 100ms period).
    The kernel scheduler enforces this at the container's cgroup."""

    def test_half_core(self) -> None:
        quota, period = _derive_cpu_quota_period(0.5)
        assert period == 100_000  # 100ms default period
        assert quota == 50_000  # 50ms quota → 0.5 cores

    def test_one_core(self) -> None:
        quota, period = _derive_cpu_quota_period(1.0)
        assert quota == 100_000
        assert period == 100_000

    def test_two_cores(self) -> None:
        quota, period = _derive_cpu_quota_period(2.0)
        assert quota == 200_000
        assert period == 100_000

    def test_quarter_core(self) -> None:
        quota, period = _derive_cpu_quota_period(0.25)
        assert quota == 25_000
        assert period == 100_000

    def test_period_is_constant_100ms_default(self) -> None:
        """The cpu_period default (100ms) is the kernel-recommended
        balance between scheduling overhead + throttling responsiveness.
        Pinned as a constant so a change is intentional + reviewable."""
        for cpu_cores in [0.1, 0.5, 1.0, 4.0]:
            _, period = _derive_cpu_quota_period(cpu_cores)
            assert period == 100_000, (
                f"CpuPeriod must be 100000us regardless of cpu_cores "
                f"(got {period} for {cpu_cores} cores)"
            )

    def test_fractional_cores_round_to_microseconds(self) -> None:
        """Quota MUST be an int (Docker rejects floats). 0.333 cores
        → 33300us quota (rounded)."""
        quota, _ = _derive_cpu_quota_period(0.333)
        assert isinstance(quota, int)
        assert 33_000 <= quota <= 33_400


# ---------------------------------------------------------------------------
# _derive_memory_caps_bytes — Memory + MemorySwap (swap disabled)
# ---------------------------------------------------------------------------


class TestDeriveMemoryCapsBytes:
    """Per spec §7 line 518 — --memory=512m + --memory-swap=512m.
    Setting MemorySwap = Memory tells Docker to NOT allocate any
    additional swap; the workload OOM-kills at the memory cap
    instead of paging out. Without this, a memory-cap-exceeded
    workload would page to disk and the test for OOM-kill would
    silently never trigger."""

    def test_256mb(self) -> None:
        memory, memory_swap = _derive_memory_caps_bytes(256)
        assert memory == 256 * 1024 * 1024  # 256 MiB in bytes
        assert memory_swap == memory, (
            "MemorySwap MUST equal Memory to disable swap; otherwise "
            "memory-cap workloads page out instead of OOM-killing"
        )

    def test_64mb(self) -> None:
        memory, memory_swap = _derive_memory_caps_bytes(64)
        assert memory == 64 * 1024 * 1024
        assert memory_swap == memory

    def test_swap_always_matches_memory(self) -> None:
        for mb in [16, 64, 256, 1024, 4096]:
            memory, memory_swap = _derive_memory_caps_bytes(mb)
            assert memory == mb * 1024 * 1024
            assert memory_swap == memory


# ---------------------------------------------------------------------------
# _build_sandbox_container_config now folds the cap fields in
# ---------------------------------------------------------------------------


class TestSandboxContainerConfigCarriesCaps:
    """T10b extension — the assembled HostConfig MUST carry the
    derived cap fields. The env-gated cap tests at
    test_docker_sibling_resource_caps.py exercise the actual kernel
    enforcement; this test pins that the config the backend hands
    Docker IS the one the env-gated tests expect."""

    def test_memory_caps_land_on_hostconfig(self) -> None:
        config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        expected_bytes = 256 * 1024 * 1024
        assert config["HostConfig"]["Memory"] == expected_bytes
        assert config["HostConfig"]["MemorySwap"] == expected_bytes

    def test_cpu_caps_land_on_hostconfig(self) -> None:
        config = _build_sandbox_container_config(
            policy=_POLICY,  # cpu_cores=0.5
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        assert config["HostConfig"]["CpuQuota"] == 50_000
        assert config["HostConfig"]["CpuPeriod"] == 100_000

    def test_caps_scale_with_policy(self) -> None:
        """Different policy → different cap fields. Pins that the
        config builder reads the policy at call time, not at
        module-load time (would be a serious bug class)."""
        policy_2x = SandboxPolicy(
            cpu_cores=2.0,
            cpu_time_budget_s=None,
            memory_mb=1024,
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(),
            vault_path=None,
        )
        config = _build_sandbox_container_config(
            policy=policy_2x,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        assert config["HostConfig"]["Memory"] == 1024 * 1024 * 1024
        assert config["HostConfig"]["MemorySwap"] == 1024 * 1024 * 1024
        assert config["HostConfig"]["CpuQuota"] == 200_000
        assert config["HostConfig"]["CpuPeriod"] == 100_000

    def test_security_defaults_unchanged_by_t10b(self) -> None:
        """T10b extends HostConfig with cap fields but MUST preserve
        all R1-P1.3 security defaults (User, CapDrop, ReadonlyRootfs,
        no-new-privileges) that prior tests rely on."""
        config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        assert config["User"] == "65534:65534"
        assert config["HostConfig"]["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in config["HostConfig"]["SecurityOpt"]
        assert config["HostConfig"]["ReadonlyRootfs"] is True

    def test_proxy_sidecar_config_does_NOT_carry_sandbox_caps(self) -> None:
        """Sidecar runs the canonical proxy image; it does NOT get
        the sandbox's resource caps (would constrain the proxy's
        own work). Sidecar caps are a separate concern (defaults
        from the proxy image's manifest)."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _build_proxy_sidecar_container_config,
        )

        config = _build_proxy_sidecar_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
            proxy_image="cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        )
        # Memory/CpuQuota fields MUST NOT be present on sidecar config
        assert "Memory" not in config["HostConfig"]
        assert "MemorySwap" not in config["HostConfig"]
        assert "CpuQuota" not in config["HostConfig"]
        assert "CpuPeriod" not in config["HostConfig"]

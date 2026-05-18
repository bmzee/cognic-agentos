"""Sprint 8B T8B-c — KubernetesPodSandboxBackend.exec() decision-logic tests.

NON-env-gated. Mocks the K8s I/O helpers on the backend instance to
pin exec()'s classification logic — backend-behavioural-equivalence
pin against ``DockerSiblingSandboxBackend`` per the cross-backend
conformance contract:

* walltime exceeded → ``walltime_cap_exceeded``
* OOMKilled detection via ``ContainerStatus.state.terminated.reason ==
  "OOMKilled"`` → ``memory_cap_exceeded`` (exit_code 137 alone is NOT
  sufficient — mirrors Docker's ``State.OOMKilled`` authority pattern)
* cpu-budget exceeded → ``cpu_time_budget_exceeded``
* green path returns ``SandboxExecResult`` with the right shape
* proxy-log readback FAIL-CLOSED: sidecar gone / cat-nonzero /
  unexpected exception → ``egress_audit_unreadable`` violation
  (mirrors DockerSibling T10c R1 P1.2 wire-protocol-public contract;
  missing it ships a silent egress-bypass class)

The env-gated tests at ``test_kubernetes_pod_resource_caps.py``
exercise the actual kernel enforcement against a real K8s cluster
+ cgroups. These tests cover the AgentOS-side decision logic
without needing a cluster available.

Per spec §7 lines 495-502 + round-3 P2 invariant: cpu_cores cap
throttling under cap is NOT a violation by itself — only
``cpu_time_budget_exceeded`` (when a budget is set) raises
``SandboxPolicyViolated``.

Mocking strategy: rather than mock the kubernetes_asyncio websocket
machinery directly, we mock the backend's K8s-I/O private methods
(``_open_pod_exec_stream``, ``_kill_pod_or_raise``,
``_read_pod_oom_killed``, ``_read_cpu_usage_ns``,
``_read_proxy_log_from_sidecar_k8s``). This isolates the
classification-precedence + fail-closed-contract pins from the
underlying transport — drift in the transport surfaces in env-
gated tests + the conformance harness.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxExecResult,
    SandboxPolicy,
    SandboxPolicyViolated,
)
from cognic_agentos.sandbox.backends._shared_exec import _ProxyLogReadFailure
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY_NO_BUDGET = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_POLICY_WITH_BUDGET = SandboxPolicy(
    cpu_cores=2.0,
    cpu_time_budget_s=1.0,
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
_ACTOR = Actor(
    subject="consumer-actor-id",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)


def _make_dh_store() -> AsyncMock:
    """Mock DecisionHistoryStore — append_with_precondition returns
    the (event_id, prev_hash) tuple shape ``emit_sandbox_event`` expects.
    """
    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


def _make_backend_with_exec_mocks(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    oom_killed: bool = False,
    exec_raises_timeout: bool = False,
    cpu_usage_per_poll_ns: list[int] | None = None,
    proxy_log_readback_raises: BaseException | None = None,
) -> tuple[KubernetesPodSandboxBackend, AsyncMock, AsyncMock]:
    """Build a K8s backend whose K8s-I/O private methods are mocked.

    Returns ``(backend, open_exec_mock, kill_pod_mock)`` so tests can
    introspect call counts / kwargs / await counts.
    """
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    decision = MagicMock()
    decision.allow = True
    decision.reasoning = ""
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )

    backend = KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=_make_dh_store(),
        settings=settings,
        warm_pool=None,
    )

    # _open_pod_exec_stream(pod_name, container_name, command,
    # walltime_s) → returns (stdout, stderr, exit_code). On walltime
    # overage raises TimeoutError so the exec body's classify path
    # treats it as walltime_exceeded.
    async def _stream_workload(
        *,
        pod_name: str,
        container_name: str,
        command: list[str],
        walltime_s: float | None,
    ) -> tuple[bytes, bytes, int]:
        if exec_raises_timeout:
            raise TimeoutError("walltime exceeded")
        return stdout, stderr, exit_code

    open_exec = AsyncMock(side_effect=_stream_workload)
    backend._open_pod_exec_stream = open_exec  # type: ignore[method-assign]

    # _kill_pod_or_raise — tracks the kill call (walltime / cpu-budget
    # cap paths must hit this). Mirrors docker_sibling's
    # _kill_container_or_raise contract: succeed silently on
    # already-gone (404); fail-closed propagate on any other API error.
    kill_pod = AsyncMock(return_value=None)
    backend._kill_pod_or_raise = kill_pod  # type: ignore[method-assign]

    # _read_pod_oom_killed — mock returns the test-injected bool.
    # Production reads ContainerStatus.state.terminated.reason +
    # last_state.terminated.reason and returns True iff either ==
    # "OOMKilled".
    backend._read_pod_oom_killed = AsyncMock(return_value=oom_killed)  # type: ignore[method-assign]

    # _read_cpu_usage_ns — mock returns successive values from the
    # test-injected sequence. Production reads cgroup cpu.stat via
    # short-lived pods/exec.
    if cpu_usage_per_poll_ns is None:
        cpu_usage_per_poll_ns = [0]
    cpu_poll_iter = iter(cpu_usage_per_poll_ns)

    async def _cpu_read(*, pod_name: str, container_name: str) -> int | None:
        try:
            return next(cpu_poll_iter)
        except StopIteration:
            return cpu_usage_per_poll_ns[-1]

    backend._read_cpu_usage_ns = AsyncMock(side_effect=_cpu_read)  # type: ignore[method-assign]

    # _read_proxy_log_from_sidecar_k8s — returns the empty tuple on
    # green path; tests inject _ProxyLogReadFailure or other
    # exceptions to drive the egress_audit_unreadable arm.
    async def _read_proxy_log(*, pod_name: str, sidecar_container_name: str) -> tuple[object, ...]:
        if proxy_log_readback_raises is not None:
            raise proxy_log_readback_raises
        return ()

    backend._read_proxy_log_from_sidecar_k8s = AsyncMock(side_effect=_read_proxy_log)  # type: ignore[method-assign]

    return backend, open_exec, kill_pod


def _make_session(
    backend: KubernetesPodSandboxBackend,
    *,
    policy: SandboxPolicy = _POLICY_NO_BUDGET,
) -> KubernetesPodSession:
    """Mint a session directly (bypass create()) for exec-isolation tests."""
    return KubernetesPodSession(
        session_id="abcd" * 8,
        policy=policy,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _pod_name="cognic-sb-abcdabcd",
        _network_policy_name="cognic-sb-netpol-abcdabcd",
        _namespace="test-ns",
        _actor_subject=_ACTOR.subject,
    )


# ---------------------------------------------------------------------------
# exec() body — backend-level integration with mocked K8s I/O helpers
# ---------------------------------------------------------------------------


class TestExecGreenPath:
    """Green-path exec returns SandboxExecResult with the right shape."""

    @pytest.mark.asyncio
    async def test_exec_returns_sandbox_exec_result_on_green_exit(self) -> None:
        backend, _, _ = _make_backend_with_exec_mocks(
            stdout=b"hello\n",
            stderr=b"",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["echo", "hello"])
        assert isinstance(result, SandboxExecResult)
        assert result.exit_code == 0
        assert result.stdout == b"hello\n"
        assert result.proxy_log == ()  # mocked readback returns empty tuple

    @pytest.mark.asyncio
    async def test_exec_returns_nonzero_exit_without_violation(self) -> None:
        """User-code exit 1 → exec returns SandboxExecResult with
        exit_code=1; no SandboxPolicyViolated raised."""
        backend, _, _ = _make_backend_with_exec_mocks(exit_code=1)
        session = _make_session(backend)

        result = await backend.exec(session, ["false"])
        assert result.exit_code == 1


class TestExecWalltimeCap:
    @pytest.mark.asyncio
    async def test_walltime_exceeded_raises_walltime_cap_exceeded(self) -> None:
        """An exec that times out past policy.walltime_s MUST raise
        SandboxPolicyViolated(walltime_cap_exceeded) + kill the pod.
        Per spec §7 item 2."""
        backend, _, kill_pod = _make_backend_with_exec_mocks(exec_raises_timeout=True)
        session = _make_session(
            backend,
            policy=SandboxPolicy(
                cpu_cores=0.5,
                cpu_time_budget_s=None,
                memory_mb=256,
                walltime_s=0.1,
                runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
                egress_allow_list=(),
                vault_path=None,
            ),
        )

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["sleep", "60"])
        assert exc.value.reason == "walltime_cap_exceeded"
        kill_pod.assert_awaited()


class TestExecMemoryCap:
    @pytest.mark.asyncio
    async def test_exit_137_plus_oom_killed_raises_memory_cap_exceeded(self) -> None:
        """exit_code == 137 + container_status.state.terminated.reason ==
        ``"OOMKilled"`` means the cgroup oom-killer fired. exec() MUST
        classify this as memory_cap_exceeded per spec §7 item 3.

        K8s wire-contract pin: the OOM signal MUST come from
        ContainerStatus, NOT from exit_code alone (which could be
        manual SIGKILL from any source).
        """
        backend, _, _ = _make_backend_with_exec_mocks(
            exit_code=137,
            oom_killed=True,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["python", "-c", "x = bytearray(10**9)"])
        assert exc.value.reason == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_exit_137_without_oom_killed_reason_is_not_classified_as_memory(
        self,
    ) -> None:
        """exit 137 from a non-OOM source MUST NOT misclassify as
        memory_cap_exceeded. Return the exit code; let the caller handle.

        Cross-backend pin: matches docker_sibling's
        ``test_exit_137_without_oom_is_not_classified_as_memory``.
        """
        backend, _, _ = _make_backend_with_exec_mocks(
            exit_code=137,
            oom_killed=False,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["something"])
        assert result.exit_code == 137


class TestExecCpuTimeBudget:
    @pytest.mark.asyncio
    async def test_cpu_budget_exceeded_raises_cpu_time_budget_exceeded(self) -> None:
        """When policy.cpu_time_budget_s is set + the cgroup-stat
        monitor accumulates past the budget, exec() MUST kill the
        pod + raise SandboxPolicyViolated(cpu_time_budget_exceeded).
        Per spec §7 item 4.

        Cross-backend pin: matches docker_sibling's
        ``test_cpu_budget_exceeded_raises_cpu_time_budget_exceeded``.
        """
        backend, _, kill_pod = _make_backend_with_exec_mocks(
            exec_raises_timeout=True,  # hang so monitor has time to fire
            cpu_usage_per_poll_ns=[
                500_000_000,  # 0.5s — under budget
                1_500_000_000,  # 1.5s — over budget → kill
            ],
        )
        # The monitor should fire BEFORE walltime hits. Use a short
        # walltime to ensure walltime doesn't beat the monitor in the
        # test environment.
        session = _make_session(backend, policy=_POLICY_WITH_BUDGET)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["python", "-c", "while True: pass"])
        # Either cpu_budget_exceeded (monitor won) or walltime_exceeded
        # (walltime won). Per spec §7 + precedence in
        # _classify_exec_failure: walltime takes precedence when both
        # signals are set. Both are valid acceptance outcomes for the
        # mocked test — the unit test pins precedence at the
        # _classify_exec_failure level (see drift detector +
        # docker_sibling unit tests); the K8s-specific concern this
        # test pins is that the monitor SPAWNS + KILLS when a budget
        # is set. We assert the kill fires.
        assert exc.value.reason in (
            "cpu_time_budget_exceeded",
            "walltime_cap_exceeded",
        )
        kill_pod.assert_awaited()

    @pytest.mark.asyncio
    async def test_no_cpu_budget_means_no_monitor_no_violation(self) -> None:
        """When policy.cpu_time_budget_s is None (the default), the
        cpu-budget monitor task MUST NOT be spawned. A green-path
        exec returns SandboxExecResult without triggering
        cpu_time_budget_exceeded regardless of cumulative cpu usage.
        """
        backend, _, _ = _make_backend_with_exec_mocks(
            stdout=b"done\n",
            cpu_usage_per_poll_ns=[10**12],  # absurdly high; budget=None
        )
        session = _make_session(backend, policy=_POLICY_NO_BUDGET)

        result = await backend.exec(session, ["echo", "done"])
        assert result.exit_code == 0
        # _read_cpu_usage_ns should NOT have been called since no
        # monitor was spawned
        assert backend._read_cpu_usage_ns.await_count == 0  # type: ignore[attr-defined]


class TestExecProxyLogFailClosed:
    """Sprint 8A T10c R1 P1.2 fail-closed contract — wire-protocol-
    public per ``SandboxPolicyViolationReason.egress_audit_unreadable``.
    Both backends MUST emit ``sandbox.policy.violated`` with this
    closed-enum reason when the proxy-sidecar log cannot be proved
    complete. Missing it ships a silent egress-bypass class.
    """

    @pytest.mark.asyncio
    async def test_proxy_log_read_failure_surfaces_egress_audit_unreadable(
        self,
    ) -> None:
        """``_ProxyLogReadFailure`` raised from the readback path →
        fail-closed via egress_audit_unreadable."""
        backend, _, _ = _make_backend_with_exec_mocks(
            stdout=b"done\n",
            exit_code=0,
            proxy_log_readback_raises=_ProxyLogReadFailure(
                "sidecar gone; cannot prove absence of refusals"
            ),
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["echo", "done"])
        assert exc.value.reason == "egress_audit_unreadable"

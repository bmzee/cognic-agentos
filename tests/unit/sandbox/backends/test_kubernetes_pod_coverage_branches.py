# ruff: noqa: SIM117
# The nested ``with patch.object(...): / with pytest.raises(...) as exc:``
# pattern is intentional throughout this file — separates the mock
# context-manager group (multiple parallel patches) from the
# raise-assertion group (which inspects the raised exception via
# ``exc``). Combining all into one ``with (..., pytest.raises(...)
# as exc)`` makes the assertion target syntactically muddier without
# improving readability for mock-heavy tests.
"""Sprint 8B T8B-d — KubernetesPodSandboxBackend coverage repair.

NON-env-gated focused regressions closing missing lines + branches
on ``src/cognic_agentos/sandbox/backends/kubernetes_pod.py`` per the
T8B-d 95% line / 90% branch coverage floor.

Mirrors the Sprint-8A T12-coverage-repair pattern (commit ``be356f1``)
which closed the same gap class on ``warm_pool.py`` + ``docker_sibling.py``.
Per the user-locked tightening edit B from Sprint 8B preflight
(2026-05-17): coverage gate promotion requires the actual gate to
pass with fresh coverage — NOT just the ``_EXPECTED_ENTRY_COUNT``
count-guard bump. Per ``feedback_strict_review_off_gate``:
"coverage gap is test-suite incompleteness, NOT off-gate justification."
DO NOT lower the floor; DO NOT demote the module.

The env-gated lifecycle/resource-cap integration tests cover the
end-to-end paths on a real K8s cluster (``COGNIC_RUN_K8S_SANDBOX=1``);
this file uses mocked ``kubernetes-asyncio`` clients to drive the
same code paths in unit-only CI.

Every test names the production branch it covers + the doctrine
that branch implements.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("kubernetes_asyncio")

from datetime import UTC, datetime

from kubernetes_asyncio.client import ApiException

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends._shared_exec import (
    _ProxyLogReadFailure,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _PROXY_SIDECAR_CONTAINER_NAME,
    _SANDBOX_CONTAINER_NAME,
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
)
from cognic_agentos.sandbox.protocol import (
    SandboxBackendHealth,
    SandboxPolicyViolated,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_POLICY_NO_BUDGET = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_POLICY_WITH_BUDGET = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=0.1,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test",
    pack_version="v1",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)
_ACTOR = Actor(
    subject="test-actor",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="service",
)


def _make_backend(
    *,
    kube_api_client: Any = None,
    catalog: Any = None,
) -> KubernetesPodSandboxBackend:
    """Construct a KubernetesPodSandboxBackend with mocked deps."""
    if kube_api_client is None:
        kube_api_client = MagicMock()
        kube_api_client.configuration = MagicMock()
    if catalog is None:
        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.is_tenant_allow_listed.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock()
        catalog.verify_sbom_policy_or_refuse = AsyncMock()
    rego = AsyncMock()
    decision = MagicMock()
    decision.allow = True
    decision.reasoning = ""
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )
    return KubernetesPodSandboxBackend(
        kube_api_client=kube_api_client,
        namespace="test-ns",
        image_catalog=catalog,
        credential_adapter=MagicMock(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=AsyncMock(),
        settings=settings,
    )


def _make_session(*, policy: SandboxPolicy = _POLICY_NO_BUDGET) -> KubernetesPodSession:
    """Construct a minimal KubernetesPodSession for exec/destroy tests."""
    return KubernetesPodSession(
        session_id="s-1",
        tenant_id="t-1",
        policy=policy,
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=MagicMock(),
        _pod_name="sandbox-s-1",
        _network_policy_name="sandbox-policy-s-1",
        _namespace="test-ns",
        _actor_subject="test-actor",
    )


# ---------------------------------------------------------------------------
# TestExecBody — drives the exec() method body
# ---------------------------------------------------------------------------


class TestExecBodyHappyPath:
    """kubernetes_pod.py:691-917 — exec() green path.

    Covers stream consumption → OOM check → classify (None) → proxy_log
    readback (empty) → lifecycle.exec_completed emission → SandboxExecResult.
    """

    @pytest.mark.asyncio
    async def test_exec_returns_result_on_green_path(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(
                backend, "_open_pod_exec_stream", AsyncMock(return_value=(b"out", b"err", 0))
            ),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(backend, "_read_proxy_log_from_sidecar_k8s", AsyncMock(return_value=())),
            patch.object(backend, "_emit_lifecycle_exec_completed", AsyncMock()),
        ):
            result = await backend.exec(session, ["echo", "ok"])
        assert result.stdout == b"out"
        assert result.stderr == b"err"
        assert result.exit_code == 0
        assert result.proxy_log == ()


class TestExecBodyClassifications:
    """kubernetes_pod.py:691-917 — exec() body cap-violation paths."""

    @pytest.mark.asyncio
    async def test_exec_walltime_cap_raises_policy_violated(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(backend, "_open_pod_exec_stream", AsyncMock(side_effect=TimeoutError())),
            patch.object(backend, "_kill_pod_or_raise", AsyncMock()),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(backend, "_emit_policy_violated", AsyncMock()) as emit,
        ):
            with pytest.raises(SandboxPolicyViolated) as exc:
                await backend.exec(session, ["sleep", "60"])
        assert exc.value.reason == "walltime_cap_exceeded"
        emit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exec_oom_killed_raises_memory_cap_exceeded(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(backend, "_open_pod_exec_stream", AsyncMock(return_value=(b"", b"", 137))),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=True)),
            patch.object(backend, "_emit_policy_violated", AsyncMock()),
        ):
            with pytest.raises(SandboxPolicyViolated) as exc:
                await backend.exec(session, ["malloc-bomb"])
        assert exc.value.reason == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_exec_cpu_budget_exceeded_raises(self) -> None:
        """Cpu-budget monitor sets the event; classify routes to
        cpu_time_budget_exceeded. The monitor + stream mocks both
        ``await asyncio.sleep(0)`` to yield control to the event loop
        so the monitor task gets a chance to run + set the event
        BEFORE exec()'s post-stream event check at line 791.
        """
        backend = _make_backend()
        session = _make_session(policy=_POLICY_WITH_BUDGET)

        async def _monitor_sets_event_immediately(*, cpu_violated_event, **_kw):
            # Yield to event loop so test_exec_cpu_budget_exceeded_raises
            # can be interleaved deterministically.
            await asyncio.sleep(0)
            cpu_violated_event.set()

        async def _stream_yields_then_returns(**_kw):
            # Give monitor task a chance to run + set the event before
            # exec() reads it.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return (b"", b"", 0)

        with (
            patch.object(
                backend,
                "_cpu_time_budget_monitor_k8s",
                AsyncMock(side_effect=_monitor_sets_event_immediately),
            ),
            patch.object(
                backend,
                "_open_pod_exec_stream",
                AsyncMock(side_effect=_stream_yields_then_returns),
            ),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(backend, "_emit_policy_violated", AsyncMock()),
        ):
            with pytest.raises(SandboxPolicyViolated) as exc:
                await backend.exec(session, ["cpu-spin"])
        assert exc.value.reason == "cpu_time_budget_exceeded"


class TestExecBodyProxyLogReadFailure:
    """kubernetes_pod.py:840-857 — fail-closed contract for proxy-log
    readback failure surfaces ``egress_audit_unreadable`` violation
    (T8B-c R1; mirrors docker_sibling T10c R1 P1.2 wire-protocol-public
    contract). Missing this would ship a silent egress-bypass class.
    """

    @pytest.mark.asyncio
    async def test_proxy_log_read_failure_surfaces_egress_audit_unreadable(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(backend, "_open_pod_exec_stream", AsyncMock(return_value=(b"", b"", 0))),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(
                backend,
                "_read_proxy_log_from_sidecar_k8s",
                AsyncMock(side_effect=_ProxyLogReadFailure("sidecar gone")),
            ),
            patch.object(backend, "_emit_policy_violated", AsyncMock()) as emit,
        ):
            with pytest.raises(SandboxPolicyViolated) as exc:
                await backend.exec(session, ["echo", "ok"])
        assert exc.value.reason == "egress_audit_unreadable"
        emit.assert_awaited_once()


class TestExecBodyEgressRefusal:
    """kubernetes_pod.py:870-882 — proxy_log carries a 'refused' record
    → ``_classify_egress_refusal`` returns matching violation reason
    → ``SandboxPolicyViolated`` raised + policy.violated audit emit.
    """

    @pytest.mark.asyncio
    async def test_egress_refusal_in_proxy_log_raises(self) -> None:
        from cognic_agentos.sandbox.protocol import ProxyAccessRecord

        refused_record = ProxyAccessRecord(
            host="forbidden.example.com",
            method="GET",
            timestamp=datetime.now(UTC),
            policy_id="t-1/policy-1",
            outcome="refused",
            refusal_reason="not_in_allow_list",
        )
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(backend, "_open_pod_exec_stream", AsyncMock(return_value=(b"", b"", 0))),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(
                backend,
                "_read_proxy_log_from_sidecar_k8s",
                AsyncMock(return_value=(refused_record,)),
            ),
            patch.object(backend, "_emit_policy_violated", AsyncMock()) as emit,
        ):
            with pytest.raises(SandboxPolicyViolated) as exc:
                await backend.exec(session, ["curl", "forbidden.example.com"])
        assert exc.value.reason == "egress_host_not_allow_listed"
        emit.assert_awaited_once()


class TestExecBodyMonitorTaskPropagation:
    """kubernetes_pod.py:908-917 — when body completes successfully but
    the monitor task fails, the monitor exception MUST propagate so
    caller knows cap enforcement was unverified (R3 P1 parity with
    docker_sibling).
    """

    @pytest.mark.asyncio
    async def test_monitor_task_exception_propagates_when_body_green(self) -> None:
        backend = _make_backend()
        session = _make_session(policy=_POLICY_WITH_BUDGET)

        async def _monitor_raises(*_a, **_kw):
            # Yield once so the task is actually scheduled + the
            # exception is observable on the awaited task in the
            # finally block.
            await asyncio.sleep(0)
            raise RuntimeError("kill failed")

        async def _stream_yields_then_returns(**_kw):
            # Multi-yield so the monitor task can run + raise before
            # the body completes + the finally block awaits the task.
            for _ in range(3):
                await asyncio.sleep(0)
            return (b"", b"", 0)

        with (
            patch.object(
                backend,
                "_cpu_time_budget_monitor_k8s",
                AsyncMock(side_effect=_monitor_raises),
            ),
            patch.object(
                backend,
                "_open_pod_exec_stream",
                AsyncMock(side_effect=_stream_yields_then_returns),
            ),
            patch.object(backend, "_read_pod_oom_killed", AsyncMock(return_value=False)),
            patch.object(backend, "_read_proxy_log_from_sidecar_k8s", AsyncMock(return_value=())),
            patch.object(backend, "_emit_lifecycle_exec_completed", AsyncMock()),
        ):
            with pytest.raises(RuntimeError, match="kill failed"):
                await backend.exec(session, ["echo", "ok"])


class TestExecRejectsForeignSession:
    """kubernetes_pod.py:731-735 — exec() rejects non-KubernetesPodSession."""

    @pytest.mark.asyncio
    async def test_exec_raises_type_error_on_foreign_session(self) -> None:
        backend = _make_backend()
        with pytest.raises(TypeError, match=r"KubernetesPodSandboxBackend\.exec expects"):
            await backend.exec(MagicMock(name="ForeignSession"), ["echo"])


# ---------------------------------------------------------------------------
# TestCpuMonitorBody — drives _cpu_time_budget_monitor_k8s
# ---------------------------------------------------------------------------


class TestCpuMonitorBody:
    """kubernetes_pod.py:1341-1400 — _cpu_time_budget_monitor_k8s."""

    @pytest.mark.asyncio
    async def test_monitor_kills_pod_and_sets_event_on_overage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Budget=0.0001s; cgroup reads 10ms (10_000_000ns) > 100_000ns
        budget → kill + set event."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        backend = _make_backend()
        event = asyncio.Event()
        with (
            patch.object(backend, "_read_cpu_usage_ns", AsyncMock(return_value=10_000_000)),
            patch.object(backend, "_kill_pod_or_raise", AsyncMock()) as kill,
        ):
            await backend._cpu_time_budget_monitor_k8s(
                pod_name="p", container_name="sandbox", budget_s=0.0001, cpu_violated_event=event
            )
        assert event.is_set()
        kill.assert_awaited_once_with("p")

    @pytest.mark.asyncio
    async def test_monitor_continues_polling_on_none_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Transient None reading → continue polling; next valid reading
        triggers the budget check."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        backend = _make_backend()
        event = asyncio.Event()
        with (
            patch.object(
                backend,
                "_read_cpu_usage_ns",
                AsyncMock(side_effect=[None, 999_999_999_999]),
            ),
            patch.object(backend, "_kill_pod_or_raise", AsyncMock()),
        ):
            await backend._cpu_time_budget_monitor_k8s(
                pod_name="p", container_name="sandbox", budget_s=0.0001, cpu_violated_event=event
            )
        assert event.is_set()

    @pytest.mark.asyncio
    async def test_monitor_re_raises_cancelled_error(self) -> None:
        backend = _make_backend()
        event = asyncio.Event()
        with (
            patch.object(
                backend, "_read_cpu_usage_ns", AsyncMock(side_effect=asyncio.CancelledError())
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await backend._cpu_time_budget_monitor_k8s(
                pod_name="p",
                container_name="sandbox",
                budget_s=0.0001,
                cpu_violated_event=event,
            )
        assert not event.is_set()

    @pytest.mark.asyncio
    async def test_monitor_continues_when_read_raises_generic_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Generic exception during _read_cpu_usage_ns → treated as
        transient (continue polling) per the best-effort contract."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        backend = _make_backend()
        event = asyncio.Event()
        with (
            patch.object(
                backend,
                "_read_cpu_usage_ns",
                AsyncMock(side_effect=[RuntimeError("transient"), 999_999_999_999]),
            ),
            patch.object(backend, "_kill_pod_or_raise", AsyncMock()),
        ):
            await backend._cpu_time_budget_monitor_k8s(
                pod_name="p", container_name="sandbox", budget_s=0.0001, cpu_violated_event=event
            )
        assert event.is_set()


# ---------------------------------------------------------------------------
# TestReadPodOomKilled — drives _read_pod_oom_killed
# ---------------------------------------------------------------------------


def _make_container_status(
    *,
    name: str,
    state_reason: str | None = None,
    last_state_reason: str | None = None,
) -> MagicMock:
    cs = MagicMock()
    cs.name = name
    state = MagicMock()
    if state_reason is not None:
        state.terminated = MagicMock(reason=state_reason)
    else:
        state.terminated = None
    cs.state = state
    last_state = MagicMock()
    if last_state_reason is not None:
        last_state.terminated = MagicMock(reason=last_state_reason)
    else:
        last_state.terminated = None
    cs.last_state = last_state
    return cs


class TestReadPodOomKilled:
    """kubernetes_pod.py:1197-1245 — _read_pod_oom_killed."""

    @pytest.mark.asyncio
    async def test_returns_true_when_state_terminated_reason_is_oom(self) -> None:
        backend = _make_backend()
        cs = _make_container_status(name=_SANDBOX_CONTAINER_NAME, state_reason="OOMKilled")
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_when_last_state_terminated_reason_is_oom(self) -> None:
        backend = _make_backend()
        cs = _make_container_status(name=_SANDBOX_CONTAINER_NAME, last_state_reason="OOMKilled")
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_no_oom_signal(self) -> None:
        backend = _make_backend()
        cs = _make_container_status(name=_SANDBOX_CONTAINER_NAME, state_reason="Completed")
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_api_exception(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(
                read_namespaced_pod_status=AsyncMock(
                    side_effect=ApiException(status=500, reason="err")
                )
            ),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False

    @pytest.mark.asyncio
    async def test_skips_non_sandbox_container_statuses(self) -> None:
        backend = _make_backend()
        # Proxy sidecar with OOMKilled — must be SKIPPED (not the sandbox)
        cs = _make_container_status(name="egress-proxy", state_reason="OOMKilled")
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False  # sandbox container's OOM not the proxy's

    @pytest.mark.asyncio
    async def test_returns_false_on_empty_container_statuses(self) -> None:
        backend = _make_backend()
        pod = MagicMock()
        pod.status.container_statuses = None
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False


# ---------------------------------------------------------------------------
# TestReadCpuUsageNs — drives _read_cpu_usage_ns (cgroup v2 + v1)
# ---------------------------------------------------------------------------


class TestReadCpuUsageNs:
    """kubernetes_pod.py:1247-1305 — _read_cpu_usage_ns cgroup probing."""

    @pytest.mark.asyncio
    async def test_returns_cgroup_v2_usage_when_present(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(return_value=(b"usage_usec 12345\nuser_usec 11000\n", 0)),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        # 12345 us * 1000 = 12_345_000 ns
        assert usage_ns == 12_345_000

    @pytest.mark.asyncio
    async def test_falls_back_to_cgroup_v1_when_v2_missing(self) -> None:
        backend = _make_backend()
        # v2 attempt: stat file exists but no usage_usec line → fall through
        # v1 attempt: cumulative ns int
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(side_effect=[(b"", 1), (b"987654321\n", 0)]),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns == 987_654_321

    @pytest.mark.asyncio
    async def test_returns_none_when_both_cgroup_paths_fail(self) -> None:
        backend = _make_backend()
        with patch.object(backend, "_exec_short_lived", AsyncMock(return_value=None)):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns is None

    @pytest.mark.asyncio
    async def test_returns_none_when_v2_usage_usec_not_int(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(return_value=(b"usage_usec NOT_AN_INT\n", 0)),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns is None

    @pytest.mark.asyncio
    async def test_returns_none_when_v1_value_not_int(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(side_effect=[(b"", 1), (b"not-an-int\n", 0)]),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns is None


# ---------------------------------------------------------------------------
# TestExecShortLived — drives _exec_short_lived
# ---------------------------------------------------------------------------


class TestExecShortLived:
    """kubernetes_pod.py:1307-1339 — _exec_short_lived best-effort wrapper."""

    @pytest.mark.asyncio
    async def test_returns_stdout_and_exit_on_success(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_open_pod_exec_stream",
            AsyncMock(return_value=(b"hello", b"", 0)),
        ):
            result = await backend._exec_short_lived(
                pod_name="p", container_name="sandbox", command=["echo", "hello"]
            )
        assert result == (b"hello", 0)

    @pytest.mark.asyncio
    async def test_returns_none_on_api_exception(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_open_pod_exec_stream",
            AsyncMock(side_effect=ApiException(status=500, reason="err")),
        ):
            result = await backend._exec_short_lived(
                pod_name="p", container_name="sandbox", command=["echo"]
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout_error(self) -> None:
        backend = _make_backend()
        with patch.object(backend, "_open_pod_exec_stream", AsyncMock(side_effect=TimeoutError())):
            result = await backend._exec_short_lived(
                pod_name="p", container_name="sandbox", command=["echo"]
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_unexpected_exception(self) -> None:
        backend = _make_backend()
        with patch.object(
            backend,
            "_open_pod_exec_stream",
            AsyncMock(side_effect=RuntimeError("transient")),
        ):
            result = await backend._exec_short_lived(
                pod_name="p", container_name="sandbox", command=["echo"]
            )
        assert result is None


# ---------------------------------------------------------------------------
# TestKillPodOrRaise — drives _kill_pod_or_raise (fail-closed)
# ---------------------------------------------------------------------------


class TestKillPodOrRaise:
    """kubernetes_pod.py:1171-1196 — _kill_pod_or_raise fail-closed contract."""

    @pytest.mark.asyncio
    async def test_swallows_api_exception_404_as_benign(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(
                delete_namespaced_pod=AsyncMock(
                    side_effect=ApiException(status=404, reason="not found")
                )
            ),
        ):
            await backend._kill_pod_or_raise("ghost")  # no raise

    @pytest.mark.asyncio
    async def test_re_raises_non_404_api_exception(self) -> None:
        backend = _make_backend()
        with (
            patch(
                "kubernetes_asyncio.client.CoreV1Api",
                return_value=MagicMock(
                    delete_namespaced_pod=AsyncMock(
                        side_effect=ApiException(status=500, reason="boom")
                    )
                ),
            ),
            pytest.raises(ApiException) as exc,
        ):
            await backend._kill_pod_or_raise("flaky")
        assert exc.value.status == 500


# ---------------------------------------------------------------------------
# TestReadProxyLogFromSidecar — drives _read_proxy_log_from_sidecar_k8s
# ---------------------------------------------------------------------------


class TestReadProxyLogFromSidecar:
    """kubernetes_pod.py:1402-1465 — _read_proxy_log_from_sidecar_k8s
    fail-closed contract (T8B-c R1; mirrors docker_sibling T10c R1 P1.2).
    """

    @pytest.mark.asyncio
    async def test_returns_empty_tuple_on_zero_exit_empty_stdout(self) -> None:
        backend = _make_backend()
        with patch.object(backend, "_exec_short_lived", AsyncMock(return_value=(b"", 0))):
            result = await backend._read_proxy_log_from_sidecar_k8s(
                pod_name="p", sidecar_container_name=_PROXY_SIDECAR_CONTAINER_NAME
            )
        assert result == ()

    @pytest.mark.asyncio
    async def test_raises_when_exec_short_lived_returns_none(self) -> None:
        backend = _make_backend()
        with patch.object(backend, "_exec_short_lived", AsyncMock(return_value=None)):
            with pytest.raises(_ProxyLogReadFailure, match="unreachable"):
                await backend._read_proxy_log_from_sidecar_k8s(
                    pod_name="p", sidecar_container_name=_PROXY_SIDECAR_CONTAINER_NAME
                )

    @pytest.mark.asyncio
    async def test_raises_when_cat_exits_nonzero(self) -> None:
        backend = _make_backend()
        with (
            patch.object(backend, "_exec_short_lived", AsyncMock(return_value=(b"", 1))),
            pytest.raises(_ProxyLogReadFailure, match="exited 1"),
        ):
            await backend._read_proxy_log_from_sidecar_k8s(
                pod_name="p", sidecar_container_name=_PROXY_SIDECAR_CONTAINER_NAME
            )

    @pytest.mark.asyncio
    async def test_raises_on_unexpected_exec_short_lived_exception(self) -> None:
        backend = _make_backend()
        with (
            patch.object(
                backend,
                "_exec_short_lived",
                AsyncMock(side_effect=RuntimeError("socket reset")),
            ),
            pytest.raises(_ProxyLogReadFailure, match="unexpected error"),
        ):
            await backend._read_proxy_log_from_sidecar_k8s(
                pod_name="p", sidecar_container_name=_PROXY_SIDECAR_CONTAINER_NAME
            )


# ---------------------------------------------------------------------------
# TestK8sObjectLifecycle — _create_network_policy + _create_pod
# ---------------------------------------------------------------------------


class TestK8sObjectLifecycle:
    """kubernetes_pod.py:980-1019 — direct K8s API call helpers."""

    @pytest.mark.asyncio
    async def test_create_network_policy_calls_networking_api(self) -> None:
        backend = _make_backend()
        api_mock = MagicMock()
        api_mock.create_namespaced_network_policy = AsyncMock()
        with patch("kubernetes_asyncio.client.NetworkingV1Api", return_value=api_mock):
            await backend._create_network_policy({"metadata": {"name": "p1"}})
        api_mock.create_namespaced_network_policy.assert_awaited_once_with(
            namespace="test-ns", body={"metadata": {"name": "p1"}}
        )

    @pytest.mark.asyncio
    async def test_create_pod_calls_core_api(self) -> None:
        backend = _make_backend()
        api_mock = MagicMock()
        api_mock.create_namespaced_pod = AsyncMock()
        with patch("kubernetes_asyncio.client.CoreV1Api", return_value=api_mock):
            await backend._create_pod({"metadata": {"name": "p1"}})
        api_mock.create_namespaced_pod.assert_awaited_once_with(
            namespace="test-ns", body={"metadata": {"name": "p1"}}
        )


class TestDeleteHelpersIdempotency:
    """kubernetes_pod.py:1044-1062 — _delete_pod_if_exists +
    _delete_network_policy_if_exists swallow 404 / re-raise non-404.
    """

    @pytest.mark.asyncio
    async def test_delete_pod_swallows_404(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(
                delete_namespaced_pod=AsyncMock(side_effect=ApiException(status=404, reason="gone"))
            ),
        ):
            await backend._delete_pod_if_exists("ghost")

    @pytest.mark.asyncio
    async def test_delete_pod_reraises_non_404(self) -> None:
        backend = _make_backend()
        with (
            patch(
                "kubernetes_asyncio.client.CoreV1Api",
                return_value=MagicMock(
                    delete_namespaced_pod=AsyncMock(
                        side_effect=ApiException(status=500, reason="boom")
                    )
                ),
            ),
            pytest.raises(ApiException),
        ):
            await backend._delete_pod_if_exists("flaky")

    @pytest.mark.asyncio
    async def test_delete_network_policy_swallows_404(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.NetworkingV1Api",
            return_value=MagicMock(
                delete_namespaced_network_policy=AsyncMock(
                    side_effect=ApiException(status=404, reason="gone")
                )
            ),
        ):
            await backend._delete_network_policy_if_exists("ghost")

    @pytest.mark.asyncio
    async def test_delete_network_policy_reraises_non_404(self) -> None:
        backend = _make_backend()
        with (
            patch(
                "kubernetes_asyncio.client.NetworkingV1Api",
                return_value=MagicMock(
                    delete_namespaced_network_policy=AsyncMock(
                        side_effect=ApiException(status=500, reason="boom")
                    )
                ),
            ),
            pytest.raises(ApiException),
        ):
            await backend._delete_network_policy_if_exists("flaky")


# ---------------------------------------------------------------------------
# TestHealth — drives health() probe
# ---------------------------------------------------------------------------


class TestHealth:
    """kubernetes_pod.py:953-974 — health() probe."""

    @pytest.mark.asyncio
    async def test_health_returns_ok_when_api_responds(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(list_namespaced_pod=AsyncMock(return_value=MagicMock())),
        ):
            health = await backend.health()
        assert isinstance(health, SandboxBackendHealth)
        assert health.status == "ok"

    @pytest.mark.asyncio
    async def test_health_returns_unavailable_on_api_exception(self) -> None:
        backend = _make_backend()
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(
                list_namespaced_pod=AsyncMock(
                    side_effect=ApiException(status=500, reason="connection refused")
                )
            ),
        ):
            health = await backend.health()
        assert health.status == "unavailable"
        assert "k8s apiserver unreachable" in health.detail


# ---------------------------------------------------------------------------
# TestDestroyAndIdempotency — destroy() body + emission-once
# ---------------------------------------------------------------------------


class TestDestroyAndIdempotency:
    """kubernetes_pod.py:919-951 — destroy() body."""

    @pytest.mark.asyncio
    async def test_destroy_raises_type_error_on_foreign_session(self) -> None:
        backend = _make_backend()
        with pytest.raises(TypeError, match=r"KubernetesPodSandboxBackend\.destroy expects"):
            await backend.destroy(MagicMock(name="ForeignSession"))

    @pytest.mark.asyncio
    async def test_destroy_emits_lifecycle_destroyed_first_call_only(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with (
            patch.object(backend, "_teardown_session_state", AsyncMock()),
            patch.object(backend, "_emit_lifecycle_destroyed", AsyncMock()) as emit,
        ):
            await backend.destroy(session)
            await backend.destroy(session)
        emit.assert_awaited_once()  # second call is idempotent — no second emit


# ---------------------------------------------------------------------------
# TestOpenPodExecStream — drives _open_pod_exec_stream
# ---------------------------------------------------------------------------


class _FakeWsMessage:
    """Mock for aiohttp.WSMessage."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class _FakeWsCtx:
    """Mock for the _WSRequestContextManager async-with target."""

    def __init__(self, messages: list[_FakeWsMessage]) -> None:
        self._messages = messages

    async def __aenter__(self) -> _FakeWsCtx:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    def __aiter__(self) -> _FakeWsCtx:
        self._iter = iter(self._messages)
        return self

    async def __anext__(self) -> _FakeWsMessage:
        try:
            return next(self._iter)
        except StopIteration as e:
            raise StopAsyncIteration from e


class _FakeAwaitableWsCtx:
    """Mock for the connect_get_namespaced_pod_exec return value.

    Returns a callable that when awaited yields a _FakeWsCtx — mimics
    the `await ws_ctx` then `async with` pattern at kubernetes_pod.py:1134.
    """

    def __init__(self, messages: list[_FakeWsMessage]) -> None:
        self._messages = messages

    def __await__(self):
        async def _resolve() -> _FakeWsCtx:
            return _FakeWsCtx(self._messages)

        return _resolve().__await__()


class TestOpenPodExecStream:
    """kubernetes_pod.py:1069-1170 — _open_pod_exec_stream wraps the K8s
    pods/exec websocket + parses the multiplexed channel format
    (STDOUT=1, STDERR=2, ERROR=3)."""

    @pytest.mark.asyncio
    async def test_parses_stdout_stderr_and_error_channels(self) -> None:
        backend = _make_backend()
        # Channel-prefixed: 0x01=stdout, 0x02=stderr, 0x03=error
        messages = [
            _FakeWsMessage(b"\x01" + b"out1"),
            _FakeWsMessage(b"\x02" + b"err1"),
            # Error channel carries a JSON document — WsApiClient.parse_error_data
            # returns the exit_code int. We use a known-good JSON shape.
            _FakeWsMessage(
                b"\x03"
                + json.dumps(
                    {
                        "status": "Failure",
                        "reason": "NonZeroExitCode",
                        "details": {"causes": [{"reason": "ExitCode", "message": "42"}]},
                    }
                ).encode("utf-8")
            ),
            _FakeWsMessage(b""),  # empty payload — skip
        ]

        mock_ws_api = MagicMock()
        mock_ws_api.connect_get_namespaced_pod_exec = MagicMock(
            return_value=_FakeAwaitableWsCtx(messages)
        )

        mock_ws_client = MagicMock()
        mock_ws_client.close = AsyncMock()
        # Patch as a callable that returns the mock instance, but keep
        # the real WsApiClient.parse_error_data static method accessible
        # (production code at kubernetes_pod.py:1147 calls it as a class
        # static method, NOT via the instance).
        from kubernetes_asyncio.stream import WsApiClient as _RealWsApiClient

        patched_ws = MagicMock(side_effect=lambda **_k: mock_ws_client)
        patched_ws.parse_error_data = _RealWsApiClient.parse_error_data
        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.WsApiClient",
                patched_ws,
            ),
            patch(
                "kubernetes_asyncio.client.CoreV1Api",
                return_value=mock_ws_api,
            ),
        ):
            stdout, stderr, exit_code = await backend._open_pod_exec_stream(
                pod_name="p",
                container_name="sandbox",
                command=["echo", "x"],
                walltime_s=5.0,
            )
        assert stdout == b"out1"
        assert stderr == b"err1"
        assert exit_code == 42

    @pytest.mark.asyncio
    async def test_malformed_error_channel_sets_exit_minus_one(self) -> None:
        backend = _make_backend()
        # Channel 3 with non-JSON payload — should set exit_code to -1
        messages = [
            _FakeWsMessage(b"\x03" + b"not-json-at-all"),
        ]
        mock_ws_api = MagicMock()
        mock_ws_api.connect_get_namespaced_pod_exec = MagicMock(
            return_value=_FakeAwaitableWsCtx(messages)
        )
        mock_ws_client = MagicMock()
        mock_ws_client.close = AsyncMock()
        # Patch as a callable that returns the mock instance, but keep
        # the real WsApiClient.parse_error_data static method accessible
        # (production code at kubernetes_pod.py:1147 calls it as a class
        # static method, NOT via the instance).
        from kubernetes_asyncio.stream import WsApiClient as _RealWsApiClient

        patched_ws = MagicMock(side_effect=lambda **_k: mock_ws_client)
        patched_ws.parse_error_data = _RealWsApiClient.parse_error_data
        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.WsApiClient",
                patched_ws,
            ),
            patch("kubernetes_asyncio.client.CoreV1Api", return_value=mock_ws_api),
        ):
            _stdout, _stderr, exit_code = await backend._open_pod_exec_stream(
                pod_name="p", container_name="sandbox", command=["x"], walltime_s=5.0
            )
        assert exit_code == -1

    @pytest.mark.asyncio
    async def test_ignores_unknown_channels(self) -> None:
        backend = _make_backend()
        messages = [
            _FakeWsMessage(b"\x05" + b"unknown-channel-payload"),
            _FakeWsMessage(b"\x01" + b"stdout"),
        ]
        mock_ws_api = MagicMock()
        mock_ws_api.connect_get_namespaced_pod_exec = MagicMock(
            return_value=_FakeAwaitableWsCtx(messages)
        )
        mock_ws_client = MagicMock()
        mock_ws_client.close = AsyncMock()
        # Patch as a callable that returns the mock instance, but keep
        # the real WsApiClient.parse_error_data static method accessible
        # (production code at kubernetes_pod.py:1147 calls it as a class
        # static method, NOT via the instance).
        from kubernetes_asyncio.stream import WsApiClient as _RealWsApiClient

        patched_ws = MagicMock(side_effect=lambda **_k: mock_ws_client)
        patched_ws.parse_error_data = _RealWsApiClient.parse_error_data
        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.WsApiClient",
                patched_ws,
            ),
            patch("kubernetes_asyncio.client.CoreV1Api", return_value=mock_ws_api),
        ):
            stdout, _stderr, _exit = await backend._open_pod_exec_stream(
                pod_name="p", container_name="sandbox", command=["x"], walltime_s=5.0
            )
        assert stdout == b"stdout"

    @pytest.mark.asyncio
    async def test_closes_ws_client_in_finally(self) -> None:
        backend = _make_backend()
        mock_ws_api = MagicMock()
        mock_ws_api.connect_get_namespaced_pod_exec = MagicMock(
            return_value=_FakeAwaitableWsCtx([])
        )
        mock_ws_client = MagicMock()
        mock_ws_client.close = AsyncMock()
        # Patch as a callable that returns the mock instance, but keep
        # the real WsApiClient.parse_error_data static method accessible
        # (production code at kubernetes_pod.py:1147 calls it as a class
        # static method, NOT via the instance).
        from kubernetes_asyncio.stream import WsApiClient as _RealWsApiClient

        patched_ws = MagicMock(side_effect=lambda **_k: mock_ws_client)
        patched_ws.parse_error_data = _RealWsApiClient.parse_error_data
        with (
            patch(
                "cognic_agentos.sandbox.backends.kubernetes_pod.WsApiClient",
                patched_ws,
            ),
            patch("kubernetes_asyncio.client.CoreV1Api", return_value=mock_ws_api),
        ):
            await backend._open_pod_exec_stream(
                pod_name="p", container_name="sandbox", command=["x"], walltime_s=5.0
            )
        mock_ws_client.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# Round 2 — close remaining gaps for 95/90 floor
# ---------------------------------------------------------------------------


class TestSessionDelegationMethods:
    """kubernetes_pod.py:481, 484 — KubernetesPodSession.exec /
    KubernetesPodSession.destroy delegate to the backend (mirror of
    docker_sibling's DockerSiblingSession pattern)."""

    @pytest.mark.asyncio
    async def test_session_exec_delegates_to_backend(self) -> None:
        backend_mock = AsyncMock()
        backend_mock.exec = AsyncMock(return_value=MagicMock(name="SandboxExecResult"))
        session = KubernetesPodSession(
            session_id="s-1",
            tenant_id="t-1",
            policy=_POLICY_NO_BUDGET,
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend_mock,
            _pod_name="sb-s-1",
            _network_policy_name="np-s-1",
            _namespace="test-ns",
            _actor_subject="test",
        )
        await session.exec(["echo", "ok"], timeout_s=5.0)
        backend_mock.exec.assert_awaited_once_with(session, ["echo", "ok"], timeout_s=5.0)

    @pytest.mark.asyncio
    async def test_session_destroy_delegates_to_backend(self) -> None:
        backend_mock = AsyncMock()
        backend_mock.destroy = AsyncMock()
        session = KubernetesPodSession(
            session_id="s-1",
            tenant_id="t-1",
            policy=_POLICY_NO_BUDGET,
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend_mock,
            _pod_name="sb-s-1",
            _network_policy_name="np-s-1",
            _namespace="test-ns",
            _actor_subject="test",
        )
        await session.destroy()
        backend_mock.destroy.assert_awaited_once_with(session)


class TestCreateWarmPoolBranches:
    """kubernetes_pod.py:577-600 — create() warm-pool checkout +
    audit-cleanup envelope."""

    @pytest.mark.asyncio
    async def test_create_returns_warm_session_when_pool_hit(self) -> None:
        backend = _make_backend()
        warm = _make_session()
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=warm)
        backend._warm_pool = warm_pool
        with patch.object(backend, "_emit_lifecycle_created", AsyncMock()) as emit:
            result = await backend.create(
                _POLICY_NO_BUDGET,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=True,
            )
        assert result is warm
        emit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_destroys_warm_session_on_audit_failure(self) -> None:
        backend = _make_backend()
        warm = _make_session()
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=warm)
        backend._warm_pool = warm_pool
        with (
            patch.object(
                backend,
                "_emit_lifecycle_created",
                AsyncMock(side_effect=RuntimeError("audit blip")),
            ),
            patch.object(backend, "destroy", AsyncMock()) as destroy_mock,
        ):
            with pytest.raises(RuntimeError, match="audit blip"):
                await backend.create(
                    _POLICY_NO_BUDGET,
                    actor=_ACTOR,
                    tenant_id="t-1",
                    pack_context=_PACK_CTX,
                    use_warm_pool=True,
                )
        destroy_mock.assert_awaited_once_with(warm)


class TestEmitLifecycleHelpers:
    """kubernetes_pod.py:1493, 1522-1523, 1603 — audit emission helpers."""

    @pytest.mark.asyncio
    async def test_emit_lifecycle_created_calls_emit_sandbox_event(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.emit_sandbox_event",
            AsyncMock(),
        ) as mock_emit:
            await backend._emit_lifecycle_created(
                session=session, actor=_ACTOR, warm_pool_hit=False
            )
        mock_emit.assert_awaited_once()
        assert mock_emit.await_args is not None
        kwargs = mock_emit.await_args.kwargs
        assert kwargs["event"] == "sandbox.lifecycle.created"
        assert kwargs["payload"] == {"warm_pool_hit": False}

    @pytest.mark.asyncio
    async def test_emit_lifecycle_destroyed_carries_duration_s(self) -> None:
        backend = _make_backend()
        session = _make_session()
        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.emit_sandbox_event",
            AsyncMock(),
        ) as mock_emit:
            await backend._emit_lifecycle_destroyed(session=session)
        mock_emit.assert_awaited_once()
        assert mock_emit.await_args is not None
        payload = mock_emit.await_args.kwargs["payload"]
        assert "duration_s" in payload
        assert isinstance(payload["duration_s"], float)

    @pytest.mark.asyncio
    async def test_emit_policy_violated_includes_proxy_log_when_non_empty(self) -> None:
        from cognic_agentos.sandbox.protocol import ProxyAccessRecord

        backend = _make_backend()
        session = _make_session()
        record = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime.now(UTC),
            policy_id="p1",
            outcome="refused",
            refusal_reason="not_in_allow_list",
        )
        with patch(
            "cognic_agentos.sandbox.backends.kubernetes_pod.emit_sandbox_event",
            AsyncMock(),
        ) as mock_emit:
            await backend._emit_policy_violated(
                session=session,
                reason="egress_host_not_allow_listed",
                proxy_log=(record,),
            )
        assert mock_emit.await_args is not None
        payload = mock_emit.await_args.kwargs["payload"]
        assert payload["reason"] == "egress_host_not_allow_listed"
        assert "proxy_log" in payload
        assert len(payload["proxy_log"]) == 1


class TestReadPodOomKilledMultiContainer:
    """kubernetes_pod.py:1231→1238, 1239→1226, 1243→1226 — branches
    in the container-status loop (sandbox container after a sidecar +
    state=None / last_state=None paths)."""

    @pytest.mark.asyncio
    async def test_returns_true_when_sandbox_oom_after_sidecar_in_loop(self) -> None:
        backend = _make_backend()
        # Loop iterates: proxy (skipped) → sandbox (oom)
        cs_proxy = _make_container_status(name="egress-proxy", state_reason="Completed")
        cs_sandbox = _make_container_status(name=_SANDBOX_CONTAINER_NAME, state_reason="OOMKilled")
        pod = MagicMock()
        pod.status.container_statuses = [cs_proxy, cs_sandbox]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_state_is_none_and_last_state_is_none(
        self,
    ) -> None:
        backend = _make_backend()
        cs = MagicMock()
        cs.name = _SANDBOX_CONTAINER_NAME
        cs.state = None  # state attribute missing
        cs.last_state = None
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_state_terminated_is_none(self) -> None:
        backend = _make_backend()
        cs = MagicMock()
        cs.name = _SANDBOX_CONTAINER_NAME
        state = MagicMock()
        state.terminated = None  # state has terminated=None
        cs.state = state
        cs.last_state = MagicMock()
        cs.last_state.terminated = None
        pod = MagicMock()
        pod.status.container_statuses = [cs]
        with patch(
            "kubernetes_asyncio.client.CoreV1Api",
            return_value=MagicMock(read_namespaced_pod_status=AsyncMock(return_value=pod)),
        ):
            result = await backend._read_pod_oom_killed(pod_name="p")
        assert result is False


class TestReadCpuUsageNsExtraBranches:
    """kubernetes_pod.py:1283→1292, 1285→1283, 1299→1305 — branches
    in the cgroup-stat parsing loop (v2 successful exit but no
    usage_usec line; v1 successful read; both fail)."""

    @pytest.mark.asyncio
    async def test_v2_with_no_usage_usec_line_falls_through_to_v1_then_returns_none(
        self,
    ) -> None:
        """v2 cpu.stat exit_code=0 but no usage_usec line → falls
        through to v1; v1 also fails → returns None."""
        backend = _make_backend()
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(
                side_effect=[
                    (b"user_usec 100\nsystem_usec 50\n", 0),  # v2 no usage_usec
                    None,  # v1 exec failure
                ]
            ),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns is None

    @pytest.mark.asyncio
    async def test_v2_with_garbage_line_still_falls_through_to_v1(self) -> None:
        """v2 cpu.stat has an irrelevant line; v1 succeeds with valid int."""
        backend = _make_backend()
        with patch.object(
            backend,
            "_exec_short_lived",
            AsyncMock(
                side_effect=[
                    (b"some garbage line\n", 0),  # v2 no usage_usec match
                    (b"123456\n", 0),  # v1 valid
                ]
            ),
        ):
            usage_ns = await backend._read_cpu_usage_ns(pod_name="p", container_name="sandbox")
        assert usage_ns == 123456


class TestCpuMonitorTrailingSleep:
    """kubernetes_pod.py:1400 — trailing ``await asyncio.sleep(...)``
    after the under-budget branch. The monitor loops back to read again."""

    @pytest.mark.asyncio
    async def test_monitor_sleeps_when_under_budget_then_event_set_by_cancel(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Under-budget reading → loop continues → on second iteration
        the monitor task gets cancelled (mirrors finally-block cancel
        from exec). Verifies the trailing sleep path."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        backend = _make_backend()
        event = asyncio.Event()
        # First read: under budget (100 ns < 1s budget = 1_000_000_000 ns)
        # Second read: raise CancelledError to exit
        with (
            patch.object(
                backend,
                "_read_cpu_usage_ns",
                AsyncMock(side_effect=[100, asyncio.CancelledError()]),
            ),
            pytest.raises(asyncio.CancelledError),
        ):
            await backend._cpu_time_budget_monitor_k8s(
                pod_name="p",
                container_name="sandbox",
                budget_s=1.0,
                cpu_violated_event=event,
            )
        assert not event.is_set()

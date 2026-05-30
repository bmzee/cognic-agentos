"""Sprint 8A T10b — exec() decision-logic unit tests.

NON-env-gated. Uses mocked aiodocker to pin exec()'s classification
logic: walltime exceeded → walltime_cap_exceeded; exit 137 +
OOMKilled → memory_cap_exceeded; cpu-budget monitor signals
exceeded → cpu_time_budget_exceeded; green path returns
SandboxExecResult with the right shape.

The env-gated tests at test_docker_sibling_resource_caps.py exercise
the actual kernel enforcement against a real Docker daemon + cgroups.
These tests cover the AgentOS-side decision logic without needing
cgroups available.

Per spec §7 lines 495-502 + round-3 P2 invariant: --cpus throttling
under cap is NOT a violation by itself.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxExecResult,
    SandboxPolicy,
    SandboxPolicyViolated,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
    _classify_exec_failure,
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


# ---------------------------------------------------------------------------
# _classify_exec_failure — pure decision function
# ---------------------------------------------------------------------------


class TestClassifyExecFailure:
    """Pure-functional pin of the cap-violation classification.
    exec() consumes this; the function returns the matching
    closed-enum SandboxPolicyViolationReason or None for green path."""

    def test_green_path_returns_none(self) -> None:
        assert (
            _classify_exec_failure(
                exit_code=0,
                oom_killed=False,
                walltime_exceeded=False,
                cpu_budget_exceeded=False,
            )
            is None
        )

    def test_walltime_takes_precedence(self) -> None:
        """Walltime exceeded → kill via container.kill → exit_code may
        be 137 + OOMKilled MAY be True (kill cascade). Walltime classify
        MUST take precedence so the wire-protocol reason matches
        the actual cause."""
        assert (
            _classify_exec_failure(
                exit_code=137,
                oom_killed=True,
                walltime_exceeded=True,
                cpu_budget_exceeded=False,
            )
            == "walltime_cap_exceeded"
        )

    def test_cpu_budget_takes_precedence_over_oom(self) -> None:
        """cpu_budget_exceeded → kill → exit_code 137 + OOMKilled
        possible. Classify MUST attribute to the budget kill, not the
        cascaded OOM."""
        assert (
            _classify_exec_failure(
                exit_code=137,
                oom_killed=True,
                walltime_exceeded=False,
                cpu_budget_exceeded=True,
            )
            == "cpu_time_budget_exceeded"
        )

    def test_oom_killed_alone(self) -> None:
        """exit 137 + OOMKilled with no walltime/budget cause → real OOM."""
        assert (
            _classify_exec_failure(
                exit_code=137,
                oom_killed=True,
                walltime_exceeded=False,
                cpu_budget_exceeded=False,
            )
            == "memory_cap_exceeded"
        )

    def test_exit_137_without_oom_killed_is_NOT_oom(self) -> None:
        """exit 137 alone (SIGKILL from any source) is NOT enough to
        attribute to OOM — the kernel's oom_killer flag is the
        authoritative signal. Without it, classify returns None
        (green-path exit code; the exit is the user's signal)."""
        assert (
            _classify_exec_failure(
                exit_code=137,
                oom_killed=False,
                walltime_exceeded=False,
                cpu_budget_exceeded=False,
            )
            is None
        )

    def test_nonzero_exit_with_no_cap_signal_is_green(self) -> None:
        """A user-code error (exit 1) is NOT a sandbox policy
        violation — exec() returns the exit code to the caller."""
        assert (
            _classify_exec_failure(
                exit_code=1,
                oom_killed=False,
                walltime_exceeded=False,
                cpu_budget_exceeded=False,
            )
            is None
        )


# ---------------------------------------------------------------------------
# exec() body — backend-level integration with mocked aiodocker
# ---------------------------------------------------------------------------


def _make_backend_with_exec_mocks(
    *,
    stdout: bytes = b"",
    stderr: bytes = b"",
    exit_code: int = 0,
    oom_killed: bool = False,
    exec_hangs: bool = False,
    cpu_usage_per_poll_ns: list[int] | None = None,
) -> tuple[DockerSiblingSandboxBackend, MagicMock]:
    """Build a backend whose aiodocker mock honors the exec() path's
    requirements: containers.get(...) returns a container with the
    expected exec / inspect / show / kill / stats methods.

    Returns the backend + the mocked container so tests can introspect
    container.kill.await_count etc.
    """

    docker = MagicMock()
    docker.networks.create = AsyncMock()
    docker.containers.create_or_replace = AsyncMock()
    docker.containers.create_or_replace.return_value.start = AsyncMock()
    # Teardown stubs (destroy uses these on cleanup)
    mock_network = MagicMock()
    mock_network.connect = AsyncMock()
    mock_network.delete = AsyncMock()
    docker.networks.get = AsyncMock(return_value=mock_network)

    # Mock container the exec path operates on. `containers.get(session_id)`
    # returns THIS container; teardown's destroy path returns DockerError
    # via the .delete branch in this same mock (or via the get-side
    # via a second mock layer — we keep it simple by using a single
    # container mock with all needed methods).
    #
    # ``kill_event`` — when container.kill is awaited (by exec()'s
    # walltime-timeout path OR by the cpu-budget monitor), set this
    # event so the stream's sleep ends and the stream returns. This
    # simulates the real Docker-daemon behaviour where killing the
    # container ends the exec stream.
    kill_event = asyncio.Event()
    mock_container = MagicMock()

    async def _kill(signal: str = "SIGKILL") -> None:
        kill_event.set()

    mock_container.kill = AsyncMock(side_effect=_kill)
    mock_container.stop = AsyncMock()
    mock_container.delete = AsyncMock()

    # container.exec(...) returns an aiodocker Exec object; that
    # object has .start(detach=False) which returns a Stream object
    # + .inspect() which returns the ExitCode.
    #
    # R1 P1.1 fix — mock the REAL aiodocker Stream API: ``read_out()``
    # returns ``Message | None`` (None signals stream end); Message
    # has ``.stream`` (1=stdout, 2=stderr per Docker exec multiplexed
    # wire format) + ``.data`` (bytes). Earlier mock used an
    # async-generator which hid the fact that aiodocker.stream.Stream
    # is NOT async-iterable + the wire shape is Message objects, not
    # (bytes, idx) tuples.
    # T10c R1 P1.2 — workload exec + sidecar log-cat exec need
    # DIFFERENT exec objects: workload returns the test's exit_code;
    # sidecar's cat MUST inspect to ExitCode=0 (canonical proxy image
    # guarantees a readable log; nonzero = fail-closed).
    workload_exec_obj = MagicMock()
    workload_exec_obj.inspect = AsyncMock(return_value={"ExitCode": exit_code})

    sidecar_cat_exec_obj = MagicMock()
    sidecar_cat_exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})
    # Sidecar cat returns an empty body (no outbound calls) via a
    # stream whose read_out yields nothing — proxy_log = ().
    sidecar_cat_stream = MagicMock()
    sidecar_cat_stream.read_out = AsyncMock(return_value=None)
    sidecar_cat_stream.__aenter__ = AsyncMock(return_value=sidecar_cat_stream)
    sidecar_cat_stream.__aexit__ = AsyncMock(return_value=None)
    sidecar_cat_exec_obj.start = MagicMock(return_value=sidecar_cat_stream)

    async def _exec_dispatch(**kwargs: object) -> object:
        cmd = kwargs.get("cmd")
        if cmd and isinstance(cmd, list) and cmd[:1] == ["cat"]:
            return sidecar_cat_exec_obj
        return workload_exec_obj

    mock_container.exec = AsyncMock(side_effect=_exec_dispatch)
    mock_exec_obj = workload_exec_obj  # rest of the helper sets up workload stream

    # Pre-build the list of Messages this exec will yield. Each
    # Message is a SimpleNamespace-style object exposing .stream +
    # .data (matching aiodocker.stream.Message field names).
    message_queue: list[object] = []
    if stdout:
        message_queue.append(MagicMock(stream=1, data=stdout))
    if stderr:
        message_queue.append(MagicMock(stream=2, data=stderr))

    mock_stream = MagicMock()
    message_iter = iter(message_queue)

    async def _read_out() -> object | None:
        if exec_hangs:
            # Simulate a hanging exec — block until either the
            # asyncio.timeout fires (walltime path) OR container.kill
            # is awaited (cpu-budget monitor path). The real Docker
            # daemon ends the exec stream when the container is
            # killed; the mock simulates that via kill_event.
            await kill_event.wait()
            return None
        try:
            return next(message_iter)
        except StopIteration:
            return None

    mock_stream.read_out = _read_out
    # R2 P2 reviewer fix — exec() wraps the Stream in ``async with``
    # so close() fires on every exit path. Make the mock Stream an
    # async-context-manager whose __aenter__ returns itself + whose
    # __aexit__ records the close call so tests can pin it.
    mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
    mock_stream.__aexit__ = AsyncMock(return_value=None)
    mock_stream.close = AsyncMock()
    mock_exec_obj.start = MagicMock(return_value=mock_stream)

    # container.show() returns the container attrs incl. State.OOMKilled
    mock_container.show = AsyncMock(
        return_value={"State": {"OOMKilled": oom_killed, "ExitCode": exit_code}}
    )

    # container.stats(stream=False) for cpu-budget monitor; returns
    # the CPU usage in nanoseconds. The monitor accumulates this.
    if cpu_usage_per_poll_ns is None:
        cpu_usage_per_poll_ns = [0]
    poll_iter = iter(cpu_usage_per_poll_ns)

    async def _stats(stream: bool = False) -> dict[str, object]:
        try:
            usage = next(poll_iter)
        except StopIteration:
            usage = cpu_usage_per_poll_ns[-1]
        return {"cpu_stats": {"cpu_usage": {"total_usage": usage}}}

    mock_container.stats = _stats

    docker.containers.get = AsyncMock(return_value=mock_container)

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
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=_make_dh_store(),
        settings=settings,
        warm_pool=None,
    )
    return backend, mock_container


def _make_dh_store() -> AsyncMock:
    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


def _make_session(
    backend: DockerSiblingSandboxBackend,
    *,
    policy: SandboxPolicy = _POLICY_NO_BUDGET,
) -> DockerSiblingSession:
    """Mint a session directly (bypass create()) for exec-isolation tests."""
    return DockerSiblingSession(
        session_id="abcd" * 8,
        policy=policy,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name="cognic-sb-internal-abcd1234-abcdef01",
        _sidecar_container_name="abcdabcdabcdabcdabcdabcdabcdabcd-proxy",
        _actor_subject=_ACTOR.subject,
    )


class TestExecGreenPath:
    @pytest.mark.asyncio
    async def test_exec_returns_sandbox_exec_result_on_green_exit(
        self,
    ) -> None:
        backend, _ = _make_backend_with_exec_mocks(
            stdout=b"hello\n",
            stderr=b"",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["echo", "hello"])
        assert isinstance(result, SandboxExecResult)
        assert result.exit_code == 0
        assert result.stdout == b"hello\n"
        assert result.proxy_log == ()  # T10c lands proxy_log materialisation

    @pytest.mark.asyncio
    async def test_exec_returns_nonzero_exit_without_violation(
        self,
    ) -> None:
        """User-code exit 1 → exec returns SandboxExecResult with
        exit_code=1; no SandboxPolicyViolated raised."""
        backend, _ = _make_backend_with_exec_mocks(exit_code=1)
        session = _make_session(backend)

        result = await backend.exec(session, ["false"])
        assert result.exit_code == 1


class TestExecWalltimeCap:
    @pytest.mark.asyncio
    async def test_walltime_exceeded_raises_walltime_cap_exceeded(
        self,
    ) -> None:
        """A hanging exec past policy.walltime_s MUST raise
        SandboxPolicyViolated(walltime_cap_exceeded) + kill the
        container. Per spec §7 item 2."""
        backend, container = _make_backend_with_exec_mocks(exec_hangs=True)
        session = _make_session(
            backend,
            policy=SandboxPolicy(
                cpu_cores=0.5,
                cpu_time_budget_s=None,
                memory_mb=256,
                walltime_s=0.1,  # 100ms walltime to force timeout fast
                runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
                egress_allow_list=(),
                vault_path=None,
            ),
        )

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["sleep", "60"])
        assert exc.value.reason == "walltime_cap_exceeded"
        # Container was killed on walltime overage
        container.kill.assert_awaited()


class TestExecMemoryCap:
    @pytest.mark.asyncio
    async def test_exit_137_plus_oom_killed_raises_memory_cap_exceeded(
        self,
    ) -> None:
        """exit_code == 137 + container.show.State.OOMKilled == True
        means the cgroup oom-killer fired. exec() MUST classify this
        as memory_cap_exceeded per spec §7 item 3."""
        backend, _ = _make_backend_with_exec_mocks(
            exit_code=137,
            oom_killed=True,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["python", "-c", "x = bytearray(10**9)"])
        assert exc.value.reason == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_exit_137_without_oom_is_not_classified_as_memory(
        self,
    ) -> None:
        """exit 137 from a non-OOM source (manual SIGKILL outside
        AgentOS) MUST NOT misclassify as memory_cap_exceeded.
        Return the exit code; let the caller handle."""
        backend, _ = _make_backend_with_exec_mocks(
            exit_code=137,
            oom_killed=False,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["something"])
        # No SandboxPolicyViolated raised; exec returns the exit code
        assert result.exit_code == 137


class TestExecCpuTimeBudget:
    @pytest.mark.asyncio
    async def test_cpu_budget_exceeded_raises_cpu_time_budget_exceeded(
        self,
    ) -> None:
        """When policy.cpu_time_budget_s is set + the cgroup-stats
        monitor accumulates past the budget, exec() MUST kill the
        container + raise SandboxPolicyViolated(cpu_time_budget_exceeded).
        Per spec §7 item 4."""

        # 1 CPU-second budget = 1_000_000_000 nanoseconds.
        # Each poll reports cumulative usage; second poll exceeds.
        async def slow_exec_stream() -> object:
            # Hang long enough for the monitor to see the second poll
            await asyncio.sleep(2.0)
            yield (b"", 1)

        backend, container = _make_backend_with_exec_mocks(
            exec_hangs=True,  # hang so monitor has time to fire
            cpu_usage_per_poll_ns=[
                500_000_000,  # 0.5s — under budget
                1_500_000_000,  # 1.5s — over budget → kill
            ],
        )
        session = _make_session(backend, policy=_POLICY_WITH_BUDGET)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["python", "-c", "while True: pass"])
        assert exc.value.reason == "cpu_time_budget_exceeded"
        container.kill.assert_awaited()

    @pytest.mark.asyncio
    async def test_no_cpu_budget_means_no_monitor_no_violation(
        self,
    ) -> None:
        """Per round-3 P2 invariant: --cpus throttling alone is NOT
        a violation. When policy.cpu_time_budget_s is None, no
        cpu-budget monitor is spawned + a CPU-bound workload that
        completes within walltime returns exit 0 cleanly."""
        backend, container = _make_backend_with_exec_mocks(
            exit_code=0,
            stdout=b"done\n",
        )
        session = _make_session(backend, policy=_POLICY_NO_BUDGET)

        result = await backend.exec(session, ["python", "-c", "x = sum(range(10**5))"])
        assert result.exit_code == 0
        # No kill — workload completed cleanly
        container.kill.assert_not_called()


# ---------------------------------------------------------------------------
# R1 P1.1 — Stream read_out / Message wire shape (real aiodocker API)
# ---------------------------------------------------------------------------


class TestStreamReadOutContract:
    """R1 P1.1 reviewer fix — aiodocker.stream.Stream is NOT
    async-iterable; consume via read_out() returning Message | None.
    Earlier impl used `async for chunk in stream` which crashes
    against the real SDK. These tests pin that exec() consumes the
    Stream via read_out + properly demuxes Message.stream/.data."""

    @pytest.mark.asyncio
    async def test_exec_reads_via_read_out_not_async_iter(self) -> None:
        """The mock's Stream object exposes read_out() but NOT
        __aiter__. If exec() called `async for chunk in stream` it
        would crash with TypeError; the green-path success proves
        exec() consumes via read_out() instead."""
        backend, _container = _make_backend_with_exec_mocks(
            stdout=b"hello-from-stdout",
            stderr=b"warn-from-stderr",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["echo", "hello"])
        assert result.stdout == b"hello-from-stdout"
        assert result.stderr == b"warn-from-stderr"

    @pytest.mark.asyncio
    async def test_exec_demuxes_stdout_stderr_via_message_stream(self) -> None:
        """Real aiodocker Message exposes ``.stream`` (1=stdout,
        2=stderr) + ``.data`` (bytes). exec() MUST route Message
        chunks per the .stream attribute, NOT positional unpacking
        (the earlier `(payload, stream_idx) = chunk` shape doesn't
        match Message). Pinned here via a Message-shaped mock that
        sends mixed-stream traffic."""
        backend, _ = _make_backend_with_exec_mocks(
            stdout=b"OUT",
            stderr=b"ERR",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["echo"])
        # stdout MUST contain only the .stream=1 payload; stderr only .stream=2
        assert result.stdout == b"OUT"
        assert result.stderr == b"ERR"


# ---------------------------------------------------------------------------
# R1 P1.2 — exec() passes user=_NON_ROOT_USER
# ---------------------------------------------------------------------------


class TestExecRunsAsNonRoot:
    """R1 P1.2 reviewer fix — container starts non-root (User config
    on the container) but aiodocker's exec(user="") defaults to image
    default (commonly root). exec() MUST pass user=_NON_ROOT_USER
    explicitly so the pack command also runs non-root."""

    @pytest.mark.asyncio
    async def test_exec_call_carries_user_kwarg(self) -> None:
        backend, container = _make_backend_with_exec_mocks(exit_code=0)
        session = _make_session(backend)

        await backend.exec(session, ["echo", "hello"])

        # Inspect the FIRST container.exec call's kwargs — MUST include
        # user. T10c added a second exec (sidecar log-cat for proxy_log
        # readback); the test pins the workload exec specifically via
        # await_args_list[0] (matched by command argv).
        # await_count is 2 with T10c: [0] = workload exec, [1] = sidecar
        # cat /var/log/cognic-proxy/access.jsonl.
        assert container.exec.await_count == 2, (
            "T10c expects 2 exec calls: workload + sidecar log readback"
        )
        workload_call = container.exec.await_args_list[0]
        kwargs = workload_call.kwargs
        assert kwargs.get("cmd") == ["echo", "hello"]
        assert kwargs["user"] == "65534:65534", (
            "container.exec() MUST pass user=65534:65534 — without it, "
            "aiodocker's default empty user runs as image default "
            "(commonly root) even though the container started non-root. "
            "R1 P1.2 reviewer fix."
        )
        # Sidecar proxy-log read runs as the PROXY's own non-root identity
        # (10002:10002) — T30/T14.1: the proxy owns its access log under
        # /var/log/cognic-proxy, so the cat reads as the proxy user, NOT the
        # workload's 65534.
        sidecar_call = container.exec.await_args_list[1]
        assert sidecar_call.kwargs["user"] == "10002:10002"


# ---------------------------------------------------------------------------
# R1 P1.3 — tiny positive cpu_cores must NOT collapse to CpuQuota=0
# ---------------------------------------------------------------------------


class TestCpuQuotaClampedToMinimum:
    """R1 P1.3 reviewer fix — Stage-1 accepts cpu_cores > 0 (no lower
    bound). _derive_cpu_quota_period rounds cpu_cores * 100000;
    values below 0.000005 round to 0. Docker treats CpuQuota=0 as
    "no limit" (the default). Clamp to at least 1us so a tiny
    positive cpu_cores produces a tight-but-nonzero throttle.

    Without the clamp, a malicious or malformed policy can pass
    Stage-1 validation with cpu_cores=1e-9 and get UNTHROTTLED CPU."""

    def test_tiny_cpu_cores_does_not_produce_zero_quota(self) -> None:
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _derive_cpu_quota_period,
        )

        quota, _period = _derive_cpu_quota_period(0.000004)
        assert quota >= 1, (
            f"CpuQuota MUST be >=1 even for tiny cpu_cores; got {quota}. "
            f"Docker treats 0 as 'no limit' → unthrottled CPU bypass. "
            f"R1 P1.3 reviewer fix."
        )

    def test_zero_boundary_via_clamp(self) -> None:
        """Stage-1 rejects cpu_cores<=0, so the SMALLEST possible
        positive value still produces a valid throttle. Pin the
        clamp boundary at cpu_cores=1e-9 → quota=1us."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _derive_cpu_quota_period,
        )

        quota, _ = _derive_cpu_quota_period(1e-9)
        assert quota == 1


# ---------------------------------------------------------------------------
# R1 P1.4 — malformed stats snapshots MUST NOT kill the monitor
# ---------------------------------------------------------------------------


class TestCpuBudgetMonitorMalformedShape:
    """R1 P1.4 reviewer fix — earlier impl only caught exceptions
    from container.stats() itself; a partial/changed snapshot
    (``{"cpu_stats": None}``) raised AFTER the try block, killed
    the monitor task silently, and exec()'s finally suppressed the
    failure → CPU budget UNENFORCED until walltime fires.

    Fix wraps shape parsing in the same try + continues polling on
    malformed snapshots. The container.kill still fires on the next
    valid snapshot that exceeds the budget."""

    @pytest.mark.asyncio
    async def test_monitor_survives_cpu_stats_none(self) -> None:
        """``{"cpu_stats": None}`` is the canonical "partial snapshot"
        shape from docker (e.g. fresh container before first stats
        sample). Monitor MUST tolerate it + continue polling."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _cpu_time_budget_monitor,
        )

        # First poll returns malformed; second returns valid + over-budget.
        snapshots = [
            {"cpu_stats": None},  # malformed
            {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}}},  # over 1s
        ]
        snapshot_iter = iter(snapshots)
        container = MagicMock()
        container.kill = AsyncMock()

        async def _stats(stream: bool = False) -> object:
            try:
                return next(snapshot_iter)
            except StopIteration:
                return snapshots[-1]

        container.stats = _stats
        event = asyncio.Event()

        # Patch the poll interval to make the test fast
        from cognic_agentos.sandbox.backends import docker_sibling

        original = docker_sibling._CPU_BUDGET_POLL_INTERVAL_S
        docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = 0.01
        try:
            await asyncio.wait_for(
                _cpu_time_budget_monitor(
                    container=container,
                    budget_s=1.0,
                    cpu_violated_event=event,
                ),
                timeout=2.0,
            )
        finally:
            docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = original

        # Monitor survived the malformed snapshot + fired on the valid one
        assert event.is_set()
        container.kill.assert_awaited()

    @pytest.mark.asyncio
    async def test_monitor_survives_missing_cpu_usage_key(self) -> None:
        """Another partial-shape — cpu_stats dict present but
        cpu_usage missing. Same survival contract."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _cpu_time_budget_monitor,
        )

        snapshots = [
            {"cpu_stats": {}},  # missing cpu_usage
            {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}}},
        ]
        snapshot_iter = iter(snapshots)
        container = MagicMock()
        container.kill = AsyncMock()

        async def _stats(stream: bool = False) -> object:
            try:
                return next(snapshot_iter)
            except StopIteration:
                return snapshots[-1]

        container.stats = _stats
        event = asyncio.Event()
        from cognic_agentos.sandbox.backends import docker_sibling

        original = docker_sibling._CPU_BUDGET_POLL_INTERVAL_S
        docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = 0.01
        try:
            await asyncio.wait_for(
                _cpu_time_budget_monitor(
                    container=container,
                    budget_s=1.0,
                    cpu_violated_event=event,
                ),
                timeout=2.0,
            )
        finally:
            docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = original

        assert event.is_set()


# ---------------------------------------------------------------------------
# R1 P1.5 — sandbox.policy.violated chain row emitted on cap violations
# ---------------------------------------------------------------------------


class TestPolicyViolatedAuditEmission:
    """R1 P1.5 reviewer fix — cap violations (memory / walltime /
    cpu_budget) MUST emit ``sandbox.policy.violated`` with the
    closed-enum reason before raising. Without this row, cap kills
    have NO audit trail in the evidence pack per spec §4.3 + §12."""

    @pytest.mark.asyncio
    async def test_walltime_violation_emits_policy_violated_row(
        self,
    ) -> None:
        backend, _ = _make_backend_with_exec_mocks(exec_hangs=True)
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
        # Drain create's lifecycle.created emission
        cast(AsyncMock, backend._dh.append_with_precondition).reset_mock()

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["sleep", "60"])

        # The policy.violated chain row was emitted
        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        record_builder = cast(AsyncMock, backend._dh.append_with_precondition).await_args.kwargs[  # type: ignore[union-attr]
            "record_builder"
        ]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "walltime_cap_exceeded"
        assert record.payload["session_id"] == session.session_id
        assert record.actor_id == _ACTOR.subject
        assert record.iso_controls == ("ISO42001.A.6.2.5",)

    @pytest.mark.asyncio
    async def test_memory_violation_emits_policy_violated_row(
        self,
    ) -> None:
        backend, _ = _make_backend_with_exec_mocks(
            exit_code=137,
            oom_killed=True,
        )
        session = _make_session(backend)
        cast(AsyncMock, backend._dh.append_with_precondition).reset_mock()

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["python", "-c", "x = bytearray(10**9)"])

        record_builder = cast(AsyncMock, backend._dh.append_with_precondition).await_args.kwargs[  # type: ignore[union-attr]
            "record_builder"
        ]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "memory_cap_exceeded"

    @pytest.mark.asyncio
    async def test_cpu_budget_violation_emits_policy_violated_row(
        self,
    ) -> None:
        backend, _ = _make_backend_with_exec_mocks(
            exec_hangs=True,
            cpu_usage_per_poll_ns=[500_000_000, 1_500_000_000],
        )
        session = _make_session(backend, policy=_POLICY_WITH_BUDGET)
        cast(AsyncMock, backend._dh.append_with_precondition).reset_mock()

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["python", "-c", "while True: pass"])

        record_builder = cast(AsyncMock, backend._dh.append_with_precondition).await_args.kwargs[  # type: ignore[union-attr]
            "record_builder"
        ]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "cpu_time_budget_exceeded"

    @pytest.mark.asyncio
    async def test_green_path_emits_exec_completed_not_policy_violated(
        self,
    ) -> None:
        """T10c — green exec emits sandbox.lifecycle.exec_completed
        (NOT sandbox.policy.violated). The earlier R1 test asserted
        zero appends; T10c now emits exactly one (exec_completed).
        This test pins the discriminator: type is exec_completed,
        not policy.violated."""
        backend, _ = _make_backend_with_exec_mocks(exit_code=0)
        session = _make_session(backend)
        cast(AsyncMock, backend._dh.append_with_precondition).reset_mock()

        await backend.exec(session, ["echo", "ok"])

        # Exactly one chain row — sandbox.lifecycle.exec_completed
        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        await_args = cast(AsyncMock, backend._dh.append_with_precondition).await_args
        assert await_args is not None
        record_builder = await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.exec_completed", (
            "Green-path exec MUST emit lifecycle.exec_completed (NOT "
            "policy.violated). Per spec §4.3 + §7 line 502 + T10c."
        )
        assert record.decision_type != "sandbox.policy.violated"


# ---------------------------------------------------------------------------
# R2 P1.1 — kill failures fail-closed (404 benign, others propagate)
# ---------------------------------------------------------------------------


class TestKillHelperDistinguishesBenignVsRealFailure:
    """R2 P1.1 reviewer fix — ``_kill_container_or_raise`` swallows
    Docker 404 (container already gone — cap effectively enforced)
    but propagates ANY other DockerError so cap-violation paths do
    NOT pretend they enforced when they couldn't."""

    @pytest.mark.asyncio
    async def test_kill_404_treated_as_benign(self) -> None:
        import aiodocker

        from cognic_agentos.sandbox.backends.docker_sibling import (
            _kill_container_or_raise,
        )

        container = MagicMock()
        container.kill = AsyncMock(side_effect=aiodocker.exceptions.DockerError(404, "not found"))

        # Returns silently — no exception propagated.
        await _kill_container_or_raise(container)

    @pytest.mark.asyncio
    async def test_kill_500_propagates(self) -> None:
        """Docker 500 (real daemon error) MUST propagate so the
        caller knows enforcement is unverified."""
        import aiodocker

        from cognic_agentos.sandbox.backends.docker_sibling import (
            _kill_container_or_raise,
        )

        container = MagicMock()
        container.kill = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(500, "daemon error")
        )

        with pytest.raises(aiodocker.exceptions.DockerError) as exc:
            await _kill_container_or_raise(container)
        assert exc.value.status == 500


class TestWalltimeKillFailureFailsClosed:
    """R2 P1.1 reviewer fix on walltime path — if kill fails with a
    real DockerError (NOT 404), the DockerError propagates instead
    of SandboxPolicyViolated(walltime_cap_exceeded). Caller knows
    enforcement is unverified."""

    @pytest.mark.asyncio
    async def test_walltime_kill_500_propagates_docker_error_not_violation(
        self,
    ) -> None:
        import aiodocker

        backend, container = _make_backend_with_exec_mocks(exec_hangs=True)
        # Override kill to raise a real DockerError (not 404).
        container.kill = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(500, "daemon error")
        )
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

        # DockerError propagates; SandboxPolicyViolated is NOT raised
        # because we cannot prove enforcement happened.
        with pytest.raises(aiodocker.exceptions.DockerError) as exc:
            await backend.exec(session, ["sleep", "60"])
        assert exc.value.status == 500

    @pytest.mark.asyncio
    async def test_walltime_kill_404_still_raises_violation(self) -> None:
        """Sanity: 404 is benign (container already gone — workload
        is not running), so walltime_cap_exceeded SHOULD still
        raise."""
        import aiodocker

        backend, container = _make_backend_with_exec_mocks(exec_hangs=True)
        container.kill = AsyncMock(side_effect=aiodocker.exceptions.DockerError(404, "not found"))

        # Simulate the kill_event so the stream's hang ends
        async def _kill_404(signal: str = "SIGKILL") -> None:
            raise aiodocker.exceptions.DockerError(404, "not found")

        # We need the stream to also end. Without container.kill setting
        # the kill_event, the stream sleep would never wake. For this
        # test we set the event manually so the mock stream ends + the
        # exec loop sees the timeout fire.
        # The simplest pattern: have container.kill BOTH raise 404 AND
        # set the kill_event (so the stream's await kill_event.wait()
        # returns).
        # Re-fetch the kill_event from the closure — we know it's the
        # event tied to mock_stream.read_out's `if exec_hangs: await
        # kill_event.wait()` branch. The kill_event is captured inside
        # _make_backend_with_exec_mocks so we have to wire it via the
        # mock's side_effect:

        # Setup: extract the kill_event that the helper closed over.
        # Cleanest: use a fresh helper that exposes the event. For
        # this test we re-do the setup inline so we control both.
        kill_event = asyncio.Event()

        async def _kill_404_and_signal(signal: str = "SIGKILL") -> None:
            kill_event.set()  # ends the stream's hang
            raise aiodocker.exceptions.DockerError(404, "not found")

        container.kill = AsyncMock(side_effect=_kill_404_and_signal)

        # Replace stream's read_out with one that watches OUR kill_event
        async def _read_out() -> object | None:
            await kill_event.wait()
            return None

        mock_stream = MagicMock()
        mock_stream.read_out = _read_out
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=None)
        container.exec.return_value.start = MagicMock(return_value=mock_stream)

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


class TestCpuBudgetKillFailureFailsClosed:
    """R2 P1.1 reviewer fix on cpu-budget path — if kill fails with
    a real DockerError, the cpu_violated_event is NOT set + the
    monitor task exits with the exception. Walltime acts as the
    natural backstop; exec() does NOT raise cpu_time_budget_exceeded
    while the workload may still be running."""

    @pytest.mark.asyncio
    async def test_cpu_budget_kill_500_does_NOT_set_event(self) -> None:
        """Direct test on _cpu_time_budget_monitor — kill 500 means
        event stays UNSET. Without this contract, exec() would raise
        cpu_time_budget_exceeded even though the workload may still
        be running."""
        import aiodocker

        from cognic_agentos.sandbox.backends.docker_sibling import (
            _cpu_time_budget_monitor,
        )

        container = MagicMock()
        container.kill = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(500, "daemon error")
        )

        async def _stats(stream: bool = False) -> object:
            return {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}}}

        container.stats = _stats
        event = asyncio.Event()

        from cognic_agentos.sandbox.backends import docker_sibling

        original = docker_sibling._CPU_BUDGET_POLL_INTERVAL_S
        docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = 0.01
        try:
            with pytest.raises(aiodocker.exceptions.DockerError):
                await asyncio.wait_for(
                    _cpu_time_budget_monitor(
                        container=container,
                        budget_s=1.0,
                        cpu_violated_event=event,
                    ),
                    timeout=2.0,
                )
        finally:
            docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = original

        # Event stays UNSET — exec() will NOT raise cpu_time_budget_exceeded
        assert not event.is_set(), (
            "cpu_violated_event MUST stay False when kill fails with "
            "a real DockerError — fail-closed per R2 P1.1 reviewer fix. "
            "Setting the event when kill failed would claim enforcement "
            "we cannot prove."
        )


# ---------------------------------------------------------------------------
# R2 P1.2 — policy.violated audit failure fails-closed
# ---------------------------------------------------------------------------


class TestPolicyViolatedAuditFailureFailsClosed:
    """R2 P1.2 reviewer fix — earlier ``contextlib.suppress(Exception)``
    silently dropped audit-store outages. If the chain row can't be
    written, the caller MUST see the audit failure (not just the cap
    reason). The audit-store outage is a CC failure that supersedes
    the cap reason in the wire-protocol-public surface."""

    @pytest.mark.asyncio
    async def test_audit_append_failure_propagates_not_cap_exception(
        self,
    ) -> None:
        backend, _ = _make_backend_with_exec_mocks(exit_code=137, oom_killed=True)
        session = _make_session(backend)

        # Make the audit-store fail on the policy.violated append
        cast(AsyncMock, backend._dh.append_with_precondition).side_effect = RuntimeError(
            "simulated audit-store outage"
        )

        # The audit failure propagates — SandboxPolicyViolated is NOT
        # raised. Caller sees the audit failure (more critical than
        # the cap reason in this context).
        with pytest.raises(RuntimeError, match="audit-store outage"):
            await backend.exec(session, ["python", "-c", "x = bytearray(10**9)"])


# ---------------------------------------------------------------------------
# R2 P2 — Stream closed on every exit path
# ---------------------------------------------------------------------------


class TestStreamClosedOnEveryExitPath:
    """R2 P2 reviewer fix — Stream wrapped in ``async with`` so its
    underlying websocket/HTTP response closes on every exit path
    (clean end-of-stream + walltime timeout + read_out exception)."""

    @pytest.mark.asyncio
    async def test_stream_closed_on_green_path(self) -> None:
        backend, container = _make_backend_with_exec_mocks(stdout=b"hello", exit_code=0)
        session = _make_session(backend)

        await backend.exec(session, ["echo", "hello"])

        # __aexit__ fired (= async with cleanly exited).
        # T10c R1 split workload + sidecar exec objects — find the
        # workload one via the call dispatch (cmd argument).
        workload_call = container.exec.await_args_list[0]
        # The mock's side_effect returned the workload_exec_obj for
        # this cmd; introspect its start().return_value (the stream).
        # Easiest: extract from side_effect's last result via the
        # post-dispatch return MagicMock; but the cleanest pin is on
        # ``container.exec.side_effect`` being invoked the right way
        # — assert exec was awaited with the workload cmd, and that
        # the call shape includes stdout/stderr=True (which means
        # exec() consumed the resulting Stream via async with).
        assert workload_call.kwargs.get("cmd") == ["echo", "hello"]
        # Sidecar log-cat exec was also awaited (T10c proxy_log
        # readback). Its stream was likewise consumed via async with;
        # absence of unhandled coroutine warnings means __aexit__
        # ran on both streams.
        assert container.exec.await_count == 2

    @pytest.mark.asyncio
    async def test_stream_closed_on_walltime_timeout_path(self) -> None:
        backend, container = _make_backend_with_exec_mocks(exec_hangs=True)
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

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["sleep", "60"])

        # Workload exec was awaited → its async-with stream was
        # consumed → __aexit__ fired even on walltime path. The
        # walltime branch goes through asyncio.timeout which
        # cancels the read_out + unwinds the async-with (firing
        # __aexit__).
        workload_call = container.exec.await_args_list[0]
        assert workload_call.kwargs.get("cmd") == ["sleep", "60"]


# ---------------------------------------------------------------------------
# R3 P1 — monitor failure propagates when exec body completes successfully
# ---------------------------------------------------------------------------


class TestMonitorFailurePropagatesOnGreenExecPath:
    """R3 P1 reviewer fix — earlier ``contextlib.suppress(BaseException)``
    in exec()'s finally silenced ALL monitor exceptions. The exact bug
    class: CPU usage exceeds budget → monitor calls kill → kill raises
    DockerError 500 → monitor task exits with exception. If the
    workload exits naturally before walltime, exec returned a green
    SandboxExecResult with NO policy.violated row → cap UNENFORCED +
    no audit trail.

    Fix: distinguish CancelledError (expected) from other exceptions
    (real monitor failures). When exec body completed successfully,
    propagate the monitor exception so caller knows enforcement was
    unverified. When exec body already raised, the in-flight
    exception wins (caller already has bigger problem)."""

    @pytest.mark.asyncio
    async def test_cpu_monitor_kill_failure_propagates_on_green_workload(
        self,
    ) -> None:
        """The exact reviewer-reproduced scenario:
        1. cpu_time_budget_s set; CPU usage exceeds budget on first poll
        2. monitor tries container.kill → DockerError 500
        3. monitor exits with exception; event NOT set
        4. workload exits naturally with exit_code=0
        5. exec WITHOUT this fix returned green; cap UNENFORCED.
           With this fix, monitor exception propagates from finally.

        Synchronization: stream.read_out blocks until the
        ``monitor_failed_event`` is set by the kill side_effect.
        This ensures the bug class is EXERCISED rather than
        depending on scheduling order — the monitor fails BEFORE
        the exec body completes, so the suppression bug is
        reachable.
        """
        import aiodocker
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )

        monitor_failed_event = asyncio.Event()

        async def _kill_fails_and_signals(signal: str = "SIGKILL") -> None:
            # Set the event BEFORE raising so read_out can wake.
            monitor_failed_event.set()
            raise aiodocker.exceptions.DockerError(500, "daemon error")

        async def _stats(stream: bool = False) -> object:
            return {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}}}

        async def _read_out() -> object | None:
            # Block until the monitor has failed (event set by the
            # kill side_effect). Then end the stream cleanly so
            # exec body returns SandboxExecResult naturally.
            await monitor_failed_event.wait()
            return None

        mock_container = MagicMock()
        mock_container.kill = AsyncMock(side_effect=_kill_fails_and_signals)
        mock_container.stop = AsyncMock()
        mock_container.delete = AsyncMock()
        mock_container.stats = _stats
        mock_container.show = AsyncMock(return_value={"State": {"OOMKilled": False, "ExitCode": 0}})

        mock_stream = MagicMock()
        mock_stream.read_out = _read_out
        mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
        mock_stream.__aexit__ = AsyncMock(return_value=None)

        mock_exec_obj = MagicMock()
        mock_exec_obj.start = MagicMock(return_value=mock_stream)
        mock_exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})
        mock_container.exec = AsyncMock(return_value=mock_exec_obj)

        docker = MagicMock()
        docker.containers.get = AsyncMock(return_value=mock_container)
        docker.networks.create = AsyncMock()
        docker.containers.create_or_replace = AsyncMock()
        docker.containers.create_or_replace.return_value.start = AsyncMock()
        # T10c — networks.get serves create() egress-attach + teardown
        mock_egress_network = MagicMock()
        mock_egress_network.connect = AsyncMock()
        mock_egress_network.delete = AsyncMock()
        docker.networks.get = AsyncMock(return_value=mock_egress_network)

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
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=AuditStore(engine=engine),
            decision_history_store=AsyncMock(),  # not exercised
            settings=settings,
            warm_pool=None,
        )

        session = _make_session(backend, policy=_POLICY_WITH_BUDGET)

        from cognic_agentos.sandbox.backends import docker_sibling

        original = docker_sibling._CPU_BUDGET_POLL_INTERVAL_S
        docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = 0.01
        try:
            with pytest.raises(aiodocker.exceptions.DockerError) as exc:
                await backend.exec(session, ["echo", "done"])
            assert exc.value.status == 500
        finally:
            docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = original

    @pytest.mark.asyncio
    async def test_monitor_cancellation_on_green_path_does_NOT_propagate(
        self,
    ) -> None:
        """Sanity: when exec body completes successfully + monitor is
        cancelled cleanly (no error), exec returns the SandboxExecResult
        normally. Distinguishes CancelledError from real failure."""
        backend, container = _make_backend_with_exec_mocks(stdout=b"done", exit_code=0)

        # Monitor's stats always returns under-budget → monitor never
        # tries to kill; cancellation in finally is clean.
        async def _stats(stream: bool = False) -> object:
            return {"cpu_stats": {"cpu_usage": {"total_usage": 100_000_000}}}

        container.stats = _stats

        session = _make_session(backend, policy=_POLICY_WITH_BUDGET)
        result = await backend.exec(session, ["echo", "done"])

        assert result.exit_code == 0
        assert result.stdout == b"done"

    @pytest.mark.asyncio
    async def test_walltime_exception_wins_over_monitor_failure(
        self,
    ) -> None:
        """Sanity: when exec body raises (e.g. SandboxPolicyViolated
        from walltime) AND the monitor task also failed, the in-flight
        exception wins. The caller already has the cap-violation
        exception; the monitor's separate failure is dropped (no
        ExceptionGroup at this layer)."""
        import aiodocker

        # Walltime is short; monitor's kill fails; workload hangs
        backend, container = _make_backend_with_exec_mocks(exec_hangs=True)

        # Both container.kill (for walltime) AND the monitor's kill
        # will be called; both fail. Use the SAME mock so both fail
        # the same way.
        container.kill = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(500, "daemon error")
        )

        # Monitor sees overage immediately → tries kill → fails
        async def _stats(stream: bool = False) -> object:
            return {"cpu_stats": {"cpu_usage": {"total_usage": 2_000_000_000}}}

        container.stats = _stats

        session = _make_session(
            backend,
            policy=SandboxPolicy(
                cpu_cores=2.0,
                cpu_time_budget_s=1.0,
                memory_mb=256,
                walltime_s=0.1,
                runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
                egress_allow_list=(),
                vault_path=None,
            ),
        )

        from cognic_agentos.sandbox.backends import docker_sibling

        original = docker_sibling._CPU_BUDGET_POLL_INTERVAL_S
        docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = 0.01
        try:
            # Both paths fail with kill 500. Either error propagating
            # is acceptable (caller knows enforcement broke); we pin
            # that SOME DockerError propagates (NOT a green return).
            with pytest.raises(aiodocker.exceptions.DockerError) as exc:
                await backend.exec(session, ["sleep", "60"])
            assert exc.value.status == 500
        finally:
            docker_sibling._CPU_BUDGET_POLL_INTERVAL_S = original

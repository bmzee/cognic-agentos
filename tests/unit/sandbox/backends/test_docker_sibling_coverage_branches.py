"""Sprint 8A T13 R6 — DockerSiblingSandboxBackend coverage repair.

NON-env-gated focused regressions closing missing lines + branches on
``src/cognic_agentos/sandbox/backends/docker_sibling.py`` per the
T12 95% line / 90% branch coverage floor (gate at
``tools/check_critical_coverage.py``). Targets meaningful negative /
error / race paths the existing suites at
``test_docker_sibling_{lifecycle,resource_caps,exec_classification,
egress_classification,audit_emission,cap_derivation,pure_helpers}.py``
did not exercise — NOT broad coverage padding.

Mirrors the Sprint-7B.4 T14 R0 ``test_stream_routes_coverage_branches.py``
pattern: a focused file dedicated to specific uncovered branches.

Every test names the production branch it covers + the doctrine that
branch implements.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiodocker

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
    _classify_egress_refusal,
    _cpu_time_budget_monitor,
    _ProxyLogReadFailure,
)
from cognic_agentos.sandbox.protocol import ProxyAccessRecord

# ---------------------------------------------------------------------------
# Shared fixtures (NON-env-gated — all aiodocker calls mocked)
# ---------------------------------------------------------------------------


_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
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
    docker_client: AsyncMock | None = None,
    catalog: MagicMock | None = None,
    warm_pool: AsyncMock | None = None,
) -> DockerSiblingSandboxBackend:
    """Construct a DockerSiblingSandboxBackend with mocked deps for
    non-env-gated unit tests. The catalog defaults to
    ``is_canonical=True`` (admission accept) so tests that care about
    the false branch must override explicitly."""
    if docker_client is None:
        docker_client = AsyncMock()
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
    return DockerSiblingSandboxBackend(
        docker_client=docker_client,
        image_catalog=catalog,
        credential_adapter=MagicMock(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=AsyncMock(),
        settings=settings,
        warm_pool=warm_pool,
    )


# ---------------------------------------------------------------------------
# _classify_egress_refusal — loop continue branch
# ---------------------------------------------------------------------------


class TestEgressClassifierLoopContinue:
    """docker_sibling.py:348-355 — pure-functional classifier; branch
    [353,348] is the loop iteration continuation when a record has
    ``outcome="refused"`` BUT ``refusal_reason`` matches NEITHER of
    the two ProxyAccessRefusalReason literal arms.

    In production this is unreachable through the proxy.py materialiser
    (the joint-invariant guard at proxy.py:342-357 rejects refused +
    unknown reason at fail-loud ValueError). But the classifier is a
    pure helper and accepts ``str | None`` for ``refusal_reason`` to
    avoid an import cycle — a malformed record constructed without
    going through the materialiser MUST be skipped, not crash.
    """

    def test_classifier_skips_refused_record_with_unknown_reason(self) -> None:
        """docker_sibling.py:353→348 — loop continue on unmatched reason.

        Two records: first refused-but-unknown-reason (skip-continue);
        second refused-with-not_in_allow_list (return first known).
        """
        unknown = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime.now(UTC),
            policy_id="t-1/policy-1",
            outcome="refused",
            refusal_reason="some_future_unknown_reason",
        )
        known = ProxyAccessRecord(
            host="forbidden.example.com",
            method="GET",
            timestamp=datetime.now(UTC),
            policy_id="t-1/policy-1",
            outcome="refused",
            refusal_reason="not_in_allow_list",
        )
        result = _classify_egress_refusal((unknown, known))
        assert result == "egress_host_not_allow_listed"

    def test_classifier_returns_none_when_only_unknown_refusal_reasons(
        self,
    ) -> None:
        """docker_sibling.py:355 — both refused records have unknown
        reasons; the loop ends + return None falls through.
        """
        record = ProxyAccessRecord(
            host="api.example.com",
            method="GET",
            timestamp=datetime.now(UTC),
            policy_id="t-1/policy-1",
            outcome="refused",
            refusal_reason="yet_another_unknown",
        )
        assert _classify_egress_refusal((record,)) is None


# ---------------------------------------------------------------------------
# _cpu_time_budget_monitor — malformed stats shape handling
# ---------------------------------------------------------------------------


class TestCpuMonitorMalformedShapes:
    """docker_sibling.py:478-501 — R1 P1.4 fix: malformed stats
    snapshots MUST NOT crash the monitor task (the in-flight exec's
    finally suppresses task failures + the CPU budget would silently
    UNENFORCE until walltime fired).

    Best-effort: continue polling on malformed shapes; container.kill
    still fires on the next VALID snapshot that exceeds the budget.
    """

    @pytest.mark.asyncio
    async def test_monitor_continues_when_stats_returns_list_then_kills_on_valid_snapshot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:480-481 — branch [480,481] stats-as-list."""
        # Mock asyncio.sleep so the test does not actually wait.
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        container = AsyncMock()
        # First call returns a list shape (line 480→481 unwrap to [0]);
        # second call returns a valid dict that exceeds budget.
        container.stats = AsyncMock(
            side_effect=[
                [{"cpu_stats": {"cpu_usage": {"total_usage": 100}}}],
                {"cpu_stats": {"cpu_usage": {"total_usage": 999_999_999_999}}},
            ]
        )
        container.kill = AsyncMock()
        event = asyncio.Event()
        # budget=0.0001s so 100_000_000ns (0.1s) already exceeds.
        # First poll returns 100 ns (under budget) so monitor loops;
        # second poll exceeds → kill + set event + return.
        await _cpu_time_budget_monitor(
            container=container, budget_s=0.0001, cpu_violated_event=event
        )
        assert event.is_set()
        container.kill.assert_awaited_once_with(signal="SIGKILL")

    @pytest.mark.asyncio
    async def test_monitor_continues_when_stats_returns_empty_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:480-481 — branch [480,481] stats=[] → {} fallback."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        container = AsyncMock()
        container.stats = AsyncMock(
            side_effect=[
                [],  # empty list — `stats[0] if stats else {}` → {}
                {"cpu_stats": {"cpu_usage": {"total_usage": 999_999_999_999}}},
            ]
        )
        container.kill = AsyncMock()
        event = asyncio.Event()
        await _cpu_time_budget_monitor(
            container=container, budget_s=0.0001, cpu_violated_event=event
        )
        assert event.is_set()

    @pytest.mark.asyncio
    async def test_monitor_continues_when_stats_returns_non_dict_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:482-483 — branch [482,483] non-dict raises TypeError."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        container = AsyncMock()
        container.stats = AsyncMock(
            side_effect=[
                "not-a-dict-or-list",  # TypeError at line 483
                {"cpu_stats": {"cpu_usage": {"total_usage": 999_999_999_999}}},
            ]
        )
        container.kill = AsyncMock()
        event = asyncio.Event()
        await _cpu_time_budget_monitor(
            container=container, budget_s=0.0001, cpu_violated_event=event
        )
        assert event.is_set()

    @pytest.mark.asyncio
    async def test_monitor_continues_when_total_usage_is_not_int(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:491-492 — branch [491,492] total_usage not int."""
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        container = AsyncMock()
        container.stats = AsyncMock(
            side_effect=[
                {"cpu_stats": {"cpu_usage": {"total_usage": "not-an-int"}}},
                {"cpu_stats": {"cpu_usage": {"total_usage": 999_999_999_999}}},
            ]
        )
        container.kill = AsyncMock()
        event = asyncio.Event()
        await _cpu_time_budget_monitor(
            container=container, budget_s=0.0001, cpu_violated_event=event
        )
        assert event.is_set()

    @pytest.mark.asyncio
    async def test_monitor_re_raises_cancelled_error_cleanly(self) -> None:
        """docker_sibling.py:494-495 — asyncio.CancelledError propagates.

        The monitor task is cancelled by exec()'s finally block; the
        coroutine MUST re-raise CancelledError so the task state
        unwinds cleanly. A swallow would leak the cancellation signal.
        """
        container = AsyncMock()
        # First stats call raises CancelledError mid-await.
        container.stats = AsyncMock(side_effect=asyncio.CancelledError())
        event = asyncio.Event()
        with pytest.raises(asyncio.CancelledError):
            await _cpu_time_budget_monitor(
                container=container, budget_s=0.001, cpu_violated_event=event
            )
        # Event MUST NOT be set on cancellation — the monitor never
        # observed a budget violation, so cpu_violated_event stays clear.
        assert not event.is_set()


# ---------------------------------------------------------------------------
# DockerSiblingSession.exec / .destroy delegation methods
# ---------------------------------------------------------------------------


class TestSessionDelegationMethods:
    """docker_sibling.py:687-696 — DockerSiblingSession.exec + .destroy
    delegate to the backend per spec §5 SandboxSession Protocol.

    The session dataclass is the Protocol-shape carrier; the actual
    work lives on the backend. These delegation methods are the
    single-line bridges that make `session.exec(...)` + `session.destroy()`
    work after the consumer receives the SandboxSession from
    `backend.create()`.
    """

    @pytest.mark.asyncio
    async def test_session_exec_delegates_to_backend(self) -> None:
        """docker_sibling.py:687-693 — session.exec → backend.exec."""
        backend = AsyncMock()
        expected_result = MagicMock(name="SandboxExecResult")
        backend.exec.return_value = expected_result
        session = DockerSiblingSession(
            session_id="s-1",
            tenant_id="t-1",
            policy=_POLICY,
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _actor_subject="test",
            _internal_network_name="net-1",
            _sidecar_container_name="proxy-1",
        )
        result = await session.exec(["echo", "ok"], timeout_s=5.0)
        backend.exec.assert_awaited_once_with(session, ["echo", "ok"], timeout_s=5.0)
        assert result is expected_result

    @pytest.mark.asyncio
    async def test_session_destroy_delegates_to_backend(self) -> None:
        """docker_sibling.py:695-696 — session.destroy → backend.destroy."""
        backend = AsyncMock()
        session = DockerSiblingSession(
            session_id="s-1",
            tenant_id="t-1",
            policy=_POLICY,
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _actor_subject="test",
            _internal_network_name="net-1",
            _sidecar_container_name="proxy-1",
        )
        await session.destroy()
        backend.destroy.assert_awaited_once_with(session)


# ---------------------------------------------------------------------------
# create() — wrong session type, warm-miss cold path, warm non-DSS branch,
# cold-create rollback
# ---------------------------------------------------------------------------


class TestCreateBranches:
    """docker_sibling.py create() branches.

    * Branch [773,808] — warm_pool.checkout returns None → falls through
      to cold-create admit_policy at line 808.
    * Branch [783,795] — warm_pool.checkout returns a SandboxSession
      that is NOT a DockerSiblingSession (alternate backend Protocol
      impl); isinstance check at 783 fails so the mutation block at
      784-785 skips, but the emit-lifecycle-created block at 795+
      still fires.
    * Lines 847-858 — cold-create exception in _start_proxy_sidecar OR
      _start_sandbox_container triggers _teardown_session_state +
      re-raise.
    """

    @pytest.mark.asyncio
    async def test_create_cold_path_when_warm_pool_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:773→808 — branch [773,808] warm-miss cold path."""
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=None)
        backend = _make_backend(warm_pool=warm_pool)
        # Mock the three create steps so we don't hit real Docker.
        # Use patch.object so we can assert they were called.
        monkeypatch.setattr(backend, "_create_internal_network", AsyncMock())
        monkeypatch.setattr(backend, "_create_egress_network", AsyncMock())
        monkeypatch.setattr(backend, "_start_proxy_sidecar", AsyncMock())
        monkeypatch.setattr(backend, "_start_sandbox_container", AsyncMock())
        monkeypatch.setattr(backend, "_emit_lifecycle_created", AsyncMock())
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=True,
        )
        # Cold-path proof: admit + create steps fired.
        backend._create_internal_network.assert_awaited_once()  # type: ignore[attr-defined]
        backend._start_proxy_sidecar.assert_awaited_once()  # type: ignore[attr-defined]
        backend._start_sandbox_container.assert_awaited_once()  # type: ignore[attr-defined]
        backend._emit_lifecycle_created.assert_awaited_once()  # type: ignore[attr-defined]
        assert isinstance(session, DockerSiblingSession)

    @pytest.mark.asyncio
    async def test_create_warm_returns_non_dss_skips_mutation_but_emits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:783-795 — branch [783,795] warm session
        from an alternate backend Protocol implementation is NOT a
        DockerSiblingSession; isinstance check fails, mutation block
        skips, but lifecycle.created emission still fires + the
        non-DSS session is returned to the caller.
        """
        # Mock SandboxSession that is NOT a DockerSiblingSession.
        warm = MagicMock(name="AlternateSandboxSession")
        warm_pool = AsyncMock()
        warm_pool.checkout = AsyncMock(return_value=warm)
        backend = _make_backend(warm_pool=warm_pool)
        monkeypatch.setattr(backend, "_emit_lifecycle_created", AsyncMock())
        monkeypatch.setattr(backend, "destroy", AsyncMock())
        result = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=True,
        )
        # Non-DSS path: emit fired, but the warm.warm_pool_hit
        # mutation at line 784 did NOT run (isinstance was False).
        backend._emit_lifecycle_created.assert_awaited_once()  # type: ignore[attr-defined]
        assert result is warm

    @pytest.mark.asyncio
    async def test_create_rolls_back_when_start_proxy_sidecar_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:847-858 — partial-create rollback envelope.

        When _start_proxy_sidecar raises after network creation,
        _teardown_session_state MUST fire to remove the created network
        before the exception propagates. Without rollback the network
        leaks per the R2 P1.1 audit-failure-ordering doctrine extended
        to cold-create failures.
        """
        backend = _make_backend()
        monkeypatch.setattr(backend, "_create_internal_network", AsyncMock())
        monkeypatch.setattr(backend, "_create_egress_network", AsyncMock())
        monkeypatch.setattr(
            backend,
            "_start_proxy_sidecar",
            AsyncMock(side_effect=RuntimeError("docker start refused")),
        )
        monkeypatch.setattr(backend, "_teardown_session_state", AsyncMock())
        with pytest.raises(RuntimeError, match="docker start refused"):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )
        backend._teardown_session_state.assert_awaited_once()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# exec() / destroy() — TypeError on wrong session type
# ---------------------------------------------------------------------------


class TestExecAndDestroyWrongSessionType:
    """docker_sibling.py:937-941 + 1191-1195 — TypeError contracts.

    Both exec() and destroy() require a DockerSiblingSession; passing
    any other SandboxSession Protocol implementation MUST raise
    TypeError so cross-backend session leaks fail-loud (the Protocol
    does not require us to handle other backends' session types, and
    docker-specific fields like _internal_network_name + _sidecar_
    container_name are absent on other implementations).
    """

    @pytest.mark.asyncio
    async def test_exec_raises_type_error_on_non_dss_session(self) -> None:
        """docker_sibling.py:937-938 — branch [937,938]."""
        backend = _make_backend()
        wrong = MagicMock(name="AlternateSandboxSession")
        with pytest.raises(TypeError, match=r"DockerSiblingSandboxBackend\.exec expects"):
            await backend.exec(wrong, ["echo", "ok"])

    @pytest.mark.asyncio
    async def test_destroy_raises_type_error_on_non_dss_session(self) -> None:
        """docker_sibling.py:1191-1192 — branch [1191,1192]."""
        backend = _make_backend()
        wrong = MagicMock(name="AlternateSandboxSession")
        with pytest.raises(TypeError, match=r"DockerSiblingSandboxBackend\.destroy expects"):
            await backend.destroy(wrong)


# ---------------------------------------------------------------------------
# health() — both paths
# ---------------------------------------------------------------------------


class TestHealth:
    """docker_sibling.py:1217-1230 — backend readiness check.

    Returns ``ok`` if docker.system.info() succeeds; ``unavailable``
    on ANY exception (broad except per R1 P1.1 — any failure to reach
    the docker daemon means the backend cannot satisfy create() so
    health MUST reflect that to the harness).
    """

    @pytest.mark.asyncio
    async def test_health_returns_ok_when_docker_info_succeeds(self) -> None:
        """docker_sibling.py:1223-1230 — green path."""
        from cognic_agentos.sandbox.protocol import SandboxBackendHealth

        docker_client = AsyncMock()
        docker_client.system.info = AsyncMock(return_value={"ID": "docker-id"})
        backend = _make_backend(docker_client=docker_client)
        health = await backend.health()
        assert isinstance(health, SandboxBackendHealth)
        assert health.status == "ok"
        assert health.detail == ""

    @pytest.mark.asyncio
    async def test_health_returns_unavailable_when_docker_info_raises(
        self,
    ) -> None:
        """docker_sibling.py:1224-1229 — exception path."""
        docker_client = AsyncMock()
        docker_client.system.info = AsyncMock(side_effect=RuntimeError("connection refused"))
        backend = _make_backend(docker_client=docker_client)
        health = await backend.health()
        assert health.status == "unavailable"
        assert "docker daemon unreachable" in health.detail
        assert "connection refused" in health.detail


# ---------------------------------------------------------------------------
# _start_proxy_sidecar — proxy image not canonical refusal
# ---------------------------------------------------------------------------


class TestStartProxySidecarCatalogRefusal:
    """docker_sibling.py:1333-1342 — branch [1333,1334] proxy sidecar
    image NOT in canonical catalog → SandboxLifecycleRefused with
    closed-enum ``sandbox_image_digest_not_in_canonical_catalog``.

    The egress enforcement component MUST be catalog-verified per spec
    §9 + T10c R1 P1.1 reviewer fix. Without this gate a swapped proxy
    sidecar could allow forbidden outbound traffic.
    """

    @pytest.mark.asyncio
    async def test_start_proxy_sidecar_refuses_when_proxy_image_not_canonical(
        self,
    ) -> None:
        """docker_sibling.py:1333-1342 — non-canonical proxy refusal."""
        catalog = MagicMock()
        # is_canonical returns False on the proxy image digest probe →
        # refusal arm fires.
        catalog.is_canonical.return_value = False
        backend = _make_backend(catalog=catalog)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend._start_proxy_sidecar(
                policy=_POLICY,
                session_id="s-1",
                container_name="s-1-proxy",
                internal_net_name="net-1",
                egress_net_name="egress-1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"


# ---------------------------------------------------------------------------
# _destroy_container_if_exists + _destroy_network_if_exists — DockerError swallow
# ---------------------------------------------------------------------------


class TestTeardownIdempotency:
    """docker_sibling.py:1419-1438 — best-effort idempotent teardown.

    Both helpers swallow ``aiodocker.exceptions.DockerError`` on
    not-found / already-removed so the teardown completes even during
    partial-create rollback OR double-destroy. The DockerError-swallow
    contract is the difference between a clean idempotent destroy() +
    a poisoned destroy() that crashes on the second call.
    """

    @pytest.mark.asyncio
    async def test_destroy_container_returns_early_on_get_docker_error(
        self,
    ) -> None:
        """docker_sibling.py:1422-1425 — early return on get DockerError."""
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(404, "no such")
        )
        backend = _make_backend(docker_client=docker_client)
        # Should NOT raise — DockerError on get means container is gone.
        await backend._destroy_container_if_exists("ghost-container")

    @pytest.mark.asyncio
    async def test_destroy_container_swallows_docker_error_on_stop_and_delete(
        self,
    ) -> None:
        """docker_sibling.py:1426-1429 — DockerError swallowed on
        stop + delete (container exists but stop / delete fails)."""
        container = AsyncMock()
        container.stop = AsyncMock(side_effect=aiodocker.exceptions.DockerError(409, "conflict"))
        container.delete = AsyncMock(side_effect=aiodocker.exceptions.DockerError(404, "gone"))
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=container)
        backend = _make_backend(docker_client=docker_client)
        # Both swallowed — no raise.
        await backend._destroy_container_if_exists("flaky-container")
        container.stop.assert_awaited_once()
        container.delete.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_destroy_network_returns_early_on_get_docker_error(self) -> None:
        """docker_sibling.py:1433-1436 — early return on get DockerError."""
        docker_client = AsyncMock()
        docker_client.networks.get = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(404, "no such")
        )
        backend = _make_backend(docker_client=docker_client)
        await backend._destroy_network_if_exists("ghost-network")

    @pytest.mark.asyncio
    async def test_destroy_network_swallows_docker_error_on_delete(self) -> None:
        """docker_sibling.py:1437-1438 — DockerError on delete swallowed."""
        network = AsyncMock()
        network.delete = AsyncMock(side_effect=aiodocker.exceptions.DockerError(409, "in use"))
        docker_client = AsyncMock()
        docker_client.networks.get = AsyncMock(return_value=network)
        backend = _make_backend(docker_client=docker_client)
        await backend._destroy_network_if_exists("flaky-network")
        network.delete.assert_awaited_once()


# ---------------------------------------------------------------------------
# _read_proxy_log_from_sidecar — fail-closed contracts
# ---------------------------------------------------------------------------


class TestReadProxyLogFailClosed:
    """docker_sibling.py:1477-1547 — T10c R1 P1.2 FAIL-CLOSED contract.

    The canonical proxy image's contract is: ``_PROXY_LOG_PATH`` ALWAYS
    exists + is readable; empty file = no outbound calls. ANY failure
    mode (container gone / cat exit nonzero / unexpected exception)
    raises ``_ProxyLogReadFailure`` so exec() can fail-closed via
    ``SandboxPolicyViolated(egress_audit_unreadable)`` — without this,
    a denied outbound request could surface as a green exec_completed
    row when the sidecar died after refusing but before backend read.
    """

    @pytest.mark.asyncio
    async def test_raises_when_sidecar_container_gone(self) -> None:
        """docker_sibling.py:1507-1513 — sidecar unreachable raises."""
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(404, "no such")
        )
        backend = _make_backend(docker_client=docker_client)
        with pytest.raises(_ProxyLogReadFailure, match="unreachable during proxy_log readback"):
            await backend._read_proxy_log_from_sidecar("dead-sidecar")

    @pytest.mark.asyncio
    async def test_raises_when_cat_exits_nonzero(self) -> None:
        """docker_sibling.py:1538-1543 — cat nonzero raises _ProxyLogReadFailure."""

        class _FakeStream:
            async def __aenter__(self) -> _FakeStream:
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def read_out(self) -> Any:
                return None  # empty stream

        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(return_value=_FakeStream())
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 1})
        sidecar = AsyncMock()
        sidecar.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=sidecar)
        backend = _make_backend(docker_client=docker_client)
        with pytest.raises(_ProxyLogReadFailure, match="exited 1"):
            await backend._read_proxy_log_from_sidecar("flaky-sidecar")

    @pytest.mark.asyncio
    async def test_re_raises_proxy_log_read_failure_unchanged(self) -> None:
        """docker_sibling.py:1544-1545 — explicit `except _ProxyLogReadFailure: raise`.

        The nonzero-cat-exit path RAISES _ProxyLogReadFailure inside
        the same try block; the symmetric exception ordering catches
        the typed exception BEFORE the broad `except Exception` so the
        nonzero-exit detail string survives unchanged. Without this
        ordering, the inner _ProxyLogReadFailure would be re-wrapped
        as "unexpected error reading proxy_log: ..." losing detail.
        """

        class _StreamRaisingProxyLogReadFailure:
            async def __aenter__(self) -> _StreamRaisingProxyLogReadFailure:
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def read_out(self) -> Any:
                raise _ProxyLogReadFailure("inner-typed-failure")

        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(return_value=_StreamRaisingProxyLogReadFailure())
        sidecar = AsyncMock()
        sidecar.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=sidecar)
        backend = _make_backend(docker_client=docker_client)
        # Original detail preserved — NOT re-wrapped by the broad except.
        with pytest.raises(_ProxyLogReadFailure, match="inner-typed-failure"):
            await backend._read_proxy_log_from_sidecar("sidecar-1")

    @pytest.mark.asyncio
    async def test_wraps_unexpected_exception_as_proxy_log_read_failure(
        self,
    ) -> None:
        """docker_sibling.py:1546-1547 — broad `except Exception` re-wrap."""

        class _StreamRaisingRuntimeError:
            async def __aenter__(self) -> _StreamRaisingRuntimeError:
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def read_out(self) -> Any:
                raise RuntimeError("socket reset mid-read")

        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(return_value=_StreamRaisingRuntimeError())
        sidecar = AsyncMock()
        sidecar.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=sidecar)
        backend = _make_backend(docker_client=docker_client)
        with pytest.raises(_ProxyLogReadFailure, match="unexpected error reading proxy_log"):
            await backend._read_proxy_log_from_sidecar("sidecar-2")

    @pytest.mark.asyncio
    async def test_skips_stderr_message_in_cat_read_loop(self) -> None:
        """docker_sibling.py:1528→1524 — branch [1528,1524] stderr skip.

        The cat-read loop appends to chunks only on `message.stream == 1`
        (stdout); a stderr message (stream==2) is skipped. The branch
        continues back to the loop top so the next read can fire.
        """

        class _MessageStderr:
            stream = 2
            data = b"warning written to stderr"

        class _MessageStdout:
            stream = 1
            data = (
                b'{"host":"api.example.com","method":"GET",'
                b'"timestamp":"2026-05-17T12:00:00+00:00","policy_id":"p",'
                b'"outcome":"allowed","refusal_reason":null}\n'
            )

        # The stream yields [stderr, stdout, None] — stderr is skipped
        # via the [1528,1524] branch; stdout is appended; None ends loop.
        messages = [_MessageStderr(), _MessageStdout(), None]
        messages_iter = iter(messages)

        class _Stream:
            async def __aenter__(self) -> _Stream:
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def read_out(self) -> Any:
                return next(messages_iter)

        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(return_value=_Stream())
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})
        sidecar = AsyncMock()
        sidecar.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=sidecar)
        backend = _make_backend(docker_client=docker_client)
        result = await backend._read_proxy_log_from_sidecar("sidecar-3")
        # Exactly one record decoded (the stdout chunk; stderr was skipped).
        assert len(result) == 1
        assert result[0].outcome == "allowed"

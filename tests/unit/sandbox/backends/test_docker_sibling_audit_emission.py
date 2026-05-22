"""Sprint 8A T10a R1 — DockerSiblingSandboxBackend audit emission.

NON-env-gated unit tests pinning the lifecycle.created +
lifecycle.destroyed chain rows per spec §4.3 wire-protocol-public
taxonomy + R1 P1.1 + R1 P1.2 reviewer fixes.

Uses MagicMock for the aiodocker client + the admit_policy seam, so
these tests do NOT need a real Docker daemon. The env-gated tests at
``test_docker_sibling_lifecycle.py`` exercise the same paths
end-to-end against a real daemon.

R1 P1.1 — both warm-hit AND cold-create paths MUST emit
``sandbox.lifecycle.created`` with payload ``{warm_pool_hit: bool}``.
R1 P1.2 — destroy() MUST emit ``sandbox.lifecycle.destroyed`` with
payload ``{duration_s: float}``; idempotent second destroy() MUST
NOT emit a second row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",),
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
    """Decision-history-store mock matching emit_sandbox_event's
    ``await store.append_with_precondition(...)`` contract."""
    store = AsyncMock()
    store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)
    return store


def _make_backend(
    *, dh_store: AsyncMock | None = None, warm_pool: AsyncMock | None = None
) -> DockerSiblingSandboxBackend:
    """Backend wired with mocked aiodocker + admit_policy seams so
    create() / destroy() can run without a real Docker daemon."""
    import aiodocker

    docker = MagicMock()
    docker.networks.create = AsyncMock()
    docker.containers.create_or_replace = AsyncMock()
    # Each created container mock returns an AsyncMock for start()
    docker.containers.create_or_replace.return_value.start = AsyncMock()
    # Teardown path: ``get`` raises DockerError so the "swallow on
    # not-found / already-removed" branches at
    # _destroy_container_if_exists / _destroy_network_if_exists fire
    # cleanly. The destroy() path's audit emission is what these
    # tests pin; the docker-teardown side is exercised by the
    # env-gated lifecycle tests.
    docker.containers.get = AsyncMock(
        side_effect=aiodocker.exceptions.DockerError(404, "not found")
    )
    # T10c — networks.get serves TWO use cases now:
    # 1. create() path attaches sidecar to egress network via
    #    networks.get(egress_name).connect(...)  → needs success
    # 2. teardown path's _destroy_network_if_exists wants 404
    #
    # The audit-emission tests pin emit behaviour, not teardown
    # behaviour, so we return a mock network whose connect() +
    # delete() are AsyncMocks; teardown just silently runs them.
    mock_network = MagicMock()
    mock_network.connect = AsyncMock()
    mock_network.delete = AsyncMock()
    docker.networks.get = AsyncMock(return_value=mock_network)
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
    return DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store or _make_dh_store(),
        settings=settings,
        warm_pool=warm_pool,
    )


# ---------------------------------------------------------------------------
# R1 P1.1 — lifecycle.created emission (both paths)
# ---------------------------------------------------------------------------


class TestLifecycleCreatedEmittedOnColdPath:
    """R1 P1.1 reviewer fix — cold-create path was previously absent
    from the evidence chain. Cold create MUST emit
    ``sandbox.lifecycle.created`` with ``{warm_pool_hit: False}``."""

    @pytest.mark.asyncio
    async def test_cold_create_emits_lifecycle_created_with_warm_pool_hit_false(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)

        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )

        # admit_policy + container start + ONE chain row for
        # lifecycle.created
        dh_store.append_with_precondition.assert_awaited_once()
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.created"
        assert record.payload["warm_pool_hit"] is False
        assert record.payload["session_id"] == session.session_id
        assert record.actor_id == "consumer-actor-id"
        assert record.tenant_id == "t-1"
        assert record.iso_controls == ("ISO42001.A.6.2.5",)


class TestLifecycleCreatedEmittedOnWarmPath:
    """R1 P1.1 reviewer fix — warm-hit path MUST also emit
    ``sandbox.lifecycle.created`` with ``{warm_pool_hit: True}``,
    pairing the warm-pool's own ``sandbox.warm_pool.checked_out``
    event into a complete warm-hit evidence pair."""

    @pytest.mark.asyncio
    async def test_warm_hit_emits_lifecycle_created_with_warm_pool_hit_true(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        # Warm pool returns a pre-existing DockerSiblingSession (one
        # the pool previously warmed).
        warm_session = DockerSiblingSession(
            session_id="warm-session-id",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,  # set to True after checkout
            _backend=MagicMock(),
            _internal_network_name="net-x",
            _sidecar_container_name="warm-session-id-proxy",
            _actor_subject="warming-service-actor",
        )
        warm_pool = AsyncMock()
        warm_pool.checkout.return_value = warm_session
        backend = _make_backend(dh_store=dh_store, warm_pool=warm_pool)

        result = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=True,
        )

        assert result is warm_session
        assert result.warm_pool_hit is True
        # _actor_subject re-bound to the consumer's actor so a later
        # destroy() audits the CONSUMER who owns the session lifetime
        # (NOT the AgentOS service actor that warmed it).
        assert result._actor_subject == "consumer-actor-id"

        # Exactly ONE chain row from the backend (the warm-pool's own
        # checked_out emission happens via the pool's own dh_store
        # call and is not on this backend's dh_store unless the pool
        # was wired with the same store — it isn't in this test).
        dh_store.append_with_precondition.assert_awaited_once()
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.created"
        assert record.payload["warm_pool_hit"] is True
        assert record.payload["session_id"] == "warm-session-id"
        assert record.actor_id == "consumer-actor-id"


# ---------------------------------------------------------------------------
# R1 P1.2 — lifecycle.destroyed emission + idempotency
# ---------------------------------------------------------------------------


class TestLifecycleDestroyedEmission:
    """R1 P1.2 reviewer fix — destroy() MUST emit
    ``sandbox.lifecycle.destroyed`` with ``{duration_s: float}``.
    Idempotent second destroy() does NOT emit again."""

    @pytest.mark.asyncio
    async def test_destroy_emits_lifecycle_destroyed_with_duration_s(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)

        # Create + reset to isolate the destroy emission
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        dh_store.append_with_precondition.reset_mock()

        await backend.destroy(session)

        dh_store.append_with_precondition.assert_awaited_once()
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.destroyed"
        assert "duration_s" in record.payload
        assert isinstance(record.payload["duration_s"], float)
        assert record.payload["duration_s"] >= 0.0
        assert record.payload["session_id"] == session.session_id
        assert record.actor_id == "consumer-actor-id"
        assert record.iso_controls == ("ISO42001.A.6.2.5",)

    @pytest.mark.asyncio
    async def test_second_destroy_does_not_emit_second_chain_row(
        self,
    ) -> None:
        """Idempotency MUST be evidence-shaped — repeat destroy()
        emits ONE chain row, not N. The session._destroyed flag is
        set on the first call so the second call short-circuits the
        emission while still tolerating the underlying docker
        teardown's idempotent no-op behavior."""
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        dh_store.append_with_precondition.reset_mock()

        await backend.destroy(session)
        await backend.destroy(session)  # idempotent — no second emit

        dh_store.append_with_precondition.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_duration_s_reflects_elapsed_time(self) -> None:
        """``duration_s`` MUST be computed from
        ``datetime.now(UTC) - session.created_at``. Patch the now()
        clock so the assertion can pin the elapsed delta without
        sleep-based flake."""
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        # Move the clock forward 42 seconds for the destroy emission's
        # now() call. session.created_at was set under the real clock
        # during create(), so we patch JUST the helper's now() lookup.
        future = session.created_at + _delta(seconds=42)
        dh_store.append_with_precondition.reset_mock()
        with patch("cognic_agentos.sandbox.backends.docker_sibling.datetime") as mock_dt:
            mock_dt.now = MagicMock(return_value=future)
            await backend.destroy(session)

        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        # Allow 0.5s tolerance for arithmetic round-trip through the patch
        assert 41.5 <= record.payload["duration_s"] <= 42.5


def _delta(*, seconds: float) -> timedelta:
    """timedelta shim so the test reads naturally."""
    return timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# R2 P1.1 — created emit failure MUST roll back / destroy the session
# ---------------------------------------------------------------------------


class _AuditFailure(Exception):
    """Sentinel exception raised by the dh_store mock to simulate a
    transient audit-append failure (DB outage, lock timeout, etc.)."""


class TestCreatedEmitFailureRollsBackColdPath:
    """R2 P1.1 reviewer fix — cold-path emit failure MUST tear down
    the containers + network it created. Without this, the caller
    never receives the session, but the docker objects keep running."""

    @pytest.mark.asyncio
    async def test_cold_create_emit_failure_tears_down_and_reraises(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        dh_store.append_with_precondition.side_effect = _AuditFailure(
            "simulated audit-append failure on lifecycle.created"
        )
        backend = _make_backend(dh_store=dh_store)
        # Spy the teardown helper so we can assert it was called with
        # the right session_id when emit fails.
        backend._teardown_session_state = AsyncMock(  # type: ignore[method-assign]
            wraps=backend._teardown_session_state
        )

        with pytest.raises(_AuditFailure):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )

        # The teardown helper was called as part of the cleanup
        # envelope after emit failed.
        backend._teardown_session_state.assert_awaited()
        # Exactly ONE audit attempt — the failed one. No second
        # lifecycle.destroyed since the session never reached the
        # consumer (no lifecycle.created was successful).
        assert dh_store.append_with_precondition.await_count == 1


class TestCreatedEmitFailureRollsBackWarmPath:
    """R2 P1.1 reviewer fix — warm-path emit failure MUST destroy the
    checked-out warm session. Without this, the pool already emitted
    warm_pool.checked_out (marking the session as taken) but the
    consumer never receives the session — orphan."""

    @pytest.mark.asyncio
    async def test_warm_hit_emit_failure_destroys_warm_session_and_reraises(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        # First call (lifecycle.created) fails; SECOND call
        # (lifecycle.destroyed from the rollback's backend.destroy)
        # succeeds.
        dh_store.append_with_precondition.side_effect = [
            _AuditFailure("simulated audit failure on lifecycle.created"),
            (uuid.uuid4(), b"\x00" * 32),
        ]
        warm_session = DockerSiblingSession(
            session_id="warm-session-id",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=MagicMock(),
            _internal_network_name="net-x",
            _sidecar_container_name="warm-session-id-proxy",
            _actor_subject="warming-service-actor",
        )
        warm_pool = AsyncMock()
        warm_pool.checkout.return_value = warm_session
        backend = _make_backend(dh_store=dh_store, warm_pool=warm_pool)

        with pytest.raises(_AuditFailure):
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=True,
            )

        # The rollback destroyed the warm session, which fired a
        # lifecycle.destroyed audit row (so total appends == 2).
        # The first append failed (lifecycle.created); the second
        # succeeded (lifecycle.destroyed from backend.destroy).
        assert dh_store.append_with_precondition.await_count == 2
        # _destroyed flag set on the warm session
        assert warm_session._destroyed is True


# ---------------------------------------------------------------------------
# R2 P1.2 — destroy flag MUST NOT be set until emit succeeds
# ---------------------------------------------------------------------------


class TestDestroyEmitFailureRetrySucceeds:
    """R2 P1.2 reviewer fix — destroy() previously set
    ``session._destroyed = True`` BEFORE awaiting the audit emit.
    A transient audit-append failure permanently lost the destroyed
    row because the next destroy() saw already_destroyed and
    short-circuited. Fix: emit FIRST, set flag AFTER success."""

    @pytest.mark.asyncio
    async def test_destroy_emit_failure_then_retry_emits_destroyed_row(
        self,
    ) -> None:
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        # backend.create returns SandboxSession Protocol; narrow to
        # the concrete DockerSiblingSession so mypy + the test can
        # access _destroyed.
        assert isinstance(session, DockerSiblingSession)
        # Reset after create's own lifecycle.created emit so we can
        # see the destroy path's emits cleanly.
        dh_store.append_with_precondition.reset_mock()
        # First destroy emit fails; second succeeds.
        dh_store.append_with_precondition.side_effect = [
            _AuditFailure("transient audit-append failure on destroy"),
            (uuid.uuid4(), b"\x00" * 32),
        ]

        with pytest.raises(_AuditFailure):
            await backend.destroy(session)
        # Flag MUST still be False because the audit emit failed —
        # otherwise the retry below would skip emission permanently.
        assert session._destroyed is False, (
            "destroy() MUST NOT set _destroyed=True before emit "
            "succeeds. R2 P1.2 reviewer fix — transient audit "
            "failure must be retry-able."
        )

        # Retry destroy — this time the audit append succeeds.
        await backend.destroy(session)

        # Flag now True after the successful retry
        assert session._destroyed is True
        # Both attempts hit the audit store; the second one emitted
        # the destroyed row.
        assert dh_store.append_with_precondition.await_count == 2
        # The second call's record_builder produces a
        # lifecycle.destroyed row (proving the retry actually
        # emitted, not just no-op'd).
        record_builder = dh_store.append_with_precondition.await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.destroyed"
        assert "duration_s" in record.payload

    @pytest.mark.asyncio
    async def test_destroy_succeeds_then_second_destroy_is_silent_no_op(
        self,
    ) -> None:
        """Sanity: the retry contract MUST coexist with idempotent
        no-op when emit DID succeed. R1 P1.2 idempotency invariant
        preserved through the R2 P1.2 reorder."""
        dh_store = _make_dh_store()
        backend = _make_backend(dh_store=dh_store)
        session = await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
        )
        assert isinstance(session, DockerSiblingSession)
        dh_store.append_with_precondition.reset_mock()

        await backend.destroy(session)
        await backend.destroy(session)  # idempotent — no second emit

        # Exactly ONE destroyed emission across two destroy() calls
        dh_store.append_with_precondition.assert_awaited_once()
        assert session._destroyed is True

"""Sprint 8.5 T12 — DockerSibling checkpoint/suspend/wake coverage repair.

NON-env-gated focused regressions closing the missing lines + branches
on ``src/cognic_agentos/sandbox/backends/docker_sibling.py`` introduced
by Sprint 8.5 T6 (the ``wake()`` / ``checkpoint()`` / ``suspend()``
resumable-session pipeline + the ``tar`` workspace-snapshot helpers).

The end-to-end suite for this code lives in the env-gated
``test_docker_sibling_checkpoint.py`` (skips unless
``COGNIC_RUN_DOCKER_SANDBOX=1`` + a live Docker daemon). CI does not
set that env var, so on a normal run the new T6 code is uncovered and
the critical-controls coverage gate (95% line / 90% branch floor at
``tools/check_critical_coverage.py``) goes RED.

This file mirrors the Sprint-8A ``test_docker_sibling_coverage_branches.py``
pattern: ``pytest.importorskip("aiodocker")`` then ``unittest.mock``
(``AsyncMock`` / ``MagicMock``) to drive the production code paths
WITHOUT a live daemon. The ``aiodocker`` calls + the
``CheckpointStore`` seam + the audit emitters are all mocked.

Every test names the production branch it covers + the doctrine /
behaviour that branch implements. None of these tests are vacuous —
each drives a real production code path AND asserts the resulting
behaviour (return value, raised exception, audit-emit shape, or
mock-call shape).
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")

import uuid as _uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    CheckpointId,
    PackAdmissionContext,
    SandboxLifecycleRefused,
    SandboxPolicy,
)
from cognic_agentos.sandbox.backends import docker_sibling as _ds
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
    _SuspendEventIdCorruptError,
)
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointMetadata,
    TombstoneCorruptError,
    TombstoneRecord,
)

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
    checkpoint_store: AsyncMock | None = None,
) -> DockerSiblingSandboxBackend:
    """Construct a DockerSiblingSandboxBackend with mocked deps.

    The catalog defaults to ``is_canonical=True`` (admission accept);
    the rego decision defaults to ``allow=True``. ``checkpoint_store``
    is None unless explicitly supplied so the store-unwired refusal
    branches can be exercised.
    """
    if docker_client is None:
        docker_client = AsyncMock()
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
        warm_pool=None,
        checkpoint_store=checkpoint_store,
    )


def _make_metadata(
    *,
    tenant_id: str = "t-1",
    created_at: datetime | None = None,
    retention_window_s: int = 86_400,
    checkpoint_id: str | None = None,
) -> CheckpointMetadata:
    """A real CheckpointMetadata so wake()'s field accesses
    (``tenant_id`` / ``created_at`` / ``retention_window_s`` /
    ``checkpoint_id`` / ``policy`` / ``pack_context``) exercise the
    genuine attribute surface, not a MagicMock auto-attribute."""
    return CheckpointMetadata(
        checkpoint_id=CheckpointId(checkpoint_id or _uuid.uuid4().hex),
        session_id="s-1",
        tenant_id=tenant_id,
        label="__suspend__",
        created_at=created_at or datetime.now(UTC),
        policy=_POLICY,
        pack_context=_PACK_CTX,
        retention_window_s=retention_window_s,
    )


def _make_session(
    backend: DockerSiblingSandboxBackend,
    *,
    suspended: bool = False,
) -> DockerSiblingSession:
    return DockerSiblingSession(
        session_id="s-1",
        tenant_id="t-1",
        policy=_POLICY,
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _actor_subject="test-actor",
        _internal_network_name="net-internal-1",
        _sidecar_container_name="s-1-proxy",
        _egress_network_name="net-egress-1",
        _suspended=suspended,
    )


# ---------------------------------------------------------------------------
# wake() — checkpoint_store-unwired NotImplementedError guard
# ---------------------------------------------------------------------------


class TestWakeStoreUnwired:
    """docker_sibling.py:1447-1452 — branch [1447,1448].

    ``wake()`` requires a ``CheckpointStore`` wired at construction;
    a backend constructed with ``checkpoint_store=None`` (the Sprint-8A
    default) MUST refuse fail-loud with ``NotImplementedError`` per the
    CLAUDE.md production-grade rule — a silent no-op would let a caller
    believe a session was restored when it was not.
    """

    @pytest.mark.asyncio
    async def test_wake_raises_not_implemented_when_store_unwired(self) -> None:
        """docker_sibling.py:1448 — store-None NotImplementedError."""
        backend = _make_backend(checkpoint_store=None)
        with pytest.raises(NotImplementedError, match="requires a CheckpointStore"):
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")


# ---------------------------------------------------------------------------
# wake() — Step 1 tombstone refusals
# ---------------------------------------------------------------------------


class TestWakeTombstoneRefusals:
    """docker_sibling.py wake() Step 1 — tombstone-first ordering.

    ``load_tombstone`` runs BEFORE ``load_latest`` (LOAD-BEARING). A
    non-None tombstone OR a ``TombstoneCorruptError`` BOTH surface as
    the SAME closed-enum ``sandbox_wake_session_tombstoned`` so an
    operator's destroy() intent survives tampering (P1.r6 fail-closed).
    """

    @pytest.mark.asyncio
    async def test_wake_refuses_when_tombstone_present(self) -> None:
        """docker_sibling.py:1478-1487 — non-None tombstone refusal."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(
            return_value=TombstoneRecord(
                tombstoned_at=datetime.now(UTC),
                tombstoned_by="operator@bank",
                retained_until=datetime.now(UTC) + timedelta(days=7),
            )
        )
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        # load_latest MUST NOT have run — tombstone-first ordering.
        store.load_latest.assert_not_called()

    @pytest.mark.asyncio
    async def test_wake_refuses_when_tombstone_sentinel_is_corrupt(self) -> None:
        """docker_sibling.py:1468-1477 — TombstoneCorruptError → SAME
        closed-enum value (fail-closed; operator intent survives)."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(
            side_effect=TombstoneCorruptError("sentinel bytes truncated")
        )
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_session_tombstoned"
        assert "corrupt" in (exc.value.detail or "")


# ---------------------------------------------------------------------------
# wake() — Step 1(c) corrupt metadata
# ---------------------------------------------------------------------------


class TestWakeCorruptMetadata:
    """docker_sibling.py:1498-1505 — ``load_latest`` raising ValueError
    (corrupt metadata bytes on disk) maps to the distinct
    ``sandbox_wake_checkpoint_corrupt`` closed-enum — separable from
    operator-destroy (tombstoned) + genuinely-absent (not_found).
    """

    @pytest.mark.asyncio
    async def test_wake_maps_value_error_to_checkpoint_corrupt(self) -> None:
        """docker_sibling.py:1502-1505 — ValueError → checkpoint_corrupt."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(side_effect=ValueError("metadata json malformed"))
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        assert "malformed" in (exc.value.detail or "")


# ---------------------------------------------------------------------------
# wake() — Step 2 tenant cross-check
# ---------------------------------------------------------------------------


class TestWakeTenantCrossCheck:
    """docker_sibling.py:1518-1527 — defence-in-depth identity boundary.

    ``session_id`` alone is NEVER authorization (spec §2.6). When the
    loaded metadata's ``tenant_id`` does not match the caller's, wake
    refuses with ``sandbox_wake_tenant_mismatch`` even though the
    prefix-keyed lookup should already have isolated tenants.
    """

    @pytest.mark.asyncio
    async def test_wake_refuses_on_metadata_tenant_mismatch(self) -> None:
        """docker_sibling.py:1519-1527 — tenant_id mismatch refusal."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        # Metadata belongs to a DIFFERENT tenant than the caller.
        store.load_latest = AsyncMock(
            return_value=(_make_metadata(tenant_id="t-OTHER"), b"tar-bytes")
        )
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_tenant_mismatch"


# ---------------------------------------------------------------------------
# wake() — Step 3 retention-expired
# ---------------------------------------------------------------------------


class TestWakeRetentionExpired:
    """docker_sibling.py:1536-1547 — branch [1538,1539].

    The reaper sweeps asynchronously; a just-expired checkpoint may
    still be on disk between expiry + the next reaper run. wake() MUST
    refuse independently of reaper progress with
    ``sandbox_wake_checkpoint_retention_expired``.
    """

    @pytest.mark.asyncio
    async def test_wake_refuses_when_checkpoint_age_exceeds_retention(self) -> None:
        """docker_sibling.py:1539 — age_s >= retention_window_s refusal."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        # Created 2 days ago, retention window 1 day → expired.
        old_created = datetime.now(UTC) - timedelta(days=2)
        store.load_latest = AsyncMock(
            return_value=(
                _make_metadata(created_at=old_created, retention_window_s=86_400),
                b"tar-bytes",
            )
        )
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_retention_expired"


# ---------------------------------------------------------------------------
# wake() — Step 4 admit_policy revalidation re-wrap
# ---------------------------------------------------------------------------


class TestWakePolicyRevalidation:
    """docker_sibling.py:1566-1581 — Step 4 re-runs ``admit_policy``
    against LIVE tenant state. A session admitted under the old tenant
    max could no longer admit today; any Sprint-8A
    ``SandboxLifecycleRefused`` is re-wrapped as
    ``sandbox_wake_policy_revalidation_failed`` with the original
    reason preserved in ``detail`` for examiner traceability.
    """

    @pytest.mark.asyncio
    async def test_wake_rewraps_admit_policy_refusal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """docker_sibling.py:1577-1581 — admit_policy refusal re-wrap."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(return_value=(_make_metadata(), b"tar-bytes"))
        backend = _make_backend(checkpoint_store=store)
        # admit_policy raises an original Sprint-8A refusal.
        monkeypatch.setattr(
            _ds,
            "admit_policy",
            AsyncMock(
                side_effect=SandboxLifecycleRefused(
                    "sandbox_policy_exceeds_tenant_max_cpu",
                    detail="tenant tightened cpu cap since suspend",
                )
            ),
        )
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"
        # Original reason preserved in detail for traceability.
        assert "sandbox_policy_exceeds_tenant_max_cpu" in (exc.value.detail or "")


# ---------------------------------------------------------------------------
# wake() — Step 5 suspend-event linkage corrupt
# ---------------------------------------------------------------------------


class TestWakeSuspendLinkageCorrupt:
    """docker_sibling.py:1590-1600 — Step 5 reads the suspend-event
    linkage side-blob BEFORE any fresh Docker resources are created.
    A missing or malformed linkage maps to
    ``sandbox_wake_checkpoint_corrupt`` — wake refuses at this seam
    rather than emitting a NIL UUID + deferring failure downstream.
    """

    @pytest.mark.asyncio
    async def test_wake_refuses_when_suspend_event_linkage_corrupt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:1596-1600 — _SuspendEventIdCorruptError →
        sandbox_wake_checkpoint_corrupt; no Docker resources created."""
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(return_value=(_make_metadata(), b"tar-bytes"))
        backend = _make_backend(checkpoint_store=store)
        monkeypatch.setattr(_ds, "admit_policy", AsyncMock())
        monkeypatch.setattr(
            backend,
            "_read_suspend_event_id",
            AsyncMock(side_effect=_SuspendEventIdCorruptError("side-blob missing")),
        )
        create_net = AsyncMock()
        monkeypatch.setattr(backend, "_create_internal_network", create_net)
        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        assert exc.value.reason == "sandbox_wake_checkpoint_corrupt"
        # Step 5 runs BEFORE Step 6 — no network created on this path.
        create_net.assert_not_awaited()


# ---------------------------------------------------------------------------
# wake() — Step 6-8 green path + rollback
# ---------------------------------------------------------------------------


class TestWakeGreenPathAndRollback:
    """docker_sibling.py:1611-1681 — wake() Steps 6-8.

    Step 6 creates fresh networks + sidecar + sandbox container +
    restores the workspace tar; Step 7 builds a fresh
    ``DockerSiblingSession`` with the ORIGINAL session_id +
    ``warm_pool_hit=False``; Step 8 emits ``sandbox.lifecycle.woken``
    with the linkage payload. The Step-6 ``except`` envelope tears
    down partial state + re-raises.
    """

    @pytest.mark.asyncio
    async def test_wake_green_path_builds_session_and_emits_woken(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:1611-1681 — full green path."""
        metadata = _make_metadata()
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(return_value=(metadata, b"tar-bytes"))
        backend = _make_backend(checkpoint_store=store)
        suspend_uuid = _uuid.uuid4()
        monkeypatch.setattr(_ds, "admit_policy", AsyncMock())
        monkeypatch.setattr(backend, "_read_suspend_event_id", AsyncMock(return_value=suspend_uuid))
        monkeypatch.setattr(backend, "_create_internal_network", AsyncMock())
        monkeypatch.setattr(backend, "_create_egress_network", AsyncMock())
        monkeypatch.setattr(backend, "_start_proxy_sidecar", AsyncMock())
        monkeypatch.setattr(backend, "_start_sandbox_container", AsyncMock())
        restore_tar = AsyncMock()
        monkeypatch.setattr(backend, "_restore_workspace_tar", restore_tar)
        woken_emit = AsyncMock()
        monkeypatch.setattr(_ds, "sandbox_lifecycle_woken", woken_emit)

        session = await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")

        assert isinstance(session, DockerSiblingSession)
        # ORIGINAL session_id preserved (continuity is the whole point).
        assert session.session_id == "s-1"
        # warm_pool_hit=False — a woken session is never a warm-pool hit.
        assert session.warm_pool_hit is False
        # Step 6 resources all created; tar restored with the loaded bytes.
        restore_tar.assert_awaited_once()
        assert restore_tar.await_args is not None
        assert restore_tar.await_args.kwargs["snapshot_bytes"] == b"tar-bytes"
        # Step 8 woken emit carries the linkage payload keys.
        woken_emit.assert_awaited_once()
        assert woken_emit.await_args is not None
        emit_kwargs = woken_emit.await_args.kwargs
        assert emit_kwargs["suspend_event_id"] == suspend_uuid
        assert emit_kwargs["restored_from_checkpoint_id"] == metadata.checkpoint_id

    @pytest.mark.asyncio
    async def test_wake_rolls_back_when_sandbox_container_start_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:1636-1646 — Step-6 except envelope.

        A failure inside the sidecar/container/restore block tears
        down partial state via ``_teardown_session_state`` + re-raises
        so the caller sees the failure + no resources leak.
        """
        store = AsyncMock()
        store.load_tombstone = AsyncMock(return_value=None)
        store.load_latest = AsyncMock(return_value=(_make_metadata(), b"tar-bytes"))
        backend = _make_backend(checkpoint_store=store)
        monkeypatch.setattr(_ds, "admit_policy", AsyncMock())
        monkeypatch.setattr(
            backend, "_read_suspend_event_id", AsyncMock(return_value=_uuid.uuid4())
        )
        monkeypatch.setattr(backend, "_create_internal_network", AsyncMock())
        monkeypatch.setattr(backend, "_create_egress_network", AsyncMock())
        monkeypatch.setattr(backend, "_start_proxy_sidecar", AsyncMock())
        monkeypatch.setattr(
            backend,
            "_start_sandbox_container",
            AsyncMock(side_effect=RuntimeError("sandbox container start refused")),
        )
        teardown = AsyncMock()
        monkeypatch.setattr(backend, "_teardown_session_state", teardown)
        with pytest.raises(RuntimeError, match="sandbox container start refused"):
            await backend.wake("s-1", actor=_ACTOR, tenant_id="t-1")
        # Partial-create rollback fired.
        teardown.assert_awaited_once()


# ---------------------------------------------------------------------------
# _do_checkpoint — store-unwired + suspended-session guards + green path
# ---------------------------------------------------------------------------


class TestDoCheckpoint:
    """docker_sibling.py:2148-2214 — ``checkpoint()`` delegates here.

    * 2166-2172 — store-unwired NotImplementedError.
    * 2173-2183 — branch [2173,2185]: a suspended session's
      checkpoint() refuses fail-loud (the container is gone).
    * 2185-2214 — green path: tar snapshot → persist → policy_digest →
      emit ``sandbox.lifecycle.checkpointed`` → return CheckpointId.
    """

    @pytest.mark.asyncio
    async def test_checkpoint_raises_not_implemented_when_store_unwired(self) -> None:
        """docker_sibling.py:2167 — store-None NotImplementedError."""
        backend = _make_backend(checkpoint_store=None)
        session = _make_session(backend)
        with pytest.raises(NotImplementedError, match="requires a CheckpointStore"):
            await session.checkpoint("manual-1")

    @pytest.mark.asyncio
    async def test_checkpoint_refuses_on_suspended_session(self) -> None:
        """docker_sibling.py:2173-2183 — branch [2173,2185] suspended guard."""
        backend = _make_backend(checkpoint_store=AsyncMock())
        session = _make_session(backend, suspended=True)
        with pytest.raises(RuntimeError, match=r"was suspend\(\)ed"):
            await session.checkpoint("manual-1")

    @pytest.mark.asyncio
    async def test_checkpoint_green_path_persists_and_emits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:2185-2214 — tar → persist → emit → return."""
        store = AsyncMock()
        minted = CheckpointId(_uuid.uuid4().hex)
        store.persist = AsyncMock(return_value=minted)
        backend = _make_backend(checkpoint_store=store)
        session = _make_session(backend)
        monkeypatch.setattr(
            backend, "_create_workspace_tar", AsyncMock(return_value=b"tar-czf-bytes")
        )
        ckpt_emit = AsyncMock()
        monkeypatch.setattr(_ds, "sandbox_lifecycle_checkpointed", ckpt_emit)

        result = await session.checkpoint("manual-label")

        assert result == minted
        # persist called with the captured tar bytes + the reserved kwargs.
        store.persist.assert_awaited_once()
        assert store.persist.await_args is not None
        persist_kwargs = store.persist.await_args.kwargs
        assert persist_kwargs["snapshot_bytes"] == b"tar-czf-bytes"
        assert persist_kwargs["label"] == "manual-label"
        # vault_lease_refs=() always in Sprint 8.5 (Q4 lock).
        assert persist_kwargs["vault_lease_refs"] == ()
        # checkpointed audit row emitted with a policy_digest.
        ckpt_emit.assert_awaited_once()
        assert ckpt_emit.await_args is not None
        emit_kwargs = ckpt_emit.await_args.kwargs
        assert emit_kwargs["checkpoint_id"] == minted
        assert emit_kwargs["label"] == "manual-label"
        # policy_digest is a sha256 hex (64 chars).
        assert len(emit_kwargs["policy_digest"]) == 64


# ---------------------------------------------------------------------------
# _do_suspend — store-unwired + double-suspend guard + green ordering
# ---------------------------------------------------------------------------


class TestDoSuspend:
    """docker_sibling.py:2216-2331 — ``suspend()`` delegates here.

    * 2268-2272 — store-unwired NotImplementedError.
    * 2273-2280 — double-suspend on the same session is a usage bug;
      surfaces fail-loud (NOT a no-op).
    * 2282-2331 — green ordering: final checkpoint → teardown → emit
      suspended → write linkage side-blob → flip ``_suspended``.
    """

    @pytest.mark.asyncio
    async def test_suspend_raises_not_implemented_when_store_unwired(self) -> None:
        """docker_sibling.py:2269 — store-None NotImplementedError."""
        backend = _make_backend(checkpoint_store=None)
        session = _make_session(backend)
        with pytest.raises(NotImplementedError, match="requires a CheckpointStore"):
            await session.suspend()

    @pytest.mark.asyncio
    async def test_suspend_refuses_on_already_suspended_session(self) -> None:
        """docker_sibling.py:2273-2280 — double-suspend guard."""
        backend = _make_backend(checkpoint_store=AsyncMock())
        session = _make_session(backend, suspended=True)
        with pytest.raises(RuntimeError, match="already suspended"):
            await session.suspend()

    @pytest.mark.asyncio
    async def test_suspend_green_path_ordering_and_flag_flip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """docker_sibling.py:2282-2331 — green-path ordering + Step 5
        ``_suspended`` flag flip.

        The reviewer-locked ordering is: checkpoint → teardown → emit
        suspended → write linkage side-blob → flip ``_suspended``.
        """
        store = AsyncMock()
        backend = _make_backend(checkpoint_store=store)
        session = _make_session(backend)
        final_id = CheckpointId(_uuid.uuid4().hex)
        record_id = _uuid.uuid4()
        do_checkpoint = AsyncMock(return_value=final_id)
        monkeypatch.setattr(backend, "_do_checkpoint", do_checkpoint)
        teardown = AsyncMock()
        monkeypatch.setattr(backend, "_teardown_session_state", teardown)
        suspended_emit = AsyncMock(return_value=(record_id, "new-hash"))
        monkeypatch.setattr(_ds, "sandbox_lifecycle_suspended", suspended_emit)
        write_linkage = AsyncMock()
        monkeypatch.setattr(backend, "_write_suspend_event_id", write_linkage)

        assert session._suspended is False
        await session.suspend()

        # Step 1 — final checkpoint with the reserved __suspend__ label.
        do_checkpoint.assert_awaited_once_with(session, "__suspend__")
        # Step 2 — teardown fired.
        teardown.assert_awaited_once()
        # Step 3 — suspended row emitted with the final checkpoint id.
        suspended_emit.assert_awaited_once()
        assert suspended_emit.await_args is not None
        assert suspended_emit.await_args.kwargs["final_checkpoint_id"] == final_id
        # Step 4 — linkage side-blob written with the emitted record_id.
        write_linkage.assert_awaited_once()
        assert write_linkage.await_args is not None
        assert write_linkage.await_args.kwargs["record_id"] == record_id
        # Step 5 — _suspended flag flipped True (in-process state lock).
        assert session._suspended is True


# ---------------------------------------------------------------------------
# _create_workspace_tar — green path + non-zero exit
# ---------------------------------------------------------------------------


class _FakeMessage:
    """Mimics an aiodocker exec stream message (stream + data)."""

    def __init__(self, stream: int, data: bytes) -> None:
        self.stream = stream
        self.data = data


def _fake_exec_stream(messages: list[Any]) -> Any:
    """Build a fake exec object whose ``start(detach=...)`` returns an
    async-context-manager stream yielding ``messages`` then None."""
    msg_iter = iter([*messages, None])

    class _Stream:
        async def __aenter__(self) -> _Stream:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def read_out(self) -> Any:
            return next(msg_iter)

        async def write_in(self, data: bytes) -> None:
            return None

        async def close(self) -> None:
            return None

    return _Stream()


class TestCreateWorkspaceTar:
    """docker_sibling.py:2333-2368 — ``tar czf - -C /workspace .`` over
    the exec channel; stdout bytes captured + returned; a non-zero
    exit raises ``RuntimeError`` carrying the stderr text.
    """

    @pytest.mark.asyncio
    async def test_create_workspace_tar_returns_stdout_bytes(self) -> None:
        """docker_sibling.py:2342-2368 — green path: stdout joined +
        returned; a stderr chunk on the same stream is ignored."""
        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(
            return_value=_fake_exec_stream(
                [
                    _FakeMessage(1, b"tar-part-1"),
                    _FakeMessage(2, b"benign tar warning"),
                    _FakeMessage(1, b"tar-part-2"),
                ]
            )
        )
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})
        container = AsyncMock()
        container.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=container)
        backend = _make_backend(docker_client=docker_client)

        result = await backend._create_workspace_tar(session_id="s-1")
        # Only the stdout (stream==1) chunks join into the tar bytes.
        assert result == b"tar-part-1tar-part-2"

    @pytest.mark.asyncio
    async def test_create_workspace_tar_raises_on_nonzero_exit(self) -> None:
        """docker_sibling.py:2362-2367 — non-zero tar exit raises
        RuntimeError carrying the captured stderr."""
        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(
            return_value=_fake_exec_stream([_FakeMessage(2, b"tar: permission denied")])
        )
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 2})
        container = AsyncMock()
        container.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=container)
        backend = _make_backend(docker_client=docker_client)

        with pytest.raises(RuntimeError, match="exited 2") as exc:
            await backend._create_workspace_tar(session_id="s-1")
        assert "permission denied" in str(exc.value)


# ---------------------------------------------------------------------------
# _restore_workspace_tar — green path + non-zero exit
# ---------------------------------------------------------------------------


class TestRestoreWorkspaceTar:
    """docker_sibling.py:2370-2409 — ``tar xzf - -C /workspace`` over the
    exec channel, snapshot bytes piped on stdin; non-zero exit raises.
    """

    @pytest.mark.asyncio
    async def test_restore_workspace_tar_writes_stdin_and_returns(self) -> None:
        """docker_sibling.py:2382-2409 — green path: snapshot written
        to stdin; exit 0 → returns cleanly."""
        exec_obj = AsyncMock()
        # A stderr message exercises the [2400,2401] stderr-append branch.
        exec_obj.start = MagicMock(return_value=_fake_exec_stream([_FakeMessage(2, b"tar: noise")]))
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})
        container = AsyncMock()
        container.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=container)
        backend = _make_backend(docker_client=docker_client)

        # Should complete without raising.
        await backend._restore_workspace_tar(session_id="s-1", snapshot_bytes=b"snapshot-tar-bytes")
        container.exec.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_restore_workspace_tar_raises_on_nonzero_exit(self) -> None:
        """docker_sibling.py:2404-2409 — non-zero tar-xzf exit raises
        RuntimeError carrying the captured stderr."""
        exec_obj = AsyncMock()
        exec_obj.start = MagicMock(
            return_value=_fake_exec_stream([_FakeMessage(2, b"tar: corrupt archive")])
        )
        exec_obj.inspect = AsyncMock(return_value={"ExitCode": 1})
        container = AsyncMock()
        container.exec = AsyncMock(return_value=exec_obj)
        docker_client = AsyncMock()
        docker_client.containers.get = AsyncMock(return_value=container)
        backend = _make_backend(docker_client=docker_client)

        with pytest.raises(RuntimeError, match="exited 1") as exc:
            await backend._restore_workspace_tar(session_id="s-1", snapshot_bytes=b"bad-bytes")
        assert "corrupt archive" in str(exc.value)


# ---------------------------------------------------------------------------
# _write_suspend_event_id / _read_suspend_event_id — linkage side-blob
# ---------------------------------------------------------------------------


class TestSuspendEventIdSideBlob:
    """docker_sibling.py:2411-2470 — the suspend→wake linkage side-blob.

    ``_write_suspend_event_id`` persists the suspend-emitted record_id
    as a UTF-8 string at ``<tenant>/<session>/<checkpoint>.suspend_event_id``;
    ``_read_suspend_event_id`` reads it back. Missing / non-UTF-8 /
    non-UUID bytes ALL surface as ``_SuspendEventIdCorruptError`` so
    wake() can map them to ``sandbox_wake_checkpoint_corrupt``.
    """

    @pytest.mark.asyncio
    async def test_write_suspend_event_id_puts_uuid_at_sibling_key(self) -> None:
        """docker_sibling.py:2428-2435 — side-blob put at the derived key."""
        object_store = AsyncMock()
        store = MagicMock()
        store._object_store = object_store
        backend = _make_backend(checkpoint_store=store)
        record_id = _uuid.uuid4()
        ckpt = CheckpointId(_uuid.uuid4().hex)

        await backend._write_suspend_event_id(
            session_id="s-1",
            tenant_id="t-1",
            checkpoint_id=ckpt,
            record_id=record_id,
        )
        object_store.put.assert_awaited_once()
        assert object_store.put.await_args is not None
        args = object_store.put.await_args.args
        # bucket, key, body — key carries the .suspend_event_id suffix.
        assert args[0] == "sandbox-checkpoints"
        assert args[1] == f"t-1/s-1/{ckpt}.suspend_event_id"
        assert args[2] == str(record_id).encode("utf-8")

    @pytest.mark.asyncio
    async def test_read_suspend_event_id_round_trips_uuid(self) -> None:
        """docker_sibling.py:2453-2462 — green path: bytes → UUID."""
        record_id = _uuid.uuid4()
        object_store = AsyncMock()
        object_store.get = AsyncMock(return_value=str(record_id).encode("utf-8"))
        store = MagicMock()
        store._object_store = object_store
        backend = _make_backend(checkpoint_store=store)
        ckpt = CheckpointId(_uuid.uuid4().hex)

        result = await backend._read_suspend_event_id(
            session_id="s-1", tenant_id="t-1", checkpoint_id=ckpt
        )
        assert result == record_id

    @pytest.mark.asyncio
    async def test_read_suspend_event_id_raises_on_missing_blob(self) -> None:
        """docker_sibling.py:2457-2460 — FileNotFoundError → corrupt marker."""
        object_store = AsyncMock()
        object_store.get = AsyncMock(side_effect=FileNotFoundError("no such key"))
        store = MagicMock()
        store._object_store = object_store
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(_SuspendEventIdCorruptError, match="missing"):
            await backend._read_suspend_event_id(
                session_id="s-1",
                tenant_id="t-1",
                checkpoint_id=CheckpointId(_uuid.uuid4().hex),
            )

    @pytest.mark.asyncio
    async def test_read_suspend_event_id_raises_on_non_uuid_bytes(self) -> None:
        """docker_sibling.py:2467-2470 — non-UUID string → corrupt marker."""
        object_store = AsyncMock()
        object_store.get = AsyncMock(return_value=b"definitely-not-a-uuid")
        store = MagicMock()
        store._object_store = object_store
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(_SuspendEventIdCorruptError, match="not a UUID"):
            await backend._read_suspend_event_id(
                session_id="s-1",
                tenant_id="t-1",
                checkpoint_id=CheckpointId(_uuid.uuid4().hex),
            )

    @pytest.mark.asyncio
    async def test_read_suspend_event_id_raises_on_non_utf8_bytes(self) -> None:
        """docker_sibling.py:2463-2466 — branch [2463,2464] non-UTF-8
        bytes → corrupt marker (UnicodeDecodeError path)."""
        object_store = AsyncMock()
        # 0xff is invalid as a UTF-8 lead byte.
        object_store.get = AsyncMock(return_value=b"\xff\xfe\xff")
        store = MagicMock()
        store._object_store = object_store
        backend = _make_backend(checkpoint_store=store)
        with pytest.raises(_SuspendEventIdCorruptError, match="not UTF-8"):
            await backend._read_suspend_event_id(
                session_id="s-1",
                tenant_id="t-1",
                checkpoint_id=CheckpointId(_uuid.uuid4().hex),
            )


# ---------------------------------------------------------------------------
# _policy_to_canonical_dict — canonical-bytes-safe projection
# ---------------------------------------------------------------------------


class TestPolicyToCanonicalDict:
    """docker_sibling.py:2472-2500 — the static helper that projects a
    ``SandboxPolicy`` onto a canonical-bytes-safe dict for the
    ``policy_digest`` computation. Drift between this dict + the
    ``CheckpointMetadata.to_storage_payload`` policy sub-tree would
    break the chain-verifier's policy_digest cross-verify.
    """

    def test_policy_to_canonical_dict_projects_all_scalar_fields(self) -> None:
        """docker_sibling.py:2482-2500 — every scalar field projected;
        egress_allow_list + writable_mounts converted to lists."""
        policy = SandboxPolicy(
            cpu_cores=2.0,
            cpu_time_budget_s=10.0,
            memory_mb=512,
            walltime_s=60.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "b" * 64,
            egress_allow_list=("api.example.com",),
            vault_path=None,
        )
        result = DockerSiblingSandboxBackend._policy_to_canonical_dict(policy)
        assert result["cpu_cores"] == 2.0
        assert result["memory_mb"] == 512
        assert result["walltime_s"] == 60.0
        assert result["runtime_image"].endswith("b" * 64)
        # egress_allow_list converted from tuple → list (canonical-safe).
        assert result["egress_allow_list"] == ["api.example.com"]
        assert isinstance(result["egress_allow_list"], list)
        # writable_mounts is a list (empty here) of dicts.
        assert result["writable_mounts"] == []
